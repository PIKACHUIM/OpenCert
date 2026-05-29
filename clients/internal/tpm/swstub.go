// Package tpm - SoftwareStub 后端：用本地受保护文件 + AES-256-GCM 模拟 TPM。
//
// 严格遵守与真 TPM 同语义的接口：
//   - bindKey（32B 随机密钥，存于 OS 受保护目录）= 模拟 TPM Storage Root Key（SRK）
//   - NV 槽数据 = bindKey + authValue 派生 KEK，再 AES-GCM 加密；元数据落 JSON 文件
//   - WrappedKey = bindKey + authValue 派生 KEK 加密 PKCS#8 私钥；签名/解密时
//     在内存中临时反序列化执行（真 TPM 后端会替换成 TBS/CNG/go-tpm 调用）
//
// 该后端"不能"真正阻止物理攻击或 root 用户读取 bind.key 文件，
// 但接口与数据流已经按真 TPM 模型组织，未来切换到真 TPM 实现时上层无需改动。
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// swStubProvider 是 SoftwareStub 后端实现。
type swStubProvider struct {
	mu          sync.Mutex
	bindKey     []byte
	rootDir     string
	nextHandle  uint32
	loaded      map[LoadedHandle]*loadedKeyState
	nextLoadedH uint32
}

type loadedKeyState struct {
	wrapped *WrappedKey
	priv    crypto.PrivateKey
}

// NewSoftwareStub 创建一个软件 stub Provider。
func NewSoftwareStub() (Provider, error) {
	dir := softwareStubDir()
	if err := os.MkdirAll(filepath.Join(dir, "nv"), 0o700); err != nil {
		return nil, fmt.Errorf("创建 sw-stub 目录失败: %w", err)
	}
	bindKey, err := loadOrCreateBindKey(filepath.Join(dir, "bind.key"))
	if err != nil {
		return nil, err
	}
	p := &swStubProvider{
		bindKey:     bindKey,
		rootDir:     dir,
		nextHandle:  0x01400000,
		loaded:      make(map[LoadedHandle]*loadedKeyState),
		nextLoadedH: 0x80000000,
	}
	p.recoverNextHandle()
	return p, nil
}

func (p *swStubProvider) Available() bool      { return true }
func (p *swStubProvider) PlatformName() string { return string(TPMPlatformSWStub) }

func (p *swStubProvider) Seal(data []byte) ([]byte, error)   { return sealWithAES(p.bindKey, data) }
func (p *swStubProvider) Unseal(blob []byte) ([]byte, error) { return unsealWithAES(p.bindKey, blob) }

// ===== NV 存储 =====

type nvFile struct {
	Label      string `json:"label"`
	Size       int    `json:"size"`
	Salt       []byte `json:"salt"`
	AuthDigest []byte `json:"auth_digest"`
	Wrap       []byte `json:"wrap"`
}

func (p *swStubProvider) nvPath(h NVHandle) string {
	return filepath.Join(p.rootDir, "nv", fmt.Sprintf("%08x.json", uint32(h)))
}

func (p *swStubProvider) NVDefine(label string, size int, authValue []byte) (NVHandle, error) {
	if size <= 0 || size > 8192 {
		return 0, fmt.Errorf("NV 槽大小 %d 超出范围 [1, 8192]", size)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		h := NVHandle(p.nextHandle)
		p.nextHandle++
		if _, err := os.Stat(p.nvPath(h)); errors.Is(err, os.ErrNotExist) {
			salt := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, salt); err != nil {
				return 0, err
			}
			f := nvFile{
				Label:      label,
				Size:       size,
				Salt:       salt,
				AuthDigest: nvAuthDigest(authValue, salt),
			}
			if err := writeJSONFile(p.nvPath(h), &f); err != nil {
				return 0, fmt.Errorf("写入 NV 元数据失败: %w", err)
			}
			return h, nil
		}
	}
}

func (p *swStubProvider) NVWrite(h NVHandle, authValue, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := readNVFile(p.nvPath(h))
	if err != nil {
		return err
	}
	if !hmac.Equal(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return ErrNVAuthFailed
	}
	if len(data) > f.Size {
		return fmt.Errorf("NV 写入数据长度 %d 超过槽容量 %d", len(data), f.Size)
	}
	kek := nvDeriveKEK(p.bindKey, authValue, f.Salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, data)
	if err != nil {
		return fmt.Errorf("NV 加密失败: %w", err)
	}
	f.Wrap = wrap
	return writeJSONFile(p.nvPath(h), f)
}

func (p *swStubProvider) NVRead(h NVHandle, authValue []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := readNVFile(p.nvPath(h))
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return nil, ErrNVAuthFailed
	}
	if len(f.Wrap) == 0 {
		return nil, fmt.Errorf("NV 槽 %08x 未写入数据", uint32(h))
	}
	kek := nvDeriveKEK(p.bindKey, authValue, f.Salt)
	defer zero(kek)
	plain, err := unsealWithAES(kek, f.Wrap)
	if err != nil {
		return nil, fmt.Errorf("NV 解密失败: %w", err)
	}
	return plain, nil
}

func (p *swStubProvider) NVUndefine(h NVHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := os.Remove(p.nvPath(h))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNVNotFound
	}
	return err
}

func (p *swStubProvider) recoverNextHandle() {
	entries, err := os.ReadDir(filepath.Join(p.rootDir, "nv"))
	if err != nil {
		return
	}
	maxH := uint32(0x01400000)
	for _, e := range entries {
		var v uint32
		if _, err := fmt.Sscanf(e.Name(), "%08x.json", &v); err == nil && v >= maxH {
			maxH = v + 1
		}
	}
	if maxH > p.nextHandle {
		p.nextHandle = maxH
	}
}

func nvAuthDigest(authValue, salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte("nv-auth/v1"))
	h.Write(salt)
	h.Write(authValue)
	return h.Sum(nil)
}

func nvDeriveKEK(bindKey, authValue, salt []byte) []byte {
	mac := hmac.New(sha256.New, bindKey)
	mac.Write([]byte("nv-kek/v1"))
	mac.Write(salt)
	mac.Write(authValue)
	return mac.Sum(nil)
}

// ===== 非对称密钥（high 模式） =====

type wrappedPrivate struct {
	Alg  KeyAlg `json:"alg"`
	Salt []byte `json:"salt"`
	Wrap []byte `json:"wrap"`
}

func (p *swStubProvider) CreateKey(alg KeyAlg, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	priv, pub, err := genKeyPair(alg)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := marshalPKCS8(priv)
	if err != nil {
		return nil, nil, err
	}
	defer zero(pkcs8)
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	kek := nvDeriveKEK(p.bindKey, authValue, salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, pkcs8)
	if err != nil {
		return nil, nil, fmt.Errorf("包装私钥失败: %w", err)
	}
	wpJSON, err := json.Marshal(wrappedPrivate{Alg: alg, Salt: salt, Wrap: wrap})
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := marshalPKIX(pub)
	if err != nil {
		return nil, nil, err
	}
	return &WrappedKey{
		Alg:        alg,
		Backend:    string(TPMPlatformSWStub),
		Public:     pubDER,
		Private:    wpJSON,
		AuthDigest: nvAuthDigest(authValue, salt),
	}, pub, nil
}

func (p *swStubProvider) ImportKey(privKeyDER []byte, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	// 解析私钥以获取算法和公钥
	priv, err := parsePKCS8(privKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析导入私钥失败: %w", err)
	}
	pub, alg, err := extractPubAndAlg(priv)
	if err != nil {
		return nil, nil, err
	}
	// 用同样的方式包装（与 CreateKey 一致）
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	kek := nvDeriveKEK(p.bindKey, authValue, salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, privKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("包装导入私钥失败: %w", err)
	}
	wpJSON, _ := json.Marshal(wrappedPrivate{Alg: alg, Salt: salt, Wrap: wrap})
	pubDER, err := marshalPKIX(pub)
	if err != nil {
		return nil, nil, err
	}
	return &WrappedKey{
		Alg:        alg,
		Backend:    string(TPMPlatformSWStub),
		Public:     pubDER,
		Private:    wpJSON,
		AuthDigest: nvAuthDigest(authValue, salt),
	}, pub, nil
}

func (p *swStubProvider) LoadKey(wrapped *WrappedKey, authValue []byte) (LoadedHandle, error) {
	if wrapped == nil {
		return 0, fmt.Errorf("wrapped 为空")
	}
	var wp wrappedPrivate
	if err := json.Unmarshal(wrapped.Private, &wp); err != nil {
		return 0, fmt.Errorf("解析 wrapped 私钥失败: %w", err)
	}
	if !hmac.Equal(wrapped.AuthDigest, nvAuthDigest(authValue, wp.Salt)) {
		return 0, ErrKeyAuthFailed
	}
	kek := nvDeriveKEK(p.bindKey, authValue, wp.Salt)
	defer zero(kek)
	pkcs8, err := unsealWithAES(kek, wp.Wrap)
	if err != nil {
		return 0, fmt.Errorf("解包装私钥失败: %w", err)
	}
	defer zero(pkcs8)
	priv, err := parsePKCS8(pkcs8)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	h := LoadedHandle(p.nextLoadedH)
	p.nextLoadedH++
	p.loaded[h] = &loadedKeyState{wrapped: wrapped, priv: priv}
	p.mu.Unlock()
	return h, nil
}

func (p *swStubProvider) Sign(h LoadedHandle, digest []byte, scheme SignScheme) ([]byte, error) {
	p.mu.Lock()
	st, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return signWithKey(st.priv, digest, scheme)
}

func (p *swStubProvider) Decrypt(h LoadedHandle, ciphertext []byte) ([]byte, error) {
	p.mu.Lock()
	st, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return decryptWithKey(st.priv, ciphertext)
}

func (p *swStubProvider) DecryptOAEP(h LoadedHandle, ciphertext, label []byte) ([]byte, error) {
	p.mu.Lock()
	st, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return decryptOAEPWithKey(st.priv, ciphertext, label)
}

func (p *swStubProvider) FlushHandle(h LoadedHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.loaded, h)
	return nil
}

// ===== 工具（mock 与 sw-stub 共享）=====

func genKeyPair(alg KeyAlg) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch alg {
	case KeyAlgRSA2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case KeyAlgRSA3072:
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case KeyAlgRSA4096:
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case KeyAlgECP256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case KeyAlgECP384:
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	case KeyAlgECP521:
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, &k.PublicKey, nil
	default:
		return nil, nil, ErrUnknownAlg
	}
}

func schemeToHashRSA(scheme SignScheme, digestLen int) (crypto.Hash, bool, error) {
	switch scheme {
	case SignSchemeRSAPKCS1SHA256:
		return crypto.SHA256, false, nil
	case SignSchemeRSAPKCS1SHA384:
		return crypto.SHA384, false, nil
	case SignSchemeRSAPKCS1SHA512:
		return crypto.SHA512, false, nil
	case SignSchemeRSAPSSSHA256:
		return crypto.SHA256, true, nil
	case SignSchemeRaw:
		switch digestLen {
		case sha256.Size:
			return crypto.SHA256, false, nil
		case 48: // SHA-384，crypto/sha512 包没有暴露常量
			return crypto.SHA384, false, nil
		case sha512.Size:
			return crypto.SHA512, false, nil
		default:
			return 0, false, fmt.Errorf("RSA Raw 模式无法识别 digest 长度 %d", digestLen)
		}
	default:
		return 0, false, ErrUnknownScheme
	}
}

func validateECDigestLen(scheme SignScheme, digestLen int) error {
	switch scheme {
	case SignSchemeECDSASHA256:
		if digestLen != sha256.Size {
			return fmt.Errorf("ECDSA-SHA256 需要 32 字节 digest，得到 %d", digestLen)
		}
	case SignSchemeECDSASHA384:
		if digestLen != 48 { // SHA-384 = 48 字节
			return fmt.Errorf("ECDSA-SHA384 需要 48 字节 digest，得到 %d", digestLen)
		}
	case SignSchemeECDSASHA512:
		if digestLen != sha512.Size {
			return fmt.Errorf("ECDSA-SHA512 需要 64 字节 digest，得到 %d", digestLen)
		}
	case SignSchemeRaw:
		// 不做严格校验
	default:
		return ErrUnknownScheme
	}
	return nil
}

func loadOrCreateBindKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("生成 SRK 失败: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("保存 SRK 失败: %w", err)
	}
	return key, nil
}

func softwareStubDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			base = os.Getenv("USERPROFILE")
		}
		return filepath.Join(base, "GlobalTrusts", "client-card", "tpm")
	default:
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".config", "globaltrusts", "clients", "tpm")
	}
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readNVFile(path string) (*nvFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNVNotFound
		}
		return nil, err
	}
	var f nvFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("解析 NV 元数据失败: %w", err)
	}
	return &f, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// 编译期断言：swStubProvider 实现 Provider。
var _ Provider = (*swStubProvider)(nil)
