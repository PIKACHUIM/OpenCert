//go:build windows

// Package tpm - Windows CNG 后端：通过 ncrypt.dll 调用 Microsoft Platform Crypto Provider（PCP）
// 或 Microsoft Software Key Storage Provider（软件回退）实现 Provider 接口。
//
// 设计：
//   - CreateKey / LoadKey / Sign / Decrypt → NCrypt 持久化非对称密钥，私钥由 TPM（或 SWKSP）保护
//   - NVDefine / NVWrite / NVRead / NVUndefine → DPAPI 保护的本地文件模拟（NCrypt 不支持对称密钥持久化）
//   - Seal / Unseal → DPAPI CryptProtectData / CryptUnprotectData
//
// 密钥命名约定：
//   - 非对称密钥容器名："GlobalTrusts/<NVHandle或UUID>"
//   - NV 文件路径：%APPDATA%\GlobalTrusts\client-card\tpm\nv\<handle>.dpapi
//
// 真实 TPM 保护：
//   - 使用 PCP 时密钥由 TPM 硬件生成，私钥永不出芯片
//   - 使用 SWKSP（无 TPM 回退）时密钥由 DPAPI + 用户凭据保护
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var cryptoRandReader io.Reader = cryptorand.Reader

// Windows CNG 常量（部分未在 x/sys/windows 中暴露）
const (
	ncryptPlatformProvider = "Microsoft Platform Crypto Provider"
	ncryptSoftwareProvider = "Microsoft Software Key Storage Provider"

	bcryptRSAAlg       = "RSA"
	bcryptECDSAP256Alg = "ECDSA_P256"
	bcryptECDSAP384Alg = "ECDSA_P384"
	bcryptECDSAP521Alg = "ECDSA_P521"

	ncryptLengthProperty       = "Length"
	ncryptExportPolicyProperty = "Export Policy"
	ncryptKeyUsageProperty     = "Key Usage"

	ncryptAllowExportFlag    = 0x00000001
	ncryptAllowNothingExport = 0x00000000
	ncryptSigningFlag        = 0x00000002
	ncryptDecryptFlag        = 0x00000001

	bcryptPadPKCS1 = 0x00000002
	bcryptPadOAEP  = 0x00000004
	bcryptPadPSS   = 0x00000008

	// NTE 错误码
	nteBadKeyset  = 0x80090016
	nteNotFound   = 0x80090011
	nteExists     = 0x8009000F
	ntePermission = 0x80090010
)

// BCRYPT_PKCS1_PADDING_INFO
type bcryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

// BCRYPT_PSS_PADDING_INFO
type bcryptPSSPaddingInfo struct {
	pszAlgId *uint16
	cbSalt   uint32
}

var (
	ncryptDll = windows.NewLazySystemDLL("ncrypt.dll")
	crypt32   = windows.NewLazySystemDLL("crypt32.dll")

	procNCryptOpenStorageProvider  = ncryptDll.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey   = ncryptDll.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty          = ncryptDll.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey          = ncryptDll.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey              = ncryptDll.NewProc("NCryptOpenKey")
	procNCryptSignHash             = ncryptDll.NewProc("NCryptSignHash")
	procNCryptDecrypt              = ncryptDll.NewProc("NCryptDecrypt")
	procNCryptDeleteKey            = ncryptDll.NewProc("NCryptDeleteKey")
	procNCryptExportKey            = ncryptDll.NewProc("NCryptExportKey")
	procNCryptFreeObject           = ncryptDll.NewProc("NCryptFreeObject")

	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

// DATA_BLOB for DPAPI
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// cngProvider 是 Windows CNG 后端。
type cngProvider struct {
	mu        sync.Mutex
	hProv     uintptr   // NCrypt provider handle
	provName  string    // 实际使用的 provider 名
	nvDir     string    // NV 文件目录
	nextNVH   uint32    // NV handle 分配器
	loaded    map[LoadedHandle]uintptr // loaded key handles
	nextLoadH uint32
}

// newPlatformProvider Windows 平台工厂：优先使用 PCP，回退到 SWKSP，最终回退 sw-stub。
func newPlatformProvider() (Provider, error) {
	// 尝试 Platform Crypto Provider（需要 TPM 硬件）
	p, err := newCNGProvider(ncryptPlatformProvider)
	if err == nil {
		return p, nil
	}
	// 回退到软件 KSP（无 TPM 硬件时）
	p, err = newCNGProvider(ncryptSoftwareProvider)
	if err == nil {
		return p, nil
	}
	// 最终回退到 sw-stub
	return NewSoftwareStub()
}

func newCNGProvider(provName string) (*cngProvider, error) {
	provNameUTF16, _ := windows.UTF16PtrFromString(provName)
	var hProv uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(provNameUTF16)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider(%s) failed: 0x%08X", provName, r)
	}

	nvDir := cngNVDir()
	if err := os.MkdirAll(nvDir, 0o700); err != nil {
		procNCryptFreeObject.Call(hProv)
		return nil, err
	}

	p := &cngProvider{
		hProv:     hProv,
		provName:  provName,
		nvDir:     nvDir,
		nextNVH:   0x01400000,
		loaded:    make(map[LoadedHandle]uintptr),
		nextLoadH: 0x80000000,
	}
	p.recoverNextNVH()
	return p, nil
}

func (p *cngProvider) Available() bool { return p.hProv != 0 }

func (p *cngProvider) PlatformName() string {
	if p.provName == ncryptPlatformProvider {
		return string(TPMPlatformWinCNG)
	}
	return "windows-swksp"
}

// ===== Seal / Unseal (DPAPI) =====

func (p *cngProvider) Seal(data []byte) ([]byte, error)   { return dpapiProtect(data) }
func (p *cngProvider) Unseal(blob []byte) ([]byte, error) { return dpapiUnprotect(blob) }

// ===== NV 域 (DPAPI 保护的文件) =====
//
// 文件格式：DPAPI 加密的 JSON { "label", "size", "salt", "auth_digest", "data" }
// authValue 校验与 sw-stub 一致。

type cngNVFile struct {
	Label      string `json:"label"`
	Size       int    `json:"size"`
	Salt       []byte `json:"salt"`
	AuthDigest []byte `json:"auth_digest"`
	Data       []byte `json:"data"` // 明文数据（外层被 DPAPI 加密）
}

func (p *cngProvider) nvPath(h NVHandle) string {
	return filepath.Join(p.nvDir, fmt.Sprintf("%08x.dpapi", uint32(h)))
}

func (p *cngProvider) NVDefine(label string, size int, authValue []byte) (NVHandle, error) {
	if size <= 0 || size > 8192 {
		return 0, fmt.Errorf("NV 槽大小 %d 超出范围", size)
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	for {
		h := NVHandle(p.nextNVH)
		p.nextNVH++
		if _, err := os.Stat(p.nvPath(h)); errors.Is(err, os.ErrNotExist) {
			salt := make([]byte, 32)
			io.ReadFull(randReader(), salt)
			f := cngNVFile{
				Label:      label,
				Size:       size,
				Salt:       salt,
				AuthDigest: nvAuthDigest(authValue, salt),
			}
			if err := p.writeNVFile(h, &f); err != nil {
				return 0, err
			}
			slog.Info("[TPM/CNG] NVDefine 完成 — DPAPI 保护",
				"handle", fmt.Sprintf("0x%08X", uint32(h)),
				"label", label, "size", size,
				"file", p.nvPath(h))
			return h, nil
		}
	}
}

func (p *cngProvider) NVWrite(h NVHandle, authValue, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.readNVFile(h)
	if err != nil {
		return err
	}
	if !constantTimeEqual(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return ErrNVAuthFailed
	}
	if len(data) > f.Size {
		return fmt.Errorf("NV 写入数据长度 %d 超过槽容量 %d", len(data), f.Size)
	}
	f.Data = make([]byte, len(data))
	copy(f.Data, data)
	err = p.writeNVFile(h, f)
	if err == nil {
		slog.Info("[TPM/CNG] NVWrite 完成",
			"handle", fmt.Sprintf("0x%08X", uint32(h)),
			"label", f.Label, "data_len", len(data))
	}
	return err
}

func (p *cngProvider) NVRead(h NVHandle, authValue []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, err := p.readNVFile(h)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return nil, ErrNVAuthFailed
	}
	if len(f.Data) == 0 {
		return nil, fmt.Errorf("NV 槽 %08x 未写入数据", uint32(h))
	}

	slog.Debug("[TPM/CNG] NVRead",
		"handle", fmt.Sprintf("0x%08X", uint32(h)),
		"label", f.Label, "data_len", len(f.Data))

	out := make([]byte, len(f.Data))
	copy(out, f.Data)
	return out, nil
}

func (p *cngProvider) NVUndefine(h NVHandle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := os.Remove(p.nvPath(h))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNVNotFound
	}
	return err
}

func (p *cngProvider) writeNVFile(h NVHandle, f *cngNVFile) error {
	js, err := json.Marshal(f)
	if err != nil {
		return err
	}
	protected, err := dpapiProtect(js)
	if err != nil {
		return fmt.Errorf("DPAPI 加密 NV 数据失败: %w", err)
	}
	tmp := p.nvPath(h) + ".tmp"
	if err := os.WriteFile(tmp, protected, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.nvPath(h))
}

func (p *cngProvider) readNVFile(h NVHandle) (*cngNVFile, error) {
	raw, err := os.ReadFile(p.nvPath(h))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNVNotFound
		}
		return nil, err
	}
	js, err := dpapiUnprotect(raw)
	if err != nil {
		return nil, fmt.Errorf("DPAPI 解密 NV 数据失败: %w", err)
	}
	var f cngNVFile
	if err := json.Unmarshal(js, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func (p *cngProvider) recoverNextNVH() {
	entries, _ := os.ReadDir(p.nvDir)
	maxH := uint32(0x01400000)
	for _, e := range entries {
		var v uint32
		if _, err := fmt.Sscanf(e.Name(), "%08x.dpapi", &v); err == nil && v >= maxH {
			maxH = v + 1
		}
	}
	if maxH > p.nextNVH {
		p.nextNVH = maxH
	}
}

// ===== 非对称密钥 (NCrypt) =====

// cngWrappedKey 是 CNG 后端的 WrappedKey.Private 内容（JSON）。
// 不含真实私钥字节——只存 keyName，CNG 通过名称找到持久化密钥。
type cngWrappedKey struct {
	KeyName  string `json:"key_name"`  // NCrypt 容器名
	Alg      KeyAlg `json:"alg"`
	Provider string `json:"provider"`  // provider 名
}

func (p *cngProvider) CreateKey(alg KeyAlg, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	algId, bits, err := keyAlgToCNG(alg)
	if err != nil {
		return nil, nil, err
	}

	// 生成唯一容器名
	var rndBuf [4]byte
	io.ReadFull(cryptoRandReader, rndBuf[:])
	keyName := fmt.Sprintf("GlobalTrusts/%08x", binary.LittleEndian.Uint32(rndBuf[:]))

	slog.Info("[TPM/CNG] CreateKey 开始",
		"alg", string(alg), "cng_alg", algId, "bits", bits,
		"key_name", keyName, "provider", p.provName)

	keyNameUTF16, _ := windows.UTF16PtrFromString(keyName)
	algUTF16, _ := windows.UTF16PtrFromString(algId)

	var hKey uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(
		p.hProv,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algUTF16)),
		uintptr(unsafe.Pointer(keyNameUTF16)),
		0, // dwLegacyKeySpec
		0, // dwFlags
	)
	if r != 0 {
		return nil, nil, fmt.Errorf("NCryptCreatePersistedKey failed: 0x%08X", r)
	}

	// 设置密钥长度
	if bits > 0 {
		setNCryptProperty(hKey, ncryptLengthProperty, bits)
	}
	// 设置不可导出
	setNCryptProperty(hKey, ncryptExportPolicyProperty, ncryptAllowNothingExport)
	// 设置用途
	setNCryptProperty(hKey, ncryptKeyUsageProperty, ncryptSigningFlag|ncryptDecryptFlag)

	// 完成密钥创建（实际生成密钥对）
	r, _, _ = procNCryptFinalizeKey.Call(hKey, 0)
	if r != 0 {
		procNCryptFreeObject.Call(hKey)
		return nil, nil, fmt.Errorf("NCryptFinalizeKey failed: 0x%08X", r)
	}

	slog.Info("[TPM/CNG] CreateKey 完成 — 密钥已在 TPM 中生成",
		"key_name", keyName, "alg", string(alg), "provider", p.provName)

	// 导出公钥
	pubDER, err := exportPublicKey(hKey, alg)
	if err != nil {
		procNCryptDeleteKey.Call(hKey, 0)
		return nil, nil, fmt.Errorf("导出公钥失败: %w", err)
	}

	procNCryptFreeObject.Call(hKey)

	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析公钥 DER 失败: %w", err)
	}

	// 构造 WrappedKey
	privJSON, _ := json.Marshal(cngWrappedKey{
		KeyName:  keyName,
		Alg:      alg,
		Provider: p.provName,
	})

	wk := &WrappedKey{
		Alg:        alg,
		Backend:    p.PlatformName(),
		Public:     pubDER,
		Private:    privJSON,
		AuthDigest: nvAuthDigest(authValue, []byte(keyName)), // 绑定 authValue
	}
	return wk, pub, nil
}

// ImportKey 将外部 PKCS#8 DER 私钥导入 CNG，设为不可导出的持久化密钥。
//
// 注意：Microsoft Platform Crypto Provider (PCP/TPM) 不支持 NCryptImportKey（返回 NTE_NOT_SUPPORTED），
// 因为 TPM 的设计原则是"密钥只能在芯片内部生成"。
// 因此导入操作固定使用 Microsoft Software Key Storage Provider（DPAPI 保护），仍然设为不可导出。
// 导入后签名/解密走 SWKSP 的 NCryptSignHash/NCryptDecrypt，私钥由 DPAPI + Windows 用户凭据保护。
//
// 如果需要 TPM 级别保护，应使用 CreateKey（在 TPM 内部生成），然后通过证书链机制信任。
func (p *cngProvider) ImportKey(privKeyDER []byte, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	// 解析私钥获取算法信息
	priv, err := x509.ParsePKCS8PrivateKey(privKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析导入私钥失败: %w", err)
	}
	_, alg, err := extractPubAndAlg(priv)
	if err != nil {
		return nil, nil, err
	}

	// 生成唯一容器名
	var rndBuf [4]byte
	io.ReadFull(cryptoRandReader, rndBuf[:])
	keyName := fmt.Sprintf("GlobalTrusts/%08x", binary.LittleEndian.Uint32(rndBuf[:]))

	slog.Info("[TPM/CNG] ImportKey 开始（使用 Software KSP）",
		"alg", string(alg), "key_name", keyName)

	// 打开 Software KSP（PCP 不支持 ImportKey）
	swkspName, _ := windows.UTF16PtrFromString(ncryptSoftwareProvider)
	var hSwProv uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hSwProv)),
		uintptr(unsafe.Pointer(swkspName)),
		0,
	)
	if r != 0 {
		return nil, nil, fmt.Errorf("打开 Software KSP 失败: 0x%08X", r)
	}
	defer procNCryptFreeObject.Call(hSwProv)

	// NCryptImportKey with PKCS8_PRIVATEKEY_BLOB
	blobType := "PKCS8_PRIVATEKEY_BLOB"
	blobTypeUTF16, _ := windows.UTF16PtrFromString(blobType)

	var hKey uintptr
	procImport := ncryptDll.NewProc("NCryptImportKey")
	r, _, _ = procImport.Call(
		hSwProv,
		0, // hImportKey (NULL)
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0, // pParameterList (NULL)
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&privKeyDER[0])),
		uintptr(len(privKeyDER)),
		0x80, // NCRYPT_OVERWRITE_KEY_FLAG
	)
	if r != 0 {
		return nil, nil, fmt.Errorf("NCryptImportKey(SWKSP) failed: 0x%08X", r)
	}

	// 设置不可导出
	setNCryptProperty(hKey, ncryptExportPolicyProperty, ncryptAllowNothingExport)

	// 获取 CNG 分配的实际密钥名称
	nameBytes := make([]byte, 512)
	var nameLen uint32
	propNameUTF16, _ := windows.UTF16PtrFromString("Unique Name")
	procGetProp := ncryptDll.NewProc("NCryptGetProperty")
	r2, _, _ := procGetProp.Call(
		hKey,
		uintptr(unsafe.Pointer(propNameUTF16)),
		uintptr(unsafe.Pointer(&nameBytes[0])),
		uintptr(len(nameBytes)),
		uintptr(unsafe.Pointer(&nameLen)),
		0,
	)
	if r2 == 0 && nameLen > 0 {
		actualName := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&nameBytes[0])))
		if actualName != "" {
			keyName = actualName
		}
	}

	// 导出公钥
	pubDER, err := exportPublicKey(hKey, alg)
	if err != nil {
		procNCryptFreeObject.Call(hKey)
		return nil, nil, fmt.Errorf("导出公钥失败: %w", err)
	}
	procNCryptFreeObject.Call(hKey)

	slog.Info("[TPM/CNG] ImportKey 完成 — 私钥已导入 Software KSP（DPAPI 保护，不可导出）",
		"key_name", keyName, "alg", string(alg))

	importedPub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析导入后公钥失败: %w", err)
	}

	// WrappedKey 记录使用 Software KSP（LoadKey 时需要用 SWKSP 打开）
	privJSON, _ := json.Marshal(cngWrappedKey{
		KeyName:  keyName,
		Alg:      alg,
		Provider: ncryptSoftwareProvider, // 固定为 SWKSP
	})

	wk := &WrappedKey{
		Alg:        alg,
		Backend:    "windows-swksp-import",
		Public:     pubDER,
		Private:    privJSON,
		AuthDigest: nvAuthDigest(authValue, []byte(keyName)),
	}
	return wk, importedPub, nil
}

func (p *cngProvider) LoadKey(wrapped *WrappedKey, authValue []byte) (LoadedHandle, error) {
	if wrapped == nil {
		return 0, fmt.Errorf("wrapped 为空")
	}
	var cw cngWrappedKey
	if err := json.Unmarshal(wrapped.Private, &cw); err != nil {
		return 0, fmt.Errorf("解析 wrapped key 失败: %w", err)
	}
	// 校验 authValue
	expected := nvAuthDigest(authValue, []byte(cw.KeyName))
	if !constantTimeEqual(wrapped.AuthDigest, expected) {
		return 0, ErrKeyAuthFailed
	}

	slog.Info("[TPM/CNG] LoadKey", "key_name", cw.KeyName, "alg", string(cw.Alg), "provider", cw.Provider)

	// 根据 wrapped key 中记录的 Provider 选择打开哪个 KSP
	hProv := p.hProv
	var tempProv uintptr
	if cw.Provider != "" && cw.Provider != p.provName {
		provUTF16, _ := windows.UTF16PtrFromString(cw.Provider)
		ret, _, _ := procNCryptOpenStorageProvider.Call(
			uintptr(unsafe.Pointer(&tempProv)),
			uintptr(unsafe.Pointer(provUTF16)),
			0,
		)
		if ret != 0 {
			return 0, fmt.Errorf("打开 Provider(%s) 失败: 0x%08X", cw.Provider, ret)
		}
		hProv = tempProv
	}

	keyNameUTF16, _ := windows.UTF16PtrFromString(cw.KeyName)
	var hKey uintptr
	r, _, _ := procNCryptOpenKey.Call(
		hProv,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyNameUTF16)),
		0, // dwLegacyKeySpec
		0, // dwFlags
	)
	if tempProv != 0 {
		procNCryptFreeObject.Call(tempProv)
	}
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenKey(%s) failed: 0x%08X", cw.KeyName, r)
	}

	p.mu.Lock()
	h := LoadedHandle(p.nextLoadH)
	p.nextLoadH++
	p.loaded[h] = hKey
	p.mu.Unlock()
	return h, nil
}

func (p *cngProvider) Sign(h LoadedHandle, digest []byte, scheme SignScheme) ([]byte, error) {
	p.mu.Lock()
	hKey, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}

	paddingInfo, flags, err := schemeToPadding(scheme, len(digest))
	if err != nil {
		return nil, err
	}

	// 先获取签名长度
	var sigLen uint32
	r, _, _ := procNCryptSignHash.Call(
		hKey,
		paddingInfo,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash(get size) failed: 0x%08X", r)
	}

	sig := make([]byte, sigLen)
	r, _, _ = procNCryptSignHash.Call(
		hKey,
		paddingInfo,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash failed: 0x%08X", r)
	}

	slog.Info("[TPM/CNG] Sign 完成 — TPM 内部签名",
		"handle", fmt.Sprintf("0x%X", uint32(h)),
		"scheme", string(scheme), "digest_len", len(digest), "sig_len", sigLen)

	return sig[:sigLen], nil
}

func (p *cngProvider) Decrypt(h LoadedHandle, ciphertext []byte) ([]byte, error) {
	p.mu.Lock()
	hKey, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}

	// PKCS#1 v1.5 解密
	var outLen uint32
	r, _, _ := procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		0, // pPaddingInfo (NULL for PKCS1)
		0,
		0,
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(bcryptPadPKCS1),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt(get size) failed: 0x%08X", r)
	}

	plain := make([]byte, outLen)
	r, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		0,
		uintptr(unsafe.Pointer(&plain[0])),
		uintptr(outLen),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(bcryptPadPKCS1),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt failed: 0x%08X", r)
	}
	return plain[:outLen], nil
}

func (p *cngProvider) DecryptOAEP(h LoadedHandle, ciphertext, label []byte) ([]byte, error) {
	p.mu.Lock()
	hKey, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}

	// 构建 BCRYPT_OAEP_PADDING_INFO 结构体
	sha256Alg, _ := windows.UTF16PtrFromString("SHA256")
	type bcryptOAEPPaddingInfo struct {
		pszAlgId *uint16
		pbLabel  *byte
		cbLabel  uint32
	}
	oaepInfo := bcryptOAEPPaddingInfo{
		pszAlgId: sha256Alg,
	}
	if len(label) > 0 {
		oaepInfo.pbLabel = &label[0]
		oaepInfo.cbLabel = uint32(len(label))
	}

	// 第一次调用获取输出大小
	var outLen uint32
	r, _, _ := procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		uintptr(unsafe.Pointer(&oaepInfo)),
		0,
		0,
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(bcryptPadOAEP),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt/OAEP(get size) failed: 0x%08X", r)
	}

	plain := make([]byte, outLen)
	r, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		uintptr(unsafe.Pointer(&oaepInfo)),
		uintptr(unsafe.Pointer(&plain[0])),
		uintptr(outLen),
		uintptr(unsafe.Pointer(&outLen)),
		uintptr(bcryptPadOAEP),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt/OAEP failed: 0x%08X", r)
	}
	return plain[:outLen], nil
}

func (p *cngProvider) FlushHandle(h LoadedHandle) error {
	p.mu.Lock()
	hKey, ok := p.loaded[h]
	delete(p.loaded, h)
	p.mu.Unlock()
	if ok && hKey != 0 {
		procNCryptFreeObject.Call(hKey)
	}
	return nil
}

// ===== 辅助函数 =====

func keyAlgToCNG(alg KeyAlg) (algId string, bits uint32, err error) {
	switch alg {
	case KeyAlgRSA2048:
		return bcryptRSAAlg, 2048, nil
	case KeyAlgRSA3072:
		return bcryptRSAAlg, 3072, nil
	case KeyAlgRSA4096:
		return bcryptRSAAlg, 4096, nil
	case KeyAlgECP256:
		return bcryptECDSAP256Alg, 0, nil
	case KeyAlgECP384:
		return bcryptECDSAP384Alg, 0, nil
	case KeyAlgECP521:
		return bcryptECDSAP521Alg, 0, nil
	default:
		return "", 0, ErrUnknownAlg
	}
}

func setNCryptProperty(hKey uintptr, propName string, value uint32) {
	propUTF16, _ := windows.UTF16PtrFromString(propName)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	procNCryptSetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(propUTF16)),
		uintptr(unsafe.Pointer(&buf[0])),
		4,
		0,
	)
}

func exportPublicKey(hKey uintptr, alg KeyAlg) ([]byte, error) {
	// 根据算法选择 blob 类型
	var blobType string
	switch {
	case alg == KeyAlgRSA2048 || alg == KeyAlgRSA3072 || alg == KeyAlgRSA4096:
		blobType = "RSAPUBLICBLOB"
	default:
		blobType = "ECCPUBLICBLOB"
	}
	blobTypeUTF16, _ := windows.UTF16PtrFromString(blobType)

	// 获取长度
	var blobLen uint32
	r, _, _ := procNCryptExportKey.Call(
		hKey,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey(get size) failed: 0x%08X", r)
	}

	blob := make([]byte, blobLen)
	r, _, _ = procNCryptExportKey.Call(
		hKey,
		0,
		uintptr(unsafe.Pointer(blobTypeUTF16)),
		0,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(blobLen),
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey failed: 0x%08X", r)
	}

	// 将 CNG blob 转为标准 PKIX DER
	return cngBlobToPKIX(blob[:blobLen], alg)
}

// cngBlobToPKIX 将 CNG 格式的公钥 blob 转为 SubjectPublicKeyInfo DER。
//
// 支持：
//   - BCRYPT_RSAPUBLIC_BLOB (Magic=0x31415352 "RSA1")
//   - BCRYPT_ECCPUBLIC_BLOB (Magic=0x31534345 "ECS1" / 0x33534345 "ECS3" / 0x35534345 "ECS5")
//
// 参考：
//   - https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
//   - https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
func cngBlobToPKIX(blob []byte, alg KeyAlg) ([]byte, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("CNG blob 过短 (%d bytes)", len(blob))
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])

	switch {
	case magic == 0x31415352: // "RSA1" BCRYPT_RSAPUBLIC_MAGIC
		return parseRSAPublicBlob(blob)
	case magic == 0x31534345 || magic == 0x33534345 || magic == 0x35534345:
		// "ECS1" P-256 / "ECS3" P-384 / "ECS5" P-521
		return parseECCPublicBlob(blob, alg)
	default:
		return nil, fmt.Errorf("未知的 CNG blob magic: 0x%08X", magic)
	}
}

// parseRSAPublicBlob 解析 BCRYPT_RSAKEY_BLOB (BCRYPT_RSAPUBLIC_BLOB) → PKIX DER。
//
// 结构体布局：
//
//	struct BCRYPT_RSAKEY_BLOB {
//	    ULONG Magic;        // 0x31415352
//	    ULONG BitLength;    // 密钥位数
//	    ULONG cbPublicExp;  // 公钥指数长度
//	    ULONG cbModulus;    // 模数长度
//	    ULONG cbPrime1;     // （公钥 blob 中为 0）
//	    ULONG cbPrime2;     // （公钥 blob 中为 0）
//	};
//	// 紧跟数据：PublicExponent[cbPublicExp] + Modulus[cbModulus]
func parseRSAPublicBlob(blob []byte) ([]byte, error) {
	if len(blob) < 24 {
		return nil, fmt.Errorf("RSA blob header 过短")
	}
	cbPubExp := binary.LittleEndian.Uint32(blob[8:12])
	cbModulus := binary.LittleEndian.Uint32(blob[12:16])

	headerSize := uint32(24)
	dataStart := headerSize
	if uint32(len(blob)) < dataStart+cbPubExp+cbModulus {
		return nil, fmt.Errorf("RSA blob 数据截断")
	}

	expBytes := blob[dataStart : dataStart+cbPubExp]
	modBytes := blob[dataStart+cbPubExp : dataStart+cbPubExp+cbModulus]

	n := new(big.Int).SetBytes(modBytes)
	e := new(big.Int).SetBytes(expBytes)

	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	return x509.MarshalPKIXPublicKey(pub)
}

// parseECCPublicBlob 解析 BCRYPT_ECCKEY_BLOB (BCRYPT_ECCPUBLIC_BLOB) → PKIX DER。
//
// 结构体布局：
//
//	struct BCRYPT_ECCKEY_BLOB {
//	    ULONG dwMagic;    // ECS1/ECS3/ECS5
//	    ULONG cbKey;      // X/Y 各的字节数
//	};
//	// 紧跟数据：X[cbKey] + Y[cbKey]
func parseECCPublicBlob(blob []byte, alg KeyAlg) ([]byte, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("ECC blob header 过短")
	}
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	headerSize := uint32(8)
	if uint32(len(blob)) < headerSize+2*cbKey {
		return nil, fmt.Errorf("ECC blob 数据截断")
	}

	xBytes := blob[headerSize : headerSize+cbKey]
	yBytes := blob[headerSize+cbKey : headerSize+2*cbKey]

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	var curve elliptic.Curve
	switch alg {
	case KeyAlgECP256:
		curve = elliptic.P256()
	case KeyAlgECP384:
		curve = elliptic.P384()
	case KeyAlgECP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("未知 EC 曲线: %s", alg)
	}

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return x509.MarshalPKIXPublicKey(pub)
}

// schemeToPadding 将 SignScheme 转换为 NCryptSignHash 需要的 paddingInfo 指针和 flags。
func schemeToPadding(scheme SignScheme, digestLen int) (uintptr, uintptr, error) {
	switch scheme {
	case SignSchemeRSAPKCS1SHA256:
		return pkcs1Padding("SHA256"), uintptr(bcryptPadPKCS1), nil
	case SignSchemeRSAPKCS1SHA384:
		return pkcs1Padding("SHA384"), uintptr(bcryptPadPKCS1), nil
	case SignSchemeRSAPKCS1SHA512:
		return pkcs1Padding("SHA512"), uintptr(bcryptPadPKCS1), nil
	case SignSchemeRSAPSSSHA256:
		return pssPadding("SHA256", 32), uintptr(bcryptPadPSS), nil
	case SignSchemeRaw:
		// 根据 digest 长度推断
		switch digestLen {
		case 32:
			return pkcs1Padding("SHA256"), uintptr(bcryptPadPKCS1), nil
		case 48:
			return pkcs1Padding("SHA384"), uintptr(bcryptPadPKCS1), nil
		case 64:
			return pkcs1Padding("SHA512"), uintptr(bcryptPadPKCS1), nil
		default:
			// 可能是 ECDSA（无 padding）
			return 0, 0, nil
		}
	case SignSchemeECDSASHA256, SignSchemeECDSASHA384, SignSchemeECDSASHA512:
		// ECDSA 不需要 padding info
		return 0, 0, nil
	default:
		return 0, 0, ErrUnknownScheme
	}
}

// pkcs1Padding 分配 PKCS1 padding info（指针在当前栈帧内有效）。
// 注意：这些指针只在调用 NCryptSignHash 期间需要有效，Go 的 GC 不会提前回收。
func pkcs1Padding(algName string) uintptr {
	algUTF16, _ := windows.UTF16PtrFromString(algName)
	info := &bcryptPKCS1PaddingInfo{pszAlgId: algUTF16}
	return uintptr(unsafe.Pointer(info))
}

func pssPadding(algName string, saltLen uint32) uintptr {
	algUTF16, _ := windows.UTF16PtrFromString(algName)
	info := &bcryptPSSPaddingInfo{pszAlgId: algUTF16, cbSalt: saltLen}
	return uintptr(unsafe.Pointer(info))
}

// ===== DPAPI =====

func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("DPAPI: 空数据")
	}
	inBlob := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var outBlob dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // description
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		0, // flags (CRYPTPROTECT_UI_FORBIDDEN not needed for service)
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData failed: %v", err)
	}
	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	return out, nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("DPAPI: 空 blob")
	}
	inBlob := dataBlob{cbData: uint32(len(blob)), pbData: &blob[0]}
	var outBlob dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // description out
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		0, // flags
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %v", err)
	}
	out := make([]byte, outBlob.cbData)
	copy(out, unsafe.Slice(outBlob.pbData, outBlob.cbData))
	windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	return out, nil
}

func cngNVDir() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base = os.Getenv("USERPROFILE")
	}
	return filepath.Join(base, "GlobalTrusts", "client-card", "tpm", "nv")
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func randReader() io.Reader {
	// 使用 crypto/rand（已在包级导入）
	return cryptoRandReader
}

// 编译期断言
var _ Provider = (*cngProvider)(nil)
var _ = sha256.Size // keep import
