// Package tpm - Mock 实现，用于测试。
//
// MockProvider 在内存中维护 NV 槽与 wrapped key（不落盘），适合单元测试。
// 行为与 SoftwareStub 完全一致，但每次 NewMock() 都是干净状态。
package tpm

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// MockProvider 是 TPM 的内存 Mock 实现。
type MockProvider struct {
	mu        sync.Mutex
	bindKey   [32]byte
	nv        map[NVHandle]*nvFile // 内存 NV
	nextNVH   uint32
	loaded    map[LoadedHandle]*loadedKeyState
	nextLoadH uint32
}

// NewMock 创建一个 Mock TPM Provider（使用随机密钥）。
func NewMock() *MockProvider {
	p := &MockProvider{
		nv:        make(map[NVHandle]*nvFile),
		nextNVH:   0x01400000,
		loaded:    make(map[LoadedHandle]*loadedKeyState),
		nextLoadH: 0x80000000,
	}
	if _, err := rand.Read(p.bindKey[:]); err != nil {
		panic(fmt.Sprintf("MockProvider 初始化失败: %v", err))
	}
	return p
}

// NewMockWithKey 创建一个使用固定密钥的 Mock Provider（用于确定性测试）。
func NewMockWithKey(key [32]byte) *MockProvider {
	p := NewMock()
	p.bindKey = key
	return p
}

func (m *MockProvider) Available() bool      { return true }
func (m *MockProvider) PlatformName() string { return string(TPMPlatformMock) }

func (m *MockProvider) Seal(data []byte) ([]byte, error)   { return sealWithAES(m.bindKey[:], data) }
func (m *MockProvider) Unseal(blob []byte) ([]byte, error) { return unsealWithAES(m.bindKey[:], blob) }

// ----- NV -----

func (m *MockProvider) NVDefine(label string, size int, authValue []byte) (NVHandle, error) {
	if size <= 0 || size > 8192 {
		return 0, fmt.Errorf("NV 槽大小 %d 超出范围 [1, 8192]", size)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return 0, err
	}
	h := NVHandle(m.nextNVH)
	m.nextNVH++
	m.nv[h] = &nvFile{
		Label:      label,
		Size:       size,
		Salt:       salt,
		AuthDigest: nvAuthDigest(authValue, salt),
	}
	return h, nil
}

func (m *MockProvider) NVWrite(h NVHandle, authValue, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.nv[h]
	if !ok {
		return ErrNVNotFound
	}
	if !hmac.Equal(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return ErrNVAuthFailed
	}
	if len(data) > f.Size {
		return fmt.Errorf("NV 写入数据长度 %d 超过槽容量 %d", len(data), f.Size)
	}
	kek := nvDeriveKEK(m.bindKey[:], authValue, f.Salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, data)
	if err != nil {
		return err
	}
	f.Wrap = wrap
	return nil
}

func (m *MockProvider) NVRead(h NVHandle, authValue []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.nv[h]
	if !ok {
		return nil, ErrNVNotFound
	}
	if !hmac.Equal(f.AuthDigest, nvAuthDigest(authValue, f.Salt)) {
		return nil, ErrNVAuthFailed
	}
	if len(f.Wrap) == 0 {
		return nil, fmt.Errorf("NV 槽 %08x 未写入数据", uint32(h))
	}
	kek := nvDeriveKEK(m.bindKey[:], authValue, f.Salt)
	defer zero(kek)
	return unsealWithAES(kek, f.Wrap)
}

func (m *MockProvider) NVUndefine(h NVHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nv[h]; !ok {
		return ErrNVNotFound
	}
	delete(m.nv, h)
	return nil
}

// ----- 非对称密钥 -----

func (m *MockProvider) CreateKey(alg KeyAlg, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
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
	kek := nvDeriveKEK(m.bindKey[:], authValue, salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, pkcs8)
	if err != nil {
		return nil, nil, err
	}
	wpJSON, err := json.Marshal(wrappedPrivate{Alg: alg, Salt: salt, Wrap: wrap})
	if err != nil {
		return nil, nil, err
	}
	pubDER, err := marshalPKIX(pub)
	if err != nil {
		return nil, nil, err
	}
	wk := &WrappedKey{
		Alg:        alg,
		Backend:    "mock",
		Public:     pubDER,
		Private:    wpJSON,
		AuthDigest: nvAuthDigest(authValue, salt),
	}
	return wk, pub, nil
}

func (m *MockProvider) ImportKey(privKeyDER []byte, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	priv, err := parsePKCS8(privKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("解析导入私钥失败: %w", err)
	}
	pub, alg, err := extractPubAndAlg(priv)
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	kek := nvDeriveKEK(m.bindKey[:], authValue, salt)
	defer zero(kek)
	wrap, err := sealWithAES(kek, privKeyDER)
	if err != nil {
		return nil, nil, err
	}
	wpJSON, _ := json.Marshal(wrappedPrivate{Alg: alg, Salt: salt, Wrap: wrap})
	pubDER, err := marshalPKIX(pub)
	if err != nil {
		return nil, nil, err
	}
	return &WrappedKey{
		Alg:        alg,
		Backend:    "mock",
		Public:     pubDER,
		Private:    wpJSON,
		AuthDigest: nvAuthDigest(authValue, salt),
	}, pub, nil
}

func (m *MockProvider) LoadKey(wrapped *WrappedKey, authValue []byte) (LoadedHandle, error) {
	if wrapped == nil {
		return 0, fmt.Errorf("wrapped 为空")
	}
	var wp wrappedPrivate
	if err := json.Unmarshal(wrapped.Private, &wp); err != nil {
		return 0, err
	}
	if !hmac.Equal(wrapped.AuthDigest, nvAuthDigest(authValue, wp.Salt)) {
		return 0, ErrKeyAuthFailed
	}
	kek := nvDeriveKEK(m.bindKey[:], authValue, wp.Salt)
	defer zero(kek)
	pkcs8, err := unsealWithAES(kek, wp.Wrap)
	if err != nil {
		return 0, err
	}
	defer zero(pkcs8)
	priv, err := parsePKCS8(pkcs8)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	h := LoadedHandle(m.nextLoadH)
	m.nextLoadH++
	m.loaded[h] = &loadedKeyState{wrapped: wrapped, priv: priv}
	m.mu.Unlock()
	return h, nil
}

func (m *MockProvider) Sign(h LoadedHandle, digest []byte, scheme SignScheme) ([]byte, error) {
	m.mu.Lock()
	st, ok := m.loaded[h]
	m.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return signWithKey(st.priv, digest, scheme)
}

func (m *MockProvider) Decrypt(h LoadedHandle, ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	st, ok := m.loaded[h]
	m.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return decryptWithKey(st.priv, ciphertext)
}

func (m *MockProvider) DecryptOAEP(h LoadedHandle, ciphertext, label []byte) ([]byte, error) {
	m.mu.Lock()
	st, ok := m.loaded[h]
	m.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}
	return decryptOAEPWithKey(st.priv, ciphertext, label)
}

func (m *MockProvider) FlushHandle(h LoadedHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.loaded, h)
	return nil
}

// 编译期验证接口实现。
var _ Provider = (*MockProvider)(nil)
var _ = sha256.Size // keep import
