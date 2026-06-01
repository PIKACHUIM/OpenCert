// Package local 实现本地智能卡 Slot。
// 证书和私钥存储在本地 SQLite 数据库中，私钥被临时密钥 AES-256 加密。
//
// medium / high 安全等级时，签名/解密路径会调用 tpm.Provider：
//   - medium：从 TPM NV 读出"TPM 证书密钥"做外层解密，再用 master 派生 KEK 解内层
//   - high  ：把 wrapped blob 加载进 TPM，由 TPM 内部完成签名/解密；私钥永不暴露
package local

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"sync"
	"time"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Slot 是本地智能卡的 Slot 实现。
type Slot struct {
	mu       sync.RWMutex
	slotID   pkcs11types.SlotID
	card     *storage.Card
	certRepo *storage.CertRepo
	cardRepo *storage.CardRepo // 用于更新 PIN 状态
	tpmProv  tpm.Provider      // medium/high 必需，可为 nil（此时仅 low 卡可用）

	// 登录状态
	loggedIn  bool
	masterKey []byte // 解密后的卡片主密鑰（登录后有效）

	// 对象缓存：handle -> certificate
	objects    map[pkcs11types.ObjectHandle]*storage.Certificate
	nextHandle uint32
}

// New 创建本地 Slot 实例（无 TPM Provider；仅 low 等级卡可正常工作）。
func New(slotID pkcs11types.SlotID, card *storage.Card, certRepo *storage.CertRepo) *Slot {
	return &Slot{
		slotID:     slotID,
		card:       card,
		certRepo:   certRepo,
		objects:    make(map[pkcs11types.ObjectHandle]*storage.Certificate),
		nextHandle: 1,
	}
}

// NewWithCardRepo 创建本地 Slot 实例（含 CardRepo，支持 PIN 锁定）。
func NewWithCardRepo(slotID pkcs11types.SlotID, card *storage.Card, certRepo *storage.CertRepo, cardRepo *storage.CardRepo) *Slot {
	s := New(slotID, card, certRepo)
	s.cardRepo = cardRepo
	return s
}

// NewWithTPM 创建本地 Slot 实例（含 CardRepo + TPM Provider，支持 medium/high）。
func NewWithTPM(slotID pkcs11types.SlotID, card *storage.Card, certRepo *storage.CertRepo, cardRepo *storage.CardRepo, tpmProv tpm.Provider) *Slot {
	s := NewWithCardRepo(slotID, card, certRepo, cardRepo)
	s.tpmProv = tpmProv
	return s
}

// SlotID 返回 Slot ID。
func (s *Slot) SlotID() pkcs11types.SlotID {
	return s.slotID
}

// SlotInfo 返回 Slot 信息。
func (s *Slot) SlotInfo() pkcs11types.SlotInfo {
	return pkcs11types.SlotInfo{
		SlotID:       s.slotID,
		Description:  fmt.Sprintf("Local Card: %s", s.card.CardName),
		Manufacturer: "GlobalTrusts",
		Flags:        pkcs11types.CKF_TOKEN_PRESENT,
		TokenPresent: true,
	}
}

// TokenInfo 返回 Token 信息。
func (s *Slot) TokenInfo() pkcs11types.TokenInfo {
	s.mu.RLock()
	loggedIn := s.loggedIn
	s.mu.RUnlock()

	flags := pkcs11types.CKF_TOKEN_INITIALIZED | pkcs11types.CKF_LOGIN_REQUIRED | pkcs11types.CKF_RNG
	if loggedIn {
		flags |= pkcs11types.CKF_USER_PIN_INITIALIZED
	}

	label := s.card.CardName
	if len(label) > 32 {
		label = label[:32]
	}

	return pkcs11types.TokenInfo{
		Label:           label,
		Manufacturer:    "GlobalTrusts",
		Model:           "LocalCard-v1",
		SerialNumber:    s.card.UUID[:16],
		Flags:           flags,
		MaxPinLen:       64,
		MinPinLen:       4,
		TotalPublicMem:  0xFFFFFFFF,
		FreePublicMem:   0xFFFFFFFF,
		TotalPrivateMem: 0xFFFFFFFF,
		FreePrivateMem:  0xFFFFFFFF,
	}
}

// Mechanisms 返回支持的算法列表。
func (s *Slot) Mechanisms() []pkcs11types.MechanismType {
	return []pkcs11types.MechanismType{
		// RSA
		pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN,
		pkcs11types.CKM_RSA_PKCS,
		pkcs11types.CKM_RSA_PKCS_OAEP,
		pkcs11types.CKM_RSA_PKCS_PSS,
		pkcs11types.CKM_SHA1_RSA_PKCS,
		pkcs11types.CKM_SHA256_RSA_PKCS,
		pkcs11types.CKM_SHA384_RSA_PKCS,
		pkcs11types.CKM_SHA512_RSA_PKCS,
		pkcs11types.CKM_SHA256_RSA_PKCS_PSS,
		// EC
		pkcs11types.CKM_EC_KEY_PAIR_GEN,
		pkcs11types.CKM_ECDSA,
		pkcs11types.CKM_ECDSA_SHA256,
		pkcs11types.CKM_ECDSA_SHA384,
		pkcs11types.CKM_ECDSA_SHA512,
		// EdDSA
		pkcs11types.CKM_EDDSA,
		// 摘要
		pkcs11types.CKM_SHA256,
		pkcs11types.CKM_SHA384,
		pkcs11types.CKM_SHA512,
		pkcs11types.CKM_SHA3_256,
		pkcs11types.CKM_SHA3_384,
		pkcs11types.CKM_SHA3_512,
		// 对称加密
		pkcs11types.CKM_AES_CBC,
		pkcs11types.CKM_AES_GCM,
		pkcs11types.CKM_CHACHA20_POLY1305,
	}
}

// Login 验证卡片密码，解密主密鑰。
// pin 是用户输入的密码（用户密码或卡片密码）。

// MasterKey 返回已解密的卡片主密钥（仅登录后有效）。
// 供 FIDO2 等需要直接访问主密钥的模块使用。
func (s *Slot) MasterKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.loggedIn || len(s.masterKey) == 0 {
		return nil
	}
	cp := make([]byte, len(s.masterKey))
	copy(cp, s.masterKey)
	return cp
}

// Login 验证卡片密码，解密主密鑰。
// pin 是用户输入的密码（用户密码或卡片密码）。
func (s *Slot) Login(ctx context.Context, userType pkcs11types.UserType, pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_ALREADY_LOGGED_IN)
	}

	// 检查 PIN 是否被锁定
	if s.card.PINLocked {
		return fmt.Errorf("%w: PIN 已锁定，请使用 PUK 解锁", pkcs11types.CKR_PIN_LOCKED)
	}

	masterKey, err := s.unlockMasterKey(pin)
	if err != nil {
		// PIN 错误，递增失败次数
		if s.cardRepo != nil {
			maxRetries := s.card.PINRetries
			if maxRetries <= 0 {
				maxRetries = 3
			}
			newFailedCount := s.card.PINFailedCount + 1
			locked := newFailedCount >= maxRetries
			s.card.PINFailedCount = newFailedCount
			s.card.PINLocked = locked
			_ = s.cardRepo.Update(ctx, s.card)
			if locked {
				return fmt.Errorf("%w: PIN 错误次数过多，已锁定", pkcs11types.CKR_PIN_LOCKED)
			}
			remaining := maxRetries - newFailedCount
			return fmt.Errorf("%w: PIN 错误，剩余 %d 次", pkcs11types.CKR_PIN_INCORRECT, remaining)
		}
		return fmt.Errorf("%w: %v", pkcs11types.CKR_PIN_INCORRECT, err)
	}

	// PIN 正确，重置失败次数
	if s.card.PINFailedCount > 0 && s.cardRepo != nil {
		s.card.PINFailedCount = 0
		s.card.PINLocked = false
		_ = s.cardRepo.Update(ctx, s.card)
	}

	s.masterKey = masterKey
	s.loggedIn = true

	// 预加载证书对象到内存缓存
	if err := s.loadObjects(ctx); err != nil {
		s.loggedIn = false
		s.masterKey = nil
		return fmt.Errorf("加载证书对象失败: %w", err)
	}

	return nil
}

// LoginWithMasterKey 使用已解锁的主密钥直接登录（供 TPM2 Slot 调用）。
// 跳过密码验证，直接加载证书对象。
func (s *Slot) LoginWithMasterKey(ctx context.Context, masterKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.masterKey = make([]byte, len(masterKey))
	copy(s.masterKey, masterKey)
	s.loggedIn = true

	if err := s.loadObjects(ctx); err != nil {
		s.loggedIn = false
		zeroBytes(s.masterKey)
		s.masterKey = nil
		return err
	}
	return nil
}

// Logout 注销，清除主密钥。
func (s *Slot) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 清零主密钥
	for i := range s.masterKey {
		s.masterKey[i] = 0
	}
	s.masterKey = nil
	s.loggedIn = false
	s.objects = make(map[pkcs11types.ObjectHandle]*storage.Certificate)
	s.nextHandle = 1
	return nil
}

// IsLoggedIn 返回登录状态。
func (s *Slot) IsLoggedIn() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loggedIn
}

// MasterKey 返回已解锁的主密钥（仅登录后有效，调用方不得修改）。
func (s *Slot) MasterKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.loggedIn {
		return nil
	}
	// 返回副本，防止外部修改
	cp := make([]byte, len(s.masterKey))
	copy(cp, s.masterKey)
	return cp
}

// FindObjects 根据属性模板查找对象。
func (s *Slot) FindObjects(ctx context.Context, template []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []pkcs11types.ObjectHandle
	for handle, cert := range s.objects {
		if matchTemplate(cert, template) {
			result = append(result, handle)
		}
	}
	return result, nil
}

// GetAttributes 获取对象属性。
func (s *Slot) GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrTypes []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	return buildAttributes(cert, attrTypes)
}

// Sign 使用私钥签名。
//
// 签名路径分三类：
//   - high   (cert.TPMPlatform == "high-v1")：把 wrapped blob LoadKey 进 TPM，由 TPM 内部签名
//   - medium (cert.TPMPlatform == "medium-v2")：先调 TPM NV 解外层，再用 master 解内层得到 privDER，
//     用 Go crypto 包签名（私钥仅短暂存在于 Go 进程中）
//   - low    ：原 master 加密的 privDER，按以前方式解出后签名
func (s *Slot) Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	masterKey := s.masterKey
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	// high 模式：在 TPM 内部完成签名
	if string(cert.TPMPlatform) == "high-v1" {
		return s.signWithTPM(cert, mechanism, data, masterKey)
	}

	// high-import-tpm 模式：私钥在 TPM 芯片内部，通过 go-tpm 签名
	if string(cert.TPMPlatform) == tpmPlatformHighImportTPM {
		return s.signWithTPM2Import(cert, mechanism, data, masterKey)
	}

	privKey, err := s.decryptPrivateKey(cert, masterKey)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	return signData(privKey, mechanism, data)
}

// Decrypt 使用私钥解密。
func (s *Slot) Decrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	masterKey := s.masterKey
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	// high 模式：在 TPM 内部完成解密
	if string(cert.TPMPlatform) == "high-v1" {
		return s.decryptWithTPM(cert, mechanism, ciphertext, masterKey)
	}

	privKey, err := s.decryptPrivateKey(cert, masterKey)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	return decryptData(privKey, mechanism, ciphertext)
}

// Encrypt 使用公钥加密。
func (s *Slot) Encrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	pubKey, err := parsePublicKey(cert)
	if err != nil {
		return nil, fmt.Errorf("解析公钥失败: %w", err)
	}

	return encryptData(pubKey, mechanism, plaintext)
}

// ---- 内部方法 ----

// unlockMasterKey 尝试用 pin 解锁卡片主密钥。
// 遍历 CardKeys 列表，找到能解密的记录。
func (s *Slot) unlockMasterKey(pin string) ([]byte, error) {
	pinBytes := []byte(pin)

	for _, entry := range s.card.CardKeys {
		// 用 HMAC(pin, salt) 作为 AES 密钥尝试解密
		aesKey := cryptoutil.HMACSHA256(pinBytes, entry.Salt)
		masterKey, err := cryptoutil.DecryptAES256GCM(aesKey, entry.EncMasterKey)
		if err == nil {
			return masterKey, nil
		}
	}
	return nil, fmt.Errorf("密码错误，无法解锁卡片")
}

// loadObjects 从数据库加载证书到内存缓存。
func (s *Slot) loadObjects(ctx context.Context) error {
	certs, err := s.certRepo.ListByCard(ctx, s.card.UUID)
	if err != nil {
		return err
	}

	s.objects = make(map[pkcs11types.ObjectHandle]*storage.Certificate)
	s.nextHandle = 1

	for _, cert := range certs {
		handle := pkcs11types.ObjectHandle(s.nextHandle)
		s.objects[handle] = cert
		s.nextHandle++
	}
	return nil
}

// ReloadObjects 在已登录状态下重新从数据库加载证书到内存缓存。
// 用于证书导入后刷新 Slot 对象列表，使新证书立即可用于签名/解密。
func (s *Slot) ReloadObjects(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn {
		return nil // 未登录时无需刷新
	}
	return s.loadObjects(ctx)
}

// decryptPrivateKey 解密证书的私钥数据，返回 crypto.PrivateKey。
//
//   - low / 旧 medium 标记：cert.PrivateData = AES-GCM(tempKey, privDER)
//   - 新 medium-v2     ：cert.PrivateData = AES-GCM(tpmCertKey, AES-GCM(tempKey, privDER))
//   - high-import-v1   ：cert.PrivateData = AES-GCM(aesKey, privDER), cert.TPMPrivateBlob = RSA-OAEP(aesKey)
//
// 高安全等级（high-v1, 片上生成）不会走这里——上层 Sign/Decrypt 已经分流到 TPM 内部完成。
func (s *Slot) decryptPrivateKey(cert *storage.Certificate, masterKey []byte) (crypto.PrivateKey, error) {
	// high-import-v1：用 TPM 解密 AES key，再 AES 解密 privDER
	if string(cert.TPMPlatform) == "high-import-v1" {
		return s.decryptHighImportPrivateKey(cert, masterKey)
	}

	// 1. 用 HMAC(masterKey, tempKeySalt) 解密临时密钥
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, cert.TempKeySalt)
	tempKey, err := cryptoutil.DecryptAES256GCM(tempKeyAESKey, cert.TempKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("解密临时密钥失败: %w", err)
	}

	privateData := cert.PrivateData

	// 2. medium-v2：先用 TPM 证书密钥解外层
	if string(cert.TPMPlatform) == "medium-v2" {
		if s.tpmProv == nil {
			return nil, fmt.Errorf("medium 卡片需要 TPM Provider 才能签名/解密")
		}
		inner, err := DecryptMediumPrivateData(s.tpmProv, s.card, cert, masterKey)
		if err != nil {
			return nil, err
		}
		privateData = inner
	}

	// 3. 用临时密钥解密私钥数据
	privDER, err := cryptoutil.DecryptAES256GCM(tempKey, privateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥数据失败: %w", err)
	}

	// 4. 解析 DER 格式私钥
	return parsePrivateKey(privDER)
}

// signWithTPM 让 TPM 在内部对 digest 做签名（high 模式）。
func (s *Slot) signWithTPM(cert *storage.Certificate, mechanism pkcs11types.Mechanism, data []byte, masterKey []byte) ([]byte, error) {
	if s.tpmProv == nil {
		return nil, fmt.Errorf("high 卡片需要 TPM Provider")
	}
	wrapped, err := unmarshalWrappedKey(cert.TPMWrappedBlob)
	if err != nil {
		return nil, err
	}
	auth := deriveTPMHighKeyAuth(masterKey, cert.UUID)
	defer zeroBytes(auth)
	h, err := s.tpmProv.LoadKey(wrapped, auth)
	if err != nil {
		return nil, fmt.Errorf("LoadKey 失败: %w", err)
	}
	defer s.tpmProv.FlushHandle(h)

	scheme, digest, err := mechanismToScheme(mechanism, data)
	if err != nil {
		return nil, err
	}
	sig, err := s.tpmProv.Sign(h, digest, scheme)
	if err != nil {
		return nil, fmt.Errorf("TPM 签名失败: %w", err)
	}
	// PKCS#11 ECDSA 期望 raw r||s；TPM 返回 ASN.1。需要转换。
	if scheme == tpm.SignSchemeECDSASHA256 || scheme == tpm.SignSchemeECDSASHA384 ||
		scheme == tpm.SignSchemeECDSASHA512 {
		raw, err := ecdsaASN1ToRaw(sig, wrapped.Alg)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	return sig, nil
}

// signWithTPM2Import 使用 go-tpm 真实导入的密钥在 TPM 内部完成签名（high-import-tpm 模式）。
func (s *Slot) signWithTPM2Import(cert *storage.Certificate, mechanism pkcs11types.Mechanism, data []byte, masterKey []byte) ([]byte, error) {
	wrapped, err := unmarshalWrappedKey(cert.TPMWrappedBlob)
	if err != nil {
		return nil, fmt.Errorf("反序列化 wrapped key 失败: %w", err)
	}

	// 初始化 TPM2 Import Provider
	importProv, err := tpm.NewTPM2ImportProvider()
	if err != nil {
		return nil, fmt.Errorf("初始化 TPM2 Import Provider 失败: %w", err)
	}

	auth := deriveTPMHighKeyAuth(masterKey, cert.UUID)
	defer zeroBytes(auth)

	// 加载密钥到 TPM
	h, err := importProv.LoadKeyTPM(wrapped, auth)
	if err != nil {
		return nil, fmt.Errorf("TPM2 LoadKey 失败: %w", err)
	}
	defer importProv.FlushHandleTPM(h)

	// 转换 PKCS#11 mechanism 到 TPM SignScheme 并准备 digest
	scheme, digest, err := mechanismToScheme(mechanism, data)
	if err != nil {
		return nil, err
	}

	// 在 TPM 内部签名
	sig, err := importProv.SignTPM(h, digest, scheme)
	if err != nil {
		return nil, fmt.Errorf("TPM2 Sign 失败: %w", err)
	}

	// PKCS#11 ECDSA 期望 raw r||s；TPM 返回 ASN.1
	if scheme == tpm.SignSchemeECDSASHA256 || scheme == tpm.SignSchemeECDSASHA384 ||
		scheme == tpm.SignSchemeECDSASHA512 {
		raw, err := ecdsaASN1ToRaw(sig, wrapped.Alg)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}
	return sig, nil
}

// decryptWithTPM 让 TPM 在内部完成 RSA 解密（high 模式）。
func (s *Slot) decryptWithTPM(cert *storage.Certificate, mechanism pkcs11types.Mechanism, ciphertext []byte, masterKey []byte) ([]byte, error) {
	if s.tpmProv == nil {
		return nil, fmt.Errorf("high 卡片需要 TPM Provider")
	}
	if mechanism.Type != pkcs11types.CKM_RSA_PKCS && mechanism.Type != pkcs11types.CKM_RSA_PKCS_OAEP {
		return nil, fmt.Errorf("high 卡片解密目前仅支持 CKM_RSA_PKCS / CKM_RSA_PKCS_OAEP")
	}
	wrapped, err := unmarshalWrappedKey(cert.TPMWrappedBlob)
	if err != nil {
		return nil, err
	}
	auth := deriveTPMHighKeyAuth(masterKey, cert.UUID)
	defer zeroBytes(auth)
	h, err := s.tpmProv.LoadKey(wrapped, auth)
	if err != nil {
		return nil, fmt.Errorf("LoadKey 失败: %w", err)
	}
	defer s.tpmProv.FlushHandle(h)
	return s.tpmProv.Decrypt(h, ciphertext)
}

// mechanismToScheme 把 PKCS#11 mechanism 翻译成 tpm.SignScheme，并返回需要传给 TPM 的 digest。
// 对未做摘要的算法（CKM_RSA_PKCS / CKM_ECDSA），data 已是 digest；
// 对一体化算法（CKM_SHA256_RSA_PKCS / CKM_ECDSA_SHA256 等），先在本地做摘要。
func mechanismToScheme(mechanism pkcs11types.Mechanism, data []byte) (tpm.SignScheme, []byte, error) {
	switch mechanism.Type {
	case pkcs11types.CKM_RSA_PKCS:
		return tpm.SignSchemeRaw, data, nil
	case pkcs11types.CKM_SHA1_RSA_PKCS:
		// 真 TPM 通常不支持 SHA-1；此处先在本地做摘要后用 raw 提交，由 sw-stub 兼容。
		h := sha1.Sum(data)
		return tpm.SignSchemeRaw, h[:], nil
	case pkcs11types.CKM_SHA256_RSA_PKCS:
		h := sha256.Sum256(data)
		return tpm.SignSchemeRSAPKCS1SHA256, h[:], nil
	case pkcs11types.CKM_SHA384_RSA_PKCS:
		h := sha512.Sum384(data)
		return tpm.SignSchemeRSAPKCS1SHA384, h[:], nil
	case pkcs11types.CKM_SHA512_RSA_PKCS:
		h := sha512.Sum512(data)
		return tpm.SignSchemeRSAPKCS1SHA512, h[:], nil
	case pkcs11types.CKM_RSA_PKCS_PSS:
		// 默认 SHA-256 PSS
		return tpm.SignSchemeRSAPSSSHA256, data, nil
	case pkcs11types.CKM_SHA256_RSA_PKCS_PSS:
		h := sha256.Sum256(data)
		return tpm.SignSchemeRSAPSSSHA256, h[:], nil
	case pkcs11types.CKM_ECDSA:
		return tpm.SignSchemeRaw, data, nil
	case pkcs11types.CKM_ECDSA_SHA256:
		h := sha256.Sum256(data)
		return tpm.SignSchemeECDSASHA256, h[:], nil
	case pkcs11types.CKM_ECDSA_SHA384:
		h := sha512.Sum384(data)
		return tpm.SignSchemeECDSASHA384, h[:], nil
	case pkcs11types.CKM_ECDSA_SHA512:
		h := sha512.Sum512(data)
		return tpm.SignSchemeECDSASHA512, h[:], nil
	case pkcs11types.CKM_EDDSA:
		return tpm.SignSchemeRaw, data, nil
	default:
		return "", nil, fmt.Errorf("不支持的 PKCS#11 机制 0x%X", uint32(mechanism.Type))
	}
}

// ecdsaASN1ToRaw 把 ASN.1 编码的 ECDSA 签名转成 PKCS#11 raw 格式（r||s 各填充到曲线字节长度）。
func ecdsaASN1ToRaw(sig []byte, alg tpm.KeyAlg) ([]byte, error) {
	var keyBytes int
	switch alg {
	case tpm.KeyAlgECP256:
		keyBytes = 32
	case tpm.KeyAlgECP384:
		keyBytes = 48
	case tpm.KeyAlgECP521:
		keyBytes = 66
	default:
		return nil, fmt.Errorf("未知 ECDSA 曲线: %s", alg)
	}
	r, ssig, err := parseECDSAASN1(sig)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2*keyBytes)
	copy(out[keyBytes-len(r):keyBytes], r)
	copy(out[2*keyBytes-len(ssig):], ssig)
	return out, nil
}

// parseECDSAASN1 解析 SEQUENCE { INTEGER r, INTEGER s }。
func parseECDSAASN1(sig []byte) ([]byte, []byte, error) {
	type ecSig struct {
		R, S []byte
	}
	// crypto/x509 已有 Marshal/Unmarshal，但避免引入私有依赖，这里用最小手写解析
	if len(sig) < 8 || sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("ECDSA ASN.1 格式错误")
	}
	// SEQUENCE 长度
	idx := 2
	if sig[1]&0x80 != 0 {
		nbytes := int(sig[1] & 0x7f)
		idx = 2 + nbytes
	}
	readInt := func(p int) ([]byte, int, error) {
		if p+2 > len(sig) || sig[p] != 0x02 {
			return nil, 0, fmt.Errorf("ECDSA ASN.1 INTEGER 缺失")
		}
		ln := int(sig[p+1])
		start := p + 2
		end := start + ln
		if end > len(sig) {
			return nil, 0, fmt.Errorf("ECDSA ASN.1 INTEGER 越界")
		}
		v := sig[start:end]
		// 去掉 INTEGER 高位 0x00 填充
		for len(v) > 0 && v[0] == 0x00 {
			v = v[1:]
		}
		return v, end, nil
	}
	r, p1, err := readInt(idx)
	if err != nil {
		return nil, nil, err
	}
	ssig, _, err := readInt(p1)
	if err != nil {
		return nil, nil, err
	}
	return r, ssig, nil
}

// decryptHighImportPrivateKey 解密 high-import-v1 格式的导入私钥。
//
// 流程：
//  1. 获取 wrapping key（从 card 的内部证书）
//  2. TPM LoadKey + Decrypt(encAESKey) → aesKey
//  3. AES-GCM(aesKey, cert.PrivateData) → privDER
func (s *Slot) decryptHighImportPrivateKey(cert *storage.Certificate, masterKey []byte) (crypto.PrivateKey, error) {
	if s.tpmProv == nil {
		return nil, fmt.Errorf("high-import 解密需要 TPM Provider")
	}
	// 1. 获取 wrapping key
	wrappingKey, err := getOrCreateWrappingKey(context.Background(), s.certRepo, s.tpmProv, masterKey, s.card)
	if err != nil {
		return nil, fmt.Errorf("获取 TPM 保护密钥失败: %w", err)
	}
	// 2. TPM 解密 AES key
	wrapAuth := deriveTPMHighKeyAuth(masterKey, "wrapping-key:"+s.card.UUID)
	defer zeroBytes(wrapAuth)
	handle, err := s.tpmProv.LoadKey(wrappingKey, wrapAuth)
	if err != nil {
		return nil, fmt.Errorf("LoadKey(wrapping) 失败: %w", err)
	}
	defer s.tpmProv.FlushHandle(handle)

	aesKey, err := s.tpmProv.Decrypt(handle, cert.TPMPrivateBlob)
	if err != nil {
		return nil, fmt.Errorf("TPM 解密 AES key 失败: %w", err)
	}
	defer zeroBytes(aesKey)

	// 3. AES 解密 privDER
	privDER, err := cryptoutil.DecryptAES256GCM(aesKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("AES 解密私钥失败: %w", err)
	}
	return parsePrivateKey(privDER)
}

// parsePrivateKey 解析 DER 格式私钥（支持 RSA/EC/Ed25519）。
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// 尝试 PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	// 尝试 RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	// 尝试 EC
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("无法解析私钥格式（支持 PKCS8/PKCS1/EC）")
}

// parsePublicKey 从证书内容解析公钥。
func parsePublicKey(cert *storage.Certificate) (crypto.PublicKey, error) {
	der := certContentDER(cert)
	if len(der) == 0 {
		return nil, fmt.Errorf("证书内容为空")
	}

	// 尝试解析 X.509 证书（宽松模式，兼容不合规扩展）
	if x509Cert, err := parseCertLenient(der); err == nil {
		return x509Cert.PublicKey, nil
	}

	// 尝试解析 DER 公钥
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		return pub, nil
	}

	return nil, fmt.Errorf("无法解析公钥")
}

// signData 使用私钥对数据签名。
func signData(privKey crypto.PrivateKey, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return signRSA(key, mechanism, data)
	case *ecdsa.PrivateKey:
		return signECDSA(key, mechanism, data)
	case ed25519.PrivateKey:
		return signEd25519(key, data)
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", privKey)
	}
}

func signRSA(key *rsa.PrivateKey, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	switch mechanism.Type {
	case pkcs11types.CKM_RSA_PKCS:
		// 原始 RSA PKCS#1 v1.5，data 已经是 DigestInfo
		return rsa.SignPKCS1v15(rand.Reader, key, 0, data)
	case pkcs11types.CKM_SHA1_RSA_PKCS:
		h := sha1.Sum(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h[:])
	case pkcs11types.CKM_SHA256_RSA_PKCS:
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case pkcs11types.CKM_SHA384_RSA_PKCS:
		h := sha512.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, h[:])
	case pkcs11types.CKM_SHA512_RSA_PKCS:
		h := sha512.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
	case pkcs11types.CKM_RSA_PKCS_PSS:
		// PSS 接收预哈希数据（由 KSP 或上层传入已哈希的值），不再次哈希
		hashAlg := hashAlgFromDataLen(len(data))
		return rsa.SignPSS(rand.Reader, key, hashAlg, data, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	case pkcs11types.CKM_SHA256_RSA_PKCS_PSS:
		h := sha256.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	default:
		return nil, fmt.Errorf("RSA 不支持算法 0x%X", uint32(mechanism.Type))
	}
}

// hashAlgFromDataLen 根据哈希值长度推断 crypto.Hash 类型。
func hashAlgFromDataLen(dataLen int) crypto.Hash {
	switch dataLen {
	case 20:
		return crypto.SHA1
	case 32:
		return crypto.SHA256
	case 48:
		return crypto.SHA384
	case 64:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func signECDSA(key *ecdsa.PrivateKey, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	var digest []byte
	var h hash.Hash

	switch mechanism.Type {
	case pkcs11types.CKM_ECDSA:
		// data 已经是摘要
		digest = data
	case pkcs11types.CKM_ECDSA_SHA256:
		h = sha256.New()
	case pkcs11types.CKM_ECDSA_SHA384:
		h = sha512.New384()
	case pkcs11types.CKM_ECDSA_SHA512:
		h = sha512.New()
	default:
		return nil, fmt.Errorf("ECDSA 不支持算法 0x%X", uint32(mechanism.Type))
	}

	if h != nil {
		h.Write(data)
		digest = h.Sum(nil)
	}

	r, sig, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}

	// 返回 DER 编码的 ECDSA 签名（r || s，各填充到曲线字节长度）
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := sig.Bytes()

	result := make([]byte, 2*keyBytes)
	copy(result[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(result[2*keyBytes-len(sBytes):], sBytes)
	return result, nil
}

// signEd25519 使用 Ed25519 私钥签名（纯签名，不做摘要）。
func signEd25519(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	return ed25519.Sign(key, data), nil
}

// decryptData 使用私钥解密数据。
func decryptData(privKey crypto.PrivateKey, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error) {
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("解密仅支持 RSA 私钥")
	}

	switch mechanism.Type {
	case pkcs11types.CKM_RSA_PKCS:
		return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
	case pkcs11types.CKM_RSA_PKCS_OAEP:
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	default:
		return nil, fmt.Errorf("不支持的解密算法 0x%X", uint32(mechanism.Type))
	}
}

// encryptData 使用公钥加密数据。
func encryptData(pubKey crypto.PublicKey, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error) {
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("加密仅支持 RSA 公钥")
	}

	switch mechanism.Type {
	case pkcs11types.CKM_RSA_PKCS:
		return rsa.EncryptPKCS1v15(rand.Reader, rsaKey, plaintext)
	case pkcs11types.CKM_RSA_PKCS_OAEP:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	default:
		return nil, fmt.Errorf("不支持的加密算法 0x%X", uint32(mechanism.Type))
	}
}

// matchTemplate 检查证书是否匹配属性模板。
func matchTemplate(cert *storage.Certificate, template []pkcs11types.Attribute) bool {
	for _, attr := range template {
		if !matchAttr(cert, attr) {
			return false
		}
	}
	return true
}

func matchAttr(cert *storage.Certificate, attr pkcs11types.Attribute) bool {
	switch attr.Type {
	case pkcs11types.CKA_CLASS:
		if len(attr.Value) < 4 {
			return false
		}
		class := pkcs11types.ObjectClass(binary.BigEndian.Uint32(attr.Value))
		switch class {
		case pkcs11types.CKO_CERTIFICATE:
			// X509 证书映射为 CKO_CERTIFICATE
			return cert.CertType == storage.CertTypeX509
		case pkcs11types.CKO_PRIVATE_KEY:
			// X509/SSH/GPG 的私钥映射为 CKO_PRIVATE_KEY
			// 有 PrivateData（加密存储）或有 TPMWrappedBlob（密钥在 TPM 内部）
			hasPrivateKey := len(cert.PrivateData) > 0 || len(cert.TPMWrappedBlob) > 0
			return hasPrivateKey &&
				(cert.CertType == storage.CertTypeX509 ||
					cert.CertType == storage.CertTypeSSH ||
					cert.CertType == storage.CertTypeGPG)
		case pkcs11types.CKO_PUBLIC_KEY:
			// X509/SSH/GPG 的公钥映射为 CKO_PUBLIC_KEY
			return len(cert.CertContent) > 0 &&
				(cert.CertType == storage.CertTypeX509 ||
					cert.CertType == storage.CertTypeSSH ||
					cert.CertType == storage.CertTypeGPG)
		case pkcs11types.CKO_DATA:
			// TOTP/FIDO/Login/Text/Note/Payment 映射为 CKO_DATA
			return cert.CertType == storage.CertTypeTOTP ||
				cert.CertType == storage.CertTypeFIDO ||
				cert.CertType == storage.CertTypeLogin ||
				cert.CertType == storage.CertTypeText ||
				cert.CertType == storage.CertTypeNote ||
				cert.CertType == storage.CertTypePayment
		}
		return false
	case pkcs11types.CKA_LABEL:
		return string(attr.Value) == cert.Remark || string(attr.Value) == cert.UUID
	case pkcs11types.CKA_ID:
		return string(attr.Value) == cert.UUID[:min(len(cert.UUID), len(attr.Value))]
	case pkcs11types.CKA_TOKEN:
		return len(attr.Value) > 0 && attr.Value[0] == 1
	}
	return true // 未知属性默认匹配
}

// buildAttributes 构建属性列表。
func buildAttributes(cert *storage.Certificate, attrTypes []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	result := make([]pkcs11types.Attribute, 0, len(attrTypes))

	for _, t := range attrTypes {
		attr := pkcs11types.Attribute{Type: t}
		switch t {
		case pkcs11types.CKA_CLASS:
			var class pkcs11types.ObjectClass
			switch cert.CertType {
			case storage.CertTypeX509:
				class = pkcs11types.CKO_CERTIFICATE
			case storage.CertTypeSSH, storage.CertTypeGPG:
				if len(cert.PrivateData) > 0 {
					class = pkcs11types.CKO_PRIVATE_KEY
				} else {
					class = pkcs11types.CKO_PUBLIC_KEY
				}
			default:
				class = pkcs11types.CKO_DATA
			}
			attr.Value = uint32ToBytes(uint32(class))
		case pkcs11types.CKA_LABEL:
			// 卡片备注作为标签；为空时回落到 UUID 前缀
			if cert.Remark != "" {
				attr.Value = []byte(cert.Remark)
			} else {
				attr.Value = []byte(cert.UUID)
			}
		case pkcs11types.CKA_ID:
			attr.Value = computeCKAID(cert)
	case pkcs11types.CKA_VALUE:
			attr.Value = certContentDER(cert)
		case pkcs11types.CKA_PUBLIC_KEY_INFO:
			// SubjectPublicKeyInfo DER：SSH/GPG 也尽量返回标准格式
			attr.Value = computePublicKeyInfo(cert)
		case pkcs11types.CKA_CERTIFICATE_TYPE:
			attr.Value = uint32ToBytes(0) // CKC_X_509
		case pkcs11types.CKA_TOKEN:
			attr.Value = []byte{1}
		case pkcs11types.CKA_PRIVATE:
			if len(cert.PrivateData) > 0 || len(cert.TPMWrappedBlob) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
		case pkcs11types.CKA_SENSITIVE:
			attr.Value = []byte{1}
		case pkcs11types.CKA_EXTRACTABLE:
			attr.Value = []byte{0}
		case pkcs11types.CKA_SIGN:
			if len(cert.PrivateData) > 0 || len(cert.TPMWrappedBlob) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
		case pkcs11types.CKA_DECRYPT:
			if len(cert.PrivateData) > 0 || len(cert.TPMWrappedBlob) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
		case pkcs11types.CKA_KEY_TYPE:
			// 从 cert.KeyType 字符串推断 PKCS#11 密钥类型
			attr.Value = keyTypeToBytes(cert.KeyType)
		case pkcs11types.CKA_MODULUS_BITS:
			// 从 cert.KeyType 字符串推断密钥位数
			attr.Value = uint32ToBytes(keyTypeToBits(cert.KeyType))
		default:
			attr.Value = nil
		}
		result = append(result, attr)
	}
	return result, nil
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// keyTypeToBytes 将 cert.KeyType 字符串转换为 PKCS#11 CKK_* 值的字节表示。
func keyTypeToBytes(keyType string) []byte {
	switch {
	case strings.HasPrefix(keyType, "rsa"):
		return uint32ToBytes(0x00000000) // CKK_RSA
	case strings.HasPrefix(keyType, "ec") || strings.HasPrefix(keyType, "p256") || strings.HasPrefix(keyType, "p384") || strings.HasPrefix(keyType, "p521"):
		return uint32ToBytes(0x00000003) // CKK_EC
	case strings.HasPrefix(keyType, "ed25519") || strings.HasPrefix(keyType, "ed"):
		return uint32ToBytes(0x00000040) // CKK_EC_EDWARDS
	default:
		return uint32ToBytes(0x00000000) // 默认 RSA
	}
}

// keyTypeToBits 从 cert.KeyType 字符串中提取密钥位数。
func keyTypeToBits(keyType string) uint32 {
	switch keyType {
	case "rsa2048":
		return 2048
	case "rsa3072":
		return 3072
	case "rsa4096":
		return 4096
	case "ec256", "p256":
		return 256
	case "ec384", "p384":
		return 384
	case "ec521", "p521":
		return 521
	case "ed25519":
		return 256
	default:
		// 尝试从字符串中提取数字
		for i := 0; i < len(keyType); i++ {
			if keyType[i] >= '0' && keyType[i] <= '9' {
				var n uint32
				for j := i; j < len(keyType) && keyType[j] >= '0' && keyType[j] <= '9'; j++ {
					n = n*10 + uint32(keyType[j]-'0')
				}
				if n > 0 {
					return n
				}
			}
		}
		return 2048 // 默认
	}
}

// computeCKAID 按证书类型派生 PKCS#11 CKA_ID。
//   - x509: 优先使用 SubjectKeyIdentifier，否则用 SHA-1(SPKI) 与 OpenSSL 习惯对齐
//   - ssh : 公钥 wire 的 SHA-256 摘要（OpenSSH 风格指纹）
//   - gpg : OpenPGP V4 keyid（fingerprint 末 8 字节）
//   - 其他: UUID 字节串
func computeCKAID(cert *storage.Certificate) []byte {
	switch cert.CertType {
	case storage.CertTypeSSH:
		if id, err := sshCKAID(cert.CertContent); err == nil {
			return id
		}
	case storage.CertTypeGPG:
		if id, err := gpgCKAID(cert.CertContent); err == nil {
			return id
		}
	case storage.CertTypeX509:
		if id, err := x509CKAID(certContentDER(cert)); err == nil {
			return id
		}
	}
	return []byte(cert.UUID)
}

// certContentDER 从证书记录的 CertContent 中提取 DER 格式数据。
// 支持 PEM 格式（自动解码）和原始 DER 格式（直接返回）。
func certContentDER(cert *storage.Certificate) []byte {
	return cert.DERContent()
}

// computePublicKeyInfo 构造 SubjectPublicKeyInfo DER。
//   - x509: 从证书提取
//   - ssh : 从 OpenSSH 公钥转换
//   - gpg : 从 V4 公钥包体转换
//   - 其他: 空
func computePublicKeyInfo(cert *storage.Certificate) []byte {
	der := certContentDER(cert)
	switch cert.CertType {
	case storage.CertTypeX509:
		if x509Cert, err := parseCertLenient(der); err == nil {
			return x509Cert.RawSubjectPublicKeyInfo
		}
		// 也可能 cert_content 直接就是 SPKI
		if _, err := x509.ParsePKIXPublicKey(der); err == nil {
			return der
		}
	case storage.CertTypeSSH:
		if spki, err := pki.SSHPublicKeyToPKIX(cert.CertContent); err == nil {
			return spki
		}
	case storage.CertTypeGPG:
		if spki, err := pki.GPGPublicKeyToPKIX(cert.CertContent); err == nil {
			return spki
		}
	}
	return nil
}

// sshCKAID 计算 OpenSSH 公钥的 SHA-256 指纹（原始字节）。
func sshCKAID(content []byte) ([]byte, error) {
	_, raw, err := pki.SSHFingerprintSHA256(content)
	return raw, err
}

// gpgCKAID 计算 GPG V4 keyid。
func gpgCKAID(content []byte) ([]byte, error) {
	// 当 content 是 V4 包体时直接派生
	if len(content) > 0 && content[0] == 0x04 {
		fp, err := gpgFingerprintFromBody(content)
		if err != nil {
			return nil, err
		}
		return pki.GPGKeyIDFromFingerprint(fp), nil
	}
	// 否则尝试当作 PKIX 公钥处理（用零时间），用于兼容历史数据
	body, err := pki.GPGPublicKeyFromPKIX(content, time.Unix(0, 0))
	if err != nil {
		return nil, err
	}
	fp, err := gpgFingerprintFromBody(body)
	if err != nil {
		return nil, err
	}
	return pki.GPGKeyIDFromFingerprint(fp), nil
}

// gpgFingerprintFromBody 通过 V4 包体直接派生 fingerprint（不依赖外部公钥构造）。
func gpgFingerprintFromBody(body []byte) ([]byte, error) {
	pub, err := pki.GPGPublicKeyToPKIX(body)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// V4 包体头 5 字节为 version+createdAt，从中读时间以保证 fingerprint 一致
	if len(body) < 5 {
		return nil, fmt.Errorf("GPG 包体过短")
	}
	createdAt := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	return pki.GPGFingerprint(parsed, createdAt)
}

// x509CKAID 计算 X.509 的 SubjectKeyIdentifier 或回落到 SPKI 的 SHA-1。
func x509CKAID(content []byte) ([]byte, error) {
	cert, err := parseCertLenient(content)
	if err != nil {
		return nil, err
	}
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId, nil
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:20], nil // 取前 20 字节（与 OpenSSL ski 长度对齐）
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
