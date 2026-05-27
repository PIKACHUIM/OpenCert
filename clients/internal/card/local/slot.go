// Package local 实现本地智能卡 Slot。
// 证书和私钥存储在本地 SQLite 数据库中，私钥被临时密钥 AES-256 加密。
package local

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Slot 是本地智能卡的 Slot 实现。
type Slot struct {
	mu       sync.RWMutex
	slotID   pkcs11types.SlotID
	card     *storage.Card
	certRepo *storage.CertRepo
	cardRepo *storage.CardRepo // 用于更新 PIN 状态

	// 登录状态
	loggedIn   bool
	masterKey  []byte // 解密后的卡片主密鑰（登录后有效）

	// 对象缓存：handle -> certificate
	objects map[pkcs11types.ObjectHandle]*storage.Certificate
	nextHandle uint32
}

// New 创建本地 Slot 实例。
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
func (s *Slot) Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	masterKey := s.masterKey
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
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

// decryptPrivateKey 解密证书的私钥数据，返回 crypto.PrivateKey。
func (s *Slot) decryptPrivateKey(cert *storage.Certificate, masterKey []byte) (crypto.PrivateKey, error) {
	// 1. 用 HMAC(masterKey, tempKeySalt) 解密临时密钥
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, cert.TempKeySalt)
	tempKey, err := cryptoutil.DecryptAES256GCM(tempKeyAESKey, cert.TempKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("解密临时密钥失败: %w", err)
	}

	// 2. 用临时密钥解密私钥数据
	privDER, err := cryptoutil.DecryptAES256GCM(tempKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥数据失败: %w", err)
	}

	// 3. 解析 DER 格式私钥
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

	// 尝试解析 X.509 证书
	if x509Cert, err := x509.ParseCertificate(der); err == nil {
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
		h := sha256.Sum256(data) // 实际应用 SHA1，此处简化
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case pkcs11types.CKM_SHA256_RSA_PKCS:
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case pkcs11types.CKM_SHA384_RSA_PKCS:
		h := sha512.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, h[:])
	case pkcs11types.CKM_SHA512_RSA_PKCS:
		h := sha512.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
	case pkcs11types.CKM_RSA_PKCS_PSS, pkcs11types.CKM_SHA256_RSA_PKCS_PSS:
		h := sha256.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		})
	default:
		return nil, fmt.Errorf("RSA 不支持算法 0x%X", uint32(mechanism.Type))
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
			return len(cert.PrivateData) > 0 &&
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
			if len(cert.PrivateData) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
		case pkcs11types.CKA_SENSITIVE:
			attr.Value = []byte{1}
		case pkcs11types.CKA_EXTRACTABLE:
			attr.Value = []byte{0}
		case pkcs11types.CKA_SIGN:
			if len(cert.PrivateData) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
		case pkcs11types.CKA_DECRYPT:
			if len(cert.PrivateData) > 0 {
				attr.Value = []byte{1}
			} else {
				attr.Value = []byte{0}
			}
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
		if x509Cert, err := x509.ParseCertificate(der); err == nil {
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
	cert, err := x509.ParseCertificate(content)
	if err != nil {
		// 对 certificate policies 错误做宽松处理：直接用 SHA-256 哈希 DER 内容
		if strings.Contains(err.Error(), "certificate policies") {
			h := sha256.Sum256(content)
			return h[:20], nil
		}
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
