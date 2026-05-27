// Package card 提供云端卡片的业务逻辑。
// 私钥在服务端加密存储，签名/解密操作在服务端执行，私钥不离开服务器。
package card

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // MD5 仅为兼容遗留签名机制保留
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA1 仅为兼容遗留签名机制保留
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/globaltrusts/server-card/internal/storage"
)

// Service 提供云端卡片的业务操作。
type Service struct {
	cardRepo *storage.CardRepo
	certRepo *storage.CertRepo
	// masterKey 是服务端主密钥，用于加密所有私钥
	// 生产环境应从 HSM 或密钥管理服务获取
	masterKey []byte
	// ekTrust 是 TPM 厂商根证书池，用于高安全等级卡片的 EK 认证。
	// 可为 nil（不强制 EK 认证）。
	ekTrust *EKTrustStore
}

// NewService 创建卡片服务。
// masterKey 是 32 字节服务端主密钥。
func NewService(cardRepo *storage.CardRepo, certRepo *storage.CertRepo, masterKey []byte) *Service {
	return &Service{
		cardRepo:  cardRepo,
		certRepo:  certRepo,
		masterKey: masterKey,
		ekTrust:   NewEKTrustStore(),
	}
}

// EKTrust 返回服务持有的 EK 信任库（用于在启动时注入厂商根）。
func (s *Service) EKTrust() *EKTrustStore {
	return s.ekTrust
}

// CreateCardRequest 是创建卡片的请求参数。
type CreateCardRequest struct {
	UserUUID        string
	CardName        string
	Remark          string
	StorageZoneUUID string
	PIN             string // 明文 PIN（加密后存储）
	PUK             string // 明文 PUK（加密后存储）
	AdminKey        string // 明文 Admin Key（加密后存储）
	PINRetries      int    // PIN 错误最大次数，默认 3

	// 以下字段用于高安全等级卡片创建（可选）。
	// 当 SecurityLevel=high 且 SlotType=tpmv2 时，必须提供 Attestation 与 AttestationNonce。
	SlotType         SlotType      // 槽类型：software/tpmv2/apple_t2/apple_se
	SecurityLevel    SecurityLevel // 安全等级：low/medium/high
	Attestation      *Attestation  // 客户端上送的 EK 认证，可为 nil（除高安全等级外）
	AttestationNonce string        // 服务端本次下发的 nonce
}

// CreateCard 创建云端卡片，支持 PIN/PUK/Admin Key 设置。
//
// 当 req.SlotType == SlotTPMv2 且 req.SecurityLevel == SecurityHigh 时，
// 必须提供 req.Attestation 与 req.AttestationNonce，否则拒绝。
// 校验通过后才会创建卡片记录。
func (s *Service) CreateCard(ctx context.Context, req *CreateCardRequest) (*storage.Card, error) {
	// 高安全等级强制 EK 认证
	if req.SlotType == SlotTPMv2 && req.SecurityLevel == SecurityHigh {
		if s.ekTrust == nil {
			return nil, fmt.Errorf("服务未启用 EK 信任库，无法创建高安全等级卡片")
		}
		if req.Attestation == nil {
			return nil, fmt.Errorf("高安全等级卡片必须提供 EK 认证；请改用中/低安全等级或更换支持 TPM 的设备")
		}
		if err := s.ekTrust.VerifyEKAttestation(req.Attestation, req.AttestationNonce, req.SecurityLevel); err != nil {
			return nil, fmt.Errorf("EK 认证失败，建议降级为中安全等级: %w", err)
		}
	} else if req.Attestation != nil && req.SecurityLevel != "" {
		// 中/低等级若也带了 attestation，做最佳努力校验，失败仅作为警告（不阻断）
		if s.ekTrust != nil {
			_ = s.ekTrust.VerifyEKAttestation(req.Attestation, req.AttestationNonce, req.SecurityLevel)
		}
	}

	card := &storage.Card{
		UserUUID:        req.UserUUID,
		CardName:        req.CardName,
		Remark:          req.Remark,
		StorageZoneUUID: req.StorageZoneUUID,
		PINRetries:      req.PINRetries,
	}
	if card.PINRetries <= 0 {
		card.PINRetries = 3
	}

	// 加密存储 PIN/PUK/Admin Key
	if req.PIN != "" {
		enc, err := encryptWithMasterKey(s.masterKey, []byte(req.PIN))
		if err != nil {
			return nil, fmt.Errorf("加密 PIN 失败: %w", err)
		}
		card.PINData = enc
	}
	if req.PUK != "" {
		enc, err := encryptWithMasterKey(s.masterKey, []byte(req.PUK))
		if err != nil {
			return nil, fmt.Errorf("加密 PUK 失败: %w", err)
		}
		card.PUKData = enc
	}
	if req.AdminKey != "" {
		enc, err := encryptWithMasterKey(s.masterKey, []byte(req.AdminKey))
		if err != nil {
			return nil, fmt.Errorf("加密 Admin Key 失败: %w", err)
		}
		card.AdminKeyData = enc
	}

	if err := s.cardRepo.Create(ctx, card); err != nil {
		return nil, fmt.Errorf("创建卡片失败: %w", err)
	}
	// 返回时清空敏感数据
	card.PINData = nil
	card.PUKData = nil
	card.AdminKeyData = nil
	return card, nil
}

// VerifyPIN 验证 PIN 码，失败时递增计数，超限时锁定。
// 返回 (是否验证成功, 剩余次数, error)
func (s *Service) VerifyPIN(ctx context.Context, cardUUID, pin string) (bool, int, error) {
	card, err := s.cardRepo.GetByUUID(ctx, cardUUID)
	if err != nil {
		return false, 0, err
	}
	if card.PINLocked {
		return false, 0, fmt.Errorf("PIN 已锁定，请使用 PUK 解锁")
	}
	if card.PINData == nil {
		// 未设置 PIN，直接通过
		return true, card.PINRetries, nil
	}

	// 解密并比较 PIN
	plainPIN, err := decryptWithMasterKey(s.masterKey, card.PINData)
	if err != nil {
		return false, 0, fmt.Errorf("解密 PIN 失败: %w", err)
	}
	if string(plainPIN) != pin {
		// PIN 错误，递增失败次数
		newFailedCount := card.PINFailedCount + 1
		locked := newFailedCount >= card.PINRetries
		if err := s.cardRepo.UpdatePINStatus(ctx, cardUUID, newFailedCount, locked); err != nil {
			return false, 0, fmt.Errorf("更新 PIN 状态失败: %w", err)
		}
		remaining := card.PINRetries - newFailedCount
		if remaining < 0 {
			remaining = 0
		}
		if locked {
			return false, 0, fmt.Errorf("PIN 错误次数过多，已锁定")
		}
		return false, remaining, fmt.Errorf("PIN 错误，剩余 %d 次", remaining)
	}

	// PIN 正确，重置失败次数
	if card.PINFailedCount > 0 {
		s.cardRepo.UpdatePINStatus(ctx, cardUUID, 0, false) //nolint:errcheck
	}
	return true, card.PINRetries, nil
}

// UnlockWithPUK 使用 PUK 解锁并重置 PIN。
func (s *Service) UnlockWithPUK(ctx context.Context, cardUUID, puk, newPIN string) error {
	card, err := s.cardRepo.GetByUUID(ctx, cardUUID)
	if err != nil {
		return err
	}
	if card.PUKData == nil {
		return fmt.Errorf("未设置 PUK")
	}

	plainPUK, err := decryptWithMasterKey(s.masterKey, card.PUKData)
	if err != nil {
		return fmt.Errorf("解密 PUK 失败: %w", err)
	}
	if string(plainPUK) != puk {
		return fmt.Errorf("PUK 错误")
	}

	// PUK 正确，重置 PIN
	if newPIN == "" {
		// 仅解锁，不重置 PIN
		return s.cardRepo.UpdatePINStatus(ctx, cardUUID, 0, false)
	}

	encPIN, err := encryptWithMasterKey(s.masterKey, []byte(newPIN))
	if err != nil {
		return fmt.Errorf("加密新 PIN 失败: %w", err)
	}
	return s.cardRepo.UpdatePINData(ctx, cardUUID, encPIN)
}

// ResetWithAdminKey 使用 Admin Key 重置 PIN 和 PUK。
func (s *Service) ResetWithAdminKey(ctx context.Context, cardUUID, adminKey, newPIN, newPUK string) error {
	card, err := s.cardRepo.GetByUUID(ctx, cardUUID)
	if err != nil {
		return err
	}
	if card.AdminKeyData == nil {
		return fmt.Errorf("未设置 Admin Key")
	}

	plainAdminKey, err := decryptWithMasterKey(s.masterKey, card.AdminKeyData)
	if err != nil {
		return fmt.Errorf("解密 Admin Key 失败: %w", err)
	}
	if string(plainAdminKey) != adminKey {
		return fmt.Errorf("Admin Key 错误")
	}

	// Admin Key 正确，重置 PIN 和 PUK
	if newPIN != "" {
		encPIN, err := encryptWithMasterKey(s.masterKey, []byte(newPIN))
		if err != nil {
			return fmt.Errorf("加密新 PIN 失败: %w", err)
		}
		if err := s.cardRepo.UpdatePINData(ctx, cardUUID, encPIN); err != nil {
			return err
		}
	}
	if newPUK != "" {
		encPUK, err := encryptWithMasterKey(s.masterKey, []byte(newPUK))
		if err != nil {
			return fmt.Errorf("加密新 PUK 失败: %w", err)
		}
		if err := s.cardRepo.UpdatePUKData(ctx, cardUUID, encPUK); err != nil {
			return fmt.Errorf("更新 PUK 失败: %w", err)
		}
	}
	return nil
}

// GetCard 获取卡片（验证归属）。
func (s *Service) GetCard(ctx context.Context, cardUUID, userUUID string) (*storage.Card, error) {
	card, err := s.cardRepo.GetByUUID(ctx, cardUUID)
	if err != nil {
		return nil, err
	}
	if card.UserUUID != userUUID {
		return nil, fmt.Errorf("无权访问此卡片")
	}
	return card, nil
}

// ListCards 列出用户的所有卡片。
func (s *Service) ListCards(ctx context.Context, userUUID string) ([]*storage.Card, error) {
	return s.cardRepo.ListByUser(ctx, userUUID)
}

// DeleteCard 删除卡片（验证归属）。
func (s *Service) DeleteCard(ctx context.Context, cardUUID, userUUID string) error {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return err
	}
	return s.cardRepo.Delete(ctx, cardUUID)
}

// GenerateKeyPair 在云端卡片中生成密钥对。
// 私钥加密存储，公钥/证书返回给调用方。
func (s *Service) GenerateKeyPair(ctx context.Context, cardUUID, userUUID, keyType, remark string) (*storage.Certificate, error) {
	// 验证卡片归属
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}

	// 生成密钥对
	privKey, pubDER, err := generateKeyPair(keyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 序列化私钥
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}

	// 用服务端主密钥加密私钥
	encPriv, err := encryptWithMasterKey(s.masterKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	cert := &storage.Certificate{
		CardUUID:    cardUUID,
		CertType:    "x509",
		KeyType:     keyType,
		CertContent: pubDER,
		PrivateData: encPriv,
		Remark:      remark,
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}

	// 返回时清空私钥字段
	cert.PrivateData = nil
	return cert, nil
}

// ImportCert 导入证书（仅公钥/证书内容，无私钥）。
func (s *Service) ImportCert(ctx context.Context, cardUUID, userUUID, certType, keyType, remark string, certContent []byte) (*storage.Certificate, error) {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}

	cert := &storage.Certificate{
		CardUUID:    cardUUID,
		CertType:    certType,
		KeyType:     keyType,
		CertContent: certContent,
		Remark:      remark,
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("导入证书失败: %w", err)
	}
	return cert, nil
}

// ListCerts 列出卡片的所有证书（不含私钥）。
func (s *Service) ListCerts(ctx context.Context, cardUUID, userUUID string) ([]*storage.Certificate, error) {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}
	return s.certRepo.ListByCard(ctx, cardUUID)
}

// DeleteCert 删除证书。
func (s *Service) DeleteCert(ctx context.Context, certUUID, cardUUID, userUUID string) error {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return err
	}
	return s.certRepo.Delete(ctx, certUUID)
}

// Sign 使用云端私钥签名（私钥不离开服务器）。
func (s *Service) Sign(ctx context.Context, certUUID, cardUUID, userUUID, mechanism string, data []byte) ([]byte, error) {
	// 验证卡片归属
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}

	// 获取证书（含私钥）
	cert, err := s.certRepo.GetByUUID(ctx, certUUID)
	if err != nil {
		return nil, err
	}
	if cert.CardUUID != cardUUID {
		return nil, fmt.Errorf("证书不属于此卡片")
	}

	// 解密私钥
	privDER, err := decryptWithMasterKey(s.masterKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	privKey, err := parsePrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	return signData(privKey, mechanism, data)
}

// Decrypt 使用云端私钥解密（私钥不离开服务器）。
func (s *Service) Decrypt(ctx context.Context, certUUID, cardUUID, userUUID, mechanism string, ciphertext []byte) ([]byte, error) {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}

	cert, err := s.certRepo.GetByUUID(ctx, certUUID)
	if err != nil {
		return nil, err
	}
	if cert.CardUUID != cardUUID {
		return nil, fmt.Errorf("证书不属于此卡片")
	}

	privDER, err := decryptWithMasterKey(s.masterKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	privKey, err := parsePrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}

	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("解密仅支持 RSA 私钥")
	}

	switch mechanism {
	case "RSA_PKCS":
		return rsa.DecryptPKCS1v15(rand.Reader, rsaKey, ciphertext)
	case "RSA_OAEP":
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKey, ciphertext, nil)
	default:
		return nil, fmt.Errorf("不支持的解密算法: %s", mechanism)
	}
}

// ExportAsPKCS12 将证书和私钥导出为 PEM 格式的组合数据。
// 注意：当前版本不支持 PKCS12 打包，返回 PEM 格式的私钥+证书。
// 如需 PKCS12 支持，请添加 software.sslmate.com/src/go-pkcs12 依赖。
func (s *Service) ExportAsPKCS12(ctx context.Context, cert *storage.Certificate, password string) ([]byte, error) {
	// 解密私钥
	privDER, err := decryptWithMasterKey(s.masterKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}

	// 将私钥编码为 PEM
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	// 将证书编码为 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.CertContent,
	})

	// 组合输出
	result := append(privPEM, certPEM...)
	return result, nil
}

// DecryptPrivateKey 解密证书的私钥（供外部使用）。
func (s *Service) DecryptPrivateKey(ctx context.Context, cert *storage.Certificate) (crypto.PrivateKey, error) {
	privDER, err := decryptWithMasterKey(s.masterKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}
	return parsePrivateKey(privDER)
}

// EncryptData 使用主密钥加密数据（供外部使用）。
func (s *Service) EncryptData(data []byte) ([]byte, error) {
	return encryptWithMasterKey(s.masterKey, data)
}

// DecryptData 使用主密钥解密数据（供外部使用）。
func (s *Service) DecryptData(blob []byte) ([]byte, error) {
	return decryptWithMasterKey(s.masterKey, blob)
}

// generateKeyPair 生成密钥对，返回私钥和公钥 DER。
// generateKeyPair 生成密钥对，返回私钥和公钥 DER。
// 支持的 keyType：
//   - RSA：rsa1024, rsa2048, rsa3072, rsa4096, rsa8192
//   - ECDSA：ec256/p256, ec384/p384, ec521/p521
//   - EdDSA：ed25519（主要用于签名，不用于加密）
//
// 注意：X25519 仅用于密钥协商（ECDH），不用于证书签名，因此不列入；
// Brainpool 曲线 Go 标准库无直接支持，如需启用需引入第三方包。
func generateKeyPair(keyType string) (crypto.PrivateKey, []byte, error) {
	var privKey crypto.PrivateKey
	var err error

	switch keyType {
	case "rsa1024":
		privKey, err = rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2048":
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		privKey, err = rsa.GenerateKey(rand.Reader, 3072)
	case "rsa4096":
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "rsa8192":
		privKey, err = rsa.GenerateKey(rand.Reader, 8192)
	case "ec256", "p256":
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384", "p384":
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ec521", "p521":
		privKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default:
		return nil, nil, fmt.Errorf("不支持的密钥类型: %s", keyType)
	}
	if err != nil {
		return nil, nil, err
	}

	// 提取公钥 DER
	var pubKey crypto.PublicKey
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化公钥失败: %w", err)
	}

	return privKey, pubDER, nil
}

// encryptWithMasterKey 用服务端主密钥 AES-256-GCM 加密数据。
func encryptWithMasterKey(masterKey, data []byte) ([]byte, error) {
	return aesGCMEncrypt(masterKey, data)
}

// decryptWithMasterKey 用服务端主密钥 AES-256-GCM 解密数据。
func decryptWithMasterKey(masterKey, blob []byte) ([]byte, error) {
	return aesGCMDecrypt(masterKey, blob)
}

// parsePrivateKey 解析 DER 格式私钥。
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("无法解析私钥格式")
}

// signData 使用私钥签名。
func signData(privKey crypto.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return signRSA(key, mechanism, data)
	case *ecdsa.PrivateKey:
		return signECDSA(key, mechanism, data)
	case ed25519.PrivateKey:
		// Ed25519 对任意长度消息直接签名，mechanism 参数被忽略（Ed25519 内置 SHA-512）。
		return ed25519.Sign(key, data), nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %T", privKey)
	}
}

func signRSA(key *rsa.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	switch mechanism {
	// ---- PKCS#1 v1.5 ----
	case "MD5_RSA_PKCS":
		h := md5.Sum(data) //nolint:gosec // 兼容遗留
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5, h[:])
	case "SHA1_RSA_PKCS":
		h := sha1.Sum(data) //nolint:gosec // 兼容遗留
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h[:])
	case "SHA256_RSA_PKCS":
		h := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	case "SHA384_RSA_PKCS":
		h := sha512.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA384, h[:])
	case "SHA512_RSA_PKCS":
		h := sha512.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, h[:])
	case "SHA3_256_RSA_PKCS":
		h := sha3.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_256, h[:])
	case "SHA3_384_RSA_PKCS":
		h := sha3.Sum384(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_384, h[:])
	case "SHA3_512_RSA_PKCS":
		h := sha3.Sum512(data)
		return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA3_512, h[:])
	// ---- RSA-PSS ----
	case "SHA256_RSA_PSS":
		h := sha256.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA384_RSA_PSS":
		h := sha512.Sum384(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA384, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA512_RSA_PSS":
		h := sha512.Sum512(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_256_RSA_PSS":
		h := sha3.Sum256(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_384_RSA_PSS":
		h := sha3.Sum384(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_384, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	case "SHA3_512_RSA_PSS":
		h := sha3.Sum512(data)
		return rsa.SignPSS(rand.Reader, key, crypto.SHA3_512, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	default:
		return nil, fmt.Errorf("不支持的 RSA 签名算法: %s", mechanism)
	}
}

func signECDSA(key *ecdsa.PrivateKey, mechanism string, data []byte) ([]byte, error) {
	var digest []byte
	switch mechanism {
	case "ECDSA":
		digest = data
	case "ECDSA_SHA1":
		h := sha1.Sum(data) //nolint:gosec // 兼容遗留
		digest = h[:]
	case "ECDSA_SHA256":
		h := sha256.Sum256(data)
		digest = h[:]
	case "ECDSA_SHA384":
		h := sha512.Sum384(data)
		digest = h[:]
	case "ECDSA_SHA512":
		h := sha512.Sum512(data)
		digest = h[:]
	case "ECDSA_SHA3_256":
		h := sha3.Sum256(data)
		digest = h[:]
	case "ECDSA_SHA3_384":
		h := sha3.Sum384(data)
		digest = h[:]
	case "ECDSA_SHA3_512":
		h := sha3.Sum512(data)
		digest = h[:]
	default:
		return nil, fmt.Errorf("不支持的 ECDSA 签名算法: %s", mechanism)
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}

	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	result := make([]byte, 2*keyBytes)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(result[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(result[2*keyBytes-len(sBytes):], sBytes)
	return result, nil
}
