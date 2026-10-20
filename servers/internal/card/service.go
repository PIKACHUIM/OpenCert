// Package card 提供云端卡片的业务逻辑。
// 私钥在服务端加密存储，签名/解密操作在服务端执行，私钥不离开服务器。
package card

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/globaltrusts/server-card/internal/keybackend"
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

	// zones 是存储区域仓储；为 nil 时所有私钥都落在本地加密存储。
	zones *storage.StorageZoneRepo
	// backends 缓存各存储区域已打开的后端（含设备登录会话）。
	backends *keybackend.Manager
}

// NewService 创建卡片服务。
// masterKey 是 32 字节服务端主密钥。
func NewService(cardRepo *storage.CardRepo, certRepo *storage.CertRepo, masterKey []byte) *Service {
	return &Service{
		cardRepo:  cardRepo,
		certRepo:  certRepo,
		masterKey: masterKey,
		ekTrust:   NewEKTrustStore(),
		backends:  keybackend.NewManager(),
	}
}

// AttachStorageZones 注入存储区域仓储，启用 TPM / HSM 私钥后端。
// 未注入时服务退化为「仅本地加密存储」（与历史行为一致）。
func (s *Service) AttachStorageZones(zones *storage.StorageZoneRepo) {
	s.zones = zones
	if s.backends == nil {
		s.backends = keybackend.NewManager()
	}
}

// StorageZones 返回存储区域仓储（未注入时为 nil）。
func (s *Service) StorageZones() *storage.StorageZoneRepo { return s.zones }

// Close 释放已打开的后端资源（优雅退出时调用）。
func (s *Service) Close() error {
	if s.backends == nil {
		return nil
	}
	return s.backends.Close()
}

// InvalidateZone 在存储区域配置变更/删除后清理后端缓存。
func (s *Service) InvalidateZone(zoneUUID string) {
	if s.backends != nil {
		s.backends.Invalidate(zoneUUID)
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
// 私钥按卡片所属存储区域存放：本地加密入库 / TPM 内生成 / HSM 内生成。
func (s *Service) GenerateKeyPair(ctx context.Context, cardUUID, userUUID, keyType, remark string) (*storage.Certificate, error) {
	// 验证卡片归属
	card, err := s.GetCard(ctx, cardUUID, userUUID)
	if err != nil {
		return nil, err
	}

	provider, driver, err := s.backendForCard(ctx, card)
	if err != nil {
		return nil, err
	}
	if err := ensureKeyTypeSupported(provider, keyType); err != nil {
		return nil, err
	}

	kp, err := provider.Generate(ctx, keybackend.KeySpec{KeyType: keyType, Label: keyLabel(remark, keyType)})
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败（存储区域：%s）: %w", driver, err)
	}
	if len(kp.PublicDER) == 0 {
		return nil, fmt.Errorf("后端 %s 未返回公钥", driver)
	}

	cert := &storage.Certificate{
		CardUUID:    cardUUID,
		UserUUID:    userUUID,
		CertType:    "x509",
		KeyType:     keyType,
		CertContent: kp.PublicDER,
		PrivateData: kp.Blob,
		KeyBackend:  driver,
		KeyRef:      kp.Ref,
		Remark:      remark,
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		// 入库失败时回收已生成的硬件密钥，避免留下孤儿对象
		if kp.Ref != "" {
			_ = provider.Destroy(ctx, keybackend.KeyHandle{Driver: driver, Ref: kp.Ref})
		}
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}

	slog.Info("已生成密钥对", "card", cardUUID, "backend", driver, "hardware", kp.Hardware, "key_type", keyType)

	// 返回时清空私钥字段
	cert.PrivateData = nil
	cert.KeyRef = ""
	return cert, nil
}

// ImportCert 导入证书（仅公钥/证书内容，无私钥）。
func (s *Service) ImportCert(ctx context.Context, cardUUID, userUUID, certType, keyType, remark string, certContent []byte) (*storage.Certificate, error) {
	if _, err := s.GetCard(ctx, cardUUID, userUUID); err != nil {
		return nil, err
	}

	cert := &storage.Certificate{
		CardUUID:    cardUUID,
		UserUUID:    userUUID,
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

// ImportCertWithKey 导入「证书 + 私钥」，私钥按卡片所属存储区域存放。
//
// 本地存储区域直接加密入库；HSM/TPM 存储区域会把私钥写入设备
// （需该存储区域显式开启「允许导入外部私钥」，TPM 因为安全模型不允许导入）。
func (s *Service) ImportCertWithKey(ctx context.Context, cardUUID, userUUID, certType, keyType, remark string, certContent, privDER []byte) (*storage.Certificate, error) {
	card, err := s.GetCard(ctx, cardUUID, userUUID)
	if err != nil {
		return nil, err
	}
	if len(privDER) == 0 {
		return nil, fmt.Errorf("私钥内容为空")
	}
	if _, err := keybackend.ParsePrivateKey(privDER); err != nil {
		return nil, fmt.Errorf("私钥格式无法解析（需要 PKCS#8/PKCS#1/SEC1 的 DER）: %w", err)
	}

	provider, driver, err := s.backendForCard(ctx, card)
	if err != nil {
		return nil, err
	}
	if keyType == "" {
		keyType = "rsa2048"
	}
	kp, err := provider.Import(ctx, privDER, keybackend.KeySpec{KeyType: keyType, Label: keyLabel(remark, keyType)})
	if err != nil {
		return nil, fmt.Errorf("导入私钥失败（存储区域：%s）: %w", describeDriver(driver), err)
	}

	// 若未显式提供证书内容，则回退为导入公钥
	content := certContent
	if len(content) == 0 && len(kp.PublicDER) > 0 {
		content = kp.PublicDER
	}
	cert := &storage.Certificate{
		CardUUID:    cardUUID,
		UserUUID:    userUUID,
		CertType:    certType,
		KeyType:     keyType,
		CertContent: content,
		PrivateData: kp.Blob,
		KeyBackend:  driver,
		KeyRef:      kp.Ref,
		Remark:      remark,
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		if kp.Ref != "" {
			_ = provider.Destroy(ctx, keybackend.KeyHandle{Driver: driver, Ref: kp.Ref})
		}
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	cert.PrivateData = nil
	cert.KeyRef = ""
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
// 对硬件后端（TPM/HSM）会尽力回收设备内的密钥对象，避免留下孤儿密钥。
func (s *Service) DeleteCert(ctx context.Context, certUUID, cardUUID, userUUID string) error {
	card, err := s.GetCard(ctx, cardUUID, userUUID)
	if err != nil {
		return err
	}
	cert, err := s.certForCard(ctx, certUUID, cardUUID)
	if err != nil {
		// 无关联私钥的证书（例如仅导入证书）允许直接删除
		if delErr := s.certRepo.Delete(ctx, certUUID); delErr != nil {
			return delErr
		}
		return nil
	}

	if keyHandleOf(cert).IsHardware() {
		provider, perr := s.backendForCert(ctx, card, cert)
		if perr != nil {
			slog.Warn("删除证书时无法打开硬件后端，设备内密钥可能残留",
				"cert", certUUID, "backend", cert.KeyBackend, "error", perr)
		} else if derr := provider.Destroy(ctx, keyHandleOf(cert)); derr != nil {
			slog.Warn("删除证书时回收设备密钥失败", "cert", certUUID, "backend", cert.KeyBackend, "error", derr)
		}
	}
	return s.certRepo.Delete(ctx, certUUID)
}

// Sign 使用云端私钥签名。私钥始终留在其所在的后端（本地加密库 / TPM / HSM）内。
func (s *Service) Sign(ctx context.Context, certUUID, cardUUID, userUUID, mechanism string, data []byte) ([]byte, error) {
	card, err := s.GetCard(ctx, cardUUID, userUUID)
	if err != nil {
		return nil, err
	}
	cert, err := s.certForCard(ctx, certUUID, cardUUID)
	if err != nil {
		return nil, err
	}
	provider, err := s.backendForCert(ctx, card, cert)
	if err != nil {
		return nil, err
	}
	return provider.Sign(ctx, keyHandleOf(cert), mechanism, data)
}

// Decrypt 使用云端私钥解密（仅 RSA）。
func (s *Service) Decrypt(ctx context.Context, certUUID, cardUUID, userUUID, mechanism string, ciphertext []byte) ([]byte, error) {
	card, err := s.GetCard(ctx, cardUUID, userUUID)
	if err != nil {
		return nil, err
	}
	cert, err := s.certForCard(ctx, certUUID, cardUUID)
	if err != nil {
		return nil, err
	}
	provider, err := s.backendForCert(ctx, card, cert)
	if err != nil {
		return nil, err
	}
	return provider.Decrypt(ctx, keyHandleOf(cert), mechanism, ciphertext)
}

// ExportPKCS12 将证书、私钥与可选证书链打包为真正的 PKCS#12（PFX）。
//
// 注意：PKCS#12 必须内嵌明文私钥，因此只有「可导出」的存储区域
// （本地加密存储，以及设备允许导出的 HSM）才能导出；TPM 与常规 HSM 会返回明确错误。
// 导出私钥属敏感操作，因此不接受空口令。
func (s *Service) ExportPKCS12(ctx context.Context, cert *storage.Certificate, password string, caPEMs []string) ([]byte, error) {
	if len(password) < 8 {
		return nil, fmt.Errorf("导出 PKCS#12 需提供至少 8 位保护口令")
	}
	privKey, err := s.exportPrivateKey(ctx, cert)
	if err != nil {
		return nil, err
	}

	leaf, err := x509.ParseCertificate(cert.CertContent)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	chain := make([]*x509.Certificate, 0, len(caPEMs))
	for _, pemStr := range caPEMs {
		if pemStr == "" {
			continue
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			chain = append(chain, c)
		}
	}

	pfx, err := pkcs12.Modern.Encode(privKey, leaf, chain, password)
	if err != nil {
		return nil, fmt.Errorf("打包 PKCS#12 失败: %w", err)
	}
	return pfx, nil
}

// ExportAsPKCS12 兼容旧调用：打包 PFX，不额外附带证书链。
func (s *Service) ExportAsPKCS12(ctx context.Context, cert *storage.Certificate, password string) ([]byte, error) {
	return s.ExportPKCS12(ctx, cert, password, nil)
}

// ExportPrivateKeyPEM 以 PKCS#8 PEM 形式返回私钥（供受控下发链路使用）。
// 调用方必须已完成授权与审计，本方法只负责格式转换。
func (s *Service) ExportPrivateKeyPEM(ctx context.Context, cert *storage.Certificate) (string, error) {
	der, err := s.exportPrivateKeyDER(ctx, cert)
	if err != nil {
		return "", err
	}
	block, err := keybackend.PKCS8PEM(der)
	if err != nil {
		return "", err
	}
	return string(block), nil
}

// DecryptPrivateKey 取出证书的私钥对象（供外部使用，例如 OCSP 委托签名）。
// 硬件后端（TPM/HSM）不支持导出，会返回错误——此时应改用服务内的 Sign 接口完成签名。
func (s *Service) DecryptPrivateKey(ctx context.Context, cert *storage.Certificate) (crypto.PrivateKey, error) {
	der, err := s.exportPrivateKeyDER(ctx, cert)
	if err != nil {
		return nil, err
	}
	return keybackend.ParsePrivateKey(der)
}

// exportPrivateKey 导出私钥对象（PKCS#8）。
func (s *Service) exportPrivateKey(ctx context.Context, cert *storage.Certificate) (crypto.PrivateKey, error) {
	der, err := s.exportPrivateKeyDER(ctx, cert)
	if err != nil {
		return nil, err
	}
	return keybackend.ParsePrivateKey(der)
}

// exportPrivateKeyDER 按证书记录的存储区域导出私钥 DER。
func (s *Service) exportPrivateKeyDER(ctx context.Context, cert *storage.Certificate) ([]byte, error) {
	provider, err := s.backendForCert(ctx, nil, cert)
	if err != nil {
		return nil, err
	}
	der, err := provider.Export(ctx, keyHandleOf(cert))
	if err != nil {
		if errors.Is(err, keybackend.ErrNotExportable) {
			return nil, fmt.Errorf("该证书的私钥位于 %s（%s），由硬件保护不可导出；"+
				"请改用云卡远程签名接口，或把证书重新签发到「本地加密存储」存储区域",
				describeDriver(cert.KeyBackend), describeKind(cert.KeyBackend))
		}
		return nil, fmt.Errorf("导出私钥失败: %w", err)
	}
	return der, nil
}

// EncryptData 使用主密钥加密数据（供外部使用）。
func (s *Service) EncryptData(data []byte) ([]byte, error) {
	return encryptWithMasterKey(s.masterKey, data)
}

// DecryptData 使用主密钥解密数据（供外部使用）。
func (s *Service) DecryptData(blob []byte) ([]byte, error) {
	return decryptWithMasterKey(s.masterKey, blob)
}

// encryptWithMasterKey 用服务端主密钥 AES-256-GCM 加密数据。
func encryptWithMasterKey(masterKey, data []byte) ([]byte, error) {
	return aesGCMEncrypt(masterKey, data)
}

// decryptWithMasterKey 用服务端主密钥 AES-256-GCM 解密数据。
func decryptWithMasterKey(masterKey, blob []byte) ([]byte, error) {
	return aesGCMDecrypt(masterKey, blob)
}

// ---- 私钥存储后端（存储区域）路由 ----

// backendForCard 返回卡片所属存储区域的后端与驱动 ID。
func (s *Service) backendForCard(ctx context.Context, card *storage.Card) (keybackend.Provider, string, error) {
	driver := storage.DriverDatabase
	if card != nil && card.StorageZoneUUID != "" {
		zone, err := s.zoneByUUID(ctx, card.StorageZoneUUID)
		if err != nil {
			return nil, "", err
		}
		driver = zone.DriverID()
		return s.providerForZone(ctx, zone)
	}
	p, err := s.localProvider(ctx)
	return p, driver, err
}

// backendForCert 返回证书私钥所在的后端。
// 本地私钥（key_backend 为空或 database）直接使用内置后端；
// 硬件私钥按卡片所属存储区域打开设备。card 为 nil 时会自行加载。
func (s *Service) backendForCert(ctx context.Context, card *storage.Card, cert *storage.Certificate) (keybackend.Provider, error) {
	driver := driverIDOf(cert.KeyBackend)
	if driver == storage.DriverDatabase {
		return s.localProvider(ctx)
	}
	if card == nil {
		loaded, err := s.cardRepo.GetByUUID(ctx, cert.CardUUID)
		if err != nil {
			return nil, fmt.Errorf("加载卡片失败: %w", err)
		}
		card = loaded
	}
	provider, actual, err := s.backendForCard(ctx, card)
	if err != nil {
		return nil, err
	}
	if actual != driver {
		return nil, fmt.Errorf("证书私钥位于 %s 存储区域（%s），但卡片当前绑定的是 %s；"+
			"请把卡片的存储区域改回原存储区域后再操作", describeDriver(driver), describeKind(driver), describeDriver(actual))
	}
	return provider, nil
}

// providerForZone 打开（并缓存）某个存储区域对应的后端。
func (s *Service) providerForZone(ctx context.Context, zone *storage.StorageZone) (keybackend.Provider, string, error) {
	if s.backends == nil {
		s.backends = keybackend.NewManager()
	}
	driver := zone.DriverID()
	params, err := s.DecryptZoneParams(zone)
	if err != nil {
		return nil, "", err
	}
	provider, err := s.backends.Open(ctx, keybackend.Config{
		Driver:    driver,
		Kind:      keybackend.NormalizeKind(zone.StorageType),
		Params:    params,
		MasterKey: s.masterKey,
		Label:     zone.Name,
		CacheKey:  zone.UUID,
	})
	if err != nil {
		return nil, "", fmt.Errorf("打开存储区域「%s」失败: %w", zone.Name, err)
	}
	return provider, driver, nil
}

// localProvider 返回内置的本地加密存储后端（无状态，可安全共享）。
func (s *Service) localProvider(ctx context.Context) (keybackend.Provider, error) {
	if s.backends == nil {
		s.backends = keybackend.NewManager()
	}
	return s.backends.Open(ctx, keybackend.Config{
		Driver:    storage.DriverDatabase,
		Kind:      keybackend.KindDatabase,
		MasterKey: s.masterKey,
		Label:     "本地加密存储",
		CacheKey:  "__local__",
	})
}

// OpenZone 打开指定存储区域的后端（供管理端做连通性测试）。
func (s *Service) OpenZone(ctx context.Context, zoneUUID string) (keybackend.Provider, *storage.StorageZone, error) {
	zone, err := s.zoneByUUID(ctx, zoneUUID)
	if err != nil {
		return nil, nil, err
	}
	provider, _, err := s.providerForZone(ctx, zone)
	if err != nil {
		return nil, zone, err
	}
	return provider, zone, nil
}

// ProbeZone 使用「尚未保存」的配置尝试打开后端，供管理端测试连接。
// 调用方负责 Close 返回的 Provider。
func (s *Service) ProbeZone(ctx context.Context, driver string, kind keybackend.Kind, params keybackend.Params) (keybackend.Provider, error) {
	return keybackend.Open(ctx, keybackend.Config{
		Driver:    driver,
		Kind:      kind,
		Params:    params,
		MasterKey: s.masterKey,
		Label:     "连接测试",
	})
}

// EncryptZoneParams 用主密钥加密存储区域参数（入库前调用）。
func (s *Service) EncryptZoneParams(params keybackend.Params) ([]byte, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("序列化存储区域参数失败: %w", err)
	}
	return encryptWithMasterKey(s.masterKey, raw)
}

// DecryptZoneParams 解密存储区域参数。
func (s *Service) DecryptZoneParams(zone *storage.StorageZone) (keybackend.Params, error) {
	if zone == nil || len(zone.ParamsEnc) == 0 {
		return keybackend.Params{}, nil
	}
	raw, err := decryptWithMasterKey(s.masterKey, zone.ParamsEnc)
	if err != nil {
		return nil, fmt.Errorf("解密存储区域参数失败（主密钥可能已更换）: %w", err)
	}
	params := keybackend.Params{}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("解析存储区域参数失败: %w", err)
	}
	return params, nil
}

// ParamsForView 返回可回显给管理端的参数（敏感项抹除）。
func (s *Service) ParamsForView(zone *storage.StorageZone) map[string]string {
	params, err := s.DecryptZoneParams(zone)
	if err != nil {
		return map[string]string{"_error": err.Error()}
	}
	driver := zone.DriverID()
	desc, ok := keybackend.Lookup(driver)
	if !ok {
		return params
	}
	safe := params.Redact(desc.SecretKeys())
	out := map[string]string{}
	for k, v := range safe {
		out[k] = v
	}
	return out
}

// ZoneCapabilities 返回存储区域驱动的能力描述（JSON）。
func (s *Service) ZoneCapabilities(zone *storage.StorageZone) keybackend.Capabilities {
	if desc, ok := keybackend.Lookup(zone.DriverID()); ok {
		return desc.Capabilities
	}
	return keybackend.Capabilities{}
}

func (s *Service) zoneByUUID(ctx context.Context, zoneUUID string) (*storage.StorageZone, error) {
	if s.zones == nil {
		return nil, fmt.Errorf("%w: 服务未启用存储区域（%s）", keybackend.ErrZoneNotFound, zoneUUID)
	}
	return s.zones.GetByUUID(ctx, zoneUUID)
}

// certForCard 校验证书归属卡片并返回证书（含私钥引用）。
func (s *Service) certForCard(ctx context.Context, certUUID, cardUUID string) (*storage.Certificate, error) {
	cert, err := s.certRepo.GetByUUID(ctx, certUUID)
	if err != nil {
		return nil, err
	}
	if cert.CardUUID != cardUUID {
		return nil, fmt.Errorf("证书不属于此卡片")
	}
	if cert.KeyBackend == "" && len(cert.PrivateData) == 0 {
		return nil, fmt.Errorf("证书没有关联的私钥")
	}
	return cert, nil
}

// keyHandleOf 把证书转换为后端私钥句柄。
func keyHandleOf(cert *storage.Certificate) keybackend.KeyHandle {
	return keybackend.KeyHandle{
		Driver: driverIDOf(cert.KeyBackend),
		Ref:    cert.KeyRef,
		Blob:   cert.PrivateData,
	}
}

// driverIDOf 归一化驱动 ID（空 = 本地加密存储）。
func driverIDOf(backend string) string {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", storage.DriverDatabase, "db", "local":
		return storage.DriverDatabase
	case "tpm", "tpm2", "tpmv2":
		return storage.DriverTPM
	default:
		return strings.ToLower(strings.TrimSpace(backend))
	}
}

// ensureKeyTypeSupported 在生成前校验后端是否支持该算法，避免多步操作后才发现。
func ensureKeyTypeSupported(provider keybackend.Provider, keyType string) error {
	caps := provider.Capabilities()
	if len(caps.KeyTypes) == 0 || strings.TrimSpace(keyType) == "" {
		return nil
	}
	for _, kt := range caps.KeyTypes {
		if strings.EqualFold(kt, keyType) {
			return nil
		}
	}
	return fmt.Errorf("存储区域（%s）不支持密钥算法 %s，支持：%s",
		describeDriver(provider.Driver()), keyType, strings.Join(caps.KeyTypes, "/"))
}

// keyLabel 生成写入设备的对象标签。
func keyLabel(remark, keyType string) string {
	remark = strings.TrimSpace(remark)
	if remark == "" {
		return keyType
	}
	if len(remark) > 48 {
		remark = remark[:48]
	}
	return remark
}

func describeDriver(driver string) string {
	switch driverIDOf(driver) {
	case storage.DriverDatabase:
		return "本地加密存储"
	case storage.DriverTPM:
		return "TPM"
	case storage.DriverPKCS11:
		return "PKCS#11 HSM"
	default:
		return driver
	}
}

func describeKind(driver string) string {
	switch driverIDOf(driver) {
	case storage.DriverDatabase:
		return "database"
	case storage.DriverTPM:
		return "tpm"
	case storage.DriverPKCS11:
		return "hsm"
	default:
		return driver
	}
}
