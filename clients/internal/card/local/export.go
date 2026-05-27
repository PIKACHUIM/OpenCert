package local

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
)

// OCSFile 是 .ocs（OpenCert Smartcard）导出文件格式。
type OCSFile struct {
	Version       int    `json:"version"`
	Salt          string `json:"salt"`           // base64 编码的随机盐
	EncryptedData string `json:"encrypted_data"` // base64(AES256GCM(HMAC256(password, salt), payload))
	Checksum      string `json:"checksum"`       // HMAC256 校验
}

// OCSPayload 是 .ocs 文件中加密的有效载荷。
type OCSPayload struct {
	// 卡片元信息
	CardUUID      string                `json:"card_uuid"`
	CardName      string                `json:"card_name"`
	SecurityLevel storage.SecurityLevel `json:"security_level"`
	SlotType      storage.SlotType      `json:"slot_type"`
	CreatedAt     string                `json:"created_at"`
	ExpiresAt     string                `json:"expires_at,omitempty"`
	Remark        string                `json:"remark,omitempty"`
	CardKeys      []storage.CardKeyEntry `json:"card_keys"`
	// TPM 证书密钥（仅 medium 安全等级）
	TPMCertKeyEnc  []byte `json:"tpm_cert_key_enc,omitempty"`
	TPMCertKeySalt []byte `json:"tpm_cert_key_salt,omitempty"`
	// 证书列表
	Certificates []OCSCertificate `json:"certificates"`
	// 安全凭据列表
	Credentials []OCSCredential `json:"credentials"`
}

// OCSCertificate 是导出的证书数据。
type OCSCertificate struct {
	UUID        string `json:"uuid"`
	CertType    string `json:"cert_type"`
	KeyType     string `json:"key_type"`
	CertContent []byte `json:"cert_content,omitempty"` // 公钥/证书部分
	TempKeySalt []byte `json:"temp_key_salt,omitempty"`
	TempKeyEnc  []byte `json:"temp_key_enc,omitempty"`
	PrivateData []byte `json:"private_data,omitempty"` // 加密的私钥
	Remark      string `json:"remark,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// OCSCredential 是导出的安全凭据数据。
type OCSCredential struct {
	UUID        string `json:"uuid"`
	CertType    string `json:"cert_type"`
	KeyType     string `json:"key_type"`
	CertContent []byte `json:"cert_content,omitempty"` // 公开元数据
	TempKeySalt []byte `json:"temp_key_salt,omitempty"`
	TempKeyEnc  []byte `json:"temp_key_enc,omitempty"`
	PrivateData []byte `json:"private_data,omitempty"` // 加密的私密数据
	Remark      string `json:"remark,omitempty"`
	CreatedAt   string `json:"created_at"`
}

// ExportCardRequest 是导出卡片的请求参数。
type ExportCardRequest struct {
	CardUUID string
	Password string // 卡片密码（low 安全等级）
	AdminKey string // AdminKey（medium 安全等级）
}

// ExportCard 导出智能卡为 .ocs 格式的 JSON 字节。
// 按安全等级限制：high 禁止、medium 需 ADMINKEY、low 需卡片密码。
func ExportCard(ctx context.Context, cardRepo *storage.CardRepo, certRepo *storage.CertRepo, req ExportCardRequest) ([]byte, error) {
	card, err := cardRepo.GetByUUID(ctx, req.CardUUID)
	if err != nil || card == nil {
		return nil, fmt.Errorf("卡片不存在")
	}

	// 安全等级检查
	switch card.SecurityLevel {
	case storage.SecurityLevelHigh:
		return nil, fmt.Errorf("高安全性卡片不可导出")
	case storage.SecurityLevelMedium:
		if req.AdminKey == "" {
			return nil, fmt.Errorf("中安全性卡片需要 AdminKey 才能导出")
		}
		// 验证 AdminKey
		if _, err := tryUnlockByType(card, "admin", req.AdminKey); err != nil {
			return nil, fmt.Errorf("AdminKey 验证失败: %w", err)
		}
	default: // low
		if req.Password == "" {
			return nil, fmt.Errorf("需要卡片密码才能导出")
		}
		// 验证密码
		if _, err := tryUnlockAny(card, req.Password); err != nil {
			return nil, fmt.Errorf("卡片密码验证失败: %w", err)
		}
	}

	// 获取卡片下的所有证书
	certs, err := certRepo.ListByCard(ctx, req.CardUUID)
	if err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %w", err)
	}

	// 构建 payload
	payload := OCSPayload{
		CardUUID:       card.UUID,
		CardName:       card.CardName,
		SecurityLevel:  card.SecurityLevel,
		SlotType:       card.SlotType,
		CreatedAt:      card.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Remark:         card.Remark,
		CardKeys:       card.CardKeys,
		TPMCertKeyEnc:  card.TPMCertKeyEnc,
		TPMCertKeySalt: card.TPMCertKeySalt,
	}
	if card.ExpiresAt != nil {
		payload.ExpiresAt = card.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}

	// 分类证书和凭据
	certTypes := map[storage.CertType]bool{
		storage.CertTypeX509: true,
		storage.CertTypeSSH:  true,
		storage.CertTypeGPG:  true,
	}
	for _, c := range certs {
		if certTypes[c.CertType] {
			payload.Certificates = append(payload.Certificates, OCSCertificate{
				UUID:        c.UUID,
				CertType:    string(c.CertType),
				KeyType:     c.KeyType,
				CertContent: c.CertContent,
				TempKeySalt: c.TempKeySalt,
				TempKeyEnc:  c.TempKeyEnc,
				PrivateData: c.PrivateData,
				Remark:      c.Remark,
				CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		} else {
			payload.Credentials = append(payload.Credentials, OCSCredential{
				UUID:        c.UUID,
				CertType:    string(c.CertType),
				KeyType:     c.KeyType,
				CertContent: c.CertContent,
				TempKeySalt: c.TempKeySalt,
				TempKeyEnc:  c.TempKeyEnc,
				PrivateData: c.PrivateData,
				Remark:      c.Remark,
				CreatedAt:   c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			})
		}
	}

	// 序列化 payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化导出数据失败: %w", err)
	}

	// 确定加密密码
	encPassword := req.Password
	if encPassword == "" {
		encPassword = req.AdminKey
	}

	// 生成盐值
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("生成盐值失败: %w", err)
	}

	// 加密：AES256GCM(HMAC256(password, salt), payload)
	aesKey := cryptoutil.HMACSHA256([]byte(encPassword), salt)
	encData, err := cryptoutil.EncryptAES256GCM(aesKey, payloadJSON)
	if err != nil {
		return nil, fmt.Errorf("加密导出数据失败: %w", err)
	}

	// 计算校验和
	mac := hmac.New(sha256.New, aesKey)
	mac.Write(encData)
	checksum := mac.Sum(nil)

	// 构建 OCS 文件
	ocsFile := OCSFile{
		Version:       1,
		Salt:          base64.StdEncoding.EncodeToString(salt),
		EncryptedData: base64.StdEncoding.EncodeToString(encData),
		Checksum:      base64.StdEncoding.EncodeToString(checksum),
	}

	result, err := json.MarshalIndent(ocsFile, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化 OCS 文件失败: %w", err)
	}
	return result, nil
}

// RestoreCardRequest 是恢复卡片的请求参数。
type RestoreCardRequest struct {
	OCSData  []byte // .ocs 文件内容
	Password string // 解密密码
	UserUUID string // 恢复到哪个用户
}

// RestoreCard 从 .ocs 文件恢复智能卡数据。
func RestoreCard(ctx context.Context, cardRepo *storage.CardRepo, certRepo *storage.CertRepo, req RestoreCardRequest) (*storage.Card, error) {
	// 1. 解析 OCS 文件
	var ocsFile OCSFile
	if err := json.Unmarshal(req.OCSData, &ocsFile); err != nil {
		return nil, fmt.Errorf("解析 OCS 文件失败: %w", err)
	}
	if ocsFile.Version != 1 {
		return nil, fmt.Errorf("不支持的 OCS 文件版本: %d", ocsFile.Version)
	}

	// 2. 解码盐值和加密数据
	salt, err := base64.StdEncoding.DecodeString(ocsFile.Salt)
	if err != nil {
		return nil, fmt.Errorf("解码盐值失败: %w", err)
	}
	encData, err := base64.StdEncoding.DecodeString(ocsFile.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("解码加密数据失败: %w", err)
	}
	checksumBytes, err := base64.StdEncoding.DecodeString(ocsFile.Checksum)
	if err != nil {
		return nil, fmt.Errorf("解码校验和失败: %w", err)
	}

	// 3. 派生 AES 密钥并验证校验和
	aesKey := cryptoutil.HMACSHA256([]byte(req.Password), salt)
	mac := hmac.New(sha256.New, aesKey)
	mac.Write(encData)
	expectedChecksum := mac.Sum(nil)
	if !hmac.Equal(checksumBytes, expectedChecksum) {
		return nil, fmt.Errorf("密码错误或文件已损坏（校验和不匹配）")
	}

	// 4. 解密 payload
	payloadJSON, err := cryptoutil.DecryptAES256GCM(aesKey, encData)
	if err != nil {
		return nil, fmt.Errorf("解密失败（密码错误）: %w", err)
	}

	// 5. 反序列化 payload
	var payload OCSPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("解析导出数据失败: %w", err)
	}

	// 6. 创建卡片
	card := &storage.Card{
		SlotType:       payload.SlotType,
		CardName:       payload.CardName + " (恢复)",
		UserUUID:       req.UserUUID,
		SecurityLevel:  payload.SecurityLevel,
		CardKeys:       payload.CardKeys,
		TPMCertKeyEnc:  payload.TPMCertKeyEnc,
		TPMCertKeySalt: payload.TPMCertKeySalt,
		Remark:         payload.Remark,
	}
	if err := cardRepo.Create(ctx, card); err != nil {
		return nil, fmt.Errorf("创建恢复卡片失败: %w", err)
	}

	// 7. 恢复证书
	for _, c := range payload.Certificates {
		cert := &storage.Certificate{
			SlotType:    storage.SlotTypeLocal,
			CardUUID:    card.UUID,
			CertType:    storage.CertType(c.CertType),
			KeyType:     c.KeyType,
			CertContent: c.CertContent,
			TempKeySalt: c.TempKeySalt,
			TempKeyEnc:  c.TempKeyEnc,
			PrivateData: c.PrivateData,
			Remark:      c.Remark,
		}
		if err := certRepo.Create(ctx, cert); err != nil {
			return nil, fmt.Errorf("恢复证书失败: %w", err)
		}
	}

	// 8. 恢复凭据
	for _, c := range payload.Credentials {
		cert := &storage.Certificate{
			SlotType:    storage.SlotTypeLocal,
			CardUUID:    card.UUID,
			CertType:    storage.CertType(c.CertType),
			KeyType:     c.KeyType,
			CertContent: c.CertContent,
			TempKeySalt: c.TempKeySalt,
			TempKeyEnc:  c.TempKeyEnc,
			PrivateData: c.PrivateData,
			Remark:      c.Remark,
		}
		if err := certRepo.Create(ctx, cert); err != nil {
			return nil, fmt.Errorf("恢复凭据失败: %w", err)
		}
	}

	return card, nil
}

// tryUnlockAny 尝试用密码解锁任意类型的 CardKeyEntry（pin/card/user）。
func tryUnlockAny(card *storage.Card, password string) ([]byte, error) {
	for _, keyType := range []string{"pin", "card", "user"} {
		mk, err := tryUnlockByType(card, keyType, password)
		if err == nil {
			return mk, nil
		}
	}
	return nil, fmt.Errorf("密码验证失败")
}
