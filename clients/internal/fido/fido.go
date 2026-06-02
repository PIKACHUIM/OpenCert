// Package fido-umdf 提供 FIDO2/WebAuthn 凭据的存储与管理逻辑。
//
// FIDO 凭据复用 storage.Certificate 表（cert_type = "fido-umdf"）：
//   - CertContent（公开）：存储 JSON 格式的公开元数据（RP ID、用户名、Credential ID 等）
//   - PrivateData（加密）：存储 JSON 格式的私密数据（私钥 PEM、key handle 等）
//
// 加密策略与其他凭据一致，由 card/local.KeyManager 负责。
package fido

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---- 数据结构 ----

// Meta 是 FIDO 凭据的公开元数据，存储在 CertContent 字段（JSON 编码）。
type Meta struct {
	// RPID 是依赖方标识符（Relying Party ID），通常是域名，如 "example.com"。
	RPID string `json:"rp_id"`
	// RPName 是依赖方名称（可选），如 "Example Corp"。
	RPName string `json:"rp_name,omitempty"`
	// UserName 是用户名（可读标识），如 "alice@example.com"。
	UserName string `json:"user_name"`
	// UserDisplayName 是用户显示名称（可选）。
	UserDisplayName string `json:"user_display_name,omitempty"`
	// UserHandle 是用户句柄（base64url 编码的不透明字节串），用于标识用户账户。
	UserHandle string `json:"user_handle,omitempty"`
	// CredentialID 是凭据 ID（base64url 编码），由认证器生成，用于标识此凭据。
	CredentialID string `json:"credential_id"`
	// Algorithm 是签名算法，如 "ES256"（ECDSA P-256）、"RS256"（RSA PKCS1v15）。
	Algorithm string `json:"algorithm,omitempty"`
	// Counter 是签名计数器，用于防重放攻击。
	Counter uint32 `json:"counter"`
	// Transports 是支持的传输方式列表，如 ["usb", "nfc", "ble", "internal"]。
	Transports []string `json:"transports,omitempty"`
	// BackupEligible 表示凭据是否支持备份（WebAuthn Level 3）。
	BackupEligible bool `json:"backup_eligible,omitempty"`
	// BackupState 表示凭据当前是否已备份。
	BackupState bool `json:"backup_state,omitempty"`
}

// Secret 是 FIDO 凭据的私密数据，存储在 PrivateData 字段（JSON 编码后加密）。
type Secret struct {
	// PrivateKeyPEM 是私钥的 PEM 编码（PKCS#8 格式）。
	// 对于软件实现的 FIDO 凭据，私钥存储在此处。
	// 对于硬件认证器（如 YubiKey），此字段为空。
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	// KeyHandle 是认证器内部的密钥句柄（base64url 编码）。
	// 用于硬件认证器或云端密钥管理场景。
	KeyHandle string `json:"key_handle,omitempty"`
	// PublicKeyDER 是公钥的 DER 编码（PKIX 格式），用于验签。
	PublicKeyDER string `json:"public_key_der,omitempty"`
	// AAGUID 是认证器的 AAGUID（16 字节，base64url 编码），标识认证器型号。
	AAGUID string `json:"aaguid,omitempty"`
}

// Entry 是一条完整的 FIDO 凭据记录（含公开元数据，不含私密数据）。
type Entry struct {
	UUID      string    `json:"uuid"`
	CardUUID  string    `json:"card_uuid"`
	Meta      Meta      `json:"meta"`
	KeyType   string    `json:"key_type"` // 如 "fido2"
	Remark    string    `json:"remark"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ---- 元数据编解码 ----

// EncodeMeta 将 Meta 编码为 JSON 字节，用于存储到 CertContent。
func EncodeMeta(m *Meta) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("编码 FIDO 元数据失败: %w", err)
	}
	return data, nil
}

// DecodeMeta 从 JSON 字节解码 Meta。
func DecodeMeta(data []byte) (*Meta, error) {
	if len(data) == 0 {
		return &Meta{}, nil
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("解码 FIDO 元数据失败: %w", err)
	}
	return &m, nil
}

// EncodeSecret 将 Secret 编码为 JSON 字节，用于加密存储到 PrivateData。
func EncodeSecret(s *Secret) ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("编码 FIDO 私密数据失败: %w", err)
	}
	return data, nil
}

// DecodeSecret 从 JSON 字节解码 Secret。
func DecodeSecret(data []byte) (*Secret, error) {
	if len(data) == 0 {
		return &Secret{}, nil
	}
	var s Secret
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("解码 FIDO 私密数据失败: %w", err)
	}
	return &s, nil
}

// ---- 验证 ----

// ValidateMeta 验证 FIDO 元数据的必填字段。
func ValidateMeta(m *Meta) error {
	if m.RPID == "" {
		return fmt.Errorf("rp_id 不能为空")
	}
	if m.UserName == "" {
		return fmt.Errorf("user_name 不能为空")
	}
	if m.CredentialID == "" {
		return fmt.Errorf("credential_id 不能为空")
	}
	return nil
}

// ZeroBytes 安全清零字节切片，防止私钥数据残留在内存中。
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
