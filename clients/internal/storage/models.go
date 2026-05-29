package storage

import (
	"encoding/pem"
	"time"
)

// ---- 用户模型 ----

// UserType 是用户类型。
type UserType string

const (
	UserTypeLocal UserType = "local"
	UserTypeCloud UserType = "cloud"
)

// User 是用户数据模型。
type User struct {
	UUID         string    `json:"uuid"`
	UserType     UserType  `json:"user_type"`
	Role         string    `json:"role"`            // admin / user / readonly
	Username     string    `json:"username"`        // 登录用户名（唯一）
	DisplayName  string    `json:"display_name"`
	Email        string    `json:"email"`
	Enabled      bool      `json:"enabled"`
	CloudURL     string    `json:"cloud_url"`
	PasswordHash string    `json:"-"`               // bcrypt 哈希，不序列化到 JSON
	AuthToken    Base64Bytes `json:"-"`             // 加密存储，不序列化到 JSON
	// 2FA (TOTP) 字段
	TwoFAEnabled bool      `json:"two_fa_enabled"` // 是否已启用 2FA
	TwoFASecret  string    `json:"-"`              // TOTP 密钥（Base32），不暴露给前端
	PasswordlessEnabled bool `json:"passwordless_enabled"` // 是否启用免密码登录（仅 2FA 验证即可）
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ---- 卡片模型 ----

// SlotType 是卡片 Slot 类型。
type SlotType string

const (
	SlotTypeLocal SlotType = "local"
	SlotTypeTPM2  SlotType = "tpm2"
	SlotTypeTPMSC SlotType = "tpmsc" // Microsoft TPM Virtual Smart Card（tpmvscmgr.exe）
	SlotTypeCloud SlotType = "cloud"
)

// SecurityLevel 是智能卡安全等级。
type SecurityLevel string

const (
	SecurityLevelHigh   SecurityLevel = "high"   // 高安全性：密钥存储于 TPM，不可导出
	SecurityLevelMedium SecurityLevel = "medium" // 中安全性：TPM 证书密钥加密 + 主密钥加密，ADMINKEY 可导出
	SecurityLevelLow    SecurityLevel = "low"    // 低安全性：仅主密钥加密，PIN/密码可导出
)

// CardKeyEntry 是卡片主密钥的一条加密记录。
// 卡片密码以列表形式存储，支持多用户权限。
type CardKeyEntry struct {
	// KeyType 区分凭据种类：
	//   "user"  = 用户密码（个人用户多端同步时常见）
	//   "card"  = 卡片设定密码（所有持卡用户共享）
	//   "pin"   = 卡片 PIN 码（最常用；与 "card" 同义，保留兼容）
	//   "puk"   = PUK 解锁码，用于重置 PIN
	//   "admin" = Admin Key，用于重置 PUK（最高权限）
	KeyType      string `json:"key_type"`
	UserUUID     string `json:"user_uuid,omitempty"` // KeyType=user 时有效
	Salt         []byte `json:"salt"`                // 32 字节随机盐值
	EncMasterKey []byte `json:"enc_master_key"`      // AES256 加密的主密钥副本
	// 失败/锁定状态（0 值=从未失败；Locked=true 表示该凭据已锁定）
	Attempts int  `json:"attempts,omitempty"`
	Locked   bool `json:"locked,omitempty"`
}

// Card 是卡片数据模型。
type Card struct {
	UUID      string         `json:"uuid"`
	SlotType  SlotType       `json:"slot_type"`
	CardName  string         `json:"card_name"`
	UserUUID  string         `json:"user_uuid"`
	Enabled   bool           `json:"enabled"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	CardKeys  []CardKeyEntry `json:"card_keys"` // 存储为 JSON TEXT
	Remark    string         `json:"remark"`
	// 安全等级
	SecurityLevel SecurityLevel `json:"security_level"` // high/medium/low
	// TPM 证书密钥（仅 medium 安全等级使用）
	TPMCertKeyEnc  Base64Bytes `json:"-"` // 被 ADMINKEY 加密的应急恢复副本
	TPMCertKeySalt Base64Bytes `json:"-"` // 应急恢复副本加密盐值
	// medium：TPM 证书密钥在 TPM NV 域中的句柄；0 表示未启用
	TPMCertKeyNVHandle uint32 `json:"-"`
	// medium/high：TPM Provider 平台名（sw-stub / windows-cng / linux-tpm2 / mock 等）
	TPMProvider string `json:"tpm_provider,omitempty"`
	// PIN 安全字段
	PINRetries     int  `json:"pin_retries"`      // PIN 错误最大次数（默认 3）
	PINFailedCount int  `json:"pin_failed_count"` // 当前连续错误次数
	PINLocked      bool `json:"pin_locked"`       // PIN 是否被锁定
	// Cloud Slot 专用字段
	CloudURL      string `json:"cloud_url,omitempty"`       // servers 服务地址，如 http://localhost:1027
	CloudCardUUID string `json:"cloud_card_uuid,omitempty"` // 在 servers 中的卡片 UUID
}

// ---- 证书模型 ----

// CertType 是证书/密钥类型。
type CertType string

const (
	CertTypeX509    CertType = "x509"
	CertTypeSSH     CertType = "ssh"
	CertTypeGPG     CertType = "gpg"
	CertTypeTOTP    CertType = "totp"
	CertTypeFIDO    CertType = "fido"
	CertTypeLogin   CertType = "login"
	CertTypeText    CertType = "text"
	CertTypeNote    CertType = "note"
	CertTypePayment CertType = "payment"
)

// TPMPlatform 是 TPM 平台类型。
type TPMPlatform string

const (
	TPMPlatformNone    TPMPlatform = ""
	TPMPlatformTPM2    TPMPlatform = "tpm2"
	TPMPlatformAppleT2 TPMPlatform = "apple_t2"
	TPMPlatformAppleSE TPMPlatform = "apple_se"
)

// Certificate 是证书/密钥数据模型。
type Certificate struct {
	UUID        string      `json:"uuid"`
	SlotType    SlotType    `json:"slot_type"`
	CardUUID    string      `json:"card_uuid"`
	CertType    CertType    `json:"cert_type"`
	KeyType     string      `json:"key_type"`     // rsa2048/ec256/ed25519/...
	CertContent Base64Bytes `json:"cert_content"` // 公开部分
	TempKeySalt Base64Bytes `json:"-"`            // 32 字节随机盐值
	TempKeyEnc  Base64Bytes `json:"-"`            // 加密的临时密钥
	PrivateData Base64Bytes `json:"-"`            // 加密的私钥/私密数据
	// medium 模式专用：TPM 证书密钥再加密层（PrivateData 已是 TPM 加密 + master 加密的双层包）
	// 该字段为空表示按旧 low/medium 路径（仅 master 加密）解密；非空时按双层解密。
	TPMCertKeySalt Base64Bytes `json:"-"`
	// TPM2 / high 模式专用
	TPMPlatform    TPMPlatform `json:"tpm_platform,omitempty"`
	TPMKeyHandle   *int64      `json:"-"`
	TPMPublicBlob  Base64Bytes `json:"-"`
	TPMPrivateBlob Base64Bytes `json:"-"`
	TPMPCRPolicy   Base64Bytes `json:"-"`
	TPMAuthPolicy  Base64Bytes `json:"-"`
	// high 模式专用：tpm.WrappedKey 序列化（JSON），私钥永不出 TPM。
	TPMWrappedBlob Base64Bytes `json:"-"`
	Remark         string      `json:"remark"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// DERContent 从 CertContent 中提取 DER 格式数据。
// 如果 CertContent 是 PEM 格式，自动解码提取 DER；
// 如果是原始 DER 格式（兼容旧数据），直接返回。
func (c *Certificate) DERContent() []byte {
	if len(c.CertContent) == 0 {
		return nil
	}
	// 尝试 PEM 解码
	block, _ := pem.Decode(c.CertContent)
	if block != nil {
		return block.Bytes
	}
	// 不是 PEM，直接当作 DER 返回（兼容旧数据）
	return c.CertContent
}

// ---- 日志模型 ----

// LogType 是日志类型。
type LogType string

const (
	LogTypeOperation LogType = "operation"
	LogTypeSecurity  LogType = "security"
	LogTypeError     LogType = "error"
)

// LogLevel 是日志等级。
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Log 是日志数据模型。
type Log struct {
	ID         int64     `json:"id"`
	LogType    LogType   `json:"log_type"`
	SlotType   SlotType  `json:"slot_type"`
	CardUUID   string    `json:"card_uuid"`
	UserUUID   string    `json:"user_uuid"`
	LogLevel   LogLevel  `json:"log_level"`
	RecordedAt time.Time `json:"recorded_at"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
}

// ---- PKI 模型 ----

// KeyStorage 是 CSR/证书密钥存储位置。
type KeyStorage string

const (
	KeyStorageDatabase  KeyStorage = "database"  // 私钥存储在本地数据库
	KeyStorageSmartcard KeyStorage = "smartcard"  // 私钥在智能卡上生成，不可导出
	KeyStorageImported  KeyStorage = "imported"   // 外部导入，来源不明
)

// CSRRecord 是 CSR 请求记录。
type CSRRecord struct {
	UUID          string     `json:"uuid"`
	CommonName    string     `json:"common_name"`
	Organization  string     `json:"organization"`
	OrgUnit       string     `json:"org_unit"`
	Country       string     `json:"country"`
	State         string     `json:"state"`
	Locality      string     `json:"locality"`
	Email         string     `json:"email"`
	KeyType       string     `json:"key_type"`
	KeyStorage    KeyStorage `json:"key_storage"`
	CardUUID      string     `json:"card_uuid"`      // KeyStorage=smartcard 时有效
	SANDN         string     `json:"san_dns"`        // 逗号分隔
	SANIP         string     `json:"san_ip"`
	SANEmail      string     `json:"san_email"`
	SANURI        string     `json:"san_uri"`
	KeyUsage      string     `json:"key_usage"`      // JSON 数组序列化
	ExtKeyUsage   string     `json:"ext_key_usage"`  // JSON 数组序列化
	ExtraSubject  string     `json:"extra_subject"`  // JSON 对象，额外 DN 字段
	CSRPEM        string     `json:"csr_pem"`
	HasPrivateKey bool       `json:"has_private_key"`
	PrivateKeyEnc Base64Bytes `json:"-"`              // AES256 加密的私钥（database 模式）
	Remark        string     `json:"remark"`
	CreatedAt     time.Time  `json:"created_at"`
}

// LocalCA 是本地 CA 机构记录。
type LocalCA struct {
	UUID         string    `json:"uuid"`
	Name         string    `json:"name"`
	CommonName   string    `json:"common_name"`
	Organization string    `json:"organization"`
	Country      string    `json:"country"`
	KeyType      string    `json:"key_type"`
	CertPEM      string    `json:"cert_pem"`
	ChainPEM     string    `json:"chain_pem"`      // 证书链（可选）
	HasPrivKey   bool      `json:"has_priv_key"`   // 是否有私钥（有才能签发）
	PrivKeyEnc   Base64Bytes `json:"-"`              // AES256 加密的私钥
	CardUUID     string    `json:"card_uuid"`      // 私钥存储在智能卡时有效
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IssuedCount  int       `json:"issued_count"`
	Revoked      bool      `json:"revoked"`
	CreatedAt    time.Time `json:"created_at"`
}

// PKICert 是 PKI 证书记录。
type PKICert struct {
	UUID          string     `json:"uuid"`
	CommonName    string     `json:"common_name"`
	SerialNumber  string     `json:"serial_number"`
	CAUUID        string     `json:"ca_uuid"`
	CAName        string     `json:"ca_name"`
	CSRUUID       string     `json:"csr_uuid"`
	KeyType       string     `json:"key_type"`
	KeyStorage    KeyStorage `json:"key_storage"`
	CardUUID      string     `json:"card_uuid"`
	CertPEM       string     `json:"cert_pem"`
	HasPrivateKey bool       `json:"has_private_key"`
	PrivateKeyEnc Base64Bytes `json:"-"`             // AES256 加密的私钥
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	KeyUsage      string     `json:"key_usage"`     // JSON 数组序列化
	ExtKeyUsage   string     `json:"ext_key_usage"` // JSON 数组序列化
	SANDN         string     `json:"san_dns"`
	SANIP         string     `json:"san_ip"`
	SANEmail      string     `json:"san_email"`
	Revoked       bool       `json:"revoked"`
	Remark        string     `json:"remark"`
	CreatedAt     time.Time  `json:"created_at"`
}
