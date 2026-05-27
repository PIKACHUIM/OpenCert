// Package storage - 数据模型定义。
package storage

import "time"

// User 是服务端用户模型。
type User struct {
	UUID           string     `json:"uuid"`
	Username       string     `json:"username"`
	DisplayName    string     `json:"display_name"`
	Email          string     `json:"email"`
	PasswordHash   string     `json:"-"`
	Role           string     `json:"role"`             // admin/user/readonly
	PublicKey      Base64Bytes `json:"public_key,omitempty"` // 用户云端公钥（用于加密私钥备份）
	TOTPSecret     string     `json:"-"`                // TOTP 密钥（加密存储）
	Enabled        bool       `json:"enabled"`
	FailedAttempts int        `json:"-"`                // 连续登录失败次数
	LockedUntil    *time.Time `json:"locked_until,omitempty"` // 锁定截止时间
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Card 是云端卡片模型。
type Card struct {
	UUID            string    `json:"uuid"`
	UserUUID        string    `json:"user_uuid"`
	CardName        string    `json:"card_name"`
	Remark          string    `json:"remark"`
	StorageZoneUUID string    `json:"storage_zone_uuid"` // 关联存储区域 UUID
	PINData         Base64Bytes `json:"-"`                 // AES-256-GCM 加密存储的 PIN
	PUKData         Base64Bytes `json:"-"`                 // AES-256-GCM 加密存储的 PUK
	AdminKeyData    Base64Bytes `json:"-"`                 // AES-256-GCM 加密存储的 Admin Key
	PINRetries      int       `json:"pin_retries"`       // PIN 错误最大次数（默认 3）
	PINFailedCount  int       `json:"pin_failed_count"`  // 当前连续错误次数
	PINLocked       bool      `json:"pin_locked"`        // PIN 是否被锁定
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Certificate 是云端证书模型。
// 私鑰加密存储在服务端，不对外暴露。
type Certificate struct {
	UUID             string     `json:"uuid"`
	CardUUID         string     `json:"card_uuid"`
	UserUUID         string     `json:"user_uuid"`          // 所属用户 UUID
	CertType         string     `json:"cert_type"`          // x509/gpg/ssh
	KeyType          string     `json:"key_type"`
	CertContent      Base64Bytes `json:"cert_content"`       // 公开部分
	PrivateData      Base64Bytes `json:"-"`                  // 加密的私鑰，不序列化
	Remark           string     `json:"remark"`
	OrderNo          string     `json:"order_no,omitempty"`
	CAUUID           string     `json:"ca_uuid,omitempty"`
	SerialNumber     string     `json:"serial_number,omitempty"` // X.509 序列号（十六进制）
	SerialHex        string     `json:"serial_hex,omitempty"`   // 序列号十六进制字符串
	SubjectDN        string     `json:"subject_dn,omitempty"`   // 主体 DN（如 CN=example.com,O=Org）
	IssuerDN         string     `json:"issuer_dn,omitempty"`    // 颁发者 DN
	NotBefore        *time.Time `json:"not_before,omitempty"`   // 生效时间
	NotAfter         *time.Time `json:"not_after,omitempty"`    // 失效时间
	KeyUsage         int        `json:"key_usage,omitempty"`    // X.509 密鑰用法位掉码
	ExtKeyUsage      string     `json:"ext_key_usage,omitempty"` // 扩展密鑰用法 OID 列表（JSON 数组）
	SANDNS           string     `json:"san_dns,omitempty"`      // SAN DNS 名称（JSON 数组）
	SANIP            string     `json:"san_ip,omitempty"`       // SAN IP 地址（JSON 数组）
	SANEmail         string     `json:"san_email,omitempty"`    // SAN 邮箋（JSON 数组）
	SANURI           string     `json:"san_uris,omitempty"`     // SAN URI 列表（JSON 数组）
	CertificatePolicies string  `json:"certificate_policies,omitempty"` // 证书策略 OID 列表（JSON 数组）
	IssuanceTmplUUID string     `json:"issuance_tmpl_uuid,omitempty"`
	TemplateUUID     string     `json:"template_uuid,omitempty"`
	StoragePolicy    string     `json:"storage_policy,omitempty"`
	RevocationStatus string     `json:"revocation_status"`      // active/revoked
	RevokeReason     int        `json:"revoke_reason,omitempty"` // RFC 5280 吹销原因码
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Log 是操作日志模型（兼容旧版）。
type Log struct {
	ID         int64     `json:"id"`
	UserUUID   string    `json:"user_uuid"`
	CardUUID   string    `json:"card_uuid"`
	CertUUID   string    `json:"cert_uuid"`
	Action     string    `json:"action"`
	IPAddr     string    `json:"ip_addr"`
	UserAgent  string    `json:"user_agent"`
	RecordedAt time.Time `json:"recorded_at"`
}

// AuditLog 是审计日志模型（链式哈希完整性）。
type AuditLog struct {
	ID           int64     `json:"id"`
	UserUUID     string    `json:"user_uuid"`
	Action       string    `json:"action"`       // 操作类型（如 create_cert/revoke_cert/login）
	ResourceType string    `json:"resource_type"` // 资源类型（如 certificate/ca/user）
	ResourceUUID string    `json:"resource_uuid"` // 资源 UUID
	Detail       string    `json:"detail"`        // 详细信息（JSON）
	IPAddress    string    `json:"ip_address"`
	PrevHash     string    `json:"prev_hash"`     // 上一条日志的 SHA-256 哈希
	CreatedAt    time.Time `json:"created_at"`
	// 不存入数据库，查询时计算
	IntegrityBroken bool `json:"integrity_broken,omitempty"`
}

// ---- 支付系统模型 ----

// OrderStatus 是订单状态。
type OrderStatus string

const (
	OrderStatusPending  OrderStatus = "pending"
	OrderStatusPaid     OrderStatus = "paid"
	OrderStatusFailed   OrderStatus = "failed"
	OrderStatusRefunded OrderStatus = "refunded"
	OrderStatusClosed   OrderStatus = "closed"
)

// PaymentPlugin 是支付插件配置模型。
type PaymentPlugin struct {
	UUID       string    `json:"uuid"`
	Name       string    `json:"name"`        // 插件显示名称
	PluginType string    `json:"plugin_type"` // alipay/wechat/stripe/paypal
	ConfigEnc  Base64Bytes `json:"-"`           // 加密存储的配置参数（API Key/Secret 等）
	Enabled    bool      `json:"enabled"`
	SortWeight int       `json:"sort_weight"` // 排序权重，越大越靠前
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// RechargeOrder 是充值订单模型。
type RechargeOrder struct {
	OrderNo      string      `json:"order_no"`      // 订单号（唯一）
	UserUUID     string      `json:"user_uuid"`
	AmountCents  int64       `json:"amount_cents"`   // 金额（分），避免浮点精度问题
	Channel      string      `json:"channel"`        // 支付渠道（对应 PaymentPlugin.PluginType）
	Status       OrderStatus `json:"status"`
	CallbackData Base64Bytes `json:"-"`              // 支付平台回调原始数据
	CreatedAt    time.Time   `json:"created_at"`
	PaidAt       *time.Time  `json:"paid_at,omitempty"`
	ExpiresAt    time.Time   `json:"expires_at"`     // 订单过期时间（默认30分钟）
}

// UserBalance 是用户余额模型。
type UserBalance struct {
	UserUUID       string `json:"user_uuid"`
	AvailableCents int64  `json:"available_cents"` // 可用余额（分）
	FrozenCents    int64  `json:"frozen_cents"`    // 冻结余额（分）
	TotalRecharge  int64  `json:"total_recharge"`  // 累计充值（分）
	TotalConsume   int64  `json:"total_consume"`   // 累计消费（分）
}

// ConsumeRecord 是消费记录模型。
type ConsumeRecord struct {
	UUID         string    `json:"uuid"`
	UserUUID     string    `json:"user_uuid"`
	OrderNo      string    `json:"order_no,omitempty"` // 关联充值订单号（可选）
	ConsumeType  string    `json:"consume_type"`       // cert_purchase/cert_renew/refund 等
	AmountCents  int64     `json:"amount_cents"`       // 金额（分），正数为消费，负数为退款
	Remark       string    `json:"remark"`
	CreatedAt    time.Time `json:"created_at"`
}

// RefundRequest 是退款工单模型。
type RefundRequest struct {
	UUID        string      `json:"uuid"`
	UserUUID    string      `json:"user_uuid"`
	OrderNo     string      `json:"order_no"`     // 关联的充值订单号
	AmountCents int64       `json:"amount_cents"`  // 退款金额（分）
	Reason      string      `json:"reason"`
	Status      OrderStatus `json:"status"`        // pending/paid(已退款)/failed
	ApprovedBy  string      `json:"approved_by,omitempty"` // 审批管理员 UUID
	CreatedAt   time.Time   `json:"created_at"`
	ProcessedAt *time.Time  `json:"processed_at,omitempty"`
}

// ---- 密钥存储类型模板模型 ----

// StorageMethod 是存储方式位掩码。
type StorageMethod uint32

const (
	StorageFileDownload  StorageMethod = 1 << 0 // 文件下载
	StorageCloudCard     StorageMethod = 1 << 1 // 云端智能卡
	StoragePhysicalCard  StorageMethod = 1 << 2 // 实体智能卡
	StorageVirtualCard   StorageMethod = 1 << 3 // 虚拟智能卡
)

// SecurityLevel 是虚拟智能卡安全等级。
type SecurityLevel string

const (
	SecurityHigh   SecurityLevel = "high"   // TPM 内部，不可导出
	SecurityMedium SecurityLevel = "medium" // 本地数据库，TPM 密钥加密 + 云端公钥加密
	SecurityLow    SecurityLevel = "low"    // 本地数据库，密码加密 + 云端公钥加密
)

// KeyStorageTemplate 是密钥存储类型模板模型。
type KeyStorageTemplate struct {
	UUID              string        `json:"uuid"`
	Name              string        `json:"name"`
	StorageMethods    StorageMethod `json:"storage_methods"`     // 允许的存储方式（位掩码多选）
	SecurityLevel     SecurityLevel `json:"security_level"`      // 虚拟卡安全等级（仅勾选虚拟卡时有效）
	AllowReimport     bool          `json:"allow_reimport"`      // 是否允许重新导入智能卡
	CloudBackup       bool          `json:"cloud_backup"`        // 是否云端备份私钥
	AllowReissue      bool          `json:"allow_reissue"`       // 是否支持重新下发
	MaxReissueCount   int           `json:"max_reissue_count"`   // 最大下发次数（-1=无限）
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

// HasMethod 检查模板是否包含指定存储方式。
func (t *KeyStorageTemplate) HasMethod(m StorageMethod) bool {
	return t.StorageMethods&m != 0
}

// CertIssuanceRecord 是证书下发记录模型。
type CertIssuanceRecord struct {
	UUID           string    `json:"uuid"`
	CertUUID       string    `json:"cert_uuid"`
	UserUUID       string    `json:"user_uuid"`
	IssuanceMethod string    `json:"issuance_method"` // download/cloud/physical/virtual
	DeviceInfo     string    `json:"device_info"`     // 目标设备信息
	IssuedAt       time.Time `json:"issued_at"`
}

// CertReissueCounter 是证书重新下发计数器。
type CertReissueCounter struct {
	CertUUID       string `json:"cert_uuid"`
	TemplateUUID   string `json:"template_uuid"`
	IssuedCount    int    `json:"issued_count"`    // 已下发次数
	MaxCount       int    `json:"max_count"`       // 最大下发次数（-1=无限）
}

// ---- CA 管理模型 ----

// CA 是证书颁发机构模型。
type CA struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	CertPEM     string    `json:"cert_pem"`       // CA 证书 PEM
	PrivateEnc  Base64Bytes `json:"-"`              // 加密存储的 CA 私钥
	ParentUUID  string    `json:"parent_uuid,omitempty"` // 父 CA UUID（根 CA 为空）
	Status      string    `json:"status"`         // active/revoked/expired
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	IssuedCount int       `json:"issued_count"`   // 已签发证书数量
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RevokedCert 是已吊销证书记录。
type RevokedCert struct {
	ID           int64     `json:"id"`
	CAUUID       string    `json:"ca_uuid"`
	SerialNumber string    `json:"serial_number"` // 证书序列号（十六进制）
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       int       `json:"reason"`        // CRL 吊销原因码（RFC 5280）
}

// ---- 证书颁发模板模型 ----

// IssuanceTemplate 是证书颁发模板。
type IssuanceTemplate struct {
	UUID               string    `json:"uuid"`
	Name               string    `json:"name"`
	IsCA               bool      `json:"is_ca"`
	PathLen            int       `json:"path_len"`
	ValidDays          string    `json:"valid_days"`           // 可选有效期列表（JSON 数组，如 "[30,90,365]"）
	AllowedKeyTypes    string    `json:"allowed_key_types"`    // 允许的密鑰类型（JSON 数组）
	AllowedCAUUIDs     string    `json:"allowed_ca_uuids"`     // 可颁发 CA 列表（JSON 数组）
	SubjectTmplUUID    string    `json:"subject_tmpl_uuid"`    // 关联主体模板 ID
	ExtensionTmplUUID  string    `json:"extension_tmpl_uuid"`  // 关联扩展模板 ID
	KeyUsageTmplUUID   string    `json:"key_usage_tmpl_uuid"`  // 关联密鑰用途模板 ID
	KeyStorageTmplUUID string    `json:"key_storage_tmpl_uuid"` // 关联密鑰存储模板 ID
	CertExtTmplUUID    string    `json:"cert_ext_tmpl_uuid"`   // 关联证书拓展模板 ID
	PriceCents         int64     `json:"price_cents"`          // 定价（分）
	Stock              int       `json:"stock"`                // 库存（-1=无限）
	Category           string    `json:"category"`             // 分类（ssl/code_sign/email/custom）
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// CertApplyTemplate 是证书申请模板（面向用户的产品化配置）。
type CertApplyTemplate struct {
	UUID              string    `json:"uuid"`
	Name              string    `json:"name"`
	IssuanceTmplUUID  string    `json:"issuance_tmpl_uuid"`  // 关联颁发模板
	ValidDays         int       `json:"valid_days"`          // 指定有效期（天）
	CAUUID            string    `json:"ca_uuid"`             // 指定签发 CA
	Enabled           bool      `json:"enabled"`             // 是否对用户可见
	RequireApproval   bool      `json:"require_approval"`    // 是否需要审批
	AllowRenewal      bool      `json:"allow_renewal"`       // 是否允许续期
	AllowedKeyTypes   string    `json:"allowed_key_types"`   // 密鑰算法选择列表（JSON 数组）
	PriceCents        int64     `json:"price_cents"`         // 定价（分）
	Description       string    `json:"description"`         // 产品描述
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// SubjectTemplate 是主体模板。
type SubjectTemplate struct {
	UUID      string    `json:"uuid"`
	Name      string    `json:"name"`
	Fields    string    `json:"fields"` // JSON 数组，每个字段：{name, required, default_value, max_length}
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ExtensionTemplate 是扩展信息模板（SAN 配置）。
type ExtensionTemplate struct {
	UUID           string    `json:"uuid"`
	Name           string    `json:"name"`
	MaxDNS         int       `json:"max_dns"`          // DNS 名称最大数量
	MaxEmail       int       `json:"max_email"`        // 邮箱最大数量
	MaxIP          int       `json:"max_ip"`           // IP 最大数量
	MaxURI         int       `json:"max_uri"`          // URI 最大数量
	MaxRID         int       `json:"max_rid"`          // RID（Registered ID）最大数量
	MaxOther       int       `json:"max_other"`        // Other SAN 最大数量
	AllowURI       bool      `json:"allow_uri"`        // 是否允许 URI SAN
	AllowRID       bool      `json:"allow_rid"`        // 是否允许 RID SAN
	AllowOther     bool      `json:"allow_other"`      // 是否允许 Other SAN
	RequireDNSVerify  bool   `json:"require_dns_verify"`  // DNS 是否需要验证
	RequireEmailVerify bool  `json:"require_email_verify"` // 邮箱是否需要验证
	VerifyExpiresDays  int   `json:"verify_expires_days"`  // 验证有效期（天，默认 90）
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// KeyUsageTemplate 是密钥用途模板。
type KeyUsageTemplate struct {
	UUID         string    `json:"uuid"`
	Name         string    `json:"name"`
	KeyUsage     int       `json:"key_usage"`      // X.509 密钥用法位掩码
	ExtKeyUsages string    `json:"ext_key_usages"` // 扩展密钥用法 OID 列表（JSON 数组）
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// CertExtTemplate 是证书拓展模板。
type CertExtTemplate struct {
	UUID            string    `json:"uuid"`
	Name            string    `json:"name"`
	CRLDistPoints   string    `json:"crl_dist_points"`  // CRL 分发点（JSON 数组）
	OCSPServers     string    `json:"ocsp_servers"`     // OCSP 服务器（JSON 数组）
	AIAIssuers      string    `json:"aia_issuers"`      // AIA 颁发者（JSON 数组）
	CTServers       string    `json:"ct_servers"`       // CT 服务器（JSON 数组）
	EVPolicyOID     string    `json:"ev_policy_oid"`    // EV 策略 OID
	NetscapeConfig  string    `json:"netscape_config"`  // Netscape 扩展配置（JSON）
	CSPConfig       string    `json:"csp_config"`       // CSP 扩展配置（JSON）
	ASN1Extensions  string    `json:"asn1_extensions"`  // 自定义 ASN.1 扩展（JSON 数组）
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ---- 证书订单与申请模型 ----

// CertOrderStatus 是证书订单状态机。
type CertOrderStatus string

const (
	CertOrderPendingPayment CertOrderStatus = "pending_payment" // 待支付
	CertOrderPaid          CertOrderStatus = "paid"            // 已支付
	CertOrderApplying      CertOrderStatus = "applying"        // 申请中
	CertOrderReviewing     CertOrderStatus = "reviewing"       // 审批中
	CertOrderIssuing       CertOrderStatus = "issuing"         // 签发中
	CertOrderCompleted     CertOrderStatus = "completed"       // 已完成
	CertOrderRejected      CertOrderStatus = "rejected"        // 已拒绝
	CertOrderCancelled     CertOrderStatus = "cancelled"       // 已取消
	CertOrderRefunded      CertOrderStatus = "refunded"        // 已退款
)

// CertOrder 是证书订单模型。
type CertOrder struct {
	UUID                string          `json:"uuid"`
	UserUUID            string          `json:"user_uuid"`
	IssuanceTmplUUID    string          `json:"issuance_tmpl_uuid"`
	CertApplyTmplUUID   string          `json:"cert_apply_tmpl_uuid"`  // 关联证书申请模板
	KeyStorageTmplUUID  string          `json:"key_storage_tmpl_uuid"`
	AmountCents         int64           `json:"amount_cents"`
	FrozenCents         int64           `json:"frozen_cents"`          // 已冻结金额
	Status              CertOrderStatus `json:"status"`
	PaidAt              *time.Time      `json:"paid_at,omitempty"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// CertApplication 是证书申请模型。
type CertApplication struct {
	UUID           string      `json:"uuid"`
	OrderUUID      string      `json:"order_uuid"`
	UserUUID       string      `json:"user_uuid"`
	SubjectJSON    string      `json:"subject_json"`    // 主体信息 JSON
	SANJSON        string      `json:"san_json"`        // SAN 信息 JSON
	KeyType        string      `json:"key_type"`
	Status         string      `json:"status"`          // pending/approved/rejected
	ApprovedBy     string      `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time  `json:"approved_at,omitempty"`
	RejectReason   string      `json:"reject_reason,omitempty"`
	CertUUID       string      `json:"cert_uuid,omitempty"` // 签发后的证书 UUID
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// ---- 主体信息与扩展信息验证模型 ----

// SubjectInfo 是用户提交的主体信息。
type SubjectInfo struct {
	UUID           string     `json:"uuid"`
	UserUUID       string     `json:"user_uuid"`
	SubjectTmplUUID string   `json:"subject_tmpl_uuid"` // 关联的主体模板 ID
	FieldValues    string     `json:"field_values"`      // 字段值 JSON（如 {"CN":"example.com","O":"Org"}）
	Status         string     `json:"status"`            // pending/approved/rejected
	ReviewedBy     string     `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ExtensionInfo 是用户提交的扩展信息（域名/邮箱/IP 验证）。
type ExtensionInfo struct {
	UUID           string     `json:"uuid"`
	UserUUID       string     `json:"user_uuid"`
	TmplUUID       string     `json:"tmpl_uuid,omitempty"` // 关联的扩展信息模板 UUID
	InfoType       string     `json:"info_type"`       // domain/email/ip
	Value          string     `json:"value"`           // 域名/邮箱/IP 值
	VerifyMethod   string     `json:"verify_method"`   // txt/http/email
	VerifyToken    string     `json:"verify_token"`    // 验证 token
	VerifyCodeHash string     `json:"-"`               // 邮箱验证码的 SHA-256（仅 email 使用）
	VerifyStatus   string     `json:"verify_status"`   // pending/verified/expired
	VerifiedAt     *time.Time `json:"verified_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"` // 验证有效期
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ---- 存储区域与 OID 管理模型 ----

// StorageZone 是云端智能卡存储区域。
type StorageZone struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	StorageType string    `json:"storage_type"` // database/hsm
	HSMDriver   string    `json:"hsm_driver,omitempty"`
	HSMAuthEnc  Base64Bytes `json:"-"`            // 加密存储的 HSM 授权信息
	Status      string    `json:"status"`       // active/disabled
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CustomOID 是自定义 OID。
type CustomOID struct {
	UUID        string    `json:"uuid"`
	OIDValue    string    `json:"oid_value"`    // OID 值（如 1.2.3.4.5）
	Name        string    `json:"name"`
	Description string    `json:"description"`
	UsageType   string    `json:"usage_type"`   // ext_key_usage/subject_field/ev_policy/asn1_extension
	ASN1Type    string    `json:"asn1_type"`    // ASN.1 数据类型（UTF8String/IA5String/BOOLEAN/INTEGER/OCTET_STRING 等）
	IsCritical  bool      `json:"is_critical"`  // 写入 X.509 扩展时是否标记为 critical
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserTOTP 是云端 TOTP 条目。
type UserTOTP struct {
	UUID      string    `json:"uuid"`
	UserUUID  string    `json:"user_uuid"`
	Issuer    string    `json:"issuer"`
	Account   string    `json:"account"`
	SecretEnc Base64Bytes `json:"-"`          // 加密存储的 TOTP 密钥
	Algorithm string    `json:"algorithm"`  // SHA1/SHA256/SHA512
	Digits    int       `json:"digits"`     // 6/8
	Period    int       `json:"period"`     // 默认 30 秒
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
