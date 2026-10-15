// Package storage - 数据模型定义。
package storage

import "time"

// User 是服务端用户模型。
type User struct {
	UUID           string      `json:"uuid"`
	Username       string      `json:"username"`
	DisplayName    string      `json:"display_name"`
	Email          string      `json:"email"`
	PasswordHash   string      `json:"-"`
	Role           string      `json:"role"`                 // admin/user/readonly
	PublicKey      Base64Bytes `json:"public_key,omitempty"` // 用户云端公钥（用于加密私钥备份）
	TOTPSecret     string      `json:"-"`                    // TOTP 密钥（加密存储）
	Enabled        bool        `json:"enabled"`
	FailedAttempts int         `json:"-"`                      // 连续登录失败次数
	LockedUntil    *time.Time  `json:"locked_until,omitempty"` // 锁定截止时间
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
}

// Card 是云端卡片模型。
type Card struct {
	UUID            string      `json:"uuid"`
	UserUUID        string      `json:"user_uuid"`
	CardName        string      `json:"card_name"`
	Remark          string      `json:"remark"`
	StorageZoneUUID string      `json:"storage_zone_uuid"`  // 关联存储区域 UUID
	PINData         Base64Bytes `json:"-"`                  // AES-256-GCM 加密存储的 PIN
	PUKData         Base64Bytes `json:"-"`                  // AES-256-GCM 加密存储的 PUK
	AdminKeyData    Base64Bytes `json:"-"`                  // AES-256-GCM 加密存储的 Admin Key
	PINRetries      int         `json:"pin_retries"`        // PIN 错误最大次数（默认 3）
	PINFailedCount  int         `json:"pin_failed_count"`   // 当前连续错误次数
	PINLocked       bool        `json:"pin_locked"`         // PIN 是否被锁定
	Kind            string      `json:"kind"`               // user=用户智能卡；hosting=证书托管容器
	OrderNo         string      `json:"order_no,omitempty"` // 销售模式下开卡所凭订单号
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// 卡片类型。
const (
	CardKindUser    = "user"    // 用户智能卡
	CardKindHosting = "hosting" // 系统证书托管容器
)

// IsHosting 判断是否为系统托管容器。
func (c *Card) IsHosting() bool { return c.Kind == CardKindHosting }

// Certificate 是云端证书模型。
// 私鑰加密存储在服务端，不对外暴露。
type Certificate struct {
	UUID                string      `json:"uuid"`
	CardUUID            string      `json:"card_uuid"`
	UserUUID            string      `json:"user_uuid"` // 所属用户 UUID
	CertType            string      `json:"cert_type"` // x509/gpg/ssh
	KeyType             string      `json:"key_type"`
	CertContent         Base64Bytes `json:"cert_content"` // 公开部分
	PrivateData         Base64Bytes `json:"-"`            // 加密的私鑰，不序列化
	Remark              string      `json:"remark"`
	OrderNo             string      `json:"order_no,omitempty"`
	CAUUID              string      `json:"ca_uuid,omitempty"`
	SerialNumber        string      `json:"serial_number,omitempty"`        // X.509 序列号（十六进制）
	SerialHex           string      `json:"serial_hex,omitempty"`           // 序列号十六进制字符串
	SubjectDN           string      `json:"subject_dn,omitempty"`           // 主体 DN（如 CN=example.com,O=Org）
	IssuerDN            string      `json:"issuer_dn,omitempty"`            // 颁发者 DN
	NotBefore           *time.Time  `json:"not_before,omitempty"`           // 生效时间
	NotAfter            *time.Time  `json:"not_after,omitempty"`            // 失效时间
	KeyUsage            int         `json:"key_usage,omitempty"`            // X.509 密鑰用法位掉码
	ExtKeyUsage         string      `json:"ext_key_usage,omitempty"`        // 扩展密鑰用法 OID 列表（JSON 数组）
	SANDNS              string      `json:"san_dns,omitempty"`              // SAN DNS 名称（JSON 数组）
	SANIP               string      `json:"san_ip,omitempty"`               // SAN IP 地址（JSON 数组）
	SANEmail            string      `json:"san_email,omitempty"`            // SAN 邮箋（JSON 数组）
	SANURI              string      `json:"san_uris,omitempty"`             // SAN URI 列表（JSON 数组）
	CertificatePolicies string      `json:"certificate_policies,omitempty"` // 证书策略 OID 列表（JSON 数组）
	IssuanceTmplUUID    string      `json:"issuance_tmpl_uuid,omitempty"`
	TemplateUUID        string      `json:"template_uuid,omitempty"`
	StoragePolicy       string      `json:"storage_policy,omitempty"`
	RevocationStatus    string      `json:"revocation_status"`       // active/revoked
	RevokeReason        int         `json:"revoke_reason,omitempty"` // RFC 5280 吹销原因码
	RevokedAt           *time.Time  `json:"revoked_at,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
	UpdatedAt           time.Time   `json:"updated_at"`
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
	Action       string    `json:"action"`        // 操作类型（如 create_cert/revoke_cert/login）
	ResourceType string    `json:"resource_type"` // 资源类型（如 certificate/ca/user）
	ResourceUUID string    `json:"resource_uuid"` // 资源 UUID
	Detail       string    `json:"detail"`        // 详细信息（JSON）
	IPAddress    string    `json:"ip_address"`
	PrevHash     string    `json:"prev_hash"` // 上一条日志的 SHA-256 哈希
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
	UUID       string      `json:"uuid"`
	Name       string      `json:"name"`        // 插件显示名称
	PluginType string      `json:"plugin_type"` // alipay/wechat/stripe/paypal
	ConfigEnc  Base64Bytes `json:"-"`           // 加密存储的配置参数（API Key/Secret 等）
	Enabled    bool        `json:"enabled"`
	SortWeight int         `json:"sort_weight"` // 排序权重，越大越靠前
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
}

// RechargeOrder 是充值订单模型。
type RechargeOrder struct {
	OrderNo      string      `json:"order_no"` // 订单号（唯一）
	UserUUID     string      `json:"user_uuid"`
	AmountCents  int64       `json:"amount_cents"` // 金额（分），避免浮点精度问题
	Channel      string      `json:"channel"`      // 支付渠道（对应 PaymentPlugin.PluginType）
	Status       OrderStatus `json:"status"`
	CallbackData Base64Bytes `json:"-"` // 支付平台回调原始数据
	CreatedAt    time.Time   `json:"created_at"`
	PaidAt       *time.Time  `json:"paid_at,omitempty"`
	ExpiresAt    time.Time   `json:"expires_at"` // 订单过期时间（默认30分钟）
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
	UUID        string    `json:"uuid"`
	UserUUID    string    `json:"user_uuid"`
	OrderNo     string    `json:"order_no,omitempty"` // 关联充值订单号（可选）
	ConsumeType string    `json:"consume_type"`       // cert_purchase/cert_renew/refund 等
	AmountCents int64     `json:"amount_cents"`       // 金额（分），正数为消费，负数为退款
	Remark      string    `json:"remark"`
	CreatedAt   time.Time `json:"created_at"`
}

// RefundRequest 是退款工单模型。
type RefundRequest struct {
	UUID        string      `json:"uuid"`
	UserUUID    string      `json:"user_uuid"`
	OrderNo     string      `json:"order_no"`            // 关联的业务/充值订单号
	BizType     string      `json:"biz_type,omitempty"`  // recharge/cert_order
	BizUUID     string      `json:"biz_uuid,omitempty"`  // 业务订单 UUID
	Channel     string      `json:"channel,omitempty"`   // 原支付渠道（balance/free/alipay...）
	RefundNo    string      `json:"refund_no,omitempty"` // 渠道退款单号
	FailReason  string      `json:"fail_reason,omitempty"`
	AmountCents int64       `json:"amount_cents"` // 退款金额（分）
	Reason      string      `json:"reason"`
	Status      OrderStatus `json:"status"`                // pending/paid(已退款)/failed
	ApprovedBy  string      `json:"approved_by,omitempty"` // 审批管理员 UUID
	CreatedAt   time.Time   `json:"created_at"`
	ProcessedAt *time.Time  `json:"processed_at,omitempty"`
}

// ---- 支付尝试 ----

// PaymentBizType 是支付尝试关联的业务类型。
type PaymentBizType string

const (
	PaymentBizCertOrder PaymentBizType = "cert_order" // 证书/云卡订单
	PaymentBizRecharge  PaymentBizType = "recharge"   // 账户充值
)

// PaymentAttemptStatus 是支付尝试状态。
type PaymentAttemptStatus string

const (
	PaymentAttemptPending PaymentAttemptStatus = "pending"
	PaymentAttemptPaid    PaymentAttemptStatus = "paid"
	PaymentAttemptFailed  PaymentAttemptStatus = "failed"
	PaymentAttemptClosed  PaymentAttemptStatus = "closed"
)

// 支付渠道的特殊取值（非第三方渠道）。
const (
	ChannelBalance = "balance" // 账户余额
	ChannelFree    = "free"    // 零金额订单，无需支付
	ChannelOffline = "offline" // 线下支付（对公转账等），由管理员确认到账
)

// PaymentAttempt 是一次"以某渠道支付某笔业务订单"的尝试。
// 回调据此校验渠道、金额与商户归属，而不是仅凭单号前缀推断。
type PaymentAttempt struct {
	UUID          string               `json:"uuid"`
	BizType       PaymentBizType       `json:"biz_type"`
	BizUUID       string               `json:"biz_uuid"`
	OrderNo       string               `json:"order_no"`
	UserUUID      string               `json:"user_uuid"`
	Channel       string               `json:"channel"`
	AmountCents   int64                `json:"amount_cents"`
	Currency      string               `json:"currency"`
	Status        PaymentAttemptStatus `json:"status"`
	TransactionID string               `json:"transaction_id,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	PaidAt        *time.Time           `json:"paid_at,omitempty"`
	ExpiresAt     *time.Time           `json:"expires_at,omitempty"`
}

// ---- 密钥存储类型模板模型 ----

// StorageMethod 是存储方式位掩码。
type StorageMethod uint32

const (
	StorageFileDownload StorageMethod = 1 << 0 // 文件下载
	StorageCloudCard    StorageMethod = 1 << 1 // 云端智能卡
	StoragePhysicalCard StorageMethod = 1 << 2 // 实体智能卡
	StorageVirtualCard  StorageMethod = 1 << 3 // 虚拟智能卡
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
	UUID            string        `json:"uuid"`
	Name            string        `json:"name"`
	StorageMethods  StorageMethod `json:"storage_methods"`   // 允许的存储方式（位掩码多选）
	SecurityLevel   SecurityLevel `json:"security_level"`    // 虚拟卡安全等级（仅勾选虚拟卡时有效）
	AllowReimport   bool          `json:"allow_reimport"`    // 是否允许重新导入智能卡
	CloudBackup     bool          `json:"cloud_backup"`      // 是否云端备份私钥
	AllowReissue    bool          `json:"allow_reissue"`     // 是否支持重新下发
	MaxReissueCount int           `json:"max_reissue_count"` // 最大下发次数（-1=无限）
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
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
	CertUUID     string `json:"cert_uuid"`
	TemplateUUID string `json:"template_uuid"`
	IssuedCount  int    `json:"issued_count"` // 已下发次数
	MaxCount     int    `json:"max_count"`    // 最大下发次数（-1=无限）
}

// ---- CA 管理模型 ----

// CA 是证书颁发机构模型。
type CA struct {
	UUID        string      `json:"uuid"`
	Name        string      `json:"name"`
	CertPEM     string      `json:"cert_pem"`              // CA 证书 PEM
	PrivateEnc  Base64Bytes `json:"-"`                     // 加密存储的 CA 私钥
	ParentUUID  string      `json:"parent_uuid,omitempty"` // 父 CA UUID（根 CA 为空）
	Status      string      `json:"status"`                // active/revoked/expired
	IsPublic    bool        `json:"is_public"`             // 是否在门户公开信任目录中展示
	NotBefore   time.Time   `json:"not_before"`
	NotAfter    time.Time   `json:"not_after"`
	IssuedCount int         `json:"issued_count"` // 已签发证书数量
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// RevokedCert 是已吊销证书记录。
type RevokedCert struct {
	ID           int64     `json:"id"`
	CAUUID       string    `json:"ca_uuid"`
	SerialNumber string    `json:"serial_number"` // 证书序列号（十六进制）
	RevokedAt    time.Time `json:"revoked_at"`
	Reason       int       `json:"reason"` // CRL 吊销原因码（RFC 5280）
}

// ---- 证书颁发模板模型 ----

// IssuanceTemplate 是证书颁发模板。
type IssuanceTemplate struct {
	UUID               string    `json:"uuid"`
	Name               string    `json:"name"`
	IsCA               bool      `json:"is_ca"`
	PathLen            int       `json:"path_len"`
	ValidDays          string    `json:"valid_days"`            // 可选有效期列表（JSON 数组，如 "[30,90,365]"）
	AllowedKeyTypes    string    `json:"allowed_key_types"`     // 允许的密鑰类型（JSON 数组）
	AllowedCAUUIDs     string    `json:"allowed_ca_uuids"`      // 可颁发 CA 列表（JSON 数组）
	SubjectTmplUUID    string    `json:"subject_tmpl_uuid"`     // 关联主体模板 ID
	ExtensionTmplUUID  string    `json:"extension_tmpl_uuid"`   // 关联扩展模板 ID
	KeyUsageTmplUUID   string    `json:"key_usage_tmpl_uuid"`   // 关联密鑰用途模板 ID
	KeyStorageTmplUUID string    `json:"key_storage_tmpl_uuid"` // 关联密鑰存储模板 ID
	CertExtTmplUUID    string    `json:"cert_ext_tmpl_uuid"`    // 关联证书拓展模板 ID
	PriceCents         int64     `json:"price_cents"`           // 定价（分）
	Stock              int       `json:"stock"`                 // 库存（-1=无限）
	Category           string    `json:"category"`              // 分类（ssl/code_sign/email/custom）
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// CertApplyTemplate 是证书申请模板（面向用户的产品化配置）。
type CertApplyTemplate struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	IssuanceTmplUUID string `json:"issuance_tmpl_uuid"` // 关联颁发模板
	ValidDays        int    `json:"valid_days"`         // 指定有效期（天）
	CAUUID           string `json:"ca_uuid"`            // 指定签发 CA
	Enabled          bool   `json:"enabled"`            // 是否对用户可见
	RequireApproval  bool   `json:"require_approval"`   // 是否需要审批
	AllowRenewal     bool   `json:"allow_renewal"`      // 是否允许续期
	AllowedKeyTypes  string `json:"allowed_key_types"`  // 密鑰算法选择列表（JSON 数组）
	PriceCents       int64  `json:"price_cents"`        // 历史字段：定价已迁移到商品规格
	Description      string `json:"description"`        // 产品描述
	// 申请资料要求：优先于颁发模板中的同名关联
	SubjectTmplUUID   string    `json:"subject_tmpl_uuid"`   // 主体模板（决定用户需填写/验证的主体字段）
	ExtensionTmplUUID string    `json:"extension_tmpl_uuid"` // 扩展信息模板（决定域名/邮箱/IP 的验证方式）
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// SubjectTemplate 是主体模板。
type SubjectTemplate struct {
	UUID               string    `json:"uuid"`
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	Fields             string    `json:"fields"`               // JSON 数组，见 identity.SubjectField
	VerifyProviderUUID string    `json:"verify_provider_uuid"` // 字段验证方式为 auto 时使用的实名认证接口
	VerifyValidity     string    `json:"verify_validity"`      // 审核/认证有效期，如 1d/7d/30d/365d
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ExtensionTemplate 是扩展信息模板（SAN 配置）。
type ExtensionTemplate struct {
	UUID               string    `json:"uuid"`
	Name               string    `json:"name"`
	MaxDNS             int       `json:"max_dns"`              // DNS 名称最大数量
	MaxEmail           int       `json:"max_email"`            // 邮箱最大数量
	MaxIP              int       `json:"max_ip"`               // IP 最大数量
	MaxURI             int       `json:"max_uri"`              // URI 最大数量
	MaxRID             int       `json:"max_rid"`              // RID（Registered ID）最大数量
	MaxOther           int       `json:"max_other"`            // Other SAN 最大数量
	AllowURI           bool      `json:"allow_uri"`            // 是否允许 URI SAN
	AllowRID           bool      `json:"allow_rid"`            // 是否允许 RID SAN
	AllowOther         bool      `json:"allow_other"`          // 是否允许 Other SAN
	RequireDNSVerify   bool      `json:"require_dns_verify"`   // DNS 是否需要验证
	RequireEmailVerify bool      `json:"require_email_verify"` // 邮箱是否需要验证
	VerifyExpiresDays  int       `json:"verify_expires_days"`  // 验证有效期（天，默认 90）
	VerifyPolicy       string    `json:"verify_policy"`        // 按类型的验证策略 JSON，见 identity.ExtensionPolicy
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
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
	UUID           string    `json:"uuid"`
	Name           string    `json:"name"`
	CRLDistPoints  string    `json:"crl_dist_points"` // CRL 分发点（JSON 数组）
	OCSPServers    string    `json:"ocsp_servers"`    // OCSP 服务器（JSON 数组）
	AIAIssuers     string    `json:"aia_issuers"`     // AIA 颁发者（JSON 数组）
	CTServers      string    `json:"ct_servers"`      // CT 服务器（JSON 数组）
	EVPolicyOID    string    `json:"ev_policy_oid"`   // EV 策略 OID
	NetscapeConfig string    `json:"netscape_config"` // Netscape 扩展配置（JSON）
	CSPConfig      string    `json:"csp_config"`      // CSP 扩展配置（JSON）
	ASN1Extensions string    `json:"asn1_extensions"` // 自定义 ASN.1 扩展（JSON 数组）
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ---- 证书订单与申请模型 ----

// CertOrderStatus 是证书订单状态机。
type CertOrderStatus string

const (
	CertOrderPendingPayment CertOrderStatus = "pending_payment" // 待支付
	CertOrderPaid           CertOrderStatus = "paid"            // 已支付
	CertOrderApplying       CertOrderStatus = "applying"        // 申请中
	CertOrderReviewing      CertOrderStatus = "reviewing"       // 审批中
	CertOrderIssuing        CertOrderStatus = "issuing"         // 签发中
	CertOrderCompleted      CertOrderStatus = "completed"       // 已完成
	CertOrderRejected       CertOrderStatus = "rejected"        // 已拒绝
	CertOrderCancelled      CertOrderStatus = "cancelled"       // 已取消
	CertOrderRefunded       CertOrderStatus = "refunded"        // 已退款
)

// CertOrder 是证书订单模型。
type CertOrder struct {
	UUID               string          `json:"uuid"`
	OrderNo            string          `json:"order_no,omitempty"` // 对外单号（门户下单生成）
	UserUUID           string          `json:"user_uuid"`
	ProductCode        string          `json:"product_code,omitempty"` // 门户商品编码快照
	SKUCode            string          `json:"sku_code,omitempty"`     // 门户规格编码快照
	SpecJSON           string          `json:"spec_json,omitempty"`    // 下单时规格快照（JSON）
	ApplicantEmail     string          `json:"applicant_email,omitempty"`
	IssuanceTmplUUID   string          `json:"issuance_tmpl_uuid"`
	CertApplyTmplUUID  string          `json:"cert_apply_tmpl_uuid"` // 关联证书申请模板
	KeyStorageTmplUUID string          `json:"key_storage_tmpl_uuid"`
	AmountCents        int64           `json:"amount_cents"`
	FrozenCents        int64           `json:"frozen_cents"`                // 已冻结金额
	SubscriptionUUID   string          `json:"subscription_uuid,omitempty"` // 由订阅额度生成的订单
	CouponCode         string          `json:"coupon_code,omitempty"`
	DiscountCents      int64           `json:"discount_cents,omitempty"`
	Status             CertOrderStatus `json:"status"`
	PaidAt             *time.Time      `json:"paid_at,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// CertApplication 是证书申请模型。
type CertApplication struct {
	UUID           string     `json:"uuid"`
	OrderUUID      string     `json:"order_uuid"`
	UserUUID       string     `json:"user_uuid"`
	SubjectJSON    string     `json:"subject_json"` // 主体信息 JSON
	SANJSON        string     `json:"san_json"`     // SAN 信息 JSON
	KeyType        string     `json:"key_type"`
	CSRPEM         string     `json:"csr_pem,omitempty"` // 用户自带 CSR（私钥不进入服务端）
	ApplicantEmail string     `json:"applicant_email,omitempty"`
	CardUUID       string     `json:"card_uuid,omitempty"` // 签发目标卡片（空=托管容器）
	Status         string     `json:"status"`              // pending/approved/rejected
	ApprovedBy     string     `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time `json:"approved_at,omitempty"`
	RejectReason   string     `json:"reject_reason,omitempty"`
	CertUUID       string     `json:"cert_uuid,omitempty"` // 签发后的证书 UUID
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ---- 主体信息与扩展信息验证模型 ----

// SubjectInfo 是用户提交的主体信息。
type SubjectInfo struct {
	UUID            string     `json:"uuid"`
	UserUUID        string     `json:"user_uuid"`
	SubjectTmplUUID string     `json:"subject_tmpl_uuid"` // 关联的主体模板 ID
	FieldValues     string     `json:"field_values"`      // 字段值 JSON（如 {"CN":"example.com","O":"Org"}）
	Status          string     `json:"status"`            // pending(待人工)/verifying(待实名)/approved/rejected
	VerifyMode      string     `json:"verify_mode"`       // manual/auto/none：本条信息需要的验证方式
	RejectReason    string     `json:"reject_reason,omitempty"`
	ReviewedBy      string     `json:"reviewed_by,omitempty"`
	ReviewedAt      *time.Time `json:"reviewed_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"` // 审核/认证有效期，过期需重新验证
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// SubjectUsable 判断主体信息当前是否可用于申请（已通过且未过期）。
func (s *SubjectInfo) SubjectUsable(now time.Time) bool {
	return s.Status == "approved" && (s.ExpiresAt == nil || now.Before(*s.ExpiresAt))
}

// ExtensionInfo 是用户提交的扩展信息（域名/邮箱/IP 验证）。
type ExtensionInfo struct {
	UUID           string     `json:"uuid"`
	UserUUID       string     `json:"user_uuid"`
	TmplUUID       string     `json:"tmpl_uuid,omitempty"` // 关联的扩展信息模板 UUID
	InfoType       string     `json:"info_type"`           // domain/email/ip
	Value          string     `json:"value"`               // 域名/邮箱/IP 值
	VerifyMethod   string     `json:"verify_method"`       // txt/http/email
	VerifyToken    string     `json:"verify_token"`        // 验证 token
	VerifyCodeHash string     `json:"-"`                   // 邮箱验证码的 SHA-256（仅 email 使用）
	VerifyStatus   string     `json:"verify_status"`       // pending(待自助验证)/reviewing(待人工)/verified/rejected
	RejectReason   string     `json:"reject_reason,omitempty"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"` // 验证有效期
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Usable 判断扩展信息当前是否可用于申请（已验证且未过期）。
func (e *ExtensionInfo) Usable(now time.Time) bool {
	return e.VerifyStatus == "verified" && (e.ExpiresAt == nil || now.Before(*e.ExpiresAt))
}

// ---- 存储区域与 OID 管理模型 ----

// StorageZone 是云端智能卡存储区域。
type StorageZone struct {
	UUID        string      `json:"uuid"`
	Name        string      `json:"name"`
	StorageType string      `json:"storage_type"` // database/hsm
	HSMDriver   string      `json:"hsm_driver,omitempty"`
	HSMAuthEnc  Base64Bytes `json:"-"`      // 加密存储的 HSM 授权信息
	Status      string      `json:"status"` // active/disabled
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// CustomOID 是自定义 OID。
type CustomOID struct {
	UUID        string    `json:"uuid"`
	OIDValue    string    `json:"oid_value"` // OID 值（如 1.2.3.4.5）
	Name        string    `json:"name"`
	Description string    `json:"description"`
	UsageType   string    `json:"usage_type"`  // ext_key_usage/subject_field/ev_policy/asn1_extension
	ASN1Type    string    `json:"asn1_type"`   // ASN.1 数据类型（UTF8String/IA5String/BOOLEAN/INTEGER/OCTET_STRING 等）
	IsCritical  bool      `json:"is_critical"` // 写入 X.509 扩展时是否标记为 critical
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserTOTP 是云端 TOTP 条目。
type UserTOTP struct {
	UUID      string      `json:"uuid"`
	UserUUID  string      `json:"user_uuid"`
	Issuer    string      `json:"issuer"`
	Account   string      `json:"account"`
	SecretEnc Base64Bytes `json:"-"`         // 加密存储的 TOTP 密钥
	Algorithm string      `json:"algorithm"` // SHA1/SHA256/SHA512
	Digits    int         `json:"digits"`    // 6/8
	Period    int         `json:"period"`    // 默认 30 秒
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// ---- 门户（官网/商城）模型 ----

// ProductCategory 是门户商品分类。
type ProductCategory string

const (
	ProductCategorySSL       ProductCategory = "ssl"       // SSL/TLS 证书
	ProductCategoryCodeSign  ProductCategory = "codesign"  // 代码签名证书
	ProductCategoryEmail     ProductCategory = "email"     // 邮件证书（S/MIME）
	ProductCategoryDocSign   ProductCategory = "docsign"   // 文档签名证书
	ProductCategoryCloudCard ProductCategory = "cloudcard" // 云端智能卡
)

// 订单类型（记录在订单规格快照 spec_json.kind 中）。
const (
	OrderKindCert = "cert" // 证书订单：支付后提交申请、审核、签发
	OrderKindCard = "card" // 云端智能卡订单：支付后凭订单开卡
)

// 业务模式（站点配置 cert_apply_mode / card_apply_mode）。
const (
	ModeSelfService = "self"  // 自助模式：用户可直接申请/开卡，无需购买
	ModeSales       = "sales" // 销售模式：必须先购买并支付订单
)

// DeliveryMode 是交付方式。
type DeliveryMode string

const (
	DeliveryDownload  DeliveryMode = "download"   // 文件下载（PEM/DER/PFX）
	DeliveryCloudCard DeliveryMode = "cloud_card" // 云端智能卡远程使用
	DeliveryCSR       DeliveryMode = "csr"        // 用户自备 CSR
)

// PortalProduct 是门户商品模型（决定"卖什么"，不含价格与签发参数）。
type PortalProduct struct {
	UUID        string          `json:"uuid"`
	Code        string          `json:"code"` // 稳定编码，供 URL/下单引用
	Name        string          `json:"name"`
	Category    ProductCategory `json:"category"` // ssl/codesign/email/docsign/cloudcard
	Level       string          `json:"level"`    // dv/ov/ev/text 等展示等级
	Summary     string          `json:"summary"`  // 一句话卖点
	Description string          `json:"description"`
	Features    string          `json:"features"`   // 权益列表（JSON 数组）
	Highlights  string          `json:"highlights"` // 高亮标识（JSON 数组）
	Badge       string          `json:"badge"`      // 推荐/新品等角标
	CoverImage  string          `json:"cover_image"`
	SortWeight  int             `json:"sort_weight"`
	Visible     bool            `json:"visible"` // 是否在前台展示
	Enabled     bool            `json:"enabled"` // 是否可售
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// PortalProductSKU 是商品规格/套餐模型（决定"按什么规格和价格卖"）。
type PortalProductSKU struct {
	UUID              string       `json:"uuid"`
	ProductUUID       string       `json:"product_uuid"`
	Code              string       `json:"code"`
	Name              string       `json:"name"`
	PriceCents        int64        `json:"price_cents"`
	Currency          string       `json:"currency"`
	Stock             int          `json:"stock"` // -1 表示不限库存，0 表示售罄
	MinQty            int          `json:"min_qty"`
	MaxQty            int          `json:"max_qty"`
	DurationMonths    int          `json:"duration_months"` // 服务期（月）
	DeliveryMode      DeliveryMode `json:"delivery_mode"`
	KeyTypes          string       `json:"key_types"`            // 允许的密钥算法（JSON 数组）
	SANIncluded       int          `json:"san_included"`         // 含多少 SAN 域名（0 表示不适用）
	CertApplyTmplUUID string       `json:"cert_apply_tmpl_uuid"` // 关联证书申请模板
	CloudCardTmplUUID string       `json:"cloud_card_tmpl_uuid"` // 预留：云卡开通模板
	SANPolicy         string       `json:"san_policy"`           // 单张证书的 SAN 限制 JSON，见 SANPolicy
	Enabled           bool         `json:"enabled"`
	SortWeight        int          `json:"sort_weight"`
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// SoldOut 判断规格是否无库存可售（-1 为不限）。
func (s *PortalProductSKU) SoldOut() bool {
	return s.Stock == 0
}

// InStock 判断给定数量是否有货。
func (s *PortalProductSKU) InStock(qty int) bool {
	if s.Stock < 0 {
		return true
	}
	return qty > 0 && qty <= s.Stock
}

// SiteSetting 是站点配置键值对。
type SiteSetting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}
