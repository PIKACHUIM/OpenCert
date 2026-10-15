// ---- 通用响应类型 ----

export interface ApiResponse<T> {
  code: number;
  message: string;
  data: T;
}

export interface PageResult<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ---- 认证类型 ----

/** 平台角色：与服务端 auth 包保持一致 */
export type UserRole = 'super_admin' | 'admin' | 'operator' | 'user' | 'readonly';

export interface AuthToken {
  token: string;
  user_uuid: string;
  username: string;
  role: UserRole;
  /** 可选：服务端未返回时由前端按 JWT 有效期兜底 */
  expires_at?: string;
}

/** 登录需要 TOTP 二次验证时的响应 */
export interface TotpChallenge {
  require_totp: true;
  session_token: string;
}

/** 判断登录响应是否为 TOTP 挑战 */
export const isTotpChallenge = (resp: AuthToken | TotpChallenge): resp is TotpChallenge =>
  (resp as TotpChallenge).require_totp === true;

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
  email: string;
  display_name: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

// ---- 用户类型 ----

export interface User {
  uuid: string;
  username: string;
  display_name: string;
  email: string;
  role: UserRole;
  enabled: boolean;
  /** 连续登录失败次数（服务端不返回密码等信息） */
  locked_until?: string;
  created_at: string;
  updated_at: string;
}

// ---- 门户（官网/商城）类型 ----

/** 商品分类 */
export type ProductCategory = 'ssl' | 'codesign' | 'email' | 'docsign' | 'cloudcard';

/** 交付方式 */
export type DeliveryMode = 'download' | 'cloud_card' | 'csr';

/** 门户商品 */
export interface PortalProduct {
  uuid: string;
  code: string;
  name: string;
  category: ProductCategory;
  level: string;
  summary: string;
  description: string;
  /** JSON 字符串数组 */
  features: string;
  /** JSON 字符串数组 */
  highlights: string;
  badge: string;
  cover_image: string;
  sort_weight: number;
  visible: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

/** 商品规格/套餐 */
export interface PortalProductSKU {
  uuid: string;
  product_uuid: string;
  code: string;
  name: string;
  price_cents: number;
  currency: string;
  /** -1 表示不限库存，0 表示售罄 */
  stock: number;
  min_qty: number;
  max_qty: number;
  duration_months: number;
  delivery_mode: DeliveryMode;
  /** JSON 字符串数组 */
  key_types: string;
  san_included: number;
  cert_apply_tmpl_uuid: string;
  cloud_card_tmpl_uuid: string;
  /** 单张证书的 SAN 数量与格式限制（JSON 字符串） */
  san_policy?: string;
  enabled: boolean;
  sort_weight: number;
  created_at: string;
  updated_at: string;
}

/** 商品 + 规格聚合视图 */
export interface ProductView {
  product: PortalProduct;
  skus: PortalProductSKU[];
}

/** 门户分类 */
export interface PortalCategory {
  code: ProductCategory;
  name: string;
  description: string;
  count: number;
}

/** 服务端权威报价 */
export interface PortalQuote {
  product_code: string;
  product_name: string;
  sku_code: string;
  sku_name: string;
  quantity: number;
  unit_price_cents: number;
  total_cents: number;
  currency: string;
  duration_months: number;
  delivery_mode: DeliveryMode;
  key_types: string[];
  san_included: number;
  san_policy?: string;
  cert_apply_tmpl_uuid: string;
  stock: number;
  in_stock: boolean;
  discount_cents?: number;
  payable_cents?: number;
  coupon_error?: string;
  quoted_at: string;
}

// ---- 独立 OCSP 响应服务 ----

export interface OcspResponder {
  uuid: string;
  name: string;
  /** 公开地址：/ocsp/r/{path} */
  path: string;
  url?: string;
  /** ca=使用某个 CA 自身签名；cert=使用平台内证书（建议 OCSP 委托签名证书） */
  signer_type: 'ca' | 'cert';
  signer_ref: string;
  /** 负责响应的 CA 列表 */
  ca_uuids: string[];
  next_update_minutes: number;
  /** 未登记序列号的响应策略：unknown（推荐）/ good */
  unknown_policy: 'unknown' | 'good';
  enabled: boolean;
}

// ---- 证书策略页面 ----

export interface CertPolicy {
  uuid: string;
  name: string;
  /** 公开地址：/policy/{path} */
  path: string;
  content_type: 'markdown' | 'html';
  content?: string;
  version: string;
  enabled: boolean;
  is_public: boolean;
  updated_at: string;
}

// ---- 认证接口（自动审核） ----

export interface VerifyProviderDriverField {
  key: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  help?: string;
}

export interface VerifyProviderDriver {
  kind: 'email' | 'identity';
  driver: string;
  name: string;
  available: boolean;
  description: string;
  fields: VerifyProviderDriverField[];
}

export interface VerifyProvider {
  uuid: string;
  name: string;
  kind: 'email' | 'identity';
  driver: string;
  config: Record<string, string>;
  enabled: boolean;
  created_at?: string;
}

// ---- 身份认证审核 ----

export interface IdentityReview<T> {
  item: T;
  username: string;
  template_name?: string;
}

// ---- 优惠与订阅 ----

export interface Coupon {
  uuid: string;
  code: string;
  name: string;
  discount_type: 'amount' | 'percent';
  discount_value: number;
  min_amount_cents: number;
  max_discount_cents: number;
  product_codes: string[];
  total_limit: number;
  used_count: number;
  per_user_limit: number;
  valid_from?: string;
  valid_until?: string;
  enabled: boolean;
}

export interface PlanItem {
  cert_apply_tmpl_uuid: string;
  quota: number;
  valid_days: number;
}

export interface PromoPlan {
  uuid: string;
  code: string;
  name: string;
  description: string;
  period_days: number;
  price_cents: number;
  items: PlanItem[];
  allow_revoke: boolean;
  revoke_release_quota: boolean;
  visible: boolean;
  enabled: boolean;
  sort_weight: number;
}

export interface QuotaUsageItem extends PlanItem {
  template_name: string;
  used: number;
  remaining: number;
}

export interface Subscription {
  uuid: string;
  user_uuid: string;
  username?: string;
  plan_uuid: string;
  plan: PromoPlan;
  source: 'order' | 'redeem' | 'admin';
  source_ref: string;
  starts_at: string;
  ends_at: string;
  status: 'active' | 'cancelled';
  usage?: QuotaUsageItem[];
  created_at: string;
}

export interface RedeemCode {
  uuid: string;
  code: string;
  batch_name: string;
  grant_type: 'plan' | 'balance';
  plan_uuid?: string;
  balance_cents?: number;
  max_uses: number;
  used_count: number;
  valid_until?: string;
  enabled: boolean;
}

// ---- 申请向导 ----

/** 证书开通模板（服务端 cert_apply_templates） */
export interface CertApplyTemplateInfo {
  uuid: string;
  name: string;
  issuance_tmpl_uuid: string;
  valid_days: number;
  ca_uuid: string;
  enabled: boolean;
  /** 是否需要人工审批 */
  require_approval: boolean;
  allow_renewal: boolean;
  /** JSON 字符串数组 */
  allowed_key_types: string;
  description: string;
  /** 申请资料要求（优先于颁发模板上的同名关联） */
  subject_tmpl_uuid: string;
  extension_tmpl_uuid: string;
  created_at?: string;
  updated_at?: string;
}

export interface ApplyContext {
  source: {
    kind: 'order' | 'self' | 'subscription';
    order_no?: string;
    product_name: string;
    remaining: number;
    template: CertApplyTemplateInfo;
    subject_tmpl_uuid: string;
    extension_tmpl_uuid: string;
    san_policy: SANPolicy;
    delivery_mode: DeliveryMode;
    key_types: string[];
    valid_days: number;
    subscription_uuid?: string;
  };
  subject: {
    template_uuid: string;
    template_name: string;
    fields: SubjectTemplateField[];
    needs_info: boolean;
    required: boolean;
    verify_mode: VerifyMode;
    validity: string;
  };
  extension: { template_uuid: string; policy: ExtensionPolicy };
  subject_infos: SubjectInfo[];
  extension_infos: ExtensionInfo[];
  cards: Card[];
}

// ---- 收银台与退款 ----

/** 可用支付渠道 */
export interface PaymentChannel {
  channel: string;
  name: string;
  type: string;
}

/** 发起支付的结果 */
export interface CheckoutResult {
  order_no: string;
  channel: string;
  amount_cents: number;
  currency: string;
  /** true 表示已直接完成（免费订单或余额支付），无需跳转渠道 */
  settled: boolean;
  pay_url?: string;
  qr_code?: string;
  trade_no?: string;
}

/** 支付尝试（用于收银台轮询） */
export interface PaymentAttempt {
  uuid: string;
  order_no: string;
  channel: string;
  amount_cents: number;
  currency: string;
  status: 'pending' | 'paid' | 'failed' | 'closed';
  transaction_id?: string;
  created_at: string;
  paid_at?: string;
  expires_at?: string;
}

/** 退款工单 */
export interface PortalRefund {
  uuid: string;
  order_no: string;
  biz_type?: string;
  channel?: string;
  amount_cents: number;
  reason: string;
  status: 'pending' | 'paid' | 'failed';
  fail_reason?: string;
  refund_no?: string;
  created_at: string;
  processed_at?: string;
}

// ---- 业务模式 ----

/** 自助模式 / 销售模式 */
export type ApplyMode = 'self' | 'sales';

/** 订单可履约额度 */
export interface OrderQuota {
  order_no: string;
  product_name: string;
  sku_name: string;
  quantity: number;
  used: number;
  remaining: number;
  delivery_mode?: DeliveryMode;
  key_types?: string[];
  status: string;
}

/** 自助模式可直接申请的证书类型 */
export interface SelfApplyTemplate {
  uuid: string;
  name: string;
  description: string;
  allowed_key_types: string[] | null;
  require_approval: boolean;
}

/** 当前用户的业务能力 */
export interface Capabilities {
  cert_apply_mode: ApplyMode;
  card_apply_mode: ApplyMode;
  card_self_limit: number;
  user_card_count: number;
  is_admin: boolean;
  can_create_card: boolean;
  card_create_reason: string;
  card_entitlements: OrderQuota[];
  cert_order_quotas: OrderQuota[];
  can_self_apply_cert: boolean;
  self_apply_templates: SelfApplyTemplate[];
}

/** 提交申请的结果 */
export interface SubmitApplicationResult {
  application: CertApplication;
  auto_issued: boolean;
  message: string;
  issue_error?: string;
}

/** 帮助文档 */
export interface HelpDoc {
  slug: string;
  title: string;
  summary: string;
  audience: 'user' | 'admin';
  order: number;
  content: string;
}

/** 公开信任目录中的 CA 及其服务地址 */
export interface PkiEndpoint {
  ca_uuid: string;
  name: string;
  status: string;
  is_root: boolean;
  fingerprint: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  /** DER 格式 CA 证书下载地址 */
  ca_url: string;
  /** PEM 格式证书链下载地址 */
  chain_url: string;
  crl_url: string;
  ocsp_url: string;
  /** 是否使用吊销服务中配置的自定义路径 */
  custom_path: boolean;
}

/** 站点展示配置 */
export interface SiteSettings {
  site_name: string;
  site_tagline: string;
  site_description: string;
  contact_email: string;
  contact_phone: string;
  icp_record: string;
  footer_note: string;
  help_url: string;
  client_download: string;
  driver_download: string;
  terms_url: string;
  privacy_url: string;
  [key: string]: string;
}

// ---- CA 管理类型 ----

export interface CA {
  uuid: string;
  name: string;
  status: 'active' | 'revoked' | 'expired';
  key_type: string;
  common_name: string;
  organization?: string;
  country?: string;
  not_before: string;
  not_after: string;
  issued_count: number;
  cert_pem?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateCARequest {
  name: string;
  key_type: 'ec256' | 'ec384' | 'rsa2048' | 'rsa4096';
  validity_years: number;
  common_name: string;
  organization?: string;
  country?: string;
}

export interface RevokedCert {
  serial: string;
  revoked_at: string;
  reason: number;
  reason_text?: string;
}

export interface RevokeCertRequest {
  serial: string;
  reason: number;
}

export interface IssueCertRequest {
  key_type: string;
  validity_days: number;
  common_name: string;
  organization?: string;
  country?: string;
  is_ca: boolean;
  san_dns?: string[];
  san_ip?: string[];
  san_email?: string[];
}

// ---- 证书类型 ----

export interface Certificate {
  uuid: string;
  card_uuid?: string;
  ca_uuid?: string;
  template_uuid?: string;
  user_uuid?: string;
  cert_type: string;
  key_type: string;
  status?: 'valid' | 'revoked' | 'expired';
  /** 服务端实际字段：吊销状态 active/revoked */
  revocation_status?: 'active' | 'revoked' | string;
  cert_content?: string;
  remark?: string;
  order_no?: string;
  serial_number?: string;
  serial_hex?: string;
  subject_dn?: string;
  issuer_dn?: string;
  san_dns?: string;
  san_ip?: string;
  san_email?: string;
  not_before?: string;
  not_after?: string;
  created_at: string;
}

// ---- 模板类型 ----

export interface IssuanceTemplate {
  uuid: string;
  name: string;
  category: 'ssl' | 'code_sign' | 'email' | 'custom';
  is_ca: boolean;
  enabled: boolean;
  validity_options: number[];
  allowed_key_types: string[];
  allowed_ca_uuids: string[];
  subject_template_uuid?: string;
  extension_template_uuid?: string;
  key_usage_template_uuid?: string;
  key_storage_template_uuid?: string;
  cert_ext_template_uuid?: string;
  price: number;
  stock: number;
  created_at: string;
}

/** 主体字段验证方式：人工审核 / 自动接口 / 免验证 */
export type VerifyMode = 'manual' | 'auto' | 'none';

/** 主体字段派生规则：由第一个域名/邮箱/IP 推导该字段值 */
export type DeriveRule = '' | 'first_domain' | 'first_email' | 'first_ip';

/** 主体模板字段定义（服务端 identity.SubjectField） */
export interface SubjectTemplateField {
  /** X.500 属性简称：CN/O/OU/C/ST/L/STREET/POSTALCODE/SERIALNUMBER/E/UID/TITLE/... */
  key: string;
  label?: string;
  required: boolean;
  min_len?: number;
  max_len?: number;
  /** 预置格式：country/email/domain/digits/uscc */
  format?: string;
  /** 自定义正则 */
  pattern?: string;
  verify?: VerifyMode;
  derive?: DeriveRule;
  default?: string;
  help?: string;
}

/** 主体模板可选字段（下拉数据源） */
export interface SubjectFieldMeta {
  key: string;
  label: string;
}

export interface SubjectTemplate {
  uuid: string;
  name: string;
  description?: string;
  fields: SubjectTemplateField[];
  /** 字段验证方式为 auto 时使用的实名认证接口 */
  verify_provider_uuid?: string;
  /** 审核/认证有效期：1d/7d/30d/365d */
  verify_validity?: string;
  created_at: string;
}

/** 单类扩展信息（域名/邮箱/IP）的验证策略 */
export interface ExtensionTypePolicy {
  enabled: boolean;
  mode: VerifyMode;
  /** 域名：dns/http/tls；IP：http；邮箱：email */
  methods: string[];
  provider_uuid?: string;
  validity: string;
}

export interface ExtensionPolicy {
  domain: ExtensionTypePolicy;
  email: ExtensionTypePolicy;
  ip: ExtensionTypePolicy;
}

export interface ExtensionTemplate {
  uuid: string;
  name: string;
  /** 按类型的验证策略（JSON 字符串，服务端读取） */
  verify_policy?: string;
  verify_expires_days?: number;
  verify_provider_uuid?: string;
  created_at: string;
}

/** 商品规格的 SAN 限制 */
export interface SANPolicy {
  max_dns: number;
  max_email: number;
  max_ip: number;
  allow_wildcard: boolean;
  ip_versions: string[];
  email_suffixes: string[];
  dns_suffixes?: string[];
}

export interface KeyUsageTemplate {
  uuid: string;
  name: string;
  key_usage: number;
  ext_key_usage: string[];
  created_at: string;
}

export interface CertExtTemplate {
  uuid: string;
  name: string;
  crl_distribution_points: string[];
  ocsp_servers: string[];
  aia_issuers: string[];
  ct_servers: string[];
  ev_policy_oid?: string;
  created_at: string;
}

export interface KeyStorageTemplate {
  uuid: string;
  name: string;
  allow_file_download: boolean;
  allow_cloud_card: boolean;
  allow_physical_card: boolean;
  allow_virtual_card: boolean;
  virtual_card_security: 'high' | 'medium' | 'low';
  allow_reimport: boolean;
  cloud_backup: boolean;
  allow_reissue: boolean;
  max_reissue_count: number;
  created_at: string;
}

// ---- 主体信息与扩展信息 ----

export interface SubjectInfo {
  uuid: string;
  user_uuid: string;
  username?: string;
  template_uuid: string;
  template_name?: string;
  fields: Record<string, string>;
  /** pending=待人工 verifying=待实名 approved/rejected */
  status: 'pending' | 'verifying' | 'approved' | 'rejected';
  verify_mode?: VerifyMode;
  reject_reason?: string;
  /** 审核/认证有效期，过期需重新验证 */
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ExtensionInfo {
  uuid: string;
  user_uuid: string;
  username?: string;
  type: 'domain' | 'email' | 'ip';
  value: string;
  verify_method: 'txt' | 'http' | 'tls' | 'email';
  verify_token?: string;
  /** pending=待自助验证 reviewing=待人工 verified/rejected */
  status: 'pending' | 'reviewing' | 'verified' | 'rejected';
  reject_reason?: string;
  /** 申请向导：当前是否可用于申请（已通过且未过期、满足策略与格式限制） */
  usable?: boolean;
  need_reverify?: boolean;
  policy_error?: string;
  expires_at?: string;
  created_at: string;
}

// ---- 证书订单与申请 ----

export interface CertOrder {
  uuid: string;
  /** 对外订单号（门户下单生成，历史订单可能为空） */
  order_no?: string;
  user_uuid: string;
  /** 运营视图附带：下单用户名 */
  username?: string;
  template_uuid?: string;
  template_name?: string;
  validity_days?: number;
  key_type?: string;
  amount?: number;
  // ---- 门户下单补充字段（服务端 cert_orders 实际列） ----
  product_code?: string;
  sku_code?: string;
  spec_json?: string;
  applicant_email?: string;
  issuance_tmpl_uuid?: string;
  cert_apply_tmpl_uuid?: string;
  key_storage_tmpl_uuid?: string;
  amount_cents?: number;
  frozen_cents?: number;
  /** 由订阅额度生成的订单 */
  subscription_uuid?: string;
  coupon_code?: string;
  discount_cents?: number;
  paid_at?: string;
  status: 'pending' | 'paid' | 'issued' | 'rejected' | string;
  created_at: string;
  updated_at: string;
}

export interface CertApplication {
  uuid: string;
  order_uuid: string;
  user_uuid: string;
  subject_info_uuid: string;
  extension_info_uuids: string[];
  key_type: string;
  /** 服务端保存的主体与 SAN（JSON 字符串） */
  subject_json?: string;
  san_json?: string;
  csr_pem?: string;
  card_uuid?: string;
  applicant_email?: string;
  status: 'pending' | 'approved' | 'rejected';
  reject_reason?: string;
  cert_uuid?: string;
  created_at: string;
  updated_at: string;
}

// ---- 支付类型 ----

export interface PaymentOrder {
  uuid: string;
  user_uuid: string;
  amount: number;
  channel: string;
  status: 'pending' | 'paid' | 'failed' | 'refunded' | 'refunding';
  pay_url?: string;
  created_at: string;
  updated_at: string;
}

export interface UserBalance {
  /** 可用余额（分）——服务端字段 */
  available_cents: number;
  /** 冻结余额（分） */
  frozen_cents: number;
  /** 累计充值（分） */
  total_recharge: number;
  /** 累计消费（分） */
  total_consume: number;
  /** 兼容旧页面使用的字段名（元/分换算由页面自行处理） */
  available?: number;
  total_recharged?: number;
  total_consumed?: number;
}

export interface RechargeRequest {
  amount: number;
  channel: string;
}

export interface RefundRequest {
  order_uuid: string;
  reason: string;
}

export interface PaymentPlugin {
  uuid: string;
  name: string;
  plugin_type: 'alipay' | 'wechat' | 'stripe' | string;
  enabled: boolean;
  sort_weight: number;
  config?: Record<string, string>;
  created_at: string;
}

// ---- 系统配置类型 ----

export interface StorageZone {
  uuid: string;
  name: string;
  storage_type: 'database' | 'hsm';
  hsm_driver?: string;
  status: 'active' | 'disabled';
  created_at: string;
}

export interface CustomOID {
  uuid: string;
  oid: string;
  name: string;
  description?: string;
  usage_type: 'ext_key_usage' | 'subject_field' | 'ev_policy' | 'asn1_extension';
  created_at: string;
}

export interface RevocationService {
  uuid: string;
  ca_uuid: string;
  ca_name?: string;
  service_type: 'crl' | 'ocsp' | 'caissuer';
  path: string;
  enabled: boolean;
  crl_interval_minutes?: number;
  created_at: string;
}

export interface ACMEConfig {
  uuid: string;
  path: string;
  ca_uuid: string;
  ca_name?: string;
  template_uuid: string;
  template_name?: string;
  enabled: boolean;
  /** 允许的挑战类型：http-01 / dns-01 / tls-alpn-01。后端缺省为 http-01,dns-01。 */
  allowed_challenges?: Array<'http-01' | 'dns-01' | 'tls-alpn-01'>;
  created_at: string;
}

// ---- CT 记录 ----

export interface CTEntry {
  uuid: string;
  cert_uuid: string;
  cert_hash: string;
  ct_server: string;
  sct_data: string;
  submitted_at: string;
}

// ---- 云端 TOTP ----

export interface CloudTOTPEntry {
  uuid: string;
  issuer: string;
  account: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
  created_at: string;
}

export interface TOTPCodeResponse {
  code: string;
  remaining: number;
}

// ---- 日志 ----

export interface Log {
  uuid: string;
  log_type: string;
  user_uuid: string;
  level: string;
  title: string;
  content: string;
  created_at: string;
}

// ---- 云端智能卡 ----

export interface Card {
  uuid: string;
  user_uuid: string;
  card_name: string;
  remark: string;
  storage_zone_uuid?: string;
  pin_retries: number;
  pin_failed_count: number;
  pin_locked: boolean;
  /** user=用户智能卡；hosting=系统证书托管容器（存放下载型证书，不支持远程签名） */
  kind?: 'user' | 'hosting';
  /** 销售模式下开卡所凭的订单号 */
  order_no?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateCardRequest {
  card_name: string;
  remark?: string;
  storage_zone_uuid?: string;
  pin?: string;
  puk?: string;
  admin_key?: string;
  pin_retries?: number;
  /** 销售模式下必填：已支付的云智能卡订单号 */
  order_no?: string;
}

export interface VerifyPINRequest {
  pin: string;
}

export interface UnlockPUKRequest {
  puk: string;
  new_pin: string;
}

export interface ResetAdminKeyRequest {
  admin_key: string;
  new_pin?: string;
  new_puk?: string;
}

