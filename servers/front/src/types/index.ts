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

export interface AuthToken {
  token: string;
  user_uuid: string;
  username: string;
  role: 'admin' | 'user' | 'readonly';
  expires_at: string;
}

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
  user_type: string;
  display_name: string;
  email: string;
  cloud_url?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
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
  cert_content?: string;
  remark?: string;
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

export interface SubjectTemplateField {
  name: string;
  required: boolean;
  default_value?: string;
  max_length?: number;
}

export interface SubjectTemplate {
  uuid: string;
  name: string;
  fields: SubjectTemplateField[];
  created_at: string;
}

export interface ExtensionTemplate {
  uuid: string;
  name: string;
  max_dns: number;
  max_email: number;
  max_ip: number;
  max_uri: number;
  require_verify: boolean;
  created_at: string;
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
  template_uuid: string;
  template_name?: string;
  fields: Record<string, string>;
  status: 'pending' | 'approved' | 'rejected';
  reject_reason?: string;
  created_at: string;
  updated_at: string;
}

export interface ExtensionInfo {
  uuid: string;
  user_uuid: string;
  type: 'domain' | 'email' | 'ip';
  value: string;
  verify_method: 'dns' | 'email' | 'none';
  verify_token?: string;
  status: 'pending' | 'verified' | 'expired';
  expires_at?: string;
  created_at: string;
}

// ---- 证书订单与申请 ----

export interface CertOrder {
  uuid: string;
  user_uuid: string;
  template_uuid: string;
  template_name?: string;
  validity_days: number;
  key_type: string;
  amount: number;
  status: 'pending' | 'paid' | 'issued' | 'rejected';
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
  available: number;
  total_recharged: number;
  total_consumed: number;
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

