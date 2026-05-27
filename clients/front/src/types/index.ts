// API 数据类型定义，与 client-card(:1026) 后端模型对应

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

export type SecurityLevel = 'high' | 'medium' | 'low';

export interface CertStats {
  x509: number;
  fido: number;
  totp: number;
  creds: number;
}

export interface Card {
  uuid: string;
  slot_type: 'local' | 'tpm2' | 'tpmsc' | 'cloud';
  card_name: string;
  user_uuid: string;
  remark?: string;
  security_level: SecurityLevel;
  cloud_url?: string;
  cloud_card_uuid?: string;
  created_at: string;
  expires_at?: string;
  cert_stats?: CertStats;
}

export interface Certificate {
  uuid: string;
  card_uuid: string;
  slot_type: string;
  cert_type: string;
  key_type: string;
  cert_content?: string; // base64
  common_name?: string;  // 证书主题 CN
  issuer_cn?: string;    // 颁发者 CN
  remark?: string;
  created_at: string;
}

export interface Log {
  uuid: string;
  log_type: string;
  slot_type: string;
  card_uuid: string;
  user_uuid: string;
  level: string;
  title: string;
  content: string;
  created_at: string;
}

export interface SlotInfo {
  slot_id: number;
  description: string;
  token_present: boolean;
}

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

// 密钥生成请求
export interface KeyGenRequest {
  key_type: 'rsa2048' | 'rsa4096' | 'ec256' | 'ec384' | 'ec521';
  remark?: string;
  password: string;
}

// 创建卡片请求
export interface CreateCardRequest {
  slot_type: 'local' | 'tpm2' | 'tpmsc' | 'cloud';
  card_name: string;
  user_uuid: string;
  user_password: string;
  pin: string;
  security_level: SecurityLevel;
  remark?: string;
  cloud_url?: string;
  cloud_card_uuid?: string;
}

// 创建用户请求
export interface CreateUserRequest {
  user_type: string;
  display_name: string;
  email: string;
  password: string;
  cloud_url?: string;
}

// ---- TOTP 类型（本地卡片内） ----

export interface TOTPEntry {
  uuid: string;
  card_uuid: string;
  issuer: string;
  account: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
  created_at: string;
}

export interface CreateTOTPRequest {
  card_uuid?: string;
  issuer: string;
  account: string;
  secret: string;       // Base32 编码
  uri?: string;          // otpauth:// URI（可选，优先解析）
  algorithm?: string;
  digits?: number;
  period?: number;
}

export interface TOTPCodeResponse {
  code: string;
  remaining: number;
}

// ---- 本地 PKI 类型 ----

/** 密钥存储位置 */
export type KeyStorage = 'database' | 'smartcard' | 'imported';

/** CSR 记录（数据库存储） */
export interface CSRRecord {
  uuid: string;
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
  key_type: string;
  key_storage: KeyStorage;
  card_uuid?: string;
  san_dns?: string;
  san_ip?: string;
  san_email?: string;
  san_uri?: string;
  key_usage?: string;
  ext_key_usage?: string;
  csr_pem: string;
  has_private_key: boolean;
  remark?: string;
  created_at: string;
}

/** 创建 CSR 请求 */
export interface CreateCSRRequest {
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
  key_type: string;
  key_storage: KeyStorage;
  card_uuid?: string;
  card_password?: string;
  san_dns?: string;
  san_ip?: string;
  san_email?: string;
  san_uri?: string;
  key_usage?: string[];
  ext_key_usage?: string[];
  remark?: string;
}

/** 本地 CA 记录 */
export interface LocalCA {
  uuid: string;
  name: string;
  common_name: string;
  organization?: string;
  country?: string;
  key_type: string;
  cert_pem?: string;
  chain_pem?: string;
  has_priv_key: boolean;
  card_uuid?: string;
  not_before: string;
  not_after: string;
  issued_count: number;
  revoked: boolean;
  created_at: string;
}

/** 创建 CA 请求 */
export interface CreateCARequest {
  name: string;
  common_name: string;
  organization?: string;
  country?: string;
  key_type: string;
  validity_years: number;
  card_uuid?: string;
}

/** 导入 CA 请求 */
export interface ImportCARequest {
  name?: string;
  cert_pem: string;
  key_pem?: string;
  chain_pem?: string;
  card_uuid?: string;
}

/** PKI 证书记录 */
export interface PKICert {
  uuid: string;
  common_name: string;
  serial_number?: string;
  ca_uuid?: string;
  ca_name?: string;
  csr_uuid?: string;
  key_type: string;
  key_storage: KeyStorage;
  card_uuid?: string;
  cert_pem?: string;
  has_private_key: boolean;
  not_before: string;
  not_after: string;
  key_usage?: string;
  ext_key_usage?: string;
  san_dns?: string;
  san_ip?: string;
  san_email?: string;
  revoked: boolean;
  remark?: string;
  created_at: string;
}

/** 证书扩展选项（签发时可覆盖 CSR 中的设置） */
export interface CertExtensions {
  key_usage?: string[];           // digitalSignature, keyEncipherment, ...
  ext_key_usage?: string[];       // serverAuth, clientAuth, ...
  is_ca?: boolean;                // 基本约束：是否 CA
  path_len_constraint?: number;   // 基本约束：CA 链最大深度（-1 表示不限制）
  crl_urls?: string[];            // CRL 分发点
  ocsp_urls?: string[];           // OCSP 响应者地址
  aia_urls?: string[];            // AIA（颁发者信息访问）地址
  csp_name?: string;              // CSP（Cryptographic Service Provider）名称
}

/** 签发证书请求 */
export interface IssueCertRequest {
  csr_uuid: string;
  ca_uuid: string;
  validity_days?: number;   // 与 not_before/not_after 二选一
  not_before?: string;      // ISO8601
  not_after?: string;       // ISO8601
  remark?: string;
  extensions?: CertExtensions;    // 证书扩展选项
}

/** 导入证书模式 */
export type ImportCertMode = 'cert_only' | 'cert_key' | 'pkcs12' | 'key_only';

/** 导入证书请求 */
export interface ImportCertRequest {
  mode: ImportCertMode;
  cert_pem?: string;
  key_pem?: string;
  pkcs12_b64?: string;
  pkcs12_password?: string;
  card_uuid?: string;
  remark?: string;
}

/** 导出证书格式 */
export type ExportCertFormat = 'pem' | 'der' | 'pkcs12' | 'key_pem';

/** 自签名证书请求 */
export interface SelfSignRequest {
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  locality?: string;
  key_type: string;
  validity_days: number;
  card_uuid: string;
  san_dns?: string;
  san_ip?: string;
  san_email?: string;
  key_usage?: string[];
  ext_key_usage?: string[];
  export_also?: boolean;
}

// 旧版兼容（保留）
export interface CSRRequest {
  common_name: string;
  key_type: string;
  card_uuid: string;
  san_dns?: string;
}

export interface CSRResponse {
  csr_pem: string;
}

export interface CreateLocalCARequest {
  name: string;
  key_type: string;
  validity_years: number;
  card_uuid: string;
}

// ---- 认证类型 ----

export interface LoginRequest {
  username: string;
  password: string;
}

export interface CloudLoginRequest {
  cloud_url: string;
  username: string;
  password: string;
}

export interface AuthToken {
  token: string;
  user_uuid: string;
  username: string;
  role: 'admin' | 'user' | 'readonly';
  /** 仅云端登录响应包含 */
  user_type?: 'local' | 'cloud';
  cloud_url?: string;
  /** 云端账户原始用户名（本地 username 形如 cloud:host:alice） */
  cloud_user?: string;
  expires_at?: string;
}

/** 前端 Store 维护的单个账号会话 */
export interface AccountSession extends AuthToken {
  /** 账号类型：local=本地注册账号；cloud=云端账号 */
  user_type: 'local' | 'cloud';
  /** 账号显示名称（优先 cloud_user，退回 username） */
  display_name: string;
  /** 添加时间（ISO8601），用于登录页按最近优先排序 */
  added_at: string;
  /** 最近一次活动时间（用于过期判断） */
  last_active_at: string;
}

/** 客户端 Settings（与后端 ClientConfig 对齐） */
export interface ClientSettings {
  language: string;
  theme: string;
  close_to_tray: boolean;
  default_cloud_url: string;
  allow_insecure_cloud: boolean;
  auto_sync: boolean;
  sync_interval_minutes: number;
  register_pkcs11_mock: boolean;
  session_expires_minutes: number;
  detailed_request_log: boolean;
}

// ---- 智能卡导出/恢复类型 ----

/** 导出卡片请求 */
export interface ExportCardRequest {
  password?: string;
  admin_key?: string;
}

/** 恢复卡片请求 */
export interface RestoreCardRequest {
  ocs_data: string; // base64 编码的 .ocs 文件内容
  password: string;
  user_uuid: string;
}

/** 证书密钥导出请求 */
export interface ExportCertKeyRequest {
  password?: string;
  admin_key?: string;
  format: 'pem' | 'pfx';
}

/** 证书密钥导出响应 */
export interface ExportCertKeyResponse {
  format: string;
  private_key: string; // base64
  certificate?: string; // base64
}

/** 证书详情（解析后的 X.509 信息） */
export interface CertPolicy {
  oid: string;
  description?: string;
}

export interface CertDetail {
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  issuer_cn: string;
  issuer_org?: string;
  issuer_ou?: string;
  issuer_country?: string;
  not_before: string;
  not_after: string;
  serial_number: string;
  sha1_fingerprint: string;
  sha256_fingerprint?: string;
  key_usage: string[];
  ext_key_usage: string[];
  is_ca: boolean;
  max_path_len: number;
  max_path_len_zero: boolean;
  key_bits?: number;
  san_dns?: string[];
  san_ip?: string[];
  san_email?: string[];
  san_uri?: string[];
  crl_dist_points?: string[];
  ocsp_servers?: string[];
  issuing_cert_url?: string[];
  cps_urls?: string[];
  cert_policies?: CertPolicy[];
  signature_algo: string;
  public_key_algo: string;
  is_self_signed: boolean;
}
