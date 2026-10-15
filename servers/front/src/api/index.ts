import axios from 'axios';
import type {
  AuthToken, LoginRequest, RegisterRequest, ChangePasswordRequest,
  User, UserRole, PageResult,
  CA, CreateCARequest, RevokedCert, RevokeCertRequest, IssueCertRequest,
  Certificate,
  IssuanceTemplate, SubjectTemplate, ExtensionTemplate,
  KeyUsageTemplate, CertExtTemplate, KeyStorageTemplate,
  SubjectInfo, ExtensionInfo,
  CertOrder, CertApplication,
  PaymentOrder, UserBalance, RechargeRequest, RefundRequest, PaymentPlugin,
  StorageZone, CustomOID, RevocationService, ACMEConfig,
  CTEntry, CloudTOTPEntry, TOTPCodeResponse, Log,
  Card, CreateCardRequest, VerifyPINRequest, UnlockPUKRequest, ResetAdminKeyRequest,
  PortalProduct, PortalProductSKU, PortalCategory, ProductView, PortalQuote, SiteSettings,
  TotpChallenge, PaymentChannel, CheckoutResult, PaymentAttempt, PortalRefund,
  PkiEndpoint, Capabilities, SubmitApplicationResult, HelpDoc,
  OcspResponder, CertPolicy, VerifyProvider, VerifyProviderDriver,
  Coupon, PromoPlan, Subscription, RedeemCode, ApplyContext, SubjectFieldMeta,
  CertApplyTemplateInfo,
} from '../types';

// API 基础地址，连接 server-card :1027
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:1027';

const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// 请求拦截器：自动附加 Bearer Token
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('platform_token');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截器：统一错误处理
http.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('platform_token');
      localStorage.removeItem('platform_user_uuid');
      localStorage.removeItem('platform_username');
      localStorage.removeItem('platform_role');
      window.location.href = '/login';
    }
    // 后端错误字段是 error，不是 message
    const msg = err.response?.data?.error || err.response?.data?.message || err.message || '请求失败';
    return Promise.reject(new Error(msg));
  }
);

// ---- 响应适配层 ----
//
// 服务端各模块历史上使用了不同的列表键（templates / zones / orders / logs …）
// 与字段命名（*_tmpl_uuid、JSON 字符串数组、位掩码等）。统一在此处转换，
// 页面只面向 src/types 中的前端模型，避免"接口有数据、页面显示为空"。

/** 从列表响应中取出数组：兼容直接数组、items 以及各模块的具名键 */
const pickList = <T,>(data: any, ...keys: string[]): T[] => {
  if (Array.isArray(data)) return data as T[];
  if (!data || typeof data !== 'object') return [];
  for (const k of ['items', ...keys]) {
    if (Array.isArray(data[k])) return data[k] as T[];
  }
  return [];
};

/** 把列表响应转为分页结构 */
const toPage = <T,>(data: any, params?: { page?: number; page_size?: number }, ...keys: string[]): PageResult<T> => {
  const items = pickList<T>(data, ...keys);
  return {
    items,
    total: typeof data?.total === 'number' ? data.total : items.length,
    page: data?.page ?? params?.page ?? 1,
    page_size: data?.page_size ?? params?.page_size ?? (items.length || 20),
  };
};

/** 解析服务端以 JSON 字符串保存的字段 */
const parseJSON = <T,>(v: unknown, fallback: T): T => {
  if (v === null || v === undefined || v === '') return fallback;
  if (typeof v !== 'string') return v as T;
  try { return JSON.parse(v) as T; } catch { return fallback; }
};

// 颁发模板：服务端 valid_days / allowed_* 为 JSON 字符串，关联字段为 *_tmpl_uuid，价格为分
const fromIssuanceTemplate = (raw: any): IssuanceTemplate => ({
  ...raw,
  validity_options: parseJSON<number[]>(raw?.valid_days, []),
  allowed_key_types: parseJSON<string[]>(raw?.allowed_key_types, []),
  allowed_ca_uuids: parseJSON<string[]>(raw?.allowed_ca_uuids, []),
  subject_template_uuid: raw?.subject_tmpl_uuid ?? '',
  extension_template_uuid: raw?.extension_tmpl_uuid ?? '',
  key_usage_template_uuid: raw?.key_usage_tmpl_uuid ?? '',
  key_storage_template_uuid: raw?.key_storage_tmpl_uuid ?? '',
  cert_ext_template_uuid: raw?.cert_ext_tmpl_uuid ?? '',
  price: raw?.price_cents ?? 0,
});
const toIssuanceTemplate = (t: Partial<IssuanceTemplate> & Record<string, any>) => ({
  name: t.name,
  category: t.category ?? 'custom',
  is_ca: !!t.is_ca,
  path_len: t.path_len ?? 0,
  enabled: t.enabled !== false,
  valid_days: JSON.stringify(t.validity_options ?? []),
  allowed_key_types: JSON.stringify(t.allowed_key_types ?? []),
  allowed_ca_uuids: JSON.stringify(t.allowed_ca_uuids ?? []),
  subject_tmpl_uuid: t.subject_template_uuid ?? '',
  extension_tmpl_uuid: t.extension_template_uuid ?? '',
  key_usage_tmpl_uuid: t.key_usage_template_uuid ?? '',
  key_storage_tmpl_uuid: t.key_storage_template_uuid ?? '',
  cert_ext_tmpl_uuid: t.cert_ext_template_uuid ?? '',
  price_cents: t.price ?? 0,
  stock: t.stock ?? -1,
});

// 主体模板：服务端 fields 为 JSON 字符串
const fromSubjectTemplate = (raw: any): SubjectTemplate => ({
  ...raw, fields: parseJSON(raw?.fields, [] as SubjectTemplate['fields']),
});

// 密钥存储模板：服务端使用 storage_methods 位掩码（1 下载 / 2 云卡 / 4 实体卡 / 8 虚拟卡）
const fromKeyStorageTemplate = (raw: any): KeyStorageTemplate => {
  const m = Number(raw?.storage_methods ?? 0);
  return {
    ...raw,
    allow_file_download: (m & 1) !== 0,
    allow_cloud_card: (m & 2) !== 0,
    allow_physical_card: (m & 4) !== 0,
    allow_virtual_card: (m & 8) !== 0,
    virtual_card_security: raw?.security_level || 'medium',
  };
};
const toKeyStorageTemplate = (t: Partial<KeyStorageTemplate> & Record<string, any>) => ({
  name: t.name,
  storage_methods:
    (t.allow_file_download ? 1 : 0) | (t.allow_cloud_card ? 2 : 0) |
    (t.allow_physical_card ? 4 : 0) | (t.allow_virtual_card ? 8 : 0),
  security_level: t.virtual_card_security || 'medium',
  allow_reimport: !!t.allow_reimport,
  cloud_backup: !!t.cloud_backup,
  allow_reissue: !!t.allow_reissue,
  max_reissue_count: t.max_reissue_count ?? -1,
});

// 主体信息：服务端 subject_tmpl_uuid + field_values(JSON 字符串)
const fromSubjectInfo = (raw: any): SubjectInfo => ({
  ...raw,
  template_uuid: raw?.subject_tmpl_uuid ?? raw?.template_uuid ?? '',
  fields: parseJSON<Record<string, string>>(raw?.field_values ?? raw?.fields, {}),
});

// 扩展信息：服务端 info_type / verify_status；验证方式 txt(DNS) / http / email
const fromExtensionInfo = (raw: any): ExtensionInfo => ({
  ...raw,
  type: raw?.info_type ?? raw?.type,
  verify_method: raw?.verify_method === 'email' ? 'email' : raw?.verify_method === 'http' ? ('http' as any) : 'dns',
  status: raw?.verify_status ?? raw?.status,
});

// 吊销服务：服务端 crl_interval
const fromRevocationService = (raw: any): RevocationService => ({
  ...raw, crl_interval_minutes: raw?.crl_interval ?? raw?.crl_interval_minutes,
});

// ACME：服务端 issuance_tmpl_uuid
const fromACMEConfig = (raw: any): ACMEConfig => ({
  ...raw, template_uuid: raw?.issuance_tmpl_uuid ?? raw?.template_uuid ?? '',
});

// ---- 通用请求函数（兼容 fetch 风格调用） ----
export const apiRequest = async (url: string, options?: { method?: string; body?: string }) => {
  const method = (options?.method || 'GET').toLowerCase();
  const data = options?.body ? JSON.parse(options.body) : undefined;
  const res = await (http as any)[method](url, data);
  return res.data;
};

// ---- 健康检查 ----
export const getHealth = () =>
  http.get<{ status: string; version: string }>('/api/health').then((r) => r.data);

// ---- 认证接口 ----
/**
 * 登录。服务端在用户绑定 TOTP 时不返回 token，
 * 而是返回 { require_totp: true, session_token }，需继续调用 verifyTotp 完成二次验证。
 */
export const login = (data: LoginRequest) =>
  http.post<AuthToken | TotpChallenge>('/api/auth/login', data).then((r) => r.data);

/** TOTP 二次验证，成功后返回正式 token */
export const verifyTotp = (data: { session_token: string; code: string }) =>
  http.post<AuthToken>('/api/auth/totp-verify', data).then((r) => r.data);

export const register = (data: RegisterRequest) =>
  http.post<AuthToken>('/api/auth/register', data).then((r) => r.data);

export const refreshToken = () =>
  http.post<AuthToken>('/api/auth/refresh').then((r) => r.data);

export const logout = () =>
  http.delete('/api/auth/logout').then((r) => r.data);

export const changePassword = (data: ChangePasswordRequest) =>
  http.put('/api/auth/password', data).then((r) => r.data);

// 找回密码：发送验证码到邮箱
export const forgotPassword = (email: string) =>
  http.post<{ message: string }>('/api/auth/forgot-password', { email }).then((r) => r.data);

// 重置密码：使用验证码重置
export const resetPassword = (data: { email: string; code: string; new_password: string }) =>
  http.post<{ message: string }>('/api/auth/reset-password', data).then((r) => r.data);

export const getMe = () =>
  http.get<User>('/api/users/me').then((r) => r.data);

export const updateMe = (data: Partial<Pick<User, 'display_name' | 'email'>>) =>
  http.put<User>('/api/users/me', data).then((r) => r.data);

export const updatePubkey = (pubkey_pem: string) =>
  http.put('/api/users/me/pubkey', { pubkey_pem }).then((r) => r.data);

// ---- 用户管理（管理员） ----
// 注意：服务端 /api/users 返回 { users, total, page }，此处统一归一化为分页结构。
export const listUsers = async (params?: { page?: number; page_size?: number; keyword?: string }) => {
  const res = await http.get<{ users?: User[]; items?: User[]; total?: number; page?: number }>(
    '/api/users', { params },
  );
  const d = res.data || {};
  return {
    items: d.users ?? d.items ?? [],
    total: d.total ?? 0,
    page: d.page ?? params?.page ?? 1,
    page_size: params?.page_size ?? 10,
  } as PageResult<User>;
};

export const createUser = (data: {
  username: string; password: string; email: string; display_name: string; role?: UserRole;
}) => http.post<User>('/api/users', data).then((r) => r.data);

export const updateUser = (uuid: string, data: { display_name?: string; email?: string; password?: string }) =>
  http.put<User>(`/api/users/${uuid}`, data).then((r) => r.data);

export const deleteUser = (uuid: string) =>
  http.delete(`/api/users/${uuid}`).then((r) => r.data);

export const updateUserRole = (uuid: string, role: UserRole) =>
  http.put(`/api/users/${uuid}/role`, { role }).then((r) => r.data);

export const toggleUserEnabled = (uuid: string, enabled: boolean) =>
  http.put(`/api/users/${uuid}/enabled`, { enabled }).then((r) => r.data);

// ---- CA 管理 ----
// 服务端返回 { cas, total }，此处归一化为分页结构，避免列表页读到空数组。
export const listCAs = async (params?: { page?: number; page_size?: number }) => {
  const res = await http.get<{ cas?: CA[]; items?: CA[]; total?: number }>('/api/cas', { params });
  const d = res.data || {};
  return {
    items: d.cas ?? d.items ?? [],
    total: d.total ?? 0,
    page: params?.page ?? 1,
    page_size: params?.page_size ?? 20,
  } as PageResult<CA>;
};

export const createCA = (data: CreateCARequest) =>
  http.post<CA>('/api/cas', data).then((r) => r.data);

export const getCA = (uuid: string) =>
  http.get<CA>(`/api/cas/${uuid}`).then((r) => r.data);

export const updateCA = (uuid: string, data: Partial<CreateCARequest>) =>
  http.put<CA>(`/api/cas/${uuid}`, data).then((r) => r.data);

export const deleteCA = (uuid: string) =>
  http.delete(`/api/cas/${uuid}`).then((r) => r.data);

export const importCAChain = (uuid: string, chain_pem: string) =>
  http.post(`/api/cas/${uuid}/import-chain`, { chain_pem }).then((r) => r.data);

export const listRevokedCerts = (caUUID: string) =>
  http.get(`/api/cas/${caUUID}/revoked`).then((r) => pickList<RevokedCert>(r.data, 'revoked_certs'));

export const revokeCAcert = (caUUID: string, data: RevokeCertRequest) =>
  http.post(`/api/cas/${caUUID}/revoke`, data).then((r) => r.data);

export const issueCert = (caUUID: string, data: IssueCertRequest) =>
  http.post<Certificate>(`/api/cas/${caUUID}/issue`, data).then((r) => r.data);

export const downloadCRL = (caUUID: string) =>
  http.get(`/crl/${caUUID}`, { responseType: 'blob' }).then((r) => r.data);

// ---- 全局证书管理 ----
export const listAllCerts = (params?: {
  ca_uuid?: string; template_uuid?: string; user_uuid?: string;
  cert_type?: string; page?: number; page_size?: number;
}) => http.get('/api/certs', { params }).then((r) => toPage<Certificate>(r.data, params, 'certs'));

export const revokeCert = (uuid: string) =>
  http.post(`/api/certs/${uuid}/revoke`).then((r) => r.data);

export const assignCert = (uuid: string, card_uuid: string) =>
  http.post(`/api/certs/${uuid}/assign`, { card_uuid }).then((r) => r.data);

export const renewCert = (uuid: string, validity_days: number) =>
  http.post(`/api/certs/${uuid}/renew`, { validity_days }).then((r) => r.data);

export const exportCert = (uuid: string, format: string) =>
  http.get(`/api/certs/${uuid}/export`, { params: { format }, responseType: 'blob' }).then((r) => r.data);

// ---- 颁发模板 ----
export const listIssuanceTemplates = async (params?: { page?: number; page_size?: number; category?: string }) => {
  const r = await http.get('/api/templates/issuance', { params });
  const page = toPage<any>(r.data, params, 'templates');
  return { ...page, items: page.items.map(fromIssuanceTemplate) } as PageResult<IssuanceTemplate>;
};

export const createIssuanceTemplate = (data: Partial<IssuanceTemplate>) =>
  http.post('/api/templates/issuance', toIssuanceTemplate(data)).then((r) => fromIssuanceTemplate(r.data));

export const updateIssuanceTemplate = (uuid: string, data: Partial<IssuanceTemplate>) =>
  http.put(`/api/templates/issuance/${uuid}`, toIssuanceTemplate(data)).then((r) => fromIssuanceTemplate(r.data));

export const deleteIssuanceTemplate = (uuid: string) =>
  http.delete(`/api/templates/issuance/${uuid}`).then((r) => r.data);

// ---- 证书开通模板（cert_apply_templates）----
export const listCertApplyTemplates = () =>
  http.get('/api/templates/cert-apply').then((r) => pickList<CertApplyTemplateInfo>(r.data, 'templates'));

export const saveCertApplyTemplate = (data: Partial<CertApplyTemplateInfo>) =>
  data.uuid
    ? http.put(`/api/templates/cert-apply/${data.uuid}`, data).then((r) => r.data)
    : http.post('/api/templates/cert-apply', data).then((r) => r.data);

export const deleteCertApplyTemplate = (uuid: string) =>
  http.delete(`/api/templates/cert-apply/${uuid}`).then((r) => r.data);

// ---- 主体模板 ----
export const listSubjectTemplates = () =>
  http.get('/api/templates/subject').then((r) => pickList<any>(r.data, 'templates').map(fromSubjectTemplate));

export const createSubjectTemplate = (data: Omit<SubjectTemplate, 'uuid' | 'created_at'>) =>
  http.post('/api/templates/subject', {
    name: data.name,
    description: data.description ?? '',
    fields: JSON.stringify(data.fields ?? []),
    verify_provider_uuid: data.verify_provider_uuid ?? '',
    verify_validity: data.verify_validity ?? '365d',
  }).then((r) => fromSubjectTemplate(r.data));

export const deleteSubjectTemplate = (uuid: string) =>
  http.delete(`/api/templates/subject/${uuid}`).then((r) => r.data);

// ---- 扩展信息模板 ----
export const listExtensionTemplates = () =>
  http.get('/api/templates/extension').then((r) => pickList<ExtensionTemplate>(r.data, 'templates'));

export const createExtensionTemplate = (data: Omit<ExtensionTemplate, 'uuid' | 'created_at'>) =>
  http.post<ExtensionTemplate>('/api/templates/extension', {
    name: data.name,
    verify_policy: data.verify_policy ?? '{}',
    verify_expires_days: data.verify_expires_days ?? 30,
  }).then((r) => r.data);

export const deleteExtensionTemplate = (uuid: string) =>
  http.delete(`/api/templates/extension/${uuid}`).then((r) => r.data);

// ---- 密钥用途模板 ----
export const listKeyUsageTemplates = () =>
  http.get('/api/templates/key-usage').then((r) => pickList<KeyUsageTemplate>(r.data, 'templates'));

export const createKeyUsageTemplate = (data: Omit<KeyUsageTemplate, 'uuid' | 'created_at'>) =>
  http.post<KeyUsageTemplate>('/api/templates/key-usage', data).then((r) => r.data);

export const deleteKeyUsageTemplate = (uuid: string) =>
  http.delete(`/api/templates/key-usage/${uuid}`).then((r) => r.data);

// ---- 证书拓展模板 ----
export const listCertExtTemplates = () =>
  http.get('/api/templates/cert-ext').then((r) => pickList<CertExtTemplate>(r.data, 'templates'));

export const createCertExtTemplate = (data: Omit<CertExtTemplate, 'uuid' | 'created_at'>) =>
  http.post<CertExtTemplate>('/api/templates/cert-ext', data).then((r) => r.data);

export const deleteCertExtTemplate = (uuid: string) =>
  http.delete(`/api/templates/cert-ext/${uuid}`).then((r) => r.data);

// ---- 密钥存储类型模板 ----
export const listKeyStorageTemplates = () =>
  http.get('/api/templates/key-storage').then((r) => pickList<any>(r.data, 'templates').map(fromKeyStorageTemplate));

export const createKeyStorageTemplate = (data: Omit<KeyStorageTemplate, 'uuid' | 'created_at'>) =>
  http.post('/api/templates/key-storage', toKeyStorageTemplate(data)).then((r) => fromKeyStorageTemplate(r.data));

export const updateKeyStorageTemplate = (uuid: string, data: Partial<KeyStorageTemplate>) =>
  http.put(`/api/templates/key-storage/${uuid}`, toKeyStorageTemplate(data)).then((r) => fromKeyStorageTemplate(r.data));

export const deleteKeyStorageTemplate = (uuid: string) =>
  http.delete(`/api/templates/key-storage/${uuid}`).then((r) => r.data);

// ---- 主体信息 ----
export const listSubjectInfos = async (params?: {
  page?: number; page_size?: number; user_uuid?: string;
  /** 管理员审核队列：all=全部用户 */
  scope?: 'all'; status?: string;
}) => {
  const r = await http.get('/api/subject-infos', { params });
  const page = toPage<any>(r.data, params, 'subject_infos');
  return { ...page, items: page.items.map(fromSubjectInfo) } as PageResult<SubjectInfo>;
};

export const createSubjectInfo = (data: { template_uuid: string; fields: Record<string, string> }) =>
  http.post('/api/subject-infos', {
    subject_tmpl_uuid: data.template_uuid,
    field_values: JSON.stringify(data.fields ?? {}),
  }).then((r) => fromSubjectInfo(r.data));

export const approveSubjectInfo = (uuid: string) =>
  http.post(`/api/subject-infos/${uuid}/approve`).then((r) => r.data);

export const rejectSubjectInfo = (uuid: string, reason: string) =>
  http.post(`/api/subject-infos/${uuid}/reject`, { reason }).then((r) => r.data);

export const deleteSubjectInfo = (uuid: string) =>
  http.delete(`/api/subject-infos/${uuid}`).then((r) => r.data);

// ---- 扩展信息 ----
export const listExtensionInfos = async (params?: { page?: number; page_size?: number }) => {
  const r = await http.get('/api/extension-infos', { params });
  const page = toPage<any>(r.data, params, 'extension_infos');
  return { ...page, items: page.items.map(fromExtensionInfo) } as PageResult<ExtensionInfo>;
};

/** 创建扩展信息。域名/IP 默认 DNS TXT 验证（也可改用 HTTP 文件验证），邮箱使用验证码 */
export const createExtensionInfo = (data: { type: string; value: string; verify_method?: 'dns' | 'http' | 'email'; tmpl_uuid?: string }) => {
  const method = data.type === 'email' ? 'email' : data.verify_method === 'http' ? 'http' : 'txt';
  return http.post('/api/extension-infos', {
    info_type: data.type, value: data.value, verify_method: method, tmpl_uuid: data.tmpl_uuid ?? '',
  }).then((r) => fromExtensionInfo(r.data?.extension_info ?? r.data));
};

export const verifyHTTP = (uuid: string) =>
  http.post(`/api/extension-infos/${uuid}/verify-http`).then((r) => r.data);

export const verifyDNS = (uuid: string) =>
  http.post(`/api/extension-infos/${uuid}/verify-dns`).then((r) => r.data);

export const verifyEmail = (uuid: string, code: string) =>
  http.post(`/api/extension-infos/${uuid}/verify-email`, { code }).then((r) => r.data);

export const deleteExtensionInfo = (uuid: string) =>
  http.delete(`/api/extension-infos/${uuid}`).then((r) => r.data);

// ---- 证书订单 ----
export const createCertOrder = (data: { template_uuid: string; validity_days: number; key_type: string }) =>
  http.post<CertOrder>('/api/cert-orders', data).then((r) => r.data);

export const listCertOrders = (params?: { page?: number; page_size?: number; status?: string }) =>
  http.get('/api/cert-orders', { params }).then((r) => toPage<CertOrder>(r.data, params, 'orders'));

// ---- 证书申请 ----
export const createCertApplication = (data: {
  order_uuid: string; subject_info_uuid: string;
  extension_info_uuids: string[]; key_type: string;
}) => http.post('/api/cert-applications', data).then((r) => (r.data?.application ?? r.data) as CertApplication);

/** 申请的 SAN 在服务端以 JSON 保存，这里补充前端展示所需的扩展信息 UUID 列表字段 */
export const listCertApplications = (params?: { page?: number; page_size?: number; status?: string }) =>
  http.get('/api/cert-applications', { params }).then((r) => {
    const page = toPage<any>(r.data, params, 'applications');
    return {
      ...page,
      items: page.items.map((a: any) => ({ ...a, extension_info_uuids: a.extension_info_uuids ?? [] })),
    } as PageResult<CertApplication>;
  });

export const approveCertApplication = (uuid: string) =>
  http.post(`/api/cert-applications/${uuid}/approve`).then((r) => r.data);

export const rejectCertApplication = (uuid: string, reason: string) =>
  http.post(`/api/cert-applications/${uuid}/reject`, { reason }).then((r) => r.data);

// ---- 支付 ----
export const getBalance = () =>
  http.get<UserBalance>('/api/payment/balance').then((r) => r.data);

export const createRecharge = (data: RechargeRequest) =>
  http.post<PaymentOrder>('/api/payment/recharge', data).then((r) => r.data);

export const listPaymentOrders = (params?: { page?: number; page_size?: number; status?: string }) =>
  http.get('/api/payment/orders', { params }).then((r) => toPage<PaymentOrder>(r.data, params, 'orders'));

export const createRefund = (data: RefundRequest) =>
  http.post('/api/payment/refund', data).then((r) => r.data);

/** 全部退款工单（管理员审批列表），status 可选 pending/paid/failed */
export const listRefunds = (params?: { page?: number; page_size?: number; status?: string }) =>
  http.get('/api/payment/refunds', { params }).then((r) => toPage<PortalRefund>(r.data, params, 'refunds'));

export const listPaymentPlugins = () =>
  http.get('/api/payment/plugins').then((r) => pickList<PaymentPlugin>(r.data, 'plugins'));

/** 更新支付插件（启用/停用、名称、排序）；修改渠道密钥需删除后重建 */
export const updatePaymentPlugin = (uuid: string, data: { name: string; enabled: boolean; sort_weight: number }) =>
  http.put(`/api/payment/plugins/${uuid}`, data).then((r) => r.data);

/** 创建支付插件。渠道密钥通过 config 对象提交，由服务端加密存储 */
export const createPaymentPlugin = (data: {
  name: string;
  plugin_type: string;
  config?: Record<string, string>;
  enabled?: boolean;
  sort_weight?: number;
}) => http.post<PaymentPlugin>('/api/payment/plugins', data).then((r) => r.data);

export const deletePaymentPlugin = (uuid: string) =>
  http.delete(`/api/payment/plugins/${uuid}`).then((r) => r.data);

export const approveRefund = (uuid: string) =>
  http.post(`/api/payment/refund/${uuid}/approve`).then((r) => r.data);

export const rejectRefund = (uuid: string, reason?: string) =>
  http.post(`/api/payment/refund/${uuid}/reject`, { reason: reason ?? '' }).then((r) => r.data);

// ---- 存储区域 ----
export const listStorageZones = () =>
  http.get('/api/storage-zones').then((r) => pickList<StorageZone>(r.data, 'zones'));

export const createStorageZone = (data: Omit<StorageZone, 'uuid' | 'created_at'>) =>
  http.post<StorageZone>('/api/storage-zones', data).then((r) => r.data);

export const deleteStorageZone = (uuid: string) =>
  http.delete(`/api/storage-zones/${uuid}`).then((r) => r.data);

// ---- OID 管理 ----
export const listOIDs = () =>
  http.get('/api/oids').then((r) => pickList<CustomOID>(r.data, 'oids'));

export const createOID = (data: Omit<CustomOID, 'uuid' | 'created_at'>) =>
  http.post<CustomOID>('/api/oids', data).then((r) => r.data);

export const deleteOID = (uuid: string) =>
  http.delete(`/api/oids/${uuid}`).then((r) => r.data);

// ---- 吊销服务 ----
export const listRevocationServices = (caUUID?: string) =>
  http.get('/api/revocation-services', { params: { ca_uuid: caUUID } })
    .then((r) => pickList<any>(r.data, 'services').map(fromRevocationService));

export const createRevocationService = (data: Omit<RevocationService, 'uuid' | 'ca_name' | 'created_at'>) =>
  http.post('/api/revocation-services', {
    ca_uuid: data.ca_uuid, service_type: data.service_type, path: data.path,
    enabled: data.enabled !== false, crl_interval: data.crl_interval_minutes ?? 60,
  }).then((r) => fromRevocationService(r.data));

export const deleteRevocationService = (uuid: string) =>
  http.delete(`/api/revocation-services/${uuid}`).then((r) => r.data);

// ---- ACME 配置 ----
export const listACMEConfigs = () =>
  http.get('/api/acme-configs').then((r) => pickList<any>(r.data, 'configs').map(fromACMEConfig));

export const createACMEConfig = (data: Omit<ACMEConfig, 'uuid' | 'ca_name' | 'template_name' | 'created_at'>) =>
  http.post('/api/acme-configs', {
    path: String(data.path || '').replace(/^\/?acme\//, '').replace(/^\//, ''),
    ca_uuid: data.ca_uuid, issuance_tmpl_uuid: data.template_uuid, enabled: data.enabled !== false,
  }).then((r) => fromACMEConfig(r.data));

export const deleteACMEConfig = (uuid: string) =>
  http.delete(`/api/acme-configs/${uuid}`).then((r) => r.data);

// ---- CT 记录 ----
export const listCTEntries = (params?: { cert_hash?: string; cert_uuid?: string; page?: number; page_size?: number }) =>
  http.get('/api/ct-entries', { params }).then((r) => toPage<CTEntry>(r.data, params, 'entries'));

export const deleteCTEntry = (uuid: string) =>
  http.delete(`/api/ct-entries/${uuid}`).then((r) => r.data);

// ---- 云端 TOTP ----
export const listCloudTOTPs = () =>
  http.get('/api/cloud-totp').then((r) => pickList<CloudTOTPEntry>(r.data, 'totps'));

export const createCloudTOTP = (data: Omit<CloudTOTPEntry, 'uuid' | 'created_at'> & { secret: string }) =>
  http.post<CloudTOTPEntry>('/api/cloud-totp', data).then((r) => r.data);

export const getCloudTOTPCode = (uuid: string) =>
  http.get<TOTPCodeResponse>(`/api/cloud-totp/${uuid}/code`).then((r) => r.data);

export const deleteCloudTOTP = (uuid: string) =>
  http.delete(`/api/cloud-totp/${uuid}`).then((r) => r.data);

// ---- 日志 ----
export const getLogs = (params?: { user_uuid?: string; level?: string; action?: string; page?: number; page_size?: number }) =>
  http.get('/api/logs', { params }).then((r) => toPage<Log>(r.data, params, 'logs'));

// ---- 云端智能卡 ----
interface CardListResp { cards: Card[]; total: number }

export const listCards = () =>
  http.get<CardListResp>('/api/cards').then((r) => r.data.cards ?? []);

export const createCard = (data: CreateCardRequest) =>
  http.post<Card>('/api/cards', data).then((r) => r.data);

export const getCard = (uuid: string) =>
  http.get<Card>(`/api/cards/${uuid}`).then((r) => r.data);

export const deleteCard = (uuid: string) =>
  http.delete(`/api/cards/${uuid}`).then((r) => r.data);

export const listCardCerts = (cardUUID: string) =>
  http.get<{ certs: Certificate[]; total: number }>(`/api/cards/${cardUUID}/certs`)
    .then((r) => r.data.certs ?? []);

export const importCardCert = (cardUUID: string, data: { cert_pem: string; private_key_pem?: string; remark?: string }) =>
  http.post(`/api/cards/${cardUUID}/certs`, data).then((r) => r.data);

export const deleteCardCert = (cardUUID: string, certUUID: string) =>
  http.delete(`/api/cards/${cardUUID}/certs/${certUUID}`).then((r) => r.data);

// 卡片 PIN/PUK/AdminKey 操作
export const verifyCardPIN = (cardUUID: string, data: VerifyPINRequest) =>
  http.post<{ session_token: string; expires_in: number }>(
    `/api/cards/${cardUUID}/verify-pin`, data,
  ).then((r) => r.data);

export const logoutCardPINSession = (cardUUID: string) =>
  http.delete(`/api/cards/${cardUUID}/pin-session`).then((r) => r.data);

export const unlockCardWithPUK = (cardUUID: string, data: UnlockPUKRequest) =>
  http.post(`/api/cards/${cardUUID}/unlock-puk`, data).then((r) => r.data);

export const resetCardWithAdminKey = (cardUUID: string, data: ResetAdminKeyRequest) =>
  http.post(`/api/cards/${cardUUID}/reset-admin`, data).then((r) => r.data);

// ---- 门户（官网/商城）----

/** 站点展示配置（公开） */
export const getSiteInfo = () =>
  http.get<SiteSettings>('/api/portal/site').then((r) => r.data);

/** 商品分类及数量（公开） */
export const listPortalCategories = () =>
  http.get<{ items: PortalCategory[] }>('/api/portal/categories').then((r) => r.data.items ?? []);

/** 商品列表（公开，仅已发布商品） */
export const listPortalProducts = (params?: { category?: string }) =>
  http.get<{ items: ProductView[]; total: number }>('/api/portal/products', { params })
    .then((r) => r.data.items ?? []);

/** 商品详情（公开） */
export const getPortalProduct = (code: string) =>
  http.get<ProductView>(`/api/portal/products/${code}`).then((r) => r.data);

/** 服务端权威报价（公开，不创建订单） */
export const quotePortalOrder = (data: { sku_code: string; quantity: number }) =>
  http.post<PortalQuote>('/api/portal/quotes', data).then((r) => r.data);

/** 创建门户订单（需登录） */
export const createPortalOrder = (data: {
  sku_code: string; quantity: number; applicant_email?: string;
}) => http.post<CertOrder>('/api/portal/orders', data).then((r) => r.data);

/** 我的订单（需登录） */
export const listMyPortalOrders = (params?: { page?: number; page_size?: number }) =>
  http.get<{ items: CertOrder[]; total: number }>('/api/portal/orders', { params })
    .then((r) => r.data.items ?? []);

/** 按对外单号查询我的订单（需登录） */
export const getMyPortalOrder = (orderNo: string) =>
  http.get<CertOrder>(`/api/portal/orders/${orderNo}`).then((r) => r.data);

// ---- 公开信任服务 ----

/** 公开 CA 目录（含 CRL/OCSP/AIA 地址） */
export const listPortalPKIEndpoints = () =>
  http.get<{ items: PkiEndpoint[]; total: number }>('/api/portal/pki-endpoints')
    .then((r) => r.data.items ?? []);

/** 控制某个 CA 是否出现在门户公开信任目录（管理员） */
export const publishCA = (uuid: string, isPublic: boolean) =>
  http.put(`/api/cas/${uuid}/publish`, { public: isPublic }).then((r) => r.data);

// ---- 收银台与退款（需登录） ----

/** 可用支付渠道 */
export const listPortalPaymentChannels = () =>
  http.get<{ items: PaymentChannel[] }>('/api/portal/payment-channels')
    .then((r) => r.data.items ?? []);

/** 发起支付：余额/免费当场结算，第三方渠道返回支付链接或二维码 */
export const payPortalOrder = (orderNo: string, channel: string) =>
  http.post<CheckoutResult>(`/api/portal/orders/${orderNo}/pay`, { channel }).then((r) => r.data);

/** 查询订单支付状态（收银台轮询） */
export const getPortalOrderPayment = (orderNo: string) =>
  http.get<PaymentAttempt>(`/api/portal/orders/${orderNo}/payment`).then((r) => r.data);

/** 申请退款 */
export const requestPortalRefund = (orderNo: string, reason: string) =>
  http.post<PortalRefund>(`/api/portal/orders/${orderNo}/refund`, { reason }).then((r) => r.data);

/** 取消待支付订单（已支付订单需申请退款） */
export const cancelPortalOrder = (orderNo: string) =>
  http.post(`/api/portal/orders/${orderNo}/cancel`).then((r) => r.data);

// ---- 业务模式与统一申请入口 ----

/** 当前用户的业务能力：是否可开卡、可用订单额度、自助申请的证书类型 */
export const getCapabilities = () =>
  http.get<Capabilities>('/api/portal/capabilities').then((r) => r.data);

/** 提交证书申请（订单或自助模式），模板无需审批时服务端会立即签发 */
export const submitApplication = (data: {
  order_no?: string;
  cert_apply_tmpl_uuid?: string;
  subject_info_uuid?: string;
  extension_info_uuids?: string[];
  key_type?: string;
  csr_pem?: string;
  card_uuid?: string;
}) => http.post<SubmitApplicationResult>('/api/portal/applications', data).then((r) => r.data);

// ---- 运营：订单与用户智能卡 ----

export const listAdminOrders = (params?: { status?: string; keyword?: string; page?: number; page_size?: number }) =>
  http.get('/api/portal/admin/orders', { params })
    .then((r) => toPage<CertOrder & { username?: string }>(r.data, params));

/** 确认线下到账（未接入在线支付插件时的收款方式） */
export const confirmOfflinePayment = (orderNo: string, reference: string) =>
  http.post(`/api/portal/admin/orders/${orderNo}/confirm-payment`, { reference }).then((r) => r.data);

export const adminCancelOrder = (orderNo: string) =>
  http.post(`/api/portal/admin/orders/${orderNo}/cancel`).then((r) => r.data);

export const listAdminCards = (params?: { user_uuid?: string; page?: number; page_size?: number }) =>
  http.get('/api/admin/cards', { params })
    .then((r) => toPage<Card & { username?: string; cert_count?: number }>(r.data, params));

export const adminUnlockCard = (uuid: string) =>
  http.post(`/api/admin/cards/${uuid}/unlock`).then((r) => r.data);

export const adminDeleteCard = (uuid: string) =>
  http.delete(`/api/admin/cards/${uuid}`).then((r) => r.data);

// ---- 帮助中心 ----

/** 用户帮助文档（公开） */
export const listHelpDocs = () =>
  http.get('/api/help/docs').then((r) => pickList<HelpDoc>(r.data, 'docs'));

/** 管理员帮助文档（仅管理员可访问） */
export const listAdminHelpDocs = () =>
  http.get('/api/help/admin-docs').then((r) => pickList<HelpDoc>(r.data, 'docs'));

/** 我的退款工单 */
export const listMyRefunds = (params?: { page?: number; page_size?: number }) =>
  http.get<{ items: PortalRefund[]; total: number }>('/api/portal/refunds', { params })
    .then((r) => r.data.items ?? []);

// ---- 门户运营后台：商品与规格 ----

export const listAdminProducts = (params?: { category?: string }) =>
  http.get<{ items: ProductView[]; total: number }>('/api/portal/admin/products', { params })
    .then((r) => r.data.items ?? []);

export const createAdminProduct = (data: Partial<PortalProduct>) =>
  http.post<PortalProduct>('/api/portal/admin/products', data).then((r) => r.data);

export const updateAdminProduct = (uuid: string, data: Partial<PortalProduct>) =>
  http.put<PortalProduct>(`/api/portal/admin/products/${uuid}`, data).then((r) => r.data);

export const deleteAdminProduct = (uuid: string) =>
  http.delete(`/api/portal/admin/products/${uuid}`).then((r) => r.data);

export const listAdminSKUs = (productUUID: string) =>
  http.get<{ items: PortalProductSKU[]; total: number }>(
    `/api/portal/admin/products/${productUUID}/skus`,
  ).then((r) => r.data.items ?? []);

export const createAdminSKU = (data: Partial<PortalProductSKU>) =>
  http.post<PortalProductSKU>('/api/portal/admin/skus', data).then((r) => r.data);

export const updateAdminSKU = (uuid: string, data: Partial<PortalProductSKU>) =>
  http.put<PortalProductSKU>(`/api/portal/admin/skus/${uuid}`, data).then((r) => r.data);

export const deleteAdminSKU = (uuid: string) =>
  http.delete(`/api/portal/admin/skus/${uuid}`).then((r) => r.data);

// ---- 站点配置（读取需登录，写入需管理员） ----

export const getSiteSettings = () =>
  http.get<SiteSettings>('/api/site-settings').then((r) => r.data);

export const updateSiteSettings = (data: Partial<SiteSettings>) =>
  http.put<SiteSettings>('/api/site-settings', data).then((r) => r.data);

// ---- 独立 OCSP 响应服务（管理员） ----

export const listOCSPResponders = () =>
  http.get('/api/ocsp-responders').then((r) => pickList<OcspResponder>(r.data, 'responders'));

export const saveOCSPResponder = (data: Partial<OcspResponder>) =>
  data.uuid
    ? http.put<OcspResponder>(`/api/ocsp-responders/${data.uuid}`, data).then((r) => r.data)
    : http.post<OcspResponder>('/api/ocsp-responders', data).then((r) => r.data);

export const deleteOCSPResponder = (uuid: string) =>
  http.delete(`/api/ocsp-responders/${uuid}`).then((r) => r.data);

// ---- 证书策略页面（CP/CPS） ----

export const listCertPolicies = () =>
  http.get('/api/cert-policies').then((r) => pickList<CertPolicy>(r.data, 'policies'));

export const getCertPolicy = (uuid: string) =>
  http.get<CertPolicy>(`/api/cert-policies/${uuid}`).then((r) => r.data);

export const saveCertPolicy = (data: Partial<CertPolicy>) =>
  data.uuid
    ? http.put<CertPolicy>(`/api/cert-policies/${data.uuid}`, data).then((r) => r.data)
    : http.post<CertPolicy>('/api/cert-policies', data).then((r) => r.data);

export const deleteCertPolicy = (uuid: string) =>
  http.delete(`/api/cert-policies/${uuid}`).then((r) => r.data);

/** 官网信任中心的公开策略列表 */
export const listPortalPolicies = () =>
  http.get<{ items: { name: string; version: string; content_type: string; url: string; updated_at: string }[] }>(
    '/api/portal/policies',
  ).then((r) => r.data.items ?? []);

// ---- 认证接口（自动审核） ----

export const listVerifyProviders = (kind?: 'email' | 'identity') =>
  http.get<{ items: VerifyProvider[]; drivers: VerifyProviderDriver[] }>('/api/verify-providers', { params: { kind } })
    .then((r) => ({ items: r.data.items ?? [], drivers: r.data.drivers ?? [] }));

export const saveVerifyProvider = (data: Partial<VerifyProvider>) =>
  data.uuid
    ? http.put<VerifyProvider>(`/api/verify-providers/${data.uuid}`, data).then((r) => r.data)
    : http.post<VerifyProvider>('/api/verify-providers', data).then((r) => r.data);

export const deleteVerifyProvider = (uuid: string) =>
  http.delete(`/api/verify-providers/${uuid}`).then((r) => r.data);

/** 邮件接口连通性测试 */
export const testVerifyProvider = (uuid: string, to: string) =>
  http.post(`/api/verify-providers/${uuid}/test`, { to }).then((r) => r.data);

// ---- 身份认证审核（管理员） ----

export const listIdentityReviews = (kind: 'subject' | 'extension', status?: string) =>
  http.get('/api/admin/identity-reviews', { params: { kind, status } })
    .then((r) => pickList<any>(r.data, 'subject_infos', 'extension_infos'));

// ---- 主体/扩展信息的补充操作 ----

export const resubmitSubjectInfo = (uuid: string, fields: Record<string, string>) =>
  http.put(`/api/subject-infos/${uuid}`, { field_values: JSON.stringify(fields ?? {}) }).then((r) => r.data);

/** 发起实名认证，返回第三方跳转地址 */
export const startSubjectIdentity = (uuid: string, returnUrl?: string) =>
  http.post<{ redirect_url: string }>(`/api/subject-infos/${uuid}/identity`, { return_url: returnUrl })
    .then((r) => r.data);

export const verifyTLS = (uuid: string) =>
  http.post(`/api/extension-infos/${uuid}/verify-tls`).then((r) => r.data);

/** 重新发起验证（可切换验证方式与适用的扩展模板） */
export const renewExtensionInfo = (uuid: string, method?: string, tmplUUID?: string) =>
  http.post(`/api/extension-infos/${uuid}/renew`, { method, tmpl_uuid: tmplUUID }).then((r) => r.data);

export const approveExtensionInfo = (uuid: string) =>
  http.post(`/api/extension-infos/${uuid}/approve`).then((r) => r.data);

export const rejectExtensionInfo = (uuid: string, reason: string) =>
  http.post(`/api/extension-infos/${uuid}/reject`, { reason }).then((r) => r.data);

// ---- 申请向导 ----

/** 申请向导上下文：来源、模板要求、SAN 限制与用户可用资料 */
export const getApplyContext = (params: { order_no?: string; tmpl?: string; subscription?: string }) =>
  http.get<ApplyContext>('/api/portal/apply-context', { params }).then((r) => r.data);

// ---- 优惠码 / 订阅套餐 / 兑换码 ----

export const listCoupons = () =>
  http.get('/api/promo/coupons').then((r) => pickList<Coupon>(r.data, 'coupons'));

export const saveCoupon = (data: Partial<Coupon>) =>
  data.uuid
    ? http.put<Coupon>(`/api/promo/coupons/${data.uuid}`, data).then((r) => r.data)
    : http.post<Coupon>('/api/promo/coupons', data).then((r) => r.data);

export const deleteCoupon = (uuid: string) =>
  http.delete(`/api/promo/coupons/${uuid}`).then((r) => r.data);

export const listPlans = (all = false) =>
  all
    ? http.get('/api/promo/plans').then((r) => pickList<PromoPlan>(r.data, 'plans'))
    : http.get('/api/portal/plans').then((r) => pickList<PromoPlan>(r.data, 'plans'));

export const savePlan = (data: Partial<PromoPlan>) =>
  data.uuid
    ? http.put<PromoPlan>(`/api/promo/plans/${data.uuid}`, data).then((r) => r.data)
    : http.post<PromoPlan>('/api/promo/plans', data).then((r) => r.data);

export const deletePlan = (uuid: string) =>
  http.delete(`/api/promo/plans/${uuid}`).then((r) => r.data);

/** 我的订阅（含额度使用情况） */
export const listMySubscriptions = () =>
  http.get<{ items: Subscription[] }>('/api/portal/subscriptions').then((r) => r.data.items ?? []);

export const listAdminSubscriptions = (userUUID?: string) =>
  http.get('/api/promo/subscriptions', { params: { user_uuid: userUUID } })
    .then((r) => pickList<Subscription>(r.data, 'subscriptions'));

export const grantSubscription = (username: string, planUUID: string, remark?: string) =>
  http.post('/api/promo/subscriptions', { username, plan_uuid: planUUID, remark }).then((r) => r.data);

export const cancelSubscription = (uuid: string) =>
  http.post(`/api/promo/subscriptions/${uuid}/cancel`).then((r) => r.data);

export const listRedeemCodes = (batch?: string) =>
  http.get('/api/promo/redeem-codes', { params: { batch } })
    .then((r) => pickList<RedeemCode>(r.data, 'codes'));

export const generateRedeemCodes = (data: Partial<RedeemCode> & { count: number }) =>
  http.post<{ items: RedeemCode[] }>('/api/promo/redeem-codes', data).then((r) => r.data.items ?? []);

export const setRedeemEnabled = (uuid: string, enabled: boolean) =>
  http.put(`/api/promo/redeem-codes/${uuid}/enabled`, { enabled }).then((r) => r.data);

/** 用户兑换：订阅套餐或账户余额 */
export const redeemCode = (code: string) =>
  http.post<{ grant_type: string; subscription?: Subscription; balance_cents?: number }>(
    '/api/portal/redeem', { code },
  ).then((r) => r.data);

/** 购买订阅套餐（返回待支付订单） */
export const buyPlan = (code: string, data?: { applicant_email?: string; coupon_code?: string }) =>
  http.post<CertOrder>(`/api/portal/plans/${code}/orders`, data ?? {}).then((r) => r.data);

/** 报价（含优惠码预览） */
export const quoteWithCoupon = (data: { sku_code?: string; plan_code?: string; quantity?: number; coupon_code?: string }) =>
  http.post<any>('/api/portal/quotes/coupon', data).then((r) => r.data);

/** 用户自助吊销自己的证书 */
export const revokeMyCert = (uuid: string, reason = 0) =>
  http.post(`/api/my/certs/${uuid}/revoke`, { reason }).then((r) => r.data);

// ---- 主体模板 / 扩展模板（新字段与更新） ----

export const listSubjectFieldMeta = () =>
  http.get<{ items: SubjectFieldMeta[] }>('/api/meta/subject-field-keys').then((r) => r.data.items ?? []);

export const updateSubjectTemplate = (uuid: string, data: Partial<SubjectTemplate>) =>
  http.put<SubjectTemplate>(`/api/templates/subject/${uuid}`, {
    name: data.name,
    description: data.description ?? '',
    fields: JSON.stringify(data.fields ?? []),
    verify_provider_uuid: data.verify_provider_uuid ?? '',
    verify_validity: data.verify_validity ?? '365d',
  }).then((r) => r.data);

export const updateExtensionTemplate = (uuid: string, data: Partial<ExtensionTemplate>) =>
  http.put<ExtensionTemplate>(`/api/templates/extension/${uuid}`, {
    name: data.name,
    verify_policy: data.verify_policy ?? '{}',
  }).then((r) => r.data);

