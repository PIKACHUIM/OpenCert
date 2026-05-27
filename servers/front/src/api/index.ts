import axios from 'axios';
import type {
  AuthToken, LoginRequest, RegisterRequest, ChangePasswordRequest,
  User, PageResult,
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
export const login = (data: LoginRequest) =>
  http.post<AuthToken>('/api/auth/login', data).then((r) => r.data);

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
export const listUsers = (params?: { page?: number; page_size?: number; keyword?: string }) =>
  http.get<PageResult<User>>('/api/users', { params }).then((r) => r.data);

export const createUser = (data: { username: string; password: string; email: string; display_name: string; user_type?: string }) =>
  http.post<User>('/api/users', data).then((r) => r.data);

export const updateUser = (uuid: string, data: Partial<User & { password?: string }>) =>
  http.put<User>(`/api/users/${uuid}`, data).then((r) => r.data);

export const deleteUser = (uuid: string) =>
  http.delete(`/api/users/${uuid}`).then((r) => r.data);

export const updateUserRole = (uuid: string, role: 'admin' | 'user' | 'readonly') =>
  http.put(`/api/users/${uuid}/role`, { role }).then((r) => r.data);

export const toggleUserEnabled = (uuid: string, enabled: boolean) =>
  http.put(`/api/users/${uuid}/enabled`, { enabled }).then((r) => r.data);

// ---- CA 管理 ----
export const listCAs = (params?: { page?: number; page_size?: number }) =>
  http.get<PageResult<CA>>('/api/cas', { params }).then((r) => r.data);

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
  http.get<RevokedCert[]>(`/api/cas/${caUUID}/revoked`).then((r) => r.data ?? []);

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
}) => http.get<PageResult<Certificate>>('/api/certs', { params }).then((r) => r.data);

export const revokeCert = (uuid: string) =>
  http.post(`/api/certs/${uuid}/revoke`).then((r) => r.data);

export const assignCert = (uuid: string, card_uuid: string) =>
  http.post(`/api/certs/${uuid}/assign`, { card_uuid }).then((r) => r.data);

export const renewCert = (uuid: string, validity_days: number) =>
  http.post(`/api/certs/${uuid}/renew`, { validity_days }).then((r) => r.data);

export const exportCert = (uuid: string, format: string) =>
  http.get(`/api/certs/${uuid}/export`, { params: { format }, responseType: 'blob' }).then((r) => r.data);

// ---- 颁发模板 ----
export const listIssuanceTemplates = (params?: { page?: number; page_size?: number }) =>
  http.get<PageResult<IssuanceTemplate>>('/api/templates/issuance', { params }).then((r) => r.data);

export const createIssuanceTemplate = (data: Partial<IssuanceTemplate>) =>
  http.post<IssuanceTemplate>('/api/templates/issuance', data).then((r) => r.data);

export const updateIssuanceTemplate = (uuid: string, data: Partial<IssuanceTemplate>) =>
  http.put<IssuanceTemplate>(`/api/templates/issuance/${uuid}`, data).then((r) => r.data);

export const deleteIssuanceTemplate = (uuid: string) =>
  http.delete(`/api/templates/issuance/${uuid}`).then((r) => r.data);

// ---- 主体模板 ----
export const listSubjectTemplates = () =>
  http.get<SubjectTemplate[]>('/api/templates/subject').then((r) => r.data ?? []);

export const createSubjectTemplate = (data: Omit<SubjectTemplate, 'uuid' | 'created_at'>) =>
  http.post<SubjectTemplate>('/api/templates/subject', data).then((r) => r.data);

export const deleteSubjectTemplate = (uuid: string) =>
  http.delete(`/api/templates/subject/${uuid}`).then((r) => r.data);

// ---- 扩展信息模板 ----
export const listExtensionTemplates = () =>
  http.get<ExtensionTemplate[]>('/api/templates/extension').then((r) => r.data ?? []);

export const createExtensionTemplate = (data: Omit<ExtensionTemplate, 'uuid' | 'created_at'>) =>
  http.post<ExtensionTemplate>('/api/templates/extension', data).then((r) => r.data);

export const deleteExtensionTemplate = (uuid: string) =>
  http.delete(`/api/templates/extension/${uuid}`).then((r) => r.data);

// ---- 密钥用途模板 ----
export const listKeyUsageTemplates = () =>
  http.get<KeyUsageTemplate[]>('/api/templates/key-usage').then((r) => r.data ?? []);

export const createKeyUsageTemplate = (data: Omit<KeyUsageTemplate, 'uuid' | 'created_at'>) =>
  http.post<KeyUsageTemplate>('/api/templates/key-usage', data).then((r) => r.data);

export const deleteKeyUsageTemplate = (uuid: string) =>
  http.delete(`/api/templates/key-usage/${uuid}`).then((r) => r.data);

// ---- 证书拓展模板 ----
export const listCertExtTemplates = () =>
  http.get<CertExtTemplate[]>('/api/templates/cert-ext').then((r) => r.data ?? []);

export const createCertExtTemplate = (data: Omit<CertExtTemplate, 'uuid' | 'created_at'>) =>
  http.post<CertExtTemplate>('/api/templates/cert-ext', data).then((r) => r.data);

export const deleteCertExtTemplate = (uuid: string) =>
  http.delete(`/api/templates/cert-ext/${uuid}`).then((r) => r.data);

// ---- 密钥存储类型模板 ----
export const listKeyStorageTemplates = () =>
  http.get<KeyStorageTemplate[]>('/api/templates/key-storage').then((r) => r.data ?? []);

export const createKeyStorageTemplate = (data: Omit<KeyStorageTemplate, 'uuid' | 'created_at'>) =>
  http.post<KeyStorageTemplate>('/api/templates/key-storage', data).then((r) => r.data);

export const updateKeyStorageTemplate = (uuid: string, data: Partial<KeyStorageTemplate>) =>
  http.put<KeyStorageTemplate>(`/api/templates/key-storage/${uuid}`, data).then((r) => r.data);

export const deleteKeyStorageTemplate = (uuid: string) =>
  http.delete(`/api/templates/key-storage/${uuid}`).then((r) => r.data);

// ---- 主体信息 ----
export const listSubjectInfos = (params?: { page?: number; page_size?: number }) =>
  http.get<PageResult<SubjectInfo>>('/api/subject-infos', { params }).then((r) => r.data);

export const createSubjectInfo = (data: { template_uuid: string; fields: Record<string, string> }) =>
  http.post<SubjectInfo>('/api/subject-infos', data).then((r) => r.data);

export const approveSubjectInfo = (uuid: string) =>
  http.post(`/api/subject-infos/${uuid}/approve`).then((r) => r.data);

export const rejectSubjectInfo = (uuid: string, reason: string) =>
  http.post(`/api/subject-infos/${uuid}/reject`, { reason }).then((r) => r.data);

export const deleteSubjectInfo = (uuid: string) =>
  http.delete(`/api/subject-infos/${uuid}`).then((r) => r.data);

// ---- 扩展信息 ----
export const listExtensionInfos = (params?: { page?: number; page_size?: number }) =>
  http.get<PageResult<ExtensionInfo>>('/api/extension-infos', { params }).then((r) => r.data);

export const createExtensionInfo = (data: { type: string; value: string }) =>
  http.post<ExtensionInfo>('/api/extension-infos', data).then((r) => r.data);

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
  http.get<PageResult<CertOrder>>('/api/cert-orders', { params }).then((r) => r.data);

// ---- 证书申请 ----
export const createCertApplication = (data: {
  order_uuid: string; subject_info_uuid: string;
  extension_info_uuids: string[]; key_type: string;
}) => http.post<CertApplication>('/api/cert-applications', data).then((r) => r.data);

export const listCertApplications = (params?: { page?: number; page_size?: number; status?: string }) =>
  http.get<PageResult<CertApplication>>('/api/cert-applications', { params }).then((r) => r.data);

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
  http.get<PageResult<PaymentOrder>>('/api/payment/orders', { params }).then((r) => r.data);

export const createRefund = (data: RefundRequest) =>
  http.post('/api/payment/refund', data).then((r) => r.data);

export const listPaymentPlugins = () =>
  http.get<PaymentPlugin[]>('/api/payment/plugins').then((r) => r.data ?? []);

export const createPaymentPlugin = (data: Omit<PaymentPlugin, 'uuid' | 'created_at'>) =>
  http.post<PaymentPlugin>('/api/payment/plugins', data).then((r) => r.data);

export const deletePaymentPlugin = (uuid: string) =>
  http.delete(`/api/payment/plugins/${uuid}`).then((r) => r.data);

export const approveRefund = (uuid: string) =>
  http.post(`/api/payment/refund/${uuid}/approve`).then((r) => r.data);

export const rejectRefund = (uuid: string) =>
  http.post(`/api/payment/refund/${uuid}/reject`).then((r) => r.data);

// ---- 存储区域 ----
export const listStorageZones = () =>
  http.get<StorageZone[]>('/api/storage-zones').then((r) => r.data ?? []);

export const createStorageZone = (data: Omit<StorageZone, 'uuid' | 'created_at'>) =>
  http.post<StorageZone>('/api/storage-zones', data).then((r) => r.data);

export const deleteStorageZone = (uuid: string) =>
  http.delete(`/api/storage-zones/${uuid}`).then((r) => r.data);

// ---- OID 管理 ----
export const listOIDs = () =>
  http.get<CustomOID[]>('/api/oids').then((r) => r.data ?? []);

export const createOID = (data: Omit<CustomOID, 'uuid' | 'created_at'>) =>
  http.post<CustomOID>('/api/oids', data).then((r) => r.data);

export const deleteOID = (uuid: string) =>
  http.delete(`/api/oids/${uuid}`).then((r) => r.data);

// ---- 吊销服务 ----
export const listRevocationServices = (caUUID?: string) =>
  http.get<RevocationService[]>('/api/revocation-services', { params: { ca_uuid: caUUID } }).then((r) => r.data ?? []);

export const createRevocationService = (data: Omit<RevocationService, 'uuid' | 'ca_name' | 'created_at'>) =>
  http.post<RevocationService>('/api/revocation-services', data).then((r) => r.data);

export const deleteRevocationService = (uuid: string) =>
  http.delete(`/api/revocation-services/${uuid}`).then((r) => r.data);

// ---- ACME 配置 ----
export const listACMEConfigs = () =>
  http.get<ACMEConfig[]>('/api/acme-configs').then((r) => r.data ?? []);

export const createACMEConfig = (data: Omit<ACMEConfig, 'uuid' | 'ca_name' | 'template_name' | 'created_at'>) =>
  http.post<ACMEConfig>('/api/acme-configs', data).then((r) => r.data);

export const deleteACMEConfig = (uuid: string) =>
  http.delete(`/api/acme-configs/${uuid}`).then((r) => r.data);

// ---- CT 记录 ----
export const listCTEntries = (params?: { cert_hash?: string; cert_uuid?: string; page?: number; page_size?: number }) =>
  http.get<PageResult<CTEntry>>('/api/ct-entries', { params }).then((r) => r.data);

export const deleteCTEntry = (uuid: string) =>
  http.delete(`/api/ct-entries/${uuid}`).then((r) => r.data);

// ---- 云端 TOTP ----
export const listCloudTOTPs = () =>
  http.get<CloudTOTPEntry[]>('/api/cloud-totp').then((r) => r.data ?? []);

export const createCloudTOTP = (data: Omit<CloudTOTPEntry, 'uuid' | 'created_at'> & { secret: string }) =>
  http.post<CloudTOTPEntry>('/api/cloud-totp', data).then((r) => r.data);

export const getCloudTOTPCode = (uuid: string) =>
  http.get<TOTPCodeResponse>(`/api/cloud-totp/${uuid}/code`).then((r) => r.data);

export const deleteCloudTOTP = (uuid: string) =>
  http.delete(`/api/cloud-totp/${uuid}`).then((r) => r.data);

// ---- 日志 ----
export const getLogs = (params?: { user_uuid?: string; level?: string; page?: number; page_size?: number }) =>
  http.get<PageResult<Log>>('/api/logs', { params }).then((r) => r.data);

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

