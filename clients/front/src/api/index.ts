import axios from 'axios';
import type {
  User, Card, Certificate, Log, SlotInfo,
  CreateUserRequest, CreateCardRequest, KeyGenRequest,
  TOTPEntry, TOTPCodeResponse, CreateTOTPRequest,
  LocalCA, SelfSignRequest, CSRRequest, CSRResponse,
  CreateCSRRequest, CSRRecord, CreateCARequest, ImportCARequest,
  PKICert, IssueCertRequest, ImportCertRequest, ExportCertFormat,
  LoginRequest, AuthToken, SecurityLevel,
} from '../types';

// Manager 连接 client-card :1026
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:1026';

const http = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// 请求拦截器：自动注入 Authorization 头
http.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截器：统一错误处理，并提取 {code, message, data} 包装格式中的 data
http.interceptors.response.use(
  (res) => {
    // 后端统一返回 { code, message, data } 格式，提取 data 字段
    if (res.data && typeof res.data === 'object' && 'code' in res.data) {
      if (res.data.code !== 0) {
        return Promise.reject(new Error(res.data.message || '请求失败'));
      }
      res.data = res.data.data;
    }
    return res;
  },
  (err) => {
    // 401 未授权：区分 Token 过期与业务验证失败
    if (err.response?.status === 401) {
      const msg = err.response?.data?.message || '';
      // 仅当 Token/Authorization 相关的 401 才清除登录态并跳转
      const isTokenExpired = /Token|Authorization|登录已过期|未登录/.test(msg);
      if (isTokenExpired) {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user_uuid');
        localStorage.removeItem('auth_username');
        localStorage.removeItem('auth_role');
        // 避免在登录页重复跳转
        if (!window.location.pathname.startsWith('/login')) {
          window.location.href = '/login';
        }
        return Promise.reject(new Error('登录已过期，请重新登录'));
      }
      // 业务验证失败（如密码错误、AdminKey 错误等），仅提示错误
      return Promise.reject(new Error(msg || '身份验证失败'));
    }
    const msg = err.response?.data?.message || err.message || '请求失败';
    return Promise.reject(new Error(msg));
  }
);

// ---- 认证 ----
export const login = (data: LoginRequest) =>
  http.post<AuthToken>('/api/auth/login', data).then((r) => r.data);

export const register = (data: { username: string; password: string; display_name: string; email?: string }) =>
  http.post<AuthToken>('/api/auth/register', data).then((r) => r.data);

export const cloudLogin = (data: { cloud_url: string; username: string; password: string }) =>
  http.post<AuthToken & { user_type: 'cloud'; cloud_url: string; cloud_user: string; expires_at: string }>(
    '/api/auth/cloud-login',
    data
  ).then((r) => r.data);

export const logout = () =>
  http.delete('/api/auth/logout').then((r) => r.data).catch(() => undefined);

export const logoutAll = () =>
  http.delete('/api/auth/logout-all').then((r) => r.data).catch(() => undefined);

// ---- Settings ----
export const getSettings = () =>
  http.get<import('../types').ClientSettings>('/api/settings').then((r) => r.data);

export const putSettings = (data: Partial<import('../types').ClientSettings>) =>
  http.put<import('../types').ClientSettings>('/api/settings', data).then((r) => r.data);

// ---- 健康检查 ----
export const getHealth = () =>
  http.get<{ status: string; version: string }>('/api/health').then((r) => r.data);

// ---- Slot 状态 ----
export const getSlots = () =>
  http.get<SlotInfo[]>('/api/slots').then((r) => r.data);

// ---- 用户管理（本地用户） ----
export const getUsers = (params?: { page?: number; page_size?: number }) =>
  http.get<User[]>('/api/users', { params }).then((r) => {
    const data = r.data;
    const items = Array.isArray(data) ? data : [];
    return { items, total: items.length };
  });

export const getUser = (uuid: string) =>
  http.get<User>(`/api/users/${uuid}`).then((r) => r.data);

export const createUser = (data: CreateUserRequest) =>
  http.post<User>('/api/users', data).then((r) => r.data);

export const updateUser = (uuid: string, data: Partial<CreateUserRequest & { enabled: boolean }>) =>
  http.put<User>(`/api/users/${uuid}`, data).then((r) => r.data);

export const deleteUser = (uuid: string) =>
  http.delete(`/api/users/${uuid}`).then((r) => r.data);

// ---- 卡片管理 ----
export const getCards = (params?: { user_uuid?: string; page?: number; page_size?: number }) =>
  http.get<Card[]>('/api/cards', { params }).then((r) => {
    const data = r.data;
    const items = Array.isArray(data) ? data : [];
    return { items, total: items.length };
  });

export const getCard = (uuid: string) =>
  http.get<Card>(`/api/cards/${uuid}`).then((r) => r.data);

export const createCard = (data: CreateCardRequest) =>
  http.post<Card>('/api/cards', data, { timeout: 120000 }).then((r) => r.data);

export const updateCard = (uuid: string, data: Partial<Card>) =>
  http.put<Card>(`/api/cards/${uuid}`, data).then((r) => r.data);

export const deleteCard = (uuid: string, data: { user_uuid: string; user_password: string }) =>
  http.delete(`/api/cards/${uuid}`, { data }).then((r) => r.data);

// ---- 证书管理 ----
export const getCerts = (cardUUID: string) =>
  http.get<Certificate[]>(`/api/cards/${cardUUID}/certs`).then((r) => {
    const data = r.data;
    return Array.isArray(data) ? data : [];
  });

export const getCert = (cardUUID: string, certUUID: string) =>
  http.get<Certificate>(`/api/cards/${cardUUID}/certs/${certUUID}`).then((r) => r.data);

export const deleteCert = (cardUUID: string, certUUID: string) =>
  http.delete(`/api/cards/${cardUUID}/certs/${certUUID}`).then((r) => r.data);

export const generateKey = (cardUUID: string, data: KeyGenRequest) =>
  http.post<Certificate>(`/api/cards/${cardUUID}/keygen`, data).then((r) => r.data);

export const exportCert = (cardUUID: string, certUUID: string, format: string) =>
  http.get(`/api/cards/${cardUUID}/certs/${certUUID}/export`, {
    params: { format },
    responseType: 'blob',
  }).then((r) => r.data);

// ---- 通用安全凭据（FIDO/Login/Note/Payment/Text）----
// 与证书共用 Certificate 表，但通过 cert_type 区分类型；
// public_meta/secret_data 均为 base64，secret_data 非空时需要 card_password。
export interface CredentialPayload {
  cert_type: 'fido' | 'login' | 'note' | 'payment' | 'text';
  key_type?: string;
  public_meta?: string;   // base64
  secret_data?: string;   // base64
  card_password?: string;
  remark?: string;
}
export const createCredential = (cardUUID: string, data: CredentialPayload) =>
  http.post<Certificate>(`/api/cards/${cardUUID}/credentials`, data).then((r) => r.data);

// ---- 日志查询 ----
export const getLogs = (params?: {
  card_uuid?: string;
  user_uuid?: string;
  level?: string;
  page?: number;
  page_size?: number;
}) => http.get<Log[]>('/api/logs', { params }).then((r) => {
    const data = r.data;
    const items = Array.isArray(data) ? data : [];
    return { items, total: items.length };
  });

// ---- TOTP 管理（本地卡片内） ----
export const getTOTPList = (cardUUID: string) =>
  http.get<TOTPEntry[]>(`/api/cards/${cardUUID}/totp`).then((r) => {
    const data = r.data;
    return Array.isArray(data) ? data : [];
  });

export const getTOTPCode = (uuid: string) =>
  http.get<TOTPCodeResponse>(`/api/totp/${uuid}/code`).then((r) => r.data);

export const createTOTP = (data: CreateTOTPRequest) =>
  http.post<TOTPEntry>(`/api/cards/${data.card_uuid}/totp`, data).then((r) => r.data);

export const deleteTOTP = (uuid: string) =>
  http.delete(`/api/totp/${uuid}`).then((r) => r.data);

// ---- 本地 PKI - 自签名 ----
export const generateSelfSigned = (data: SelfSignRequest) =>
  http.post<Certificate>('/api/pki/selfsign', data).then((r) => r.data);

// ---- 本地 PKI - CSR 管理 ----
export const getCSRList = (params?: { page?: number; page_size?: number }) =>
  http.get<{ items: CSRRecord[]; total: number }>('/api/pki/csr', { params })
    .then((r) => ({ items: r.data?.items ?? [], total: r.data?.total ?? 0 }));

export const createCSR = (data: CreateCSRRequest) =>
  http.post<CSRRecord>('/api/pki/csr', data).then((r) => r.data);

export const getCSR = (uuid: string) =>
  http.get<CSRRecord>(`/api/pki/csr/${uuid}`).then((r) => r.data);

export const deleteCSR = (uuid: string) =>
  http.delete(`/api/pki/csr/${uuid}`).then((r) => r.data);

export const downloadCSRFile = (uuid: string, filename: string) => {
  return http.get(`/api/pki/csr/${uuid}/download`, { responseType: 'blob' })
    .then((r) => {
      const url = URL.createObjectURL(r.data);
      const a = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    });
};

// ---- 本地 PKI - CA 管理 ----
export const getLocalCAs = (params?: { page?: number; page_size?: number }) =>
  http.get<{ items: LocalCA[]; total: number }>('/api/pki/ca', { params })
    .then((r) => ({ items: r.data?.items ?? [], total: r.data?.total ?? 0 }));

export const createLocalCA = (data: CreateCARequest) =>
  http.post<LocalCA>('/api/pki/ca', data).then((r) => r.data);

export const importLocalCA = (data: ImportCARequest) =>
  http.post<LocalCA>('/api/pki/ca/import', data).then((r) => r.data);

export const getLocalCA = (uuid: string) =>
  http.get<LocalCA>(`/api/pki/ca/${uuid}`).then((r) => r.data);

export const revokeLocalCA = (uuid: string) =>
  http.post(`/api/pki/ca/${uuid}/revoke`).then((r) => r.data);

export const deleteLocalCA = (uuid: string) =>
  http.delete(`/api/pki/ca/${uuid}`).then((r) => r.data);

export const exportLocalCA = (uuid: string, format: 'pem' | 'chain', name: string) => {
  return http.get(`/api/pki/ca/${uuid}/export`, { params: { format }, responseType: 'blob' })
    .then((r) => {
      const url = URL.createObjectURL(r.data);
      const a = document.createElement('a');
      a.href = url; a.download = `${name}_${format}.pem`; a.click();
      URL.revokeObjectURL(url);
    });
};

// ---- 本地 PKI - 证书管理 ----
export const getPKICerts = (params?: { page?: number; page_size?: number }) =>
  http.get<{ items: PKICert[]; total: number }>('/api/pki/certs', { params })
    .then((r) => ({ items: r.data?.items ?? [], total: r.data?.total ?? 0 }));

export const issuePKICert = (data: IssueCertRequest) =>
  http.post<PKICert>('/api/pki/certs/issue', data).then((r) => r.data);

export const selfSignFromCSR = (csrUUID: string, validityDays: number, remark?: string, notBefore?: string, notAfter?: string, cardPassword?: string, extensions?: import('../types').CertExtensions) =>
  http.post<PKICert>('/api/pki/certs/selfsign', {
    csr_uuid: csrUUID,
    validity_days: validityDays,
    not_before: notBefore,
    not_after: notAfter,
    remark,
    card_password: cardPassword,
    extensions,
  }).then((r) => r.data);

export const importPKICert = (data: ImportCertRequest) =>
  http.post<{ cert: PKICert; key_matched: boolean }>('/api/pki/certs/import', data).then((r) => r.data);

export const getPKICert = (uuid: string) =>
  http.get<PKICert>(`/api/pki/certs/${uuid}`).then((r) => r.data);

export const deletePKICert = (uuid: string) =>
  http.delete(`/api/pki/certs/${uuid}`).then((r) => r.data);

export const deletePKICertKey = (uuid: string) =>
  http.delete(`/api/pki/certs/${uuid}/key`).then((r) => r.data);

export const exportPKICert = (uuid: string, format: ExportCertFormat, password: string | undefined, filename: string) => {
  return http.post(`/api/pki/certs/${uuid}/export`, { format, password }, { responseType: 'blob' })
    .then((r) => {
      const url = URL.createObjectURL(r.data);
      const a = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    });
};

export const importPKICertToCard = (uuid: string, cardUUID: string) =>
  http.post(`/api/pki/certs/${uuid}/import-to-card`, { card_uuid: cardUUID }).then((r) => r.data);

export const revokePKICert = (uuid: string) =>
  http.post(`/api/pki/certs/${uuid}/revoke`).then((r) => r.data);

// ---- 卡片 PIN/PUK/AdminKey 重置 ----
export const resetCardPIN = (cardUUID: string, data: { puk?: string; admin_key?: string; new_pin: string }) =>
  http.post(`/api/cards/${cardUUID}/reset-pin`, data).then((r) => r.data);

export const resetCardPUK = (cardUUID: string, data: { admin_key: string; current_pin: string; new_puk: string }) =>
  http.post(`/api/cards/${cardUUID}/reset-puk`, data).then((r) => r.data);

// ---- 智能卡导出/恢复 ----
export const exportCard = (cardUUID: string, data: { user_uuid: string; user_password: string; password?: string; admin_key?: string }) =>
  http.post(`/api/cards/${cardUUID}/export`, data, { responseType: 'blob' }).then((r) => r.data);

export const exportCardDownload = (cardUUID: string, data: { user_uuid: string; user_password: string; password?: string; admin_key?: string }, filename?: string) =>
  http.post(`/api/cards/${cardUUID}/export`, data, { responseType: 'blob' })
    .then((r) => {
      const url = URL.createObjectURL(r.data);
      const a = document.createElement('a');
      a.href = url; a.download = filename || `card-${cardUUID}.ocs`; a.click();
      URL.revokeObjectURL(url);
    });

export const restoreCard = (data: { ocs_data: string; password: string; user_uuid: string; user_password: string }) =>
  http.post<Card>('/api/cards/restore', data).then((r) => r.data);

// ---- 证书密钥导出 ----
export const exportCertKey = (cardUUID: string, certUUID: string, data: { password?: string; admin_key?: string; format: string; pfx_password?: string }) =>
  http.post<{ format: string; private_key?: string; certificate?: string; pfx_data?: string }>(`/api/cards/${cardUUID}/certs/${certUUID}/export`, data).then((r) => r.data);

// ---- 证书+密钥导入（到卡片） ----
export const importCertWithKey = (cardUUID: string, data: {
  mode: 'pem' | 'pfx';
  cert_pem?: string;
  key_pem?: string;
  pfx_b64?: string;
  pfx_password?: string;
  card_password: string;
  remark?: string;
}) => http.post<{ cert_uuid: string }>(`/api/cards/${cardUUID}/certs/import`, data).then((r) => r.data);

// ---- 证书详情解析 ----
export const getCertDetail = (cardUUID: string, certUUID: string) =>
  http.get<import('../types').CertDetail>(`/api/cards/${cardUUID}/certs/${certUUID}/detail`).then((r) => r.data);

// ---- 云端同步与下发 ----
export const cloudSync = () =>
  http.post('/api/cloud/sync').then((r) => r.data);

export const cloudStatus = () =>
  http.get('/api/cloud/status').then((r) => r.data);

export const deliverCert = (data: {
  cert_uuid: string;
  source_cloud_url?: string;
  source_card_uuid?: string;
  target: 'database' | 'card';
  target_card_uuid?: string;
  card_password?: string;
  remark?: string;
}) => http.post('/api/cloud/deliver', data).then((r) => r.data);

// ---- 旧版兼容 ----
export const generateCSR = (data: CSRRequest) =>
  http.post<CSRResponse>('/api/pki/csr', data).then((r) => r.data);

export const importCert = (formData: FormData) =>
  http.post('/api/pki/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }).then((r) => r.data);