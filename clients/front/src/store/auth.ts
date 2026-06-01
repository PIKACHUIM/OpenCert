// 多账号会话 Store。
// 设计：
//   - accounts: 已登录过的账号列表（持久化到 localStorage，key=auth_accounts_v2）
//   - activeUUID: 当前活跃账号的 user_uuid；activeUUID=null 视为"未登录"
//   - 请求拦截器从 getActiveToken() 拿 token（同步、零延迟）
// 兼容：首次加载时会把旧版 auth_token/auth_user_uuid/... 自动迁移为一个 AccountSession。
import { create } from 'zustand';
import type { AccountSession, AuthToken } from '../types';

const LS_KEY = 'auth_accounts_v2';
const LS_ACTIVE = 'auth_active_uuid';

interface AuthState {
  accounts: AccountSession[];
  activeUUID: string | null;
  /** 是否已完成初始化（包括旧版迁移）。用于避免 PrivateRoute 在 hydrate 前误判未登录。 */
  hydrated: boolean;

  // ---- selectors ----
  getActive: () => AccountSession | null;
  isAuthenticated: () => boolean;

  // ---- mutations ----
  addAccount: (acc: AuthToken, opts?: { userType?: 'local' | 'cloud'; cloudUrl?: string; cloudUser?: string; expiresAt?: string; savedPassword?: string }) => void;
  removeAccount: (uuid: string) => void;
  setActive: (uuid: string | null) => void;
  /** 退出当前账号：只清 token/activeUUID，保留账号记录（下次可快速重新登录） */
  deactivate: (uuid: string) => void;
  clearAll: () => void;
  /** 更新活动账号的 token（刷新场景） */
  setActiveToken: (token: string) => void;
  touchActive: () => void;
}

function loadAccounts(): AccountSession[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) return arr;
    }
  } catch {
    // ignore parse error
  }
  // 迁移旧版单账号数据
  const oldToken = localStorage.getItem('auth_token');
  const oldUUID = localStorage.getItem('auth_user_uuid');
  const oldUser = localStorage.getItem('auth_username');
  const oldRole = localStorage.getItem('auth_role') as AccountSession['role'];
  if (oldToken && oldUUID && oldUser && oldRole) {
    const now = new Date().toISOString();
    return [
      {
        token: oldToken,
        user_uuid: oldUUID,
        username: oldUser,
        role: oldRole,
        user_type: 'local',
        display_name: oldUser,
        added_at: now,
        last_active_at: now,
      },
    ];
  }
  return [];
}

function saveAccounts(accs: AccountSession[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(accs));
}

function loadActive(fallback: AccountSession[]): string | null {
  const raw = localStorage.getItem(LS_ACTIVE);
  if (raw && fallback.some((a) => a.user_uuid === raw)) return raw;
  return fallback[0]?.user_uuid ?? null;
}

const initial = (() => {
  const accounts = loadAccounts();
  const activeUUID = loadActive(accounts);
  // 首次迁移完成后把旧版 token 回写为活动账号的 token，保持已注册拦截器的兼容
  const active = accounts.find((a) => a.user_uuid === activeUUID);
  if (active) localStorage.setItem('auth_token', active.token);
  else localStorage.removeItem('auth_token');
  if (activeUUID) localStorage.setItem(LS_ACTIVE, activeUUID);
  return { accounts, activeUUID, hydrated: true };
})();

export const useAuthStore = create<AuthState>((set, get) => ({
  ...initial,

  getActive: () => {
    const { accounts, activeUUID } = get();
    return accounts.find((a) => a.user_uuid === activeUUID) ?? null;
  },

  isAuthenticated: () => get().getActive() !== null,

  addAccount: (auth, opts) => {
    const now = new Date().toISOString();
    const userType = opts?.userType ?? 'local';
    const display = opts?.cloudUser || auth.username;
    const next: AccountSession = {
      token: auth.token,
      user_uuid: auth.user_uuid,
      username: auth.username,
      role: auth.role,
      user_type: userType,
      cloud_url: opts?.cloudUrl,
      cloud_user: opts?.cloudUser,
      expires_at: opts?.expiresAt,
      display_name: display,
      added_at: now,
      last_active_at: now,
      saved_password: opts?.savedPassword,
    };
    set((s) => {
      const others = s.accounts.filter((a) => a.user_uuid !== next.user_uuid);
      const accounts = [next, ...others];
      saveAccounts(accounts);
      localStorage.setItem('auth_token', next.token);
      localStorage.setItem(LS_ACTIVE, next.user_uuid);
      return { accounts, activeUUID: next.user_uuid };
    });
  },

  removeAccount: (uuid) => {
    set((s) => {
      const accounts = s.accounts.filter((a) => a.user_uuid !== uuid);
      saveAccounts(accounts);
      let activeUUID = s.activeUUID;
      if (activeUUID === uuid) {
        activeUUID = accounts[0]?.user_uuid ?? null;
        if (activeUUID) {
          localStorage.setItem(LS_ACTIVE, activeUUID);
          const active = accounts.find((a) => a.user_uuid === activeUUID)!;
          localStorage.setItem('auth_token', active.token);
        } else {
          localStorage.removeItem(LS_ACTIVE);
          localStorage.removeItem('auth_token');
        }
      }
      return { accounts, activeUUID };
    });
  },

  setActive: (uuid) => {
    set((s) => {
      if (!uuid) {
        localStorage.removeItem(LS_ACTIVE);
        localStorage.removeItem('auth_token');
        return { activeUUID: null };
      }
      const acc = s.accounts.find((a) => a.user_uuid === uuid);
      if (!acc) return {};
      localStorage.setItem(LS_ACTIVE, uuid);
      localStorage.setItem('auth_token', acc.token);
      return { activeUUID: uuid };
    });
  },

  deactivate: (uuid) => {
    set((s) => {
      if (s.activeUUID !== uuid) return {};
      localStorage.removeItem('auth_token');
      localStorage.removeItem(LS_ACTIVE);
      return { activeUUID: null };
    });
  },

  clearAll: () => {
    localStorage.removeItem(LS_KEY);
    localStorage.removeItem(LS_ACTIVE);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_user_uuid');
    localStorage.removeItem('auth_username');
    localStorage.removeItem('auth_role');
    set({ accounts: [], activeUUID: null });
  },

  setActiveToken: (token) => {
    set((s) => {
      if (!s.activeUUID) return {};
      const accounts = s.accounts.map((a) =>
        a.user_uuid === s.activeUUID ? { ...a, token, last_active_at: new Date().toISOString() } : a
      );
      saveAccounts(accounts);
      localStorage.setItem('auth_token', token);
      return { accounts };
    });
  },

  touchActive: () => {
    set((s) => {
      if (!s.activeUUID) return {};
      const now = new Date().toISOString();
      const accounts = s.accounts.map((a) =>
        a.user_uuid === s.activeUUID ? { ...a, last_active_at: now } : a
      );
      saveAccounts(accounts);
      return { accounts };
    });
  },
}));

/** 兼容旧 API：返回当前活动账号（若无则为 null）的扁平 AuthToken */
export function useActiveAuth() {
  const active = useAuthStore((s) => s.getActive());
  return active;
}