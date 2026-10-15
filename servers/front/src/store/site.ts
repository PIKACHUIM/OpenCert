import { create } from 'zustand';
import type { SiteSettings } from '../types';
import { getSiteInfo } from '../api';

/** 站点配置默认值：接口不可用时仍能正常渲染页脚与品牌信息。 */
const DEFAULTS: SiteSettings = {
  site_name: 'OpenCert',
  site_tagline: '云端证书与智能卡服务平台',
  site_description: '统一申请、签发与管理数字证书，并通过云端智能卡在设备上安全使用。',
  contact_email: '',
  contact_phone: '',
  icp_record: '',
  footer_note: '',
  help_url: '',
  client_download: '',
  driver_download: '',
  terms_url: '',
  privacy_url: '',
};

interface SiteState {
  settings: SiteSettings;
  loaded: boolean;
  loading: boolean;
  load: () => Promise<void>;
}

export const useSiteStore = create<SiteState>((set, get) => ({
  settings: DEFAULTS,
  loaded: false,
  loading: false,

  load: async () => {
    // 已加载或正在加载时不重复请求
    if (get().loaded || get().loading) return;
    set({ loading: true });
    try {
      const data = await getSiteInfo();
      set({ settings: { ...DEFAULTS, ...data }, loaded: true, loading: false });
    } catch {
      // 站点配置获取失败不阻断门户渲染
      set({ loaded: true, loading: false });
    }
  },
}));
