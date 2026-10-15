import { theme as antdTheme } from 'antd';
import type { ThemeConfig } from 'antd';

/**
 * 全局设计令牌。
 *
 * 视觉基准来自门户官网（PortalLayout / Home）：
 *   - 主品牌色   #1d4ed8（深蓝）
 *   - 辅助强调色 #0891b2 / #38bdf8（青）
 *   - 深色区块   #0b1220
 *   - 浅色底     #f7f9fc，卡片边框 #e6ebf2
 *
 * 注意：`index.css` 中的 CSS 变量是本文件的镜像（供纯 CSS 类使用），
 * 修改色值时必须两处同步，避免主题漂移。
 */

/** 中文技术界面统一字体栈（与门户一致，避免引入外部字体依赖）。 */
export const FONT_STACK =
  "'PingFang SC', 'Microsoft YaHei', 'Segoe UI', system-ui, -apple-system, sans-serif";

export interface Palette {
  brand: string;
  brandStrong: string;
  brandSoft: string;
  brandBorder: string;
  cyan: string;
  cyanSoft: string;
  pageBg: string;
  cardBg: string;
  cardBgSubtle: string;
  border: string;
  borderSoft: string;
  textPrimary: string;
  textSecondary: string;
  textTertiary: string;
  shadowCard: string;
  shadowLift: string;
  siderBg: string;
  headerBg: string;
  success: string;
  warning: string;
  danger: string;
}

export const lightPalette: Palette = {
  brand: '#1d4ed8',
  brandStrong: '#1e40af',
  brandSoft: '#eff4ff',
  brandBorder: '#dbe6ff',
  cyan: '#0891b2',
  cyanSoft: '#ecfeff',
  pageBg: '#f7f9fc',
  cardBg: '#ffffff',
  cardBgSubtle: '#f8fafc',
  border: '#e6ebf2',
  borderSoft: '#eef2f7',
  textPrimary: '#0f172a',
  textSecondary: '#5b6472',
  textTertiary: '#94a3b8',
  shadowCard: '0 1px 2px rgba(15,23,42,0.04), 0 16px 40px -30px rgba(15,23,42,0.30)',
  shadowLift: '0 2px 6px rgba(15,23,42,0.06), 0 26px 52px -26px rgba(15,23,42,0.35)',
  siderBg: '#0b1220',
  headerBg: 'rgba(255,255,255,0.88)',
  success: '#16a34a',
  warning: '#d97706',
  danger: '#dc2626',
};

export const darkPalette: Palette = {
  brand: '#3b82f6',
  brandStrong: '#60a5fa',
  brandSoft: 'rgba(59,130,246,0.16)',
  brandBorder: 'rgba(59,130,246,0.34)',
  cyan: '#38bdf8',
  cyanSoft: 'rgba(56,189,248,0.14)',
  pageBg: '#0b1220',
  cardBg: '#111a2b',
  cardBgSubtle: '#0e1626',
  border: 'rgba(148,163,184,0.16)',
  borderSoft: 'rgba(148,163,184,0.10)',
  textPrimary: '#e6edf3',
  textSecondary: '#94a3b8',
  textTertiary: '#64748b',
  shadowCard: '0 1px 2px rgba(2,6,16,0.5), 0 20px 48px -30px rgba(2,6,16,0.9)',
  shadowLift: '0 4px 10px rgba(2,6,16,0.5), 0 30px 60px -30px rgba(2,6,16,0.95)',
  siderBg: '#0a101d',
  headerBg: 'rgba(11,18,32,0.9)',
  success: '#34d399',
  warning: '#fbbf24',
  danger: '#f87171',
};

export const getPalette = (dark: boolean): Palette => (dark ? darkPalette : lightPalette);

/** 构建 antd 主题配置：登录页与控制台共用同一套令牌。 */
export const buildAntdTheme = (dark: boolean): ThemeConfig => {
  const p = getPalette(dark);
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: p.brand,
      colorInfo: p.brand,
      colorSuccess: p.success,
      colorWarning: p.warning,
      colorError: p.danger,
      colorBgLayout: p.pageBg,
      colorBgContainer: p.cardBg,
      colorBgElevated: dark ? '#152036' : '#ffffff',
      colorBorder: p.border,
      colorBorderSecondary: p.borderSoft,
      colorText: p.textPrimary,
      colorTextSecondary: p.textSecondary,
      colorTextTertiary: p.textTertiary,
      borderRadius: 10,
      fontFamily: FONT_STACK,
      boxShadowTertiary: p.shadowCard,
    },
    components: {
      Layout: {
        siderBg: p.siderBg,
        headerBg: p.headerBg,
        bodyBg: p.pageBg,
      },
      Menu: {
        itemBorderRadius: 10,
        itemMarginInline: 8,
        itemHeight: 38,
        darkItemBg: 'transparent',
        darkSubMenuItemBg: 'transparent',
        darkItemColor: 'rgba(203,213,225,0.75)',
        darkItemHoverBg: 'rgba(148,163,184,0.12)',
        darkItemSelectedBg: 'rgba(59,130,246,0.22)',
        darkItemSelectedColor: '#ffffff',
      },
      Card: { borderRadiusLG: 16 },
      Button: { fontWeight: 600, controlHeightLG: 44 },
      Input: { controlHeightLG: 46, borderRadiusLG: 12 },
      Table: {
        headerBg: dark ? '#0f1728' : '#f8fafc',
        headerColor: p.textSecondary,
        rowHoverBg: dark ? 'rgba(148,163,184,0.07)' : '#f8fafc',
        borderColor: p.borderSoft,
      },
      Tag: { borderRadiusSM: 6 },
      Dropdown: { borderRadiusLG: 12 },
      Tooltip: { borderRadius: 8 },
    },
  };
};
