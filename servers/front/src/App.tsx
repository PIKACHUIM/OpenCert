import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, Spin } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { useThemeStore } from './store/theme';
import { buildAntdTheme } from './theme/tokens';
import MainLayout from './layouts/MainLayout';
import PortalLayout from './layouts/PortalLayout';
import ErrorBoundary from './components/ErrorBoundary';
import PrivateRoute from './components/PrivateRoute';

// ---- 门户（官网）页面 ----
const Home = lazy(() => import('./pages/Home'));
const PortalProducts = lazy(() => import('./pages/portal/Products'));
const PortalProductDetail = lazy(() => import('./pages/portal/ProductDetail'));
const PortalBuy = lazy(() => import('./pages/portal/Buy'));
const PortalCheckout = lazy(() => import('./pages/portal/Checkout'));
const PortalTrust = lazy(() => import('./pages/portal/Trust'));
const PortalDownloads = lazy(() => import('./pages/portal/Downloads'));

// ---- 认证页面 ----
const Login = lazy(() => import('./pages/Login'));

// ---- 控制台页面（懒加载） ----
const Dashboard = lazy(() => import('./pages/Dashboard'));
const CA = lazy(() => import('./pages/CA'));
const Templates = lazy(() => import('./pages/Templates'));
const Certs = lazy(() => import('./pages/Certs'));
const Users = lazy(() => import('./pages/Users'));
const CertOrders = lazy(() => import('./pages/CertOrders'));
const AuditLogs = lazy(() => import('./pages/AuditLogs'));
const CertApplyTemplates = lazy(() => import('./pages/CertApplyTemplates'));
const Settings = lazy(() => import('./pages/Settings'));
const Logs = lazy(() => import('./pages/Logs'));
const Profile = lazy(() => import('./pages/Profile'));

const Cards = lazy(() => import('./pages/Cards'));
const AllCerts = lazy(() => import('./pages/AllCerts'));
const SubjectInfos = lazy(() => import('./pages/SubjectInfos'));
const ExtensionInfos = lazy(() => import('./pages/ExtensionInfos'));
const CloudTOTP = lazy(() => import('./pages/CloudTOTP'));
const KeyStorageTemplates = lazy(() => import('./pages/KeyStorageTemplates'));
const StorageZones = lazy(() => import('./pages/StorageZones'));
const RevocationServices = lazy(() => import('./pages/RevocationServices'));
const ACMEConfigs = lazy(() => import('./pages/ACMEConfigs'));
const CertApplications = lazy(() => import('./pages/CertApplications'));
const PaymentPlugins = lazy(() => import('./pages/PaymentPlugins'));

// ---- 控制台：新模块（订单管理、订阅优惠、身份审核、OCSP、策略、申请向导） ----
const AdminOrders = lazy(() => import('./pages/AdminOrders'));
const Promo = lazy(() => import('./pages/Promo'));
const IdentityReviews = lazy(() => import('./pages/IdentityReviews'));
const OCSPResponders = lazy(() => import('./pages/OCSPResponders'));
const CertPolicies = lazy(() => import('./pages/CertPolicies'));
const ApplyWizard = lazy(() => import('./pages/Apply'));
const MyApplications = lazy(() => import('./pages/MyApplications'));
const Help = lazy(() => import('./pages/Help'));

// ---- 控制台：商品与站点配置 ----
const ConsoleProducts = lazy(() => import('./pages/console/Products'));
const ConsoleSiteSettings = lazy(() => import('./pages/console/SiteSettings'));

/**
 * 历史控制台路径：旧链接、浏览器收藏与邮件中的地址统一重定向到 /console 下，
 * 避免一次路由分层改动导致已有入口失效。
 */
const LEGACY_CONSOLE_PATHS = [
  'dashboard', 'cards', 'certs', 'subject-infos', 'extension-infos', 'cert-orders',
  'cloud-totp', 'profile', 'ca', 'all-certs', 'templates', 'key-storage-templates',
  'cert-apply-templates', 'cert-applications', 'users', 'audit-logs',
  'storage-zones', 'revocation-services', 'acme-configs', 'payment-plugins', 'logs', 'settings',
  'admin-orders', 'promo', 'identity-reviews', 'ocsp-responders', 'cert-policies', 'apply', 'apply-records',
  'help',
];

/**
 * 页面合并后的历史路径跳转：
 *   - 身份认证管理 → 主体/扩展信息（认证与审核已并入证书颁发 → 身份认证审核）
 *   - 财务支付管理 → 账号信息管理（余额、充值、订阅与兑换）
 *   - 证书 OIDS 管理 → 证书颁发模板（OID 选项卡）
 *   - 证书透明度 CT → 证书审计日志（CT 选项卡）
 */
const MERGED_CONSOLE_PATHS: Record<string, string> = {
  '/console/identity': '/console/subject-infos',
  '/console/payment': '/console/profile',
  '/console/oids': '/console/templates?tab=oids',
  '/console/ct-records': '/console/audit-logs?tab=ct',
};

const PageLoader = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '60vh' }}>
    <Spin size="large" />
  </div>
);

const S = ({ children }: { children: React.ReactNode }) => (
  <Suspense fallback={<PageLoader />}>{children}</Suspense>
);

const App: React.FC = () => {
  const { darkMode, themeMode, setThemeMode } = useThemeStore();

  // 监听系统主题变化
  useEffect(() => {
    if (themeMode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => setThemeMode('system');
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [themeMode, setThemeMode]);

  // 将当前主题同步到 <html data-theme>，供全局 CSS 变量（滚动条、卡片、表单）使用
  useEffect(() => {
    document.documentElement.dataset.theme = darkMode ? 'dark' : 'light';
  }, [darkMode]);

  return (
    <ConfigProvider locale={zhCN} theme={buildAntdTheme(darkMode)}>
      <ErrorBoundary>
        <BrowserRouter>
          <Routes>
            {/* ---- 门户官网（/） ---- */}
            <Route element={<PortalLayout />}>
              <Route path="/" element={<S><Home /></S>} />
              <Route path="/products" element={<S><PortalProducts /></S>} />
              <Route path="/products/:category" element={<S><PortalProducts /></S>} />
              <Route path="/products/:category/:code" element={<S><PortalProductDetail /></S>} />
              <Route path="/buy/:skuCode" element={<S><PortalBuy /></S>} />
              <Route path="/checkout/:orderNo" element={<S><PortalCheckout /></S>} />
              <Route path="/trust" element={<S><PortalTrust /></S>} />
              <Route path="/downloads" element={<S><PortalDownloads /></S>} />
            </Route>

            {/* ---- 认证（登录页内含注册与找回密码） ---- */}
            <Route path="/login" element={<S><Login /></S>} />
            <Route path="/register" element={<S><Login /></S>} />
            <Route path="/forgot-password" element={<S><Login /></S>} />

            {/* ---- 控制台（/console） ---- */}
            <Route element={<PrivateRoute><MainLayout /></PrivateRoute>}>
              <Route path="/console" element={<Navigate to="/console/dashboard" replace />} />
              <Route path="/console/dashboard" element={<S><Dashboard /></S>} />

              {/* 个人业务 */}
              <Route path="/console/cards" element={<S><Cards /></S>} />
              <Route path="/console/certs" element={<S><Certs /></S>} />
              <Route path="/console/cloud-totp" element={<S><CloudTOTP /></S>} />

              {/* 证书申请 */}
              <Route path="/console/apply" element={<S><ApplyWizard /></S>} />
              <Route path="/console/apply-records" element={<S><MyApplications /></S>} />
              <Route path="/console/subject-infos" element={<S><SubjectInfos /></S>} />
              <Route path="/console/extension-infos" element={<S><ExtensionInfos /></S>} />
              <Route path="/console/cert-orders" element={<S><CertOrders /></S>} />

              {/* 证书颁发 */}
              <Route path="/console/ca" element={<S><CA /></S>} />
              <Route path="/console/identity-reviews" element={<S><IdentityReviews /></S>} />
              <Route path="/console/cert-applications" element={<S><CertApplications /></S>} />
              <Route path="/console/all-certs" element={<S><AllCerts /></S>} />
              <Route path="/console/audit-logs" element={<S><AuditLogs /></S>} />
              <Route path="/console/users" element={<S><Users /></S>} />

              {/* 证书模板 */}
              <Route path="/console/cert-apply-templates" element={<S><CertApplyTemplates /></S>} />
              <Route path="/console/templates" element={<S><Templates /></S>} />
              <Route path="/console/key-storage-templates" element={<S><KeyStorageTemplates /></S>} />

              {/* 证书服务 */}
              <Route path="/console/storage-zones" element={<S><StorageZones /></S>} />
              <Route path="/console/revocation-services" element={<S><RevocationServices /></S>} />
              <Route path="/console/ocsp-responders" element={<S><OCSPResponders /></S>} />
              <Route path="/console/acme-configs" element={<S><ACMEConfigs /></S>} />
              <Route path="/console/cert-policies" element={<S><CertPolicies /></S>} />

              {/* 销售管理 */}
              <Route path="/console/products" element={<S><ConsoleProducts /></S>} />
              <Route path="/console/admin-orders" element={<S><AdminOrders /></S>} />
              <Route path="/console/promo" element={<S><Promo /></S>} />
              <Route path="/console/payment-plugins" element={<S><PaymentPlugins /></S>} />

              {/* 系统 */}
              <Route path="/console/logs" element={<S><Logs /></S>} />
              <Route path="/console/settings" element={<S><Settings /></S>} />
              <Route path="/console/site-settings" element={<S><ConsoleSiteSettings /></S>} />
              <Route path="/console/profile" element={<S><Profile /></S>} />
              <Route path="/console/help" element={<S><Help basePath="/console/help" /></S>} />
              <Route path="/console/help/:slug" element={<S><Help basePath="/console/help" /></S>} />
            </Route>

            {/* ---- 官网帮助中心（公开） ---- */}
            <Route element={<PortalLayout />}>
              <Route path="/help" element={<S><Help basePath="/help" /></S>} />
              <Route path="/help/:slug" element={<S><Help basePath="/help" /></S>} />
            </Route>

            {/* ---- 合并页面后的历史路径 ---- */}
            {Object.entries(MERGED_CONSOLE_PATHS).map(([from, to]) => (
              <Route key={from} path={from} element={<Navigate to={to} replace />} />
            ))}

            {/* ---- 历史路径重定向 ---- */}
            {LEGACY_CONSOLE_PATHS.map((p) => (
              <Route key={p} path={`/${p}`} element={<Navigate to={`/console/${p}`} replace />} />
            ))}
            {/* 旧公开申请入口：改为从产品中心进入选购与申请 */}
            <Route path="/apply" element={<Navigate to="/products" replace />} />

            {/* 兜底 */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ErrorBoundary>
    </ConfigProvider>
  );
};

export default App;
