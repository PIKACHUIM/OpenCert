import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme, Spin } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { useThemeStore } from './store/theme';
import MainLayout from './layouts/MainLayout';
import ErrorBoundary from './components/ErrorBoundary';
import PrivateRoute from './components/PrivateRoute';

// 公开页面
const Home = lazy(() => import('./pages/Home'));
const Login = lazy(() => import('./pages/Login'));
const Apply = lazy(() => import('./pages/Apply'));

// 受保护页面（懒加载）
const Dashboard = lazy(() => import('./pages/Dashboard'));
const CA = lazy(() => import('./pages/CA'));
const Templates = lazy(() => import('./pages/Templates'));
const Certs = lazy(() => import('./pages/Certs'));
const Users = lazy(() => import('./pages/Users'));
const Payment = lazy(() => import('./pages/Payment'));
const Identity = lazy(() => import('./pages/Identity'));
const CertOrders = lazy(() => import('./pages/CertOrders'));
const CTRecords = lazy(() => import('./pages/CTRecords'));
const AuditLogs = lazy(() => import('./pages/AuditLogs'));
const CertApplyTemplates = lazy(() => import('./pages/CertApplyTemplates'));
const Settings = lazy(() => import('./pages/Settings'));
const Logs = lazy(() => import('./pages/Logs'));
const Profile = lazy(() => import('./pages/Profile'));

// 新增页面
const Cards = lazy(() => import('./pages/Cards'));
const AllCerts = lazy(() => import('./pages/AllCerts'));
const SubjectInfos = lazy(() => import('./pages/SubjectInfos'));
const ExtensionInfos = lazy(() => import('./pages/ExtensionInfos'));
const CloudTOTP = lazy(() => import('./pages/CloudTOTP'));
const KeyStorageTemplates = lazy(() => import('./pages/KeyStorageTemplates'));
const OIDs = lazy(() => import('./pages/OIDs'));
const StorageZones = lazy(() => import('./pages/StorageZones'));
const RevocationServices = lazy(() => import('./pages/RevocationServices'));
const ACMEConfigs = lazy(() => import('./pages/ACMEConfigs'));
const CertApplications = lazy(() => import('./pages/CertApplications'));
const PaymentPlugins = lazy(() => import('./pages/PaymentPlugins'));

const PageLoader = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
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

  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: darkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 8,
          fontFamily: "'PingFang SC', 'Microsoft YaHei', 'Segoe UI', sans-serif",
        },
        components: {
          Layout: { siderBg: darkMode ? '#0d1117' : '#001529' },
          Menu: { darkItemBg: 'transparent', darkSubMenuItemBg: 'transparent' },
        },
      }}
    >
      <ErrorBoundary>
        <BrowserRouter>
          <Routes>
            {/* 公开路由 */}
            <Route path="/" element={<S><Home /></S>} />
            <Route path="/login" element={<S><Login /></S>} />
            <Route path="/apply" element={<S><Apply /></S>} />

            {/* 受保护路由：使用独立路径避免与公开路由冲突 */}
            <Route element={<PrivateRoute><MainLayout /></PrivateRoute>}>
              <Route path="/dashboard" element={<S><Dashboard /></S>} />
              {/* 我的功能 */}
              <Route path="/cards" element={<S><Cards /></S>} />
              <Route path="/certs" element={<S><Certs /></S>} />
              <Route path="/identity" element={<S><Identity /></S>} />
              <Route path="/subject-infos" element={<S><SubjectInfos /></S>} />
              <Route path="/extension-infos" element={<S><ExtensionInfos /></S>} />
              <Route path="/cert-orders" element={<S><CertOrders /></S>} />
              <Route path="/cloud-totp" element={<S><CloudTOTP /></S>} />
              <Route path="/payment" element={<S><Payment /></S>} />
              <Route path="/profile" element={<S><Profile /></S>} />
              {/* 平台管理（admin / operator） */}
              <Route path="/ca" element={<S><CA /></S>} />
              <Route path="/all-certs" element={<S><AllCerts /></S>} />
              <Route path="/templates" element={<S><Templates /></S>} />
              <Route path="/key-storage-templates" element={<S><KeyStorageTemplates /></S>} />
              <Route path="/cert-apply-templates" element={<S><CertApplyTemplates /></S>} />
              <Route path="/cert-applications" element={<S><CertApplications /></S>} />
              <Route path="/oids" element={<S><OIDs /></S>} />
              <Route path="/users" element={<S><Users /></S>} />
              <Route path="/ct-records" element={<S><CTRecords /></S>} />
              <Route path="/audit-logs" element={<S><AuditLogs /></S>} />
              <Route path="/storage-zones" element={<S><StorageZones /></S>} />
              <Route path="/revocation-services" element={<S><RevocationServices /></S>} />
              <Route path="/acme-configs" element={<S><ACMEConfigs /></S>} />
              <Route path="/payment-plugins" element={<S><PaymentPlugins /></S>} />
              {/* 系统 */}
              <Route path="/logs" element={<S><Logs /></S>} />
              <Route path="/settings" element={<S><Settings /></S>} />
            </Route>

            {/* 兜底重定向 */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </ErrorBoundary>
    </ConfigProvider>
  );
};

export default App;
