import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme, Spin } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { useAppStore } from './store/appStore';
import MainLayout from './layouts/MainLayout';
import ErrorBoundary from './components/ErrorBoundary';
import PrivateRoute from './components/PrivateRoute';

// Manager 本地功能页面（懒加载）
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Users = lazy(() => import('./pages/Users'));
const Cards = lazy(() => import('./pages/Cards'));
const Certs = lazy(() => import('./pages/Certs'));
const Credentials = lazy(() => import('./pages/Credentials'));
const CredentialsFido = lazy(() => import('./pages/Credentials/Fido'));
const TOTP = lazy(() => import('./pages/TOTP'));
const PKI = lazy(() => import('./pages/PKI'));
const PKILocalCA = lazy(() => import('./pages/PKI/LocalCA'));
const PKICSR = lazy(() => import('./pages/PKI/CSR'));
const PKICerts = lazy(() => import('./pages/PKI/Certs'));
const PKIImportCert = lazy(() => import('./pages/PKI/ImportCert'));
const Logs = lazy(() => import('./pages/Logs'));
const Settings = lazy(() => import('./pages/Settings'));
const Login = lazy(() => import('./pages/Login'));
const Welcome = lazy(() => import('./pages/Welcome'));

const PageLoader = () => (
  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
    <Spin size="large" />
  </div>
);

const S = ({ children }: { children: React.ReactNode }) => (
  <Suspense fallback={<PageLoader />}>{children}</Suspense>
);

const App: React.FC = () => {
  const { darkMode, themeMode, setThemeMode } = useAppStore();

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
            {/* 登录页（无需认证） */}
            <Route path="/login" element={<S><Login /></S>} />
            {/* 首次运行向导（无需认证） */}
            <Route path="/welcome" element={<S><Welcome /></S>} />
            {/* Manager 本地管理路由，需要登录认证 */}
            <Route path="/" element={<PrivateRoute><MainLayout /></PrivateRoute>}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<S><Dashboard /></S>} />
              <Route path="users" element={<S><Users /></S>} />
              <Route path="cards" element={<S><Cards /></S>} />
              <Route path="certs" element={<S><Certs /></S>} />
              <Route path="credentials" element={<S><Credentials /></S>} />
              <Route path="credentials/fido" element={<S><CredentialsFido /></S>} />
              <Route path="totp" element={<S><TOTP /></S>} />
              <Route path="pki" element={<S><PKI /></S>}>
                <Route index element={<Navigate to="/pki/csr" replace />} />
                <Route path="selfsign" element={<Navigate to="/pki/certs" replace />} />
                <Route path="ca" element={<S><PKILocalCA /></S>} />
                <Route path="csr" element={<S><PKICSR /></S>} />
                <Route path="certs" element={<S><PKICerts /></S>} />
                <Route path="import" element={<S><PKIImportCert /></S>} />
              </Route>
              <Route path="logs" element={<S><Logs /></S>} />
              <Route path="settings" element={<S><Settings /></S>} />
            </Route>
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </BrowserRouter>
      </ErrorBoundary>
    </ConfigProvider>
  );
};

export default App;
