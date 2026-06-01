import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuthStore } from '../store/auth';
import { login } from '../api';

const LS_SAVED_LOCAL = 'login_saved_local';

interface PrivateRouteProps {
  children: React.ReactNode;
}

const PrivateRoute: React.FC<PrivateRouteProps> = ({ children }) => {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated());
  const addAccount = useAuthStore((s) => s.addAccount);
  const location = useLocation();

  // 三态：checking（启动检测中）、ok（已认证）、fail（需要登录）
  const [status, setStatus] = useState<'checking' | 'ok' | 'fail'>(() =>
    isAuthenticated ? 'ok' : 'checking'
  );

  useEffect(() => {
    if (status !== 'checking') return;

    // 尝试用已保存的凭据静默登录
    const raw = localStorage.getItem(LS_SAVED_LOCAL);
    if (!raw) { setStatus('fail'); return; }

    let creds: { username?: string; password?: string };
    try { creds = JSON.parse(raw); } catch { setStatus('fail'); return; }
    if (!creds.username || !creds.password) { setStatus('fail'); return; }

    login({ username: creds.username, password: creds.password })
      .then((auth) => {
        addAccount(auth, { userType: 'local', savedPassword: creds.password });
        setStatus('ok');
      })
      .catch(() => setStatus('fail'));
  }, []);

  if (status === 'checking') {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="正在验证登录状态..." />
      </div>
    );
  }

  if (status === 'fail') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export default PrivateRoute;
