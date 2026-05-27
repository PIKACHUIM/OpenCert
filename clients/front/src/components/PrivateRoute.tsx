import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/auth';

interface PrivateRouteProps {
  children: React.ReactNode;
}

const PrivateRoute: React.FC<PrivateRouteProps> = ({ children }) => {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated());
  const accounts = useAuthStore((s) => s.accounts);
  const location = useLocation();

  if (!isAuthenticated) {
    // 无任何账号记录 → 首次运行向导；有账号但未激活 → 登录页
    const target = accounts.length === 0 ? '/welcome' : '/login';
    return <Navigate to={target} state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export default PrivateRoute;
