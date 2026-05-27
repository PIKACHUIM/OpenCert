import React from 'react';
import { Outlet } from 'react-router-dom';

/** PKI 工具入口：直接渲染子路由 */
const PKIPage: React.FC = () => {
  return (
    <div>
      <Outlet />
    </div>
  );
};

export default PKIPage;
