import React from 'react';
import {
  Layout, Menu, Typography, Space, Tag, Avatar, Dropdown, Switch, Tooltip,
} from 'antd';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import {
  DashboardOutlined, ApartmentOutlined, AppstoreOutlined,
  SafetyCertificateOutlined, UserOutlined, WalletOutlined,
  IdcardOutlined, ShoppingOutlined, AuditOutlined, SettingOutlined,
  FileTextOutlined, LogoutOutlined, ProfileOutlined, BulbOutlined,
  CreditCardOutlined, DatabaseOutlined, NumberOutlined, StopOutlined,
  CloudServerOutlined, ClockCircleOutlined, SafetyOutlined, LinkOutlined,
} from '@ant-design/icons';
import { useAuthStore } from '../store/auth';
import { useThemeStore } from '../store/theme';
import { logout } from '../api';

const { Sider, Content, Header } = Layout;
const { Text } = Typography;

const MainLayout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { role, username, clearAuth } = useAuthStore();
  const { darkMode, toggleDarkMode } = useThemeStore();

  const selectedKey = '/' + location.pathname.split('/')[1] || '/dashboard';

  const handleLogout = async () => {
    try { await logout(); } catch {}
    clearAuth();
    navigate('/login', { replace: true });
  };

  // 判断是否为管理员（super_admin 或 admin）
  const isAdmin = role === 'admin' || role === 'super_admin';
  // 判断是否为操作员或以上
  const isOperatorOrAbove = isAdmin || role === 'operator';

  // 构建分组菜单
  const menuItems: any[] = [
    { key: '/dashboard', icon: <DashboardOutlined />, label: '平台概览' },
    {
      key: 'group-card', icon: <CreditCardOutlined />, label: '个人业务',
      children: [
        { key: '/cards', icon: <CreditCardOutlined />, label: '智能卡片管理' },
        { key: '/certs', icon: <SafetyCertificateOutlined />, label: '个人证书管理' },
        { key: '/cloud-totp', icon: <ClockCircleOutlined />, label: 'TOTP认证管理' },
      ],
    },
    {
      key: 'group-apply', icon: <ShoppingOutlined />, label: '证书申请',
      children: [
        { key: '/subject-infos', icon: <IdcardOutlined />, label: '证书主体信息' },
        { key: '/extension-infos', icon: <LinkOutlined />, label: '证书扩展信息' },
        { key: '/cert-orders', icon: <ShoppingOutlined />, label: '个人订单管理' },
        { key: '/identity', icon: <IdcardOutlined />, label: '身份认证管理' },
        { key: '/payment', icon: <WalletOutlined />, label: '财务支付管理' },
      ],
    },
    // 平台管理分组：admin / super_admin / operator 可见
    ...(isOperatorOrAbove ? [{
      key: 'group-admin', icon: <ApartmentOutlined />, label: '平台管理',
      children: [
        { key: '/ca', icon: <ApartmentOutlined />, label: '颁发机构管理' },
        { key: '/all-certs', icon: <SafetyCertificateOutlined />, label: '全局证书管理' },
        { key: '/cert-applications', icon: <AuditOutlined />, label: '证书申请审核' },
        { key: '/users', icon: <UserOutlined />, label: '平台用户管理' },
        { key: '/ct-records', icon: <AuditOutlined />, label: '证书透明度CT' },
        { key: '/audit-logs', icon: <FileTextOutlined />, label: '证书审计日志' },
      ],
    }] : []),
    // 模板管理分组：admin / super_admin 可见
    ...(isAdmin ? [{
      key: 'group-template', icon: <AppstoreOutlined />, label: '模板管理',
      children: [
        { key: '/templates', icon: <AppstoreOutlined />, label: '证书颁发模板' },
        { key: '/key-storage-templates', icon: <SafetyOutlined />, label: '密钥存储模板' },
        { key: '/cert-apply-templates', icon: <AppstoreOutlined />, label: '证书申请模板' },
        { key: '/oids', icon: <NumberOutlined />, label: '证书OID 管理' },
      ],
    }] : []),
    // 服务配置分组：admin / super_admin 可见
    ...(isAdmin ? [{
      key: 'group-service', icon: <CloudServerOutlined />, label: '服务配置',
      children: [
        { key: '/storage-zones', icon: <DatabaseOutlined />, label: '存储区域配置' },
        { key: '/revocation-services', icon: <StopOutlined />, label: '证书吊销服务' },
        { key: '/acme-configs', icon: <CloudServerOutlined />, label: '证书ACME服务' },
        { key: '/payment-plugins', icon: <WalletOutlined />, label: '支付插件配置' },
      ],
    }] : []),
    {
      key: 'group-system', icon: <SettingOutlined />, label: '系统管理',
      children: [
        { key: '/logs', icon: <FileTextOutlined />, label: '操作日志审计' },
        { key: '/settings', icon: <SettingOutlined />, label: '全局系统设置' },
      ],
    },
  ];

  const userMenuItems = [
    { key: 'profile', icon: <ProfileOutlined />, label: '个人中心', onClick: () => navigate('/profile') },
    { type: 'divider' as const },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true, onClick: handleLogout },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {/* 侧边栏 */}
      <Sider
        width={220}
        style={{
          background: darkMode ? '#0d1117' : '#001529',
          borderRight: darkMode ? '1px solid #21262d' : 'none',
          overflow: 'auto',
          height: '100vh',
          position: 'fixed',
          left: 0, top: 0, bottom: 0,
        }}
      >
        {/* Logo 区域 */}
        <div style={{
          padding: '20px 16px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.08)',
          marginBottom: 8,
        }}>
          <Space align="center">
            <SafetyCertificateOutlined style={{ fontSize: 24, color: '#1677ff' }} />
            <div>
              <div style={{ color: '#fff', fontWeight: 700, fontSize: 14, lineHeight: 1.2 }}>OpenCert Platform</div>
              <div style={{ color: 'rgba(255,255,255,0.45)', fontSize: 11 }}>
                云端平台管理 - {role === 'admin' ? '管理员' : '证书管理平台'}
              </div>
            </div>
          </Space>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          defaultOpenKeys={['group-card', 'group-apply', 'group-admin', 'group-template', 'group-service', 'group-system']}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ background: 'transparent', border: 'none' }}
        />
      </Sider>

      <Layout style={{ marginLeft: 220 }}>
        {/* 顶部栏 */}
        <Header style={{
          background: darkMode ? '#161b22' : '#fff',
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
          height: 56,
          position: 'sticky',
          top: 0,
          zIndex: 10,
        }}>
          {/* 连接状态 */}
          <Space>
            <Tag color="green" style={{ fontSize: 12 }}>● server-card :1027</Tag>
          </Space>

          {/* 右侧工具栏 */}
          <Space>
            <Tooltip title={darkMode ? '切换亮色模式' : '切换暗色模式'}>
              <Switch
                checkedChildren={<BulbOutlined />}
                unCheckedChildren={<BulbOutlined />}
                checked={darkMode}
                onChange={toggleDarkMode}
                size="small"
              />
            </Tooltip>
            <Dropdown menu={{ items: userMenuItems as any }} placement="bottomRight" arrow>
              <Space style={{ cursor: 'pointer' }}>
                <Avatar
                  size={32}
                  style={{ background: 'linear-gradient(135deg, #1677ff, #722ed1)', cursor: 'pointer' }}
                  icon={<UserOutlined />}
                />
                <Text style={{ fontSize: 13, color: darkMode ? '#c9d1d9' : undefined }}>{username}</Text>
              {role === 'admin' && <Tag color="gold" style={{ fontSize: 11 }}>管理员</Tag>}
              {role === 'super_admin' && <Tag color="red" style={{ fontSize: 11 }}>超级管理员</Tag>}
              {role === 'operator' && <Tag color="blue" style={{ fontSize: 11 }}>操作员</Tag>}
              {role === 'readonly' && <Tag color="default" style={{ fontSize: 11 }}>只读</Tag>}
              </Space>
            </Dropdown>
          </Space>
        </Header>

        {/* 主内容区 */}
        <Content style={{
          background: darkMode ? '#0d1117' : '#f5f5f5',
          minHeight: 'calc(100vh - 56px)',
          overflow: 'auto',
          padding: 24,
        }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  );
};

export default MainLayout;
