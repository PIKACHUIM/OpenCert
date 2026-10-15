import React, { useEffect, useMemo, useState } from 'react';
import {
  Layout, Menu, Tooltip, Typography, Space, Tag, Dropdown, Avatar,
} from 'antd';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  DashboardOutlined, UserOutlined, CreditCardOutlined, FileTextOutlined,
  SettingOutlined, SafetyCertificateOutlined, BulbOutlined,
  ClockCircleOutlined, FileProtectOutlined, BankOutlined, KeyOutlined,
  LogoutOutlined, FileDoneOutlined, CloudOutlined, PlusOutlined, CheckOutlined,
  LockOutlined,
} from '@ant-design/icons';
import { useAppStore } from '../store/appStore';
import { useAuthStore } from '../store/auth';
import { logout as apiLogout } from '../api';

const { Sider, Content, Header } = Layout;
const { Text } = Typography;

const MainLayout: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const { connected, serverVersion, darkMode, toggleDarkMode, checkConnection, loadSlots } = useAppStore();
  const accounts = useAuthStore((s) => s.accounts);
  const activeUUID = useAuthStore((s) => s.activeUUID);
  const setActive = useAuthStore((s) => s.setActive);
  const deactivate = useAuthStore((s) => s.deactivate);
  const clearAll = useAuthStore((s) => s.clearAll);
  const active = accounts.find((a) => a.user_uuid === activeUUID) || null;
  const [collapsed, setCollapsed] = useState(false);

  const menuItems = useMemo(() => [
    {
      type: 'group' as const,
      label: t('nav.groupOverview'),
      children: [
        { key: '/dashboard', icon: <DashboardOutlined />, label: t('nav.overview') },
      ],
    },
    {
      key: 'group-local',
      icon: <CreditCardOutlined />,
      label: t('nav.groupDevices'),
      children: [
        { key: '/cards', icon: <CreditCardOutlined />, label: t('nav.cardsManage') },
        { key: '/certs', icon: <SafetyCertificateOutlined />, label: t('nav.certsManage') },
        { key: '/users', icon: <CloudOutlined />, label: t('nav.cloudUsers') },
      ],
    },
    {
      key: 'group-pki',
      icon: <FileProtectOutlined />,
      label: t('nav.groupPki'),
      children: [
        { key: '/pki/csr', icon: <KeyOutlined />, label: t('nav.localCsr') },
        { key: '/pki/ca', icon: <BankOutlined />, label: t('nav.localCa') },
        { key: '/pki/certs', icon: <FileDoneOutlined />, label: t('nav.certIssuance') },
      ],
    },
    {
      key: 'group-security',
      icon: <LockOutlined />,
      label: t('nav.groupSecurity'),
      children: [
        { key: '/credentials/fido', icon: <KeyOutlined />, label: t('nav.fidoManage') },
        { key: '/totp', icon: <ClockCircleOutlined />, label: t('nav.totpManage') },
        { key: '/credentials', icon: <LockOutlined />, label: t('nav.credentialsManage') },
      ],
    },
    {
      key: 'group-system',
      icon: <SettingOutlined />,
      label: t('nav.groupSystem'),
      children: [
        { key: '/logs', icon: <FileTextOutlined />, label: t('nav.opLogs') },
        { key: '/settings', icon: <SettingOutlined />, label: t('nav.systemSettings') },
      ],
    },
  ], [t]);

  const handleLogout = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    if (activeUUID) deactivate(activeUUID);
    navigate('/login', { replace: true });
  };

  const handleLogoutAll = () => {
    clearAll();
    navigate('/login', { replace: true });
  };

  const handleSwitch = (uuid: string) => {
    setActive(uuid);
    loadSlots();
  };

  useEffect(() => {
    checkConnection();
    loadSlots();
    const timer = setInterval(() => checkConnection(), 30000);
    return () => clearInterval(timer);
  }, []);

  const selectedKey = location.pathname;
  const getOpenKey = () => {
    const p = location.pathname;
    if (p.startsWith('/pki')) return 'group-pki';
    if (['/cards', '/certs', '/users'].some(r => p.startsWith(r))) return 'group-local';
    if (['/credentials', '/totp'].some(r => p.startsWith(r))) return 'group-security';
    return 'group-system';
  };

  const accountMenuItems = useMemo(() => [
    {
      key: 'header',
      type: 'group',
      label: <span className="account-menu-header">{t('account.loggedAccounts')} · {accounts.length}</span>,
    },
    ...accounts.map((a) => ({
      key: a.user_uuid,
      icon: a.user_type === 'cloud'
        ? <CloudOutlined className="account-icon-cloud" />
        : <UserOutlined className="account-icon-local" />,
      label: (
        <Space>
          <span>{a.display_name}</span>
          {a.user_type === 'cloud' && <Tag className="account-tag">{t('layout.cloudTag')}</Tag>}
          {a.user_uuid === activeUUID && <CheckOutlined className="account-check" />}
        </Space>
      ),
      onClick: () => handleSwitch(a.user_uuid),
    })),
    { type: 'divider' as const },
    {
      key: 'add',
      icon: <PlusOutlined />,
      label: t('account.addAccount'),
      onClick: () => navigate('/login', { state: { addMode: true } }),
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: t('account.logoutCurrent'),
      onClick: handleLogout,
      disabled: !active,
    },
    {
      key: 'logout-all',
      icon: <LogoutOutlined />,
      label: t('account.logoutAll'),
      danger: true,
      onClick: handleLogoutAll,
      disabled: accounts.length === 0,
    },
  ], [accounts, active, activeUUID, t, navigate]);

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        className="app-sider"
        width={220}
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        trigger={null}
        style={{
          overflow: 'auto',
          height: '100vh',
          position: 'fixed',
          left: 0, top: 0, bottom: 0,
        }}
      >
        <div className="brand-block" style={{ padding: collapsed ? '0 12px' : '0 20px' }}>
          <div className="brand-mark">
            <SafetyCertificateOutlined />
          </div>
          {!collapsed && (
            <div className="brand-copy">
              <div className="brand-kicker">SECURE CONSOLE</div>
              <div className="brand-title">{t('layout.appName')}</div>
            </div>
          )}
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          defaultOpenKeys={[getOpenKey()]}
          items={menuItems as any}
          onClick={({ key }) => navigate(key)}
          style={{ background: 'transparent', border: 'none', fontSize: 13, paddingTop: 6 }}
        />
      </Sider>

      <Layout style={{ marginLeft: collapsed ? 80 : 220, transition: 'margin-left var(--t-normal) var(--ease-out-expo)' }}>
        <Header className="app-header" style={{
          padding: '0 22px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: 56,
          position: 'sticky',
          top: 0,
          zIndex: 10,
        }}>
          <Space size={12} align="center">
            <button
              className="topbar-collapse-btn"
              onClick={() => setCollapsed((c) => !c)}
              aria-label={collapsed ? t('layout.expand') : t('layout.collapse')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 17l-5-5 5-5M18 17l-5-5 5-5"/></svg>
            </button>
            <div className="topbar-context">
              <span className="topbar-eyebrow">WORKSPACE</span>
              <div className="topbar-title">{t('layout.platformName')}</div>
            </div>
            <Tag className="env-tag">LOCAL</Tag>
          </Space>

          <Space size={12} align="center">
            <div className={`connection-pill ${connected ? 'is-online' : 'is-offline'}`}>
              <span className="connection-dot" />
              <Text className="connection-text">
                {connected ? t('layout.connected', { version: serverVersion }) : t('layout.disconnected')}
              </Text>
              {connected && <span className="connection-port">:1026</span>}
            </div>

            <Tooltip title={darkMode ? t('layout.toggleLight') : t('layout.toggleDark')}>
              <button className="topbar-icon-btn" onClick={toggleDarkMode}>
                <BulbOutlined />
              </button>
            </Tooltip>

            <Dropdown placement="bottomRight" trigger={['click']} menu={{ items: accountMenuItems as any }}>
              <button className="account-trigger">
                <Avatar
                  size={26}
                  className={`account-avatar ${active?.user_type === 'cloud' ? 'is-cloud' : 'is-local'}`}
                  icon={active?.user_type === 'cloud' ? <CloudOutlined /> : <UserOutlined />}
                />
                <Text className="account-name">{active?.display_name || t('layout.notLogin')}</Text>
                {accounts.length > 1 && (
                  <span className="account-count">+{accounts.length - 1}</span>
                )}
              </button>
            </Dropdown>
          </Space>
        </Header>

        <Content className="app-content" style={{
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
