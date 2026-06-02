import React, { useEffect } from 'react';
import {
  Layout, Menu, Badge, Tooltip, Switch, Typography, Space, Tag, Button, Dropdown, Avatar,
} from 'antd';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  DashboardOutlined, UserOutlined, CreditCardOutlined, FileTextOutlined,
  SettingOutlined, SafetyCertificateOutlined, BulbOutlined, ApiOutlined,
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
  const removeAccount = useAuthStore((s) => s.removeAccount);
  const deactivate = useAuthStore((s) => s.deactivate);
  const clearAll = useAuthStore((s) => s.clearAll);
  const active = accounts.find((a) => a.user_uuid === activeUUID) || null;

  // Manager 菜单项（使用 i18n key 动态构建，确保语言切换实时生效）
  const menuItems = [
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
      icon: <KeyOutlined />,
      label: t('nav.groupSecurity'),
      children: [
        { key: '/credentials/fido-umdf', icon: <KeyOutlined />, label: t('nav.fidoManage') },
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
  ];

  // 退出：只清除当前 token/activeUUID，保留账号记录（下次可在"已有账号"Tab 快速重新登录）
  const handleLogout = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    if (activeUUID) deactivate(activeUUID);
    navigate('/login', { replace: true });
  };

  // 全部登出：清所有账号并返回登录页
  const handleLogoutAll = () => {
    clearAll();
    navigate('/login', { replace: true });
  };

  // 切换账号：刷新 Slots
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
  // 根据当前路径计算应展开的父菜单 key（概览不需要展开）
  const getOpenKey = () => {
    const p = location.pathname;
    if (p.startsWith('/pki')) return 'group-pki';
    if (['/cards', '/certs', '/users'].some(r => p.startsWith(r))) return 'group-local';
    if (['/credentials', '/totp'].some(r => p.startsWith(r))) return 'group-security';
    return 'group-system';
  };

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
              <div style={{ color: '#fff', fontWeight: 700, fontSize: 14, lineHeight: 1.2 }}>
                {t('layout.appName')}
              </div>
              <div style={{ color: 'rgba(255,255,255,0.45)', fontSize: 11 }}>
                {t('layout.appDesc')}
              </div>
            </div>
          </Space>
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          defaultOpenKeys={[getOpenKey()]}
          items={menuItems as any}
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
          {/* 连接状态（连接 client-card :1026） */}
          <Space>
            <ApiOutlined style={{ color: connected ? '#52c41a' : '#ff4d4f' }} />
            <Badge
              status={connected ? 'success' : 'error'}
              text={
                <Text style={{ fontSize: 13, color: darkMode ? '#c9d1d9' : undefined }}>
                  {connected
                    ? t('layout.connected', { version: serverVersion })
                    : t('layout.disconnected')}
                </Text>
              }
            />
            {connected && <Tag color="blue" style={{ fontSize: 11 }}>:1026</Tag>}
          </Space>

          {/* 右侧：主题切换 + 多账号下拉 */}
          <Space>
            <Tooltip title={darkMode ? t('layout.toggleLight') : t('layout.toggleDark')}>
              <Switch
                checkedChildren={<BulbOutlined />}
                unCheckedChildren={<BulbOutlined />}
                checked={darkMode}
                onChange={toggleDarkMode}
                size="small"
              />
            </Tooltip>
            <Dropdown
              placement="bottomRight"
              trigger={['click']}
              menu={{
                items: [
                  {
                    key: 'header',
                    type: 'group',
                    label: <span style={{ fontSize: 12, color: '#8b949e' }}>{t('account.loggedAccounts')}（{accounts.length}）</span>,
                  },
                  ...accounts.map((a) => ({
                    key: a.user_uuid,
                    icon: a.user_type === 'cloud' ? <CloudOutlined /> : <UserOutlined />,
                    label: (
                      <Space>
                        <span>{a.display_name}</span>
                        {a.user_type === 'cloud' && <Tag color="blue" style={{ fontSize: 11 }}>{t('layout.cloudTag')}</Tag>}
                        {a.user_uuid === activeUUID && <CheckOutlined style={{ color: '#52c41a' }} />}
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
                ],
              }}
            >
              <Button
                type="text"
                size="small"
                style={{ color: darkMode ? '#c9d1d9' : '#333', padding: '0 8px' }}
              >
                <Space size={6}>
                  <Avatar
                    size={24}
                    style={{
                      background: active?.user_type === 'cloud'
                        ? 'linear-gradient(135deg, #1677ff, #13c2c2)'
                        : 'linear-gradient(135deg, #722ed1, #eb2f96)',
                    }}
                    icon={active?.user_type === 'cloud' ? <CloudOutlined /> : <UserOutlined />}
                  />
                  <Text style={{ fontSize: 13, color: darkMode ? '#c9d1d9' : '#333' }}>
                    {active?.display_name || t('layout.notLogin')}
                  </Text>
                  {accounts.length > 1 && (
                    <Tag color="purple" style={{ fontSize: 11, marginLeft: 2 }}>
                      +{accounts.length - 1}
                    </Tag>
                  )}
                </Space>
              </Button>
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
