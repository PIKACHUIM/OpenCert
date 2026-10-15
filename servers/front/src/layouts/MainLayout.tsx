import React, { useMemo, useState } from 'react';
import { Layout, Menu, Avatar, Dropdown, Grid, Tooltip } from 'antd';
import { useNavigate, useLocation, Outlet } from 'react-router-dom';
import {
  DashboardOutlined, ApartmentOutlined, AppstoreOutlined,
  SafetyCertificateOutlined, UserOutlined, WalletOutlined,
  IdcardOutlined, ShoppingOutlined, AuditOutlined, SettingOutlined,
  FileTextOutlined, LogoutOutlined, ProfileOutlined,
  CreditCardOutlined, DatabaseOutlined, StopOutlined,
  CloudServerOutlined, ClockCircleOutlined, SafetyOutlined, LinkOutlined,
  ShopOutlined, GlobalOutlined, HomeOutlined, GiftOutlined, BookOutlined,
  MenuFoldOutlined, MenuUnfoldOutlined,
} from '@ant-design/icons';
import { useAuthStore } from '../store/auth';
import { logout } from '../api';
import ThemeToggle from '../components/ThemeToggle';

const { Sider, Content, Header } = Layout;

/** 角色展示名 */
const ROLE_LABEL: Record<string, string> = {
  super_admin: '超级管理员',
  admin: '管理员',
  operator: '操作员',
  readonly: '只读成员',
  user: '普通用户',
};

const SIDER_WIDTH = 232;
const SIDER_COLLAPSED_WIDTH = 76;

const MainLayout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const screens = Grid.useBreakpoint();
  const { role, username, clearAuth } = useAuthStore();
  const [collapsed, setCollapsed] = useState(false);

  // 小屏：侧栏改为 0 宽抽屉式覆盖，避免内容被挤压
  const isMobile = screens.lg === false;

  // 菜单 key 使用完整路径（/console/xxx），避免多级路径被截断后无法高亮
  const selectedKey = location.pathname === '/console' ? '/console/dashboard' : location.pathname;

  const handleLogout = async () => {
    try { await logout(); } catch {}
    clearAuth();
    navigate('/login', { replace: true });
  };

  // 判断是否为管理员（super_admin 或 admin）
  const isAdmin = role === 'admin' || role === 'super_admin';
  // 判断是否为操作员或以上
  const isOperatorOrAbove = isAdmin || role === 'operator';

  // 构建分组菜单（路径统一加 /console 前缀）
  const menuItems: any[] = useMemo(() => [
    { key: '/console/dashboard', icon: <DashboardOutlined />, label: '平台概览' },
    {
      key: 'group-card', icon: <CreditCardOutlined />, label: '个人业务',
      children: [
        { key: '/console/cards', icon: <CreditCardOutlined />, label: '智能卡片管理' },
        { key: '/console/certs', icon: <SafetyCertificateOutlined />, label: '我的证书' },
        { key: '/console/cloud-totp', icon: <ClockCircleOutlined />, label: '认证信息管理' },
        { key: '/console/cert-orders', icon: <ShoppingOutlined />, label: '支付订单管理' },
        // 财务（余额、充值、订阅与兑换）已合并到账号信息管理
        { key: '/console/profile', icon: <WalletOutlined />, label: '账号信息管理' },
      ],
    },
    {
      key: 'group-apply', icon: <ShoppingOutlined />, label: '证书申请',
      children: [
        { key: '/console/apply', icon: <ShoppingOutlined />, label: '申请证书' },
        { key: '/console/apply-records', icon: <AuditOutlined />, label: '我的证书申请' },
        { key: '/console/subject-infos', icon: <IdcardOutlined />, label: '证书主体信息' },
        { key: '/console/extension-infos', icon: <LinkOutlined />, label: '证书扩展信息' },
      ],
    },
    // 证书颁发分组：admin / super_admin / operator 可见
    ...(isOperatorOrAbove ? [{
      key: 'group-admin', icon: <ApartmentOutlined />, label: '证书颁发',
      children: [
        { key: '/console/ca', icon: <ApartmentOutlined />, label: '证书颁发机构' },
        { key: '/console/identity-reviews', icon: <IdcardOutlined />, label: '身份认证审核' },
        { key: '/console/cert-applications', icon: <AuditOutlined />, label: '证书申请审核' },
        { key: '/console/all-certs', icon: <SafetyCertificateOutlined />, label: '全部证书' },
        // CT 记录已合并到审计日志（透明度选项卡）
        { key: '/console/audit-logs', icon: <FileTextOutlined />, label: '证书审计日志' },
      ],
    }] : []),
    // 证书模板分组：admin / super_admin 可见
    ...(isAdmin ? [{
      key: 'group-template', icon: <AppstoreOutlined />, label: '证书模板',
      children: [
        { key: '/console/cert-apply-templates', icon: <AppstoreOutlined />, label: '证书开通模板' },
        { key: '/console/templates', icon: <AppstoreOutlined />, label: '证书颁发模板' },
        { key: '/console/key-storage-templates', icon: <SafetyOutlined />, label: '密钥存储模板' },
      ],
    }] : []),
    // 证书服务分组：admin / super_admin 可见
    ...(isAdmin ? [{
      key: 'group-service', icon: <CloudServerOutlined />, label: '证书服务',
      children: [
        { key: '/console/storage-zones', icon: <DatabaseOutlined />, label: '证书存储区域' },
        { key: '/console/revocation-services', icon: <StopOutlined />, label: '证书吊销服务' },
        { key: '/console/ocsp-responders', icon: <SafetyOutlined />, label: '证书OCSP服务' },
        { key: '/console/acme-configs', icon: <CloudServerOutlined />, label: '证书ACME服务' },
        { key: '/console/cert-policies', icon: <FileTextOutlined />, label: '证书策略管理' },
      ],
    }] : []),
    // 销售管理分组：admin / super_admin 可见
    ...(isAdmin ? [{
      key: 'group-commerce', icon: <ShopOutlined />, label: '销售管理',
      children: [
        { key: '/console/products', icon: <ShopOutlined />, label: '销售商品管理' },
        { key: '/console/admin-orders', icon: <ProfileOutlined />, label: '订单管理' },
        { key: '/console/promo', icon: <GiftOutlined />, label: '订阅优惠管理' },
        { key: '/console/payment-plugins', icon: <WalletOutlined />, label: '支付渠道配置' },
      ],
    }] : []),
    {
      key: 'group-system', icon: <SettingOutlined />, label: '系统管理',
      children: [
        // 用户管理：仅管理员可见，普通用户不可见
        ...(isAdmin ? [{ key: '/console/users', icon: <UserOutlined />, label: '平台用户管理' }] : []),
        { key: '/console/logs', icon: <FileTextOutlined />, label: '平台操作日志' },
        { key: '/console/help', icon: <BookOutlined />, label: '帮助中心' },
        ...(isAdmin ? [
          { key: '/console/site-settings', icon: <GlobalOutlined />, label: '全局站点设置' },
          { key: '/console/settings', icon: <SettingOutlined />, label: '全局系统设置' },
        ] : []),
      ],
    },
  ], [isAdmin, isOperatorOrAbove]);

  /** 路径 → 页面标题，用于顶栏面包屑 */
  const pageTitle = useMemo(() => {
    const flat: Record<string, string> = {};
    const collect = (items: any[]) => {
      items.forEach((item) => {
        if (item.children) collect(item.children);
        else flat[item.key] = String(item.label);
      });
    };
    collect(menuItems);
    return flat[selectedKey] ?? '控制台';
  }, [menuItems, selectedKey]);

  const roleLabel = ROLE_LABEL[role ?? 'user'] ?? '普通用户';
  const initial = (username || 'U').trim().charAt(0).toUpperCase();

  const userMenuItems = [
    {
      key: 'account',
      label: (
        <div style={{ padding: '2px 2px', minWidth: 150 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--oc-text)' }}>{username || '未登录'}</div>
          <div style={{ fontSize: 12, color: 'var(--oc-text-3)', marginTop: 2 }}>{roleLabel}</div>
        </div>
      ),
    },
    { type: 'divider' as const },
    { key: 'portal', icon: <HomeOutlined />, label: '访问官网', onClick: () => navigate('/') },
    { key: 'profile', icon: <ProfileOutlined />, label: '个人中心', onClick: () => navigate('/console/profile') },
    { type: 'divider' as const },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true, onClick: handleLogout },
  ];

  const siderWidth = collapsed ? (isMobile ? 0 : SIDER_COLLAPSED_WIDTH) : SIDER_WIDTH;

  return (
    <Layout className="oc-console" style={{ minHeight: '100vh' }}>
      {/* 小屏展开侧栏时的遮罩 */}
      {isMobile && !collapsed && (
        <div
          onClick={() => setCollapsed(true)}
          style={{
            position: 'fixed', inset: 0, zIndex: 15,
            background: 'rgba(8, 13, 24, 0.52)', backdropFilter: 'blur(2px)',
          }}
        />
      )}

      {/* 侧边栏 */}
      <Sider
        className="oc-sider"
        width={SIDER_WIDTH}
        collapsedWidth={isMobile ? 0 : SIDER_COLLAPSED_WIDTH}
        collapsed={collapsed}
        collapsible
        trigger={null}
        breakpoint="lg"
        onBreakpoint={(broken) => setCollapsed(broken)}
        style={{ zIndex: 20 }}
      >
        {/* 品牌区 */}
        <div className="oc-sider__brand" style={{ justifyContent: collapsed && !isMobile ? 'center' : 'flex-start' }}>
          <span className="oc-logo-mark">
            <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 18 }} />
          </span>
          {!(collapsed && !isMobile) && (
            <div className="oc-sider__brand-text">
              <div className="oc-sider__brand-name">OpenCert Platform</div>
              <div className="oc-sider__brand-sub">云端证书 · 智能卡管理</div>
            </div>
          )}
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          defaultOpenKeys={['group-card', 'group-apply', 'group-admin', 'group-commerce', 'group-template', 'group-service', 'group-system']}
          items={menuItems}
          onClick={({ key }) => {
            navigate(key);
            if (isMobile) setCollapsed(true);
          }}
          style={{ background: 'transparent', border: 'none', paddingBottom: 24 }}
        />
      </Sider>

      <Layout
        style={{
          marginInlineStart: siderWidth,
          transition: 'margin-inline-start 0.28s cubic-bezier(0.16, 1, 0.3, 1)',
          background: 'var(--oc-page-bg)',
        }}
      >
        {/* 顶部栏 */}
        <Header className="oc-header">
          <div className="oc-header__crumb">
            <Tooltip title={collapsed ? '展开侧边栏' : '收起侧边栏'}>
              <button
                type="button"
                className="oc-icon-btn"
                aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}
                onClick={() => setCollapsed((v) => !v)}
              >
                {collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
              </button>
            </Tooltip>
            <span>控制台</span>
            <span className="oc-header__crumb-sep">/</span>
            <span className="oc-header__crumb-current">{pageTitle}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {screens.sm !== false && (
              <span className="oc-status-pill" title="已连接 OpenCert Platform 服务节点">
                <i className="oc-dot" />
                server-card :1027
              </span>
            )}
            <ThemeToggle variant="ghost" />
            <Dropdown menu={{ items: userMenuItems as any }} placement="bottomRight" arrow>
              <div className="oc-user-trigger">
                <Avatar
                  size={30}
                  style={{
                    background: 'linear-gradient(135deg, #1d4ed8, #0891b2)',
                    fontSize: 13,
                    fontWeight: 600,
                  }}
                >
                  {initial}
                </Avatar>
                {screens.sm !== false && (
                  <span className="oc-user-trigger__name">{username}</span>
                )}
              </div>
            </Dropdown>
          </div>
        </Header>

        {/* 主内容区 */}
        <Content className="oc-content">
          <div className="oc-content__inner">
            <Outlet />
          </div>
        </Content>
      </Layout>
    </Layout>
  );
};

export default MainLayout;
