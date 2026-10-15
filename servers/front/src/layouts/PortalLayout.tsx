import React, { useEffect } from 'react';
import { Layout, Menu, Space, Button, Typography, Dropdown, Divider } from 'antd';
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  SafetyCertificateOutlined, CloudServerOutlined, AppstoreOutlined,
  UserOutlined, DownloadOutlined, QuestionCircleOutlined,
} from '@ant-design/icons';
import { useSiteStore } from '../store/site';
import { useAuthStore } from '../store/auth';

const { Header, Content, Footer } = Layout;
const { Text } = Typography;

/**
 * 门户布局：官网顶栏 + 页脚。
 * 与控制台（/console）共用账号体系，但使用独立的浅色品牌视觉与信息架构。
 */
const PortalLayout: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { settings, load } = useSiteStore();
  const { isAuthenticated, username } = useAuthStore();

  useEffect(() => { load(); }, [load]);

  /** 顶级导航：仅保留已有页面的入口，避免出现死链 */
  const navItems = [
    { key: '/products', label: '产品中心', icon: <AppstoreOutlined /> },
    { key: '/products/cloudcard', label: '云端智能卡', icon: <CloudServerOutlined /> },
    { key: '/trust', label: '信任服务', icon: <SafetyCertificateOutlined /> },
    { key: '/downloads', label: '下载与接入', icon: <DownloadOutlined /> },
    { key: '/help', label: '帮助中心', icon: <QuestionCircleOutlined /> },
  ];

  // 选中态：/products/xxx 一并归属"产品中心"
  const selected = location.pathname.startsWith('/products/cloudcard')
    ? '/products/cloudcard'
    : location.pathname.startsWith('/products') ? '/products'
    : location.pathname.startsWith('/trust') ? '/trust'
    : location.pathname.startsWith('/downloads') ? '/downloads'
    : location.pathname.startsWith('/help') ? '/help' : '';

  const accountMenu = {
    items: [
      { key: '/console', label: '控制台' },
      { key: '/console/orders', label: '我的订单' },
      { key: '/console/profile', label: '个人中心' },
    ],
    onClick: ({ key }: { key: string }) => navigate(key),
  };

  return (
    <Layout style={{ minHeight: '100vh', background: '#fff' }}>
      <Header
        style={{
          position: 'sticky', top: 0, zIndex: 20, height: 64, lineHeight: '64px',
          padding: '0 32px', background: 'rgba(255,255,255,0.92)',
          backdropFilter: 'blur(12px)', borderBottom: '1px solid #eef0f4',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}
      >
        <Space size={40} align="center">
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 9,
              background: 'linear-gradient(135deg, #1d4ed8, #0891b2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 17 }} />
            </div>
            <Text strong style={{ fontSize: 17, letterSpacing: '-0.2px', color: '#111827' }}>
              {settings.site_name}
            </Text>
          </Link>

          <Menu
            mode="horizontal"
            selectedKeys={[selected]}
            items={navItems}
            onClick={({ key }) => navigate(key)}
            style={{ borderBottom: 'none', minWidth: 320, background: 'transparent' }}
          />
        </Space>

        <Space size={8}>
          {isAuthenticated ? (
            <Dropdown menu={accountMenu} placement="bottomRight" arrow>
              <Button type="text" icon={<UserOutlined />} style={{ fontWeight: 500 }}>
                {username || '我的账户'}
              </Button>
            </Dropdown>
          ) : (
            <>
              <Button type="text" onClick={() => navigate('/login')}>登录</Button>
              <Button type="primary" onClick={() => navigate('/register')}>免费注册</Button>
            </>
          )}
        </Space>
      </Header>

      <Content style={{ background: '#fff' }}>
        <Outlet />
      </Content>

      <Footer style={{ background: '#0b1220', color: 'rgba(255,255,255,0.72)', padding: '48px 32px 28px' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 48, justifyContent: 'space-between' }}>
            <div style={{ minWidth: 260, maxWidth: 360 }}>
              <Space align="center" style={{ marginBottom: 12 }}>
                <SafetyCertificateOutlined style={{ color: '#38bdf8', fontSize: 20 }} />
                <Text strong style={{ color: '#fff', fontSize: 16 }}>{settings.site_name}</Text>
              </Space>
              <div style={{ fontSize: 13, lineHeight: 1.9, color: 'rgba(255,255,255,0.6)' }}>
                {settings.site_description}
              </div>
            </div>

            <div style={{ minWidth: 150 }}>
              <Text strong style={{ color: '#fff', display: 'block', marginBottom: 12 }}>产品</Text>
              <Space direction="vertical" size={6}>
                <Link to="/products/ssl" style={footerLinkStyle}>SSL/TLS 证书</Link>
                <Link to="/products/codesign" style={footerLinkStyle}>代码签名证书</Link>
                <Link to="/products/email" style={footerLinkStyle}>邮件证书</Link>
                <Link to="/products/docsign" style={footerLinkStyle}>文档签名证书</Link>
                <Link to="/products/cloudcard" style={footerLinkStyle}>云端智能卡</Link>
              </Space>
            </div>

            <div style={{ minWidth: 150 }}>
              <Text strong style={{ color: '#fff', display: 'block', marginBottom: 12 }}>服务与支持</Text>
              <Space direction="vertical" size={6}>
                {settings.help_url && (
                  <a href={settings.help_url} target="_blank" rel="noreferrer" style={footerLinkStyle}>帮助中心</a>
                )}
                {settings.client_download && (
                  <a href={settings.client_download} target="_blank" rel="noreferrer" style={footerLinkStyle}>客户端下载</a>
                )}
                {settings.driver_download && (
                  <a href={settings.driver_download} target="_blank" rel="noreferrer" style={footerLinkStyle}>驱动下载</a>
                )}
                <Link to="/console/orders" style={footerLinkStyle}>订单查询</Link>
              </Space>
            </div>

            <div style={{ minWidth: 180 }}>
              <Text strong style={{ color: '#fff', display: 'block', marginBottom: 12 }}>联系我们</Text>
              <Space direction="vertical" size={6}>
                {settings.contact_email && <span style={footerLinkStyle}>{settings.contact_email}</span>}
                {settings.contact_phone && <span style={footerLinkStyle}>{settings.contact_phone}</span>}
                {settings.terms_url && (
                  <a href={settings.terms_url} target="_blank" rel="noreferrer" style={footerLinkStyle}>服务条款</a>
                )}
                {settings.privacy_url && (
                  <a href={settings.privacy_url} target="_blank" rel="noreferrer" style={footerLinkStyle}>隐私政策</a>
                )}
              </Space>
            </div>
          </div>

          <Divider style={{ borderColor: 'rgba(255,255,255,0.1)', margin: '28px 0 16px' }} />
          <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.45)', textAlign: 'center' }}>
            {settings.footer_note || `© ${new Date().getFullYear()} ${settings.site_name}`}
            {settings.icp_record ? ` · ${settings.icp_record}` : ''}
          </div>
        </div>
      </Footer>
    </Layout>
  );
};

const footerLinkStyle: React.CSSProperties = {
  color: 'rgba(255,255,255,0.72)',
  fontSize: 13,
};

export default PortalLayout;
