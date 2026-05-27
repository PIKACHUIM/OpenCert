import React from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Button, Typography, Row, Col, Card, Space, Tag } from 'antd';
import {
  SafetyCertificateOutlined, ApartmentOutlined, AppstoreOutlined,
  UserOutlined, WalletOutlined, ApiOutlined, ArrowRightOutlined,
  CloudServerOutlined, AuditOutlined, KeyOutlined,
} from '@ant-design/icons';
import { useAuthStore } from '../../store/auth';

const { Title, Text, Paragraph } = Typography;

const features = [
  { icon: <ApartmentOutlined />, title: 'CA 管理', desc: '创建和管理证书颁发机构，支持证书链导入、CRL/OCSP 吊销服务', color: '#1677ff' },
  { icon: <AppstoreOutlined />, title: '模板管理', desc: '灵活配置颁发模板、主体模板、密钥用途、证书拓展、密钥存储策略', color: '#722ed1' },
  { icon: <SafetyCertificateOutlined />, title: '证书管理', desc: '全生命周期管理：颁发、吊销、续期、分配，支持 X.509/GPG/SSH', color: '#13c2c2' },
  { icon: <UserOutlined />, title: '用户管理', desc: '多角色权限控制，管理用户账号、主体信息、扩展信息审核', color: '#52c41a' },
  { icon: <WalletOutlined />, title: '支付系统', desc: '多支付渠道插件，证书订单管理，用户充值与消费记录', color: '#fa8c16' },
  { icon: <ApiOutlined />, title: 'ACME 服务', desc: '内置 ACME 协议，自动化证书申请与续期，支持多 CA 配置', color: '#eb2f96' },
  { icon: <CloudServerOutlined />, title: '存储区域', desc: '支持数据库和 HSM 硬件存储，灵活配置密钥存储策略', color: '#faad14' },
  { icon: <AuditOutlined />, title: 'CT 透明度', desc: '证书透明度日志提交与查询，符合现代 PKI 安全规范', color: '#f5222d' },
  { icon: <KeyOutlined />, title: 'TOTP 管理', desc: '云端 TOTP 密钥安全存储，支持 SHA1/SHA256/SHA512 算法', color: '#1890ff' },
];

const Home: React.FC = () => {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuthStore();

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0d1117', color: '#e6edf3' }}>
      {/* 顶部导航 */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        padding: '0 48px', height: 64,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'rgba(13,17,23,0.85)', backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(48,54,61,0.6)',
      }}>
        <Space align="center">
          <div style={{ width: 32, height: 32, borderRadius: 8, background: 'linear-gradient(135deg, #1677ff, #722ed1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 16 }} />
          </div>
          <Text strong style={{ color: '#e6edf3', fontSize: 18, letterSpacing: '-0.3px' }}>OpenCert Platform</Text>
          <Tag color="blue" style={{ fontSize: 11 }}>:1027</Tag>
        </Space>
        <Space>
          <Button type="text" style={{ color: '#8b949e' }} onClick={() => navigate('/login')}>登录</Button>
          <Button type="primary" onClick={() => navigate('/login')}
            style={{ background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none', borderRadius: 8 }}>
            立即开始
          </Button>
        </Space>
      </div>

      {/* Hero 区域 */}
      <div style={{
        paddingTop: 160, paddingBottom: 100, textAlign: 'center',
        background: 'radial-gradient(ellipse at 50% 0%, rgba(22,119,255,0.12) 0%, transparent 60%)',
        position: 'relative',
      }}>
        <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none',
          backgroundImage: 'linear-gradient(rgba(48,54,61,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(48,54,61,0.3) 1px, transparent 1px)',
          backgroundSize: '60px 60px', opacity: 0.4 }} />
        <div style={{ position: 'relative', zIndex: 1, maxWidth: 800, margin: '0 auto', padding: '0 24px' }}>
          <Tag color="blue" style={{ marginBottom: 24, borderRadius: 20, padding: '4px 16px', fontSize: 13 }}>
            🔐 企业级 PKI 云端管理平台
          </Tag>
          <Title style={{ color: '#e6edf3', fontSize: 52, fontWeight: 800, lineHeight: 1.15, margin: '0 0 24px', letterSpacing: '-1.5px' }}>
            OpenCert Platform<br />
            <span style={{ background: 'linear-gradient(135deg, #1677ff, #722ed1)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              证书全生命周期管理
            </span>
          </Title>
          <Paragraph style={{ color: '#8b949e', fontSize: 18, maxWidth: 560, margin: '0 auto 40px', lineHeight: 1.7 }}>
            连接 server-card 服务端，提供完整的 CA 管理、证书颁发、用户管理、支付系统和 ACME 自动化服务。
          </Paragraph>
          <Space size={16}>
            <Button type="primary" size="large" icon={<ArrowRightOutlined />} onClick={() => navigate('/login')}
              style={{ height: 48, padding: '0 32px', borderRadius: 10, fontWeight: 600, fontSize: 16,
                background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none',
                boxShadow: '0 8px 24px rgba(22,119,255,0.4)' }}>
              进入管理平台
            </Button>
            <Button size="large" icon={<SafetyCertificateOutlined />} onClick={() => navigate('/apply')}
              style={{ height: 48, padding: '0 32px', borderRadius: 10, fontWeight: 600, fontSize: 16,
                color: '#e6edf3', borderColor: '#30363d', background: 'rgba(22,27,34,0.8)' }}>
              申请证书
            </Button>
          </Space>
        </div>
      </div>

      {/* 功能特性 */}
      <div style={{ padding: '80px 48px', maxWidth: 1200, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 56 }}>
          <Title level={2} style={{ color: '#e6edf3', margin: '0 0 12px', fontWeight: 700 }}>平台核心功能</Title>
          <Text style={{ color: '#8b949e', fontSize: 16 }}>server-card 服务端提供的完整 PKI 管理能力</Text>
        </div>
        <Row gutter={[24, 24]}>
          {features.map((f) => (
            <Col xs={24} sm={12} lg={8} key={f.title}>
              <Card hoverable style={{
                background: 'rgba(22,27,34,0.8)', border: '1px solid rgba(48,54,61,0.6)',
                borderRadius: 12, height: '100%', transition: 'border-color 0.3s, transform 0.3s',
              }}
                bodyStyle={{ padding: 28 }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = f.color; (e.currentTarget as HTMLElement).style.transform = 'translateY(-4px)'; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(48,54,61,0.6)'; (e.currentTarget as HTMLElement).style.transform = 'translateY(0)'; }}
              >
                <div style={{ width: 48, height: 48, borderRadius: 12, background: `${f.color}20`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 22, color: f.color, marginBottom: 16 }}>
                  {f.icon}
                </div>
                <Title level={5} style={{ color: '#e6edf3', margin: '0 0 8px', fontWeight: 600 }}>{f.title}</Title>
                <Text style={{ color: '#8b949e', fontSize: 14, lineHeight: 1.6 }}>{f.desc}</Text>
              </Card>
            </Col>
          ))}
        </Row>
      </div>

      {/* 架构说明 */}
      <div style={{ padding: '60px 48px', background: 'rgba(22,27,34,0.4)', borderTop: '1px solid rgba(48,54,61,0.4)', borderBottom: '1px solid rgba(48,54,61,0.4)' }}>
        <div style={{ maxWidth: 900, margin: '0 auto', textAlign: 'center' }}>
          <Title level={3} style={{ color: '#e6edf3', margin: '0 0 32px', fontWeight: 700 }}>系统架构</Title>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 16, flexWrap: 'wrap' }}>
            {[
              { name: 'pkcs11-mock', desc: 'PKCS#11 驱动', color: '#13c2c2' },
              { name: '←→', desc: '', color: '#8b949e' },
              { name: 'client-card :1026', desc: 'OpenCert Manager', color: '#52c41a' },
              { name: '←→', desc: '', color: '#8b949e' },
              { name: 'server-card :1027', desc: 'OpenCert Platform ← 当前', color: '#1677ff' },
            ].map((item, i) => (
              item.name === '←→' ? (
                <Text key={i} style={{ color: '#8b949e', fontSize: 20 }}>←→</Text>
              ) : (
                <div key={i} style={{ padding: '12px 20px', borderRadius: 10, border: `1px solid ${item.color}40`, background: `${item.color}10`, textAlign: 'center' }}>
                  <Text strong style={{ color: item.color, display: 'block', fontFamily: 'monospace' }}>{item.name}</Text>
                  <Text style={{ color: '#8b949e', fontSize: 12 }}>{item.desc}</Text>
                </div>
              )
            ))}
          </div>
        </div>
      </div>

      {/* 页脚 */}
      <div style={{ padding: '32px 48px', textAlign: 'center' }}>
        <Text style={{ color: '#8b949e', fontSize: 13 }}>© 2025 OpenCert Platform · 企业级 PKI 云端管理平台</Text>
      </div>
    </div>
  );
};

export default Home;
