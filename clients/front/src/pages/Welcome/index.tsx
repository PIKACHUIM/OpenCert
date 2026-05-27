// 首次运行向导页：当数据库无用户时自动跳转至此。
// 提供两个入口：注册本地账号 / 登录云端账号。
import React, { useState } from 'react';
import { Form, Input, Button, message, Typography, Space, Card, Row, Col } from 'antd';
import {
  UserOutlined, LockOutlined, SafetyCertificateOutlined, CloudOutlined,
  LinkOutlined, MailOutlined, IdcardOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { register, cloudLogin } from '../../api';
import { useAuthStore } from '../../store/auth';
import { useAppStore } from '../../store/appStore';

const { Title, Text, Paragraph } = Typography;

const WelcomePage: React.FC = () => {
  const navigate = useNavigate();
  const addAccount = useAuthStore((s) => s.addAccount);
  const { darkMode } = useAppStore();
  const [mode, setMode] = useState<'choose' | 'register' | 'cloud'>('choose');
  const [loading, setLoading] = useState(false);
  const [regForm] = Form.useForm();
  const [cloudForm] = Form.useForm();

  const bg = darkMode ? '#0d1117' : '#f0f2f5';
  const cardBg = darkMode ? '#161b22' : '#fff';
  const border = darkMode ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(0,0,0,0.06)';

  // 注册本地账号
  const handleRegister = async () => {
    try {
      const values = await regForm.validateFields();
      setLoading(true);
      const auth = await register(values);
      addAccount(auth, { userType: 'local' });
      message.success('注册成功，欢迎使用 OpenCert Manager！');
      navigate('/dashboard', { replace: true });
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 云端登录
  const handleCloudLogin = async () => {
    try {
      const values = await cloudForm.validateFields();
      setLoading(true);
      const auth = await cloudLogin(values);
      addAccount(auth as any, {
        userType: 'cloud',
        cloudUrl: (auth as any).cloud_url || values.cloud_url,
        cloudUser: (auth as any).cloud_user || values.username,
        expiresAt: (auth as any).expires_at,
      });
      message.success('云端登录成功！');
      navigate('/dashboard', { replace: true });
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 选择入口
  if (mode === 'choose') {
    return (
      <div style={{ minHeight: '100vh', background: bg, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <div style={{ maxWidth: 640, width: '100%' }}>
          {/* Logo */}
          <div style={{ textAlign: 'center', marginBottom: 40 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 20,
              background: 'linear-gradient(135deg, #1677ff, #722ed1)',
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 8px 24px rgba(22,119,255,0.4)', marginBottom: 16,
            }}>
              <SafetyCertificateOutlined style={{ fontSize: 36, color: '#fff' }} />
            </div>
            <Title level={2} style={{ margin: 0, color: darkMode ? '#c9d1d9' : '#1a1a2e' }}>
              欢迎使用 OpenCert Manager
            </Title>
            <Paragraph style={{ color: darkMode ? '#8b949e' : '#999', fontSize: 14, marginTop: 8 }}>
              本地智能卡与证书管理系统 · 首次运行配置
            </Paragraph>
          </div>

          <Row gutter={24}>
            <Col xs={24} sm={12}>
              <Card
                hoverable
                onClick={() => setMode('register')}
                style={{ background: cardBg, border, borderRadius: 16, textAlign: 'center', height: '100%' }}
              >
                <div style={{
                  width: 56, height: 56, borderRadius: 14,
                  background: 'linear-gradient(135deg, #722ed1, #eb2f96)',
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  marginBottom: 16,
                }}>
                  <UserOutlined style={{ fontSize: 26, color: '#fff' }} />
                </div>
                <Title level={4} style={{ color: darkMode ? '#c9d1d9' : '#333' }}>注册本地账号</Title>
                <Text type="secondary">数据完全存储在本地，无需联网</Text>
              </Card>
            </Col>
            <Col xs={24} sm={12}>
              <Card
                hoverable
                onClick={() => setMode('cloud')}
                style={{ background: cardBg, border, borderRadius: 16, textAlign: 'center', height: '100%' }}
              >
                <div style={{
                  width: 56, height: 56, borderRadius: 14,
                  background: 'linear-gradient(135deg, #1677ff, #13c2c2)',
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  marginBottom: 16,
                }}>
                  <CloudOutlined style={{ fontSize: 26, color: '#fff' }} />
                </div>
                <Title level={4} style={{ color: darkMode ? '#c9d1d9' : '#333' }}>登录云端账号</Title>
                <Text type="secondary">连接已有的 OpenCert 云端服务</Text>
              </Card>
            </Col>
          </Row>

          <div style={{ textAlign: 'center', marginTop: 32 }}>
            <Button type="link" onClick={() => navigate('/login')}>跳过，稍后配置</Button>
          </div>
        </div>
      </div>
    );
  }

  // 注册表单
  if (mode === 'register') {
    return (
      <div style={{ minHeight: '100vh', background: bg, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <div style={{ width: 420, padding: '36px 32px', background: cardBg, border, borderRadius: 16, boxShadow: darkMode ? '0 8px 40px rgba(0,0,0,0.5)' : '0 8px 40px rgba(0,0,0,0.1)' }}>
          <div style={{ textAlign: 'center', marginBottom: 24 }}>
            <Title level={4} style={{ color: darkMode ? '#c9d1d9' : '#333' }}>注册本地账号</Title>
            <Text type="secondary">创建您的第一个本地管理员账号</Text>
          </div>
          <Form form={regForm} layout="vertical" onFinish={handleRegister}>
            <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }, { min: 3, message: '至少 3 个字符' }]}>
              <Input prefix={<UserOutlined />} placeholder="用户名" size="large" />
            </Form.Item>
            <Form.Item name="display_name" rules={[{ required: true, message: '请输入显示名称' }]}>
              <Input prefix={<IdcardOutlined />} placeholder="显示名称" size="large" />
            </Form.Item>
            <Form.Item name="email">
              <Input prefix={<MailOutlined />} placeholder="邮箱（可选）" size="large" />
            </Form.Item>
            <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }, { min: 8, message: '至少 8 个字符' }]}>
              <Input.Password prefix={<LockOutlined />} placeholder="密码" size="large" />
            </Form.Item>
            <Form.Item style={{ marginBottom: 8 }}>
              <Button type="primary" htmlType="submit" size="large" block loading={loading}
                style={{ background: 'linear-gradient(135deg, #722ed1, #eb2f96)', border: 'none', height: 44, fontWeight: 600 }}>
                注册并开始使用
              </Button>
            </Form.Item>
          </Form>
          <div style={{ textAlign: 'center' }}>
            <Button type="link" onClick={() => setMode('choose')}>← 返回选择</Button>
          </div>
        </div>
      </div>
    );
  }

  // 云端登录表单
  return (
    <div style={{ minHeight: '100vh', background: bg, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
      <div style={{ width: 420, padding: '36px 32px', background: cardBg, border, borderRadius: 16, boxShadow: darkMode ? '0 8px 40px rgba(0,0,0,0.5)' : '0 8px 40px rgba(0,0,0,0.1)' }}>
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <Title level={4} style={{ color: darkMode ? '#c9d1d9' : '#333' }}>登录云端账号</Title>
          <Text type="secondary">连接您的 OpenCert 云端服务</Text>
        </div>
        <Form form={cloudForm} layout="vertical" onFinish={handleCloudLogin}>
          <Form.Item name="cloud_url" rules={[{ required: true, message: '请输入云端 URL' }]}>
            <Input prefix={<LinkOutlined />} placeholder="https://server.example.com" size="large" />
          </Form.Item>
          <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input prefix={<UserOutlined />} placeholder="用户名" size="large" />
          </Form.Item>
          <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password prefix={<LockOutlined />} placeholder="密码" size="large" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 8 }}>
            <Button type="primary" htmlType="submit" size="large" block loading={loading}
              style={{ background: 'linear-gradient(135deg, #1677ff, #13c2c2)', border: 'none', height: 44, fontWeight: 600 }}>
              云端登录
            </Button>
          </Form.Item>
        </Form>
        <div style={{ textAlign: 'center' }}>
          <Button type="link" onClick={() => setMode('choose')}>← 返回选择</Button>
        </div>
      </div>
    </div>
  );
};

export default WelcomePage;
