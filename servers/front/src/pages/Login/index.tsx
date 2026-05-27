import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Form, Input, Button, Tabs, message, Typography, Space } from 'antd';
import { UserOutlined, LockOutlined, MailOutlined, IdcardOutlined, SafetyOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import { login, register, forgotPassword, resetPassword } from '../../api';
import { useAuthStore } from '../../store/auth';

const { Title, Text } = Typography;

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { setAuth, isAuthenticated } = useAuthStore();
  const [loginLoading, setLoginLoading] = useState(false);
  const [registerLoading, setRegisterLoading] = useState(false);
  // 找回密码状态
  const [forgotMode, setForgotMode] = useState(false);
  const [forgotStep, setForgotStep] = useState<'email' | 'reset'>('email');
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotLoading, setForgotLoading] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleLogin = async (values: { username: string; password: string }) => {
    setLoginLoading(true);
    try {
      const auth = await login(values);
      setAuth(auth);
      message.success('登录成功');
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      message.error(err.message || '用户名或密码错误');
    } finally {
      setLoginLoading(false);
    }
  };

  const handleRegister = async (values: { username: string; password: string; confirm: string; email: string; display_name: string }) => {
    if (values.password !== values.confirm) { message.error('两次密码不一致'); return; }
    setRegisterLoading(true);
    try {
      const auth = await register({ username: values.username, password: values.password, email: values.email, display_name: values.display_name });
      setAuth(auth);
      message.success('注册成功');
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      message.error(err.message || '注册失败');
    } finally {
      setRegisterLoading(false);
    }
  };

  // ---- 找回密码：发送验证码 ----
  const handleForgotSendCode = async (values: { email: string }) => {
    setForgotLoading(true);
    try {
      await forgotPassword(values.email);
      setForgotEmail(values.email);
      setForgotStep('reset');
      message.success('验证码已发送，请检查邮箱');
    } catch (err: any) {
      message.error(err.message || '发送验证码失败');
    } finally {
      setForgotLoading(false);
    }
  };

  // ---- 找回密码：重置密码 ----
  const handleResetPassword = async (values: { code: string; new_password: string; confirm: string }) => {
    if (values.new_password !== values.confirm) { message.error('两次密码不一致'); return; }
    setForgotLoading(true);
    try {
      await resetPassword({ email: forgotEmail, code: values.code, new_password: values.new_password });
      message.success('密码已重置，请重新登录');
      setForgotMode(false);
      setForgotStep('email');
      setForgotEmail('');
    } catch (err: any) {
      message.error(err.message || '重置密码失败');
    } finally {
      setForgotLoading(false);
    }
  };

  // 通用输入框样式
  const inputStyle = { background: 'rgba(13,17,23,0.6)', border: '1px solid rgba(48,54,61,0.8)', color: '#e6edf3', borderRadius: 8 };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%)',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none',
        background: 'radial-gradient(ellipse at 20% 50%, rgba(22,119,255,0.15) 0%, transparent 60%), radial-gradient(ellipse at 80% 20%, rgba(114,46,209,0.1) 0%, transparent 50%)' }} />
      <div style={{
        width: 420, padding: '40px 40px 32px',
        background: 'rgba(22,27,34,0.85)', backdropFilter: 'blur(20px)',
        border: '1px solid rgba(48,54,61,0.8)', borderRadius: 16,
        boxShadow: '0 24px 64px rgba(0,0,0,0.5)', position: 'relative', zIndex: 1,
      }}>
        <Space direction="vertical" align="center" style={{ width: '100%', marginBottom: 32 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 14,
            background: 'linear-gradient(135deg, #1677ff, #722ed1)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 28, boxShadow: '0 8px 24px rgba(22,119,255,0.4)',
          }}>
            <SafetyOutlined style={{ color: '#fff' }} />
          </div>
          <Title level={3} style={{ margin: 0, color: '#e6edf3', fontWeight: 700, letterSpacing: '-0.5px' }}>OpenCert Platform</Title>
          <Text style={{ color: '#8b949e', fontSize: 13 }}>企业级证书管理云平台</Text>
        </Space>

        {/* ---- 找回密码模式 ---- */}
        {forgotMode ? (
          <div>
            <Button type="text" icon={<ArrowLeftOutlined />}
              style={{ color: '#8b949e', marginBottom: 16, padding: 0 }}
              onClick={() => { setForgotMode(false); setForgotStep('email'); }}>
              返回登录
            </Button>
            <Title level={5} style={{ color: '#e6edf3', marginBottom: 16 }}>
              {forgotStep === 'email' ? '找回密码' : '重置密码'}
            </Title>

            {forgotStep === 'email' ? (
              <Form layout="vertical" onFinish={handleForgotSendCode} size="large">
                <Form.Item name="email" rules={[{ required: true, type: 'email', message: '请输入注册时使用的邮箱' }]}>
                  <Input prefix={<MailOutlined style={{ color: '#8b949e' }} />} placeholder="注册邮箱" style={inputStyle} />
                </Form.Item>
                <Text style={{ color: '#8b949e', fontSize: 12, display: 'block', marginBottom: 16 }}>
                  验证码将发送到您的注册邮箱，请注意查收。
                </Text>
                <Form.Item style={{ marginBottom: 0 }}>
                  <Button type="primary" htmlType="submit" block loading={forgotLoading}
                    style={{ height: 44, borderRadius: 8, fontWeight: 600, fontSize: 15,
                      background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none',
                      boxShadow: '0 4px 16px rgba(22,119,255,0.4)' }}>
                    发送验证码
                  </Button>
                </Form.Item>
              </Form>
            ) : (
              <Form layout="vertical" onFinish={handleResetPassword} size="large">
                <Text style={{ color: '#8b949e', fontSize: 12, display: 'block', marginBottom: 12 }}>
                  验证码已发送至 <Text strong style={{ color: '#1677ff' }}>{forgotEmail}</Text>
                </Text>
                <Form.Item name="code" rules={[{ required: true, message: '请输入6位验证码' }, { len: 6, message: '验证码为6位数字' }]}>
                  <Input prefix={<SafetyOutlined style={{ color: '#8b949e' }} />} placeholder="6位验证码" maxLength={6} style={inputStyle} />
                </Form.Item>
                <Form.Item name="new_password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}>
                  <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="新密码（至少8位）" style={inputStyle} />
                </Form.Item>
                <Form.Item name="confirm" rules={[{ required: true, message: '请确认新密码' }]}>
                  <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="确认新密码" style={inputStyle} />
                </Form.Item>
                <Form.Item style={{ marginBottom: 8 }}>
                  <Button type="primary" htmlType="submit" block loading={forgotLoading}
                    style={{ height: 44, borderRadius: 8, fontWeight: 600, fontSize: 15,
                      background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none',
                      boxShadow: '0 4px 16px rgba(22,119,255,0.4)' }}>
                    重置密码
                  </Button>
                </Form.Item>
                <Button type="link" block style={{ color: '#8b949e' }}
                  onClick={() => setForgotStep('email')}>
                  重新发送验证码
                </Button>
              </Form>
            )}
          </div>
        ) : (
          /* ---- 登录/注册模式 ---- */
          <Tabs centered items={[
            {
              key: 'login', label: '登录',
              children: (
                <Form layout="vertical" onFinish={handleLogin} size="large" style={{ marginTop: 8 }}>
                  <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                    <Input prefix={<UserOutlined style={{ color: '#8b949e' }} />} placeholder="用户名" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="密码" style={inputStyle} />
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 8, marginTop: 8 }}>
                    <Button type="primary" htmlType="submit" block loading={loginLoading}
                      style={{ height: 44, borderRadius: 8, fontWeight: 600, fontSize: 15,
                        background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none',
                        boxShadow: '0 4px 16px rgba(22,119,255,0.4)' }}>
                      登录
                    </Button>
                  </Form.Item>
                  <div style={{ textAlign: 'center' }}>
                    <Button type="link" style={{ color: '#8b949e', fontSize: 13 }}
                      onClick={() => { setForgotMode(true); setForgotStep('email'); }}>
                      忘记密码？
                    </Button>
                  </div>
                </Form>
              ),
            },
            {
              key: 'register', label: '注册',
              children: (
                <Form layout="vertical" onFinish={handleRegister} size="large" style={{ marginTop: 8 }}>
                  <Form.Item name="username" rules={[{ required: true }, { min: 3, message: '用户名至少3位' }]}>
                    <Input prefix={<UserOutlined style={{ color: '#8b949e' }} />} placeholder="用户名（至少3位）" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="display_name" rules={[{ required: true, message: '请输入显示名称' }]}>
                    <Input prefix={<IdcardOutlined style={{ color: '#8b949e' }} />} placeholder="显示名称" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="email" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
                    <Input prefix={<MailOutlined style={{ color: '#8b949e' }} />} placeholder="邮箱" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="密码（至少8位）" style={inputStyle} />
                  </Form.Item>
                  <Form.Item name="confirm" rules={[{ required: true, message: '请确认密码' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="确认密码" style={inputStyle} />
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0, marginTop: 8 }}>
                    <Button type="primary" htmlType="submit" block loading={registerLoading}
                      style={{ height: 44, borderRadius: 8, fontWeight: 600, fontSize: 15,
                        background: 'linear-gradient(135deg, #722ed1, #531dab)', border: 'none',
                        boxShadow: '0 4px 16px rgba(114,46,209,0.4)' }}>
                      注册账号
                    </Button>
                  </Form.Item>
                </Form>
              ),
            },
          ]} />
        )}

        <div style={{ textAlign: 'center', marginTop: 24, paddingTop: 16, borderTop: '1px solid rgba(48,54,61,0.5)' }}>
          <Text style={{ color: '#8b949e', fontSize: 12 }}>© 2025 OpenCert Platform · 连接 server-card :1027</Text>
        </div>
      </div>
    </div>
  );
};

export default Login;
