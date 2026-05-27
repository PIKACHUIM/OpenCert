// 登录页：支持三种入口
//   1) 本地登录（默认）：用户名 + 密码
//   2) 云端登录：cloud_url + 用户名 + 密码
//   3) 已有账号：点击卡片直接切换为活跃账号
// 通过 location.state.addMode=true 进入"添加账号模式"——登录成功后不 replace 而是返回上页。
import React, { useState } from 'react';
import { Form, Input, Button, message, Typography, Space, Tabs, List, Avatar, Tag, Empty, Popconfirm } from 'antd';
import {
  UserOutlined, LockOutlined, SafetyCertificateOutlined, CloudOutlined, LinkOutlined,
  LoginOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { login, cloudLogin } from '../../api';
import { useAuthStore } from '../../store/auth';
import { useAppStore } from '../../store/appStore';

const { Title, Text } = Typography;

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const accounts = useAuthStore((s) => s.accounts);
  const addAccount = useAuthStore((s) => s.addAccount);
  const setActive = useAuthStore((s) => s.setActive);
  const removeAccount = useAuthStore((s) => s.removeAccount);
  const { darkMode } = useAppStore();
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<'local' | 'cloud' | 'existing'>(accounts.length > 0 ? 'existing' : 'local');
  const [localForm] = Form.useForm();
  const [cloudForm] = Form.useForm();

  // addMode：MainLayout 通过 {state: {addMode:true}} 触发"添加账号而非顶掉"
  const addMode = Boolean((location.state as any)?.addMode);
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  // 本地登录
  const handleLocalLogin = async () => {
    try {
      const values = await localForm.validateFields();
      setLoading(true);
      const auth = await login(values);
      addAccount(auth, { userType: 'local' });
      message.success(`欢迎 ${auth.username}`);
      navigate(addMode ? -1 as any : from, { replace: !addMode });
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
      message.success(`云端登录成功：${(auth as any).cloud_user || values.username}`);
      navigate(addMode ? -1 as any : from, { replace: !addMode });
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 选择已有账号
  const handlePickAccount = (uuid: string) => {
    setActive(uuid);
    navigate(from, { replace: true });
  };

  const bg = darkMode ? '#0d1117' : '#f0f2f5';
  const cardBg = darkMode ? '#161b22' : '#fff';
  const border = darkMode ? '1px solid rgba(255,255,255,0.08)' : '1px solid rgba(0,0,0,0.06)';

  return (
    <div style={{
      minHeight: '100vh',
      background: bg,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 16,
    }}>
      <div style={{
        width: 440,
        padding: '36px 32px',
        background: cardBg,
        border,
        borderRadius: 16,
        boxShadow: darkMode
          ? '0 8px 40px rgba(0,0,0,0.5)'
          : '0 8px 40px rgba(0,0,0,0.1)',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 24 }}>
          <div style={{
            width: 56,
            height: 56,
            borderRadius: 16,
            background: 'linear-gradient(135deg, #1677ff, #722ed1)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 6px 20px rgba(22,119,255,0.4)',
            marginBottom: 12,
          }}>
            <SafetyCertificateOutlined style={{ fontSize: 28, color: '#fff' }} />
          </div>
          <Title level={4} style={{ margin: 0, color: darkMode ? '#c9d1d9' : '#1a1a2e' }}>
            OpenCert Manager
          </Title>
          <Text style={{ color: darkMode ? '#8b949e' : '#999', fontSize: 13 }}>
            {addMode ? '添加新账号' : '本地智能卡管理系统'}
          </Text>
        </div>

        <Tabs
          activeKey={tab}
          onChange={(k) => setTab(k as any)}
          items={[
            ...(accounts.length > 0 ? [{
              key: 'existing',
              label: (<Space size={4}><LoginOutlined />已有账号</Space>),
              children: (
                <List
                  size="small"
                  dataSource={accounts}
                  locale={{ emptyText: <Empty description="无已保存账号" /> }}
                  renderItem={(a) => (
                    <List.Item
                      actions={[
                        <Popconfirm
                          key="del"
                          title="从本地移除该账号？"
                          onConfirm={() => removeAccount(a.user_uuid)}
                        >
                          <Button type="text" size="small" danger icon={<DeleteOutlined />} />
                        </Popconfirm>,
                      ]}
                      onClick={() => handlePickAccount(a.user_uuid)}
                      style={{ cursor: 'pointer', borderRadius: 8, padding: '8px 10px' }}
                    >
                      <List.Item.Meta
                        avatar={
                          <Avatar
                            style={{
                              background: a.user_type === 'cloud'
                                ? 'linear-gradient(135deg, #1677ff, #13c2c2)'
                                : 'linear-gradient(135deg, #722ed1, #eb2f96)',
                            }}
                            icon={a.user_type === 'cloud' ? <CloudOutlined /> : <UserOutlined />}
                          />
                        }
                        title={
                          <Space>
                            <span style={{ color: darkMode ? '#c9d1d9' : '#333' }}>{a.display_name}</span>
                            {a.user_type === 'cloud' && <Tag color="blue" style={{ fontSize: 11 }}>云端</Tag>}
                          </Space>
                        }
                        description={
                          <Text type="secondary" style={{ fontSize: 11 }}>
                            {a.user_type === 'cloud' ? a.cloud_url : a.username}
                          </Text>
                        }
                      />
                    </List.Item>
                  )}
                />
              ),
            }] : []),
            {
              key: 'local',
              label: (<Space size={4}><UserOutlined />本地登录</Space>),
              children: (
                <Form form={localForm} layout="vertical" onFinish={handleLocalLogin} initialValues={{ username: 'admin' }}>
                  <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                    <Input prefix={<UserOutlined style={{ color: '#8b949e' }} />} placeholder="用户名" size="large" autoComplete="username" />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="密码" size="large" autoComplete="current-password" />
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0, marginTop: 4 }}>
                    <Button
                      type="primary" htmlType="submit" size="large" block loading={loading}
                      style={{
                        background: 'linear-gradient(135deg, #1677ff, #722ed1)',
                        border: 'none', height: 44, fontSize: 15, fontWeight: 600,
                      }}
                    >登 录</Button>
                  </Form.Item>
                </Form>
              ),
            },
            {
              key: 'cloud',
              label: (<Space size={4}><CloudOutlined />云端登录</Space>),
              children: (
                <Form form={cloudForm} layout="vertical" onFinish={handleCloudLogin}>
                  <Form.Item
                    name="cloud_url"
                    rules={[{ required: true, message: '请输入云端 URL' }, { type: 'url', message: 'URL 格式不正确' }]}
                  >
                    <Input prefix={<LinkOutlined style={{ color: '#8b949e' }} />} placeholder="https://server.example.com" size="large" />
                  </Form.Item>
                  <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                    <Input prefix={<UserOutlined style={{ color: '#8b949e' }} />} placeholder="用户名 / 邮箱" size="large" autoComplete="username" />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="密码" size="large" autoComplete="current-password" />
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0, marginTop: 4 }}>
                    <Button
                      type="primary" htmlType="submit" size="large" block loading={loading}
                      style={{
                        background: 'linear-gradient(135deg, #1677ff, #13c2c2)',
                        border: 'none', height: 44, fontSize: 15, fontWeight: 600,
                      }}
                    >云端登录</Button>
                  </Form.Item>
                </Form>
              ),
            },
          ]}
        />

        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <Text style={{ fontSize: 12, color: darkMode ? '#6e7681' : '#bbb' }}>
            {tab === 'local' ? '默认账号：admin / admin' : '同时支持本地与云端多账号并行登录'}
          </Text>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
