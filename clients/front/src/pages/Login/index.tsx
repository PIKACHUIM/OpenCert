// 登录页：支持三种入口
//   1) 本地登录（默认）：用户名 + 密码
//   2) 云端登录：cloud_url + 用户名 + 密码
//   3) 已有账号：点击卡片直接切换为活跃账号
// 通过 location.state.addMode=true 进入"添加账号模式"——登录成功后不 replace 而是返回上页。
import React, { useState, useEffect } from 'react';
import { Form, Input, Button, message, Typography, Space, Tabs, List, Avatar, Tag, Empty, Popconfirm, Checkbox } from 'antd';
import {
  UserOutlined, LockOutlined, SafetyCertificateOutlined, CloudOutlined, LinkOutlined,
  LoginOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { login, cloudLogin } from '../../api';
import { useAuthStore } from '../../store/auth';
import { useAppStore } from '../../store/appStore';

const { Title, Text } = Typography;

// 记住密码功能的 localStorage keys
const LS_REMEMBER_LOCAL = 'login_remember_local';
const LS_REMEMBER_CLOUD = 'login_remember_cloud';
const LS_SAVED_LOCAL = 'login_saved_local';
const LS_SAVED_CLOUD = 'login_saved_cloud';

function loadSavedCreds(key: string): { username?: string; password?: string; cloud_url?: string } {
  try {
    const raw = localStorage.getItem(key);
    if (raw) return JSON.parse(raw);
  } catch { /* ignore */ }
  return {};
}

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const accounts = useAuthStore((s) => s.accounts);
  const addAccount = useAuthStore((s) => s.addAccount);
  const removeAccount = useAuthStore((s) => s.removeAccount);
  const { darkMode } = useAppStore();

  // addMode：MainLayout 通过 {state: {addMode:true}} 触发"添加账号而非顶掉"
  const addMode = Boolean((location.state as any)?.addMode);
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<'local' | 'cloud' | 'existing'>(() => {
    if (addMode) return 'local';
    if (accounts.length > 0) return 'existing';
    return 'local';
  });
  const [localForm] = Form.useForm();
  const [cloudForm] = Form.useForm();
  const [rememberLocal, setRememberLocal] = useState(() => localStorage.getItem(LS_REMEMBER_LOCAL) === 'true');
  const [rememberCloud, setRememberCloud] = useState(() => localStorage.getItem(LS_REMEMBER_CLOUD) === 'true');

  // 加载已保存的凭据
  useEffect(() => {
    if (rememberLocal) {
      const saved = loadSavedCreds(LS_SAVED_LOCAL);
      if (saved.username) localForm.setFieldsValue(saved);
    }
    if (rememberCloud) {
      const saved = loadSavedCreds(LS_SAVED_CLOUD);
      if (saved.username) cloudForm.setFieldsValue(saved);
    }
  }, []);

  // 2FA 状态
  const [need2FA, setNeed2FA] = useState(false);
  const [pending2FAValues, setPending2FAValues] = useState<any>(null);
  const [totpCode, setTotpCode] = useState('');

  // 本地登录
  const handleLocalLogin = async (extraData?: { totp_code?: string }) => {
    try {
      const values = extraData ? { ...pending2FAValues, ...extraData } : await localForm.validateFields();
      setLoading(true);
      const auth = await login(values);
      // 保存/清除凭据
      if (rememberLocal) {
        localStorage.setItem(LS_REMEMBER_LOCAL, 'true');
        localStorage.setItem(LS_SAVED_LOCAL, JSON.stringify({ username: values.username, password: values.password }));
      } else {
        localStorage.removeItem(LS_REMEMBER_LOCAL);
        localStorage.removeItem(LS_SAVED_LOCAL);
      }
      setNeed2FA(false);
      setTotpCode('');
      // 勾选了记住密码则把密码存入账号记录，用于进程重启后静默重新登录
      addAccount(auth, { userType: 'local', savedPassword: rememberLocal ? values.password : undefined });
      message.success(`欢迎 ${auth.username}`);
      navigate(addMode ? -1 as any : from, { replace: !addMode });
    } catch (e: any) {
      // 检查是否需要 2FA
      if (e?.response?.status === 428 || e?.response?.data?.code === 428) {
        const values = await localForm.validateFields();
        setPending2FAValues(values);
        setNeed2FA(true);
        setTotpCode('');
        message.info('需要输入 2FA 验证码');
      } else {
        if (e.message) message.error(e.message);
        else if (e?.response?.data?.message) message.error(e.response.data.message);
      }
    } finally {
      setLoading(false);
    }
  };

  // 提交 2FA 验证码
  const handle2FASubmit = () => {
    if (!totpCode || totpCode.length < 6) {
      message.warning('请输入 6 位验证码');
      return;
    }
    handleLocalLogin({ totp_code: totpCode });
  };

  // 云端登录
  const handleCloudLogin = async () => {
    try {
      const values = await cloudForm.validateFields();
      setLoading(true);
      const auth = await cloudLogin(values);
      // 保存/清除凭据
      if (rememberCloud) {
        localStorage.setItem(LS_REMEMBER_CLOUD, 'true');
        localStorage.setItem(LS_SAVED_CLOUD, JSON.stringify({ cloud_url: values.cloud_url, username: values.username, password: values.password }));
      } else {
        localStorage.removeItem(LS_REMEMBER_CLOUD);
        localStorage.removeItem(LS_SAVED_CLOUD);
      }
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

  // 记住密码切换
  const handleRememberLocalChange = (checked: boolean) => {
    setRememberLocal(checked);
    if (!checked) {
      localStorage.removeItem(LS_REMEMBER_LOCAL);
      localStorage.removeItem(LS_SAVED_LOCAL);
    }
  };
  const handleRememberCloudChange = (checked: boolean) => {
    setRememberCloud(checked);
    if (!checked) {
      localStorage.removeItem(LS_REMEMBER_CLOUD);
      localStorage.removeItem(LS_SAVED_CLOUD);
    }
  };

  // 选择已有账号：用保存的密码重新登录（进程重启后 token 已失效，需重新获取）
  const handlePickAccount = async (uuid: string) => {
    const account = accounts.find((a) => a.user_uuid === uuid);
    if (!account) return;

    // 有保存的密码则静默重新登录，拿到新 token
    if (account.saved_password) {
      setLoading(true);
      try {
        const auth = await login({ username: account.username, password: account.saved_password });
        addAccount(auth, { userType: account.user_type as 'local', savedPassword: account.saved_password });
        message.success(`欢迎回来，${account.display_name}`);
        navigate(from, { replace: true });
      } catch {
        message.error('自动登录失败，请手动输入密码');
        setTab('local');
        localForm.setFieldsValue({ username: account.username });
      } finally {
        setLoading(false);
      }
    } else {
      // 没有保存密码，切到本地登录 Tab 并预填用户名
      setTab('local');
      localForm.setFieldsValue({ username: account.username });
      message.info('请输入密码登录');
    }
  };

  // 删除账号后，若账号列表为空则切换到本地登录 Tab
  const handleRemoveAccount = (uuid: string) => {
    removeAccount(uuid);
    // 删除后账号数量 -1，若只剩 1 个（即删完后为 0）则切换 Tab
    if (accounts.length <= 1) {
      setTab('local');
    }
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
            // 有已有账号时显示账号切换列表
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
                          onConfirm={(e) => { e?.stopPropagation(); handleRemoveAccount(a.user_uuid); }}
                          onCancel={(e) => e?.stopPropagation()}
                        >
                          <Button
                            type="text"
                            size="small"
                            danger
                            icon={<DeleteOutlined />}
                            onClick={(e) => e.stopPropagation()}
                          />
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
            // 本地登录和云端登录始终显示
            ...[
            {
              key: 'local',
              label: (<Space size={4}><UserOutlined />本地登录</Space>),
              children: (
                <Form form={localForm} layout="vertical" onFinish={() => handleLocalLogin()} initialValues={{ username: 'admin' }}>
                  <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                    <Input prefix={<UserOutlined style={{ color: '#8b949e' }} />} placeholder="用户名" size="large" autoComplete="username" />
                  </Form.Item>
                  <Form.Item name="password" rules={[{ required: !need2FA, message: '请输入密码' }]}>
                    <Input.Password prefix={<LockOutlined style={{ color: '#8b949e' }} />} placeholder="密码" size="large" autoComplete="current-password" />
                  </Form.Item>
                  {need2FA && (
                    <Form.Item label={<Text style={{ color: darkMode ? '#c9d1d9' : '#333' }}>2FA 验证码</Text>}>
                      <Space.Compact style={{ width: '100%' }}>
                        <Input
                          prefix={<SafetyCertificateOutlined style={{ color: '#52c41a' }} />}
                          placeholder="输入 6 位验证码"
                          size="large"
                          maxLength={6}
                          value={totpCode}
                          onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                          onPressEnter={handle2FASubmit}
                          style={{ flex: 1 }}
                        />
                        <Button type="primary" size="large" onClick={handle2FASubmit} loading={loading}
                          style={{ background: '#52c41a', border: 'none' }}>
                          验证
                        </Button>
                      </Space.Compact>
                    </Form.Item>
                  )}
                  <Form.Item style={{ marginBottom: 12 }}>
                    <Checkbox checked={rememberLocal} onChange={(e) => handleRememberLocalChange(e.target.checked)}>
                      <Text style={{ fontSize: 13, color: darkMode ? '#8b949e' : '#666' }}>记住密码</Text>
                    </Checkbox>
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0 }}>
                    <Button
                      type="primary" htmlType="submit" size="large" block loading={loading}
                      style={{
                        background: 'linear-gradient(135deg, #1677ff, #722ed1)',
                        border: 'none', height: 44, fontSize: 15, fontWeight: 600,
                      }}
                    >{need2FA ? '重新登录' : '登 录'}</Button>
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
                  <Form.Item style={{ marginBottom: 12 }}>
                    <Checkbox checked={rememberCloud} onChange={(e) => handleRememberCloudChange(e.target.checked)}>
                      <Text style={{ fontSize: 13, color: darkMode ? '#8b949e' : '#666' }}>记住密码</Text>
                    </Checkbox>
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0 }}>
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
            ],
          ]}
        />

        <div style={{ textAlign: 'center', marginTop: 16 }}>
          {accounts.length > 0 && !addMode ? (
            <Button
              type="link"
              size="small"
              onClick={() => setTab('local')}
              style={{ fontSize: 12, color: darkMode ? '#6e7681' : '#999' }}
            >
              + 使用其他账号登录
            </Button>
          ) : (
            <Text style={{ fontSize: 12, color: darkMode ? '#6e7681' : '#bbb' }}>
              {tab === 'local' ? '默认账号：admin / admin' : '同时支持本地与云端多账号并行登录'}
            </Text>
          )}
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
