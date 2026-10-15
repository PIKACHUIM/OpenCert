import React, { useMemo, useState } from 'react';
import { useNavigate, Navigate, useLocation } from 'react-router-dom';
import { Form, Input, Button, message, Space } from 'antd';
import {
  UserOutlined, LockOutlined, MailOutlined, IdcardOutlined, SafetyOutlined,
  ArrowLeftOutlined, SafetyCertificateOutlined, CloudServerOutlined,
  ApiOutlined, AuditOutlined,
} from '@ant-design/icons';
import { login, register, forgotPassword, resetPassword, verifyTotp } from '../../api';
import { useAuthStore } from '../../store/auth';
import ThemeToggle from '../../components/ThemeToggle';
import { isTotpChallenge } from '../../types';
import type { TotpChallenge } from '../../types';

/** 品牌区能力点：与门户首页「云端智能卡」区块的卖点保持一致 */
const BRAND_FEATURES: { icon: React.ReactNode; title: string; desc: string }[] = [
  {
    icon: <ApiOutlined />,
    title: '兼容 PKCS#11 / KSP',
    desc: '现有业务系统无需改造，直接调用云端智能卡完成签名与解密。',
  },
  {
    icon: <CloudServerOutlined />,
    title: '私钥不出服务端',
    desc: '本地仅同步公开证书与元数据，签名与解密在云端安全执行。',
  },
  {
    icon: <AuditOutlined />,
    title: '全链路可审计',
    desc: 'CA 签发、吊销、密钥操作与登录行为统一留痕，随时可追溯。',
  },
];

type AuthTab = 'login' | 'register';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { setAuth, isAuthenticated } = useAuthStore();
  const [tab, setTab] = useState<AuthTab>('login');
  const [loginLoading, setLoginLoading] = useState(false);
  const [registerLoading, setRegisterLoading] = useState(false);
  // 找回密码状态
  const [forgotMode, setForgotMode] = useState(false);
  const [forgotStep, setForgotStep] = useState<'email' | 'reset'>('email');
  const [forgotEmail, setForgotEmail] = useState('');
  const [forgotLoading, setForgotLoading] = useState(false);
  // TOTP 二次验证
  const [totp, setTotp] = useState<TotpChallenge | null>(null);
  const [totpLoading, setTotpLoading] = useState(false);

  /**
   * 登录后的落地页：优先 ?redirect=（门户购买等场景），
   * 其次来源路由，最后进入控制台。
   */
  const redirectTo = useMemo(() => {
    const queryRedirect = new URLSearchParams(location.search).get('redirect');
    if (queryRedirect && queryRedirect.startsWith('/')) return queryRedirect;
    const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname;
    return from && from !== '/login' ? from : '/console';
  }, [location.search, location.state]);

  if (isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  const handleLogin = async (values: { username: string; password: string }) => {
    setLoginLoading(true);
    try {
      const resp = await login(values);
      // 服务端在绑定 TOTP 时不返回 token，需要继续二次验证
      if (isTotpChallenge(resp)) {
        setTotp(resp);
        message.info('请输入动态验证码完成二次验证');
        return;
      }
      setAuth(resp);
      message.success('登录成功');
      navigate(redirectTo, { replace: true });
    } catch (err: any) {
      message.error(err.message || '用户名或密码错误');
    } finally {
      setLoginLoading(false);
    }
  };

  /** 提交 TOTP 验证码，成功后拿到正式 token */
  const handleTotpVerify = async (values: { code: string }) => {
    if (!totp) return;
    setTotpLoading(true);
    try {
      const auth = await verifyTotp({ session_token: totp.session_token, code: values.code });
      setAuth(auth);
      message.success('登录成功');
      navigate(redirectTo, { replace: true });
    } catch (err: any) {
      message.error(err.message || '验证码错误');
      // 会话过期或验证码错误次数过多时回到密码登录
      setTotp(null);
    } finally {
      setTotpLoading(false);
    }
  };

  const handleRegister = async (values: { username: string; password: string; confirm: string; email: string; display_name: string }) => {
    if (values.password !== values.confirm) { message.error('两次密码不一致'); return; }
    setRegisterLoading(true);
    try {
      const auth = await register({ username: values.username, password: values.password, email: values.email, display_name: values.display_name });
      setAuth(auth);
      message.success('注册成功');
      navigate(redirectTo, { replace: true });
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

  /** 卡片标题随模式切换 */
  const head = totp
    ? { title: '两步验证', desc: '该账号已启用动态口令牌，请输入验证器应用中的 6 位验证码。' }
    : forgotMode
      ? (forgotStep === 'email'
        ? { title: '找回密码', desc: '输入注册邮箱，我们会发送验证码用于重置密码。' }
        : { title: '重置密码', desc: `验证码已发送至 ${forgotEmail}，请在有效期内完成重置。` })
      : tab === 'login'
        ? { title: '欢迎回来', desc: '登录控制台，管理证书、云端卡片与订单。' }
        : { title: '创建账号', desc: '注册后即可申领数字证书并使用云端智能卡。' };

  const year = new Date().getFullYear();

  return (
    <div className="oc-auth">
      {/* ---- 左侧品牌区 ---- */}
      <aside className="oc-auth__aside">
        <div className="oc-auth__brand">
          <span className="oc-logo-mark">
            <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 19 }} />
          </span>
          <div>
            <div className="oc-auth__brand-name">OpenCert Platform</div>
            <div className="oc-auth__brand-sub">Certificate Authority Cloud</div>
          </div>
        </div>

        <div className="oc-auth__pitch">
          <span className="oc-auth__eyebrow">
            <SafetyOutlined /> 数字证书 · 云端智能卡
          </span>
          <h1 className="oc-auth__headline">
            统一签发数字证书
            <br />
            <em>在设备上安全使用</em>
          </h1>
          <p className="oc-auth__desc">
            从申请、验证、签发到吊销，证书生命周期在一处完成；
            私钥由云端智能卡托管，通过标准接口被系统与应用直接调用。
          </p>

          <div className="oc-auth__features">
            {BRAND_FEATURES.map((f) => (
              <div className="oc-auth__feature" key={f.title}>
                <span className="oc-auth__feature-icon">{f.icon}</span>
                <div>
                  <div className="oc-auth__feature-title">{f.title}</div>
                  <div className="oc-auth__feature-desc">{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="oc-auth__aside-foot">
          <span>© {year} OpenCert Platform</span>
          <span>·</span>
          <span>PKCS#11 · X.509 · ACME</span>
        </div>
      </aside>

      {/* ---- 右侧表单区 ---- */}
      <main className="oc-auth__main">
        <div className="oc-auth__topbar">
          <div className="oc-auth__topbar-brand">
            <span className="oc-logo-mark" style={{ width: 28, height: 28, flex: '0 0 28px', borderRadius: 9 }}>
              <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 15 }} />
            </span>
            OpenCert Platform
          </div>
          <ThemeToggle />
        </div>

        <div className="oc-auth__body">
          <div className="oc-auth__card oc-fade-up">
            {/* 标题 */}
            <div className="oc-auth__card-head">
              <div className="oc-auth__card-title">{head.title}</div>
              <div className="oc-auth__card-sub">{head.desc}</div>
            </div>

            {/* ---- TOTP 二次验证 ---- */}
            {totp ? (
              <div>
                <Button type="text" className="oc-auth__back" icon={<ArrowLeftOutlined />}
                  onClick={() => setTotp(null)}>
                  返回登录
                </Button>
                <Form layout="vertical" onFinish={handleTotpVerify} size="large">
                  <Form.Item name="code" rules={[{ required: true, message: '请输入验证码' }]}>
                    <Input
                      className="oc-field"
                      prefix={<SafetyOutlined />}
                      placeholder="6 位动态验证码" maxLength={8}
                    />
                  </Form.Item>
                  <Form.Item style={{ marginBottom: 0 }}>
                    <Button type="primary" htmlType="submit" block loading={totpLoading} className="oc-submit">
                      验证并登录
                    </Button>
                  </Form.Item>
                </Form>
              </div>
            ) : forgotMode ? (
              <div>
                <Button type="text" className="oc-auth__back" icon={<ArrowLeftOutlined />}
                  onClick={() => { setForgotMode(false); setForgotStep('email'); }}>
                  返回登录
                </Button>

                {forgotStep === 'email' ? (
                  <Form layout="vertical" onFinish={handleForgotSendCode} size="large">
                    <Form.Item name="email" rules={[{ required: true, type: 'email', message: '请输入注册时使用的邮箱' }]}>
                      <Input className="oc-field" prefix={<MailOutlined />} placeholder="注册邮箱" />
                    </Form.Item>
                    <div className="oc-auth__hint">验证码将发送到您的注册邮箱，请注意查收。</div>
                    <Form.Item style={{ marginBottom: 0 }}>
                      <Button type="primary" htmlType="submit" block loading={forgotLoading} className="oc-submit">
                        发送验证码
                      </Button>
                    </Form.Item>
                  </Form>
                ) : (
                  <Form layout="vertical" onFinish={handleResetPassword} size="large">
                    <Form.Item name="code" rules={[{ required: true, message: '请输入6位验证码' }, { len: 6, message: '验证码为6位数字' }]}>
                      <Input className="oc-field" prefix={<SafetyOutlined />} placeholder="6位验证码" maxLength={6} />
                    </Form.Item>
                    <Form.Item name="new_password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}>
                      <Input.Password className="oc-field" prefix={<LockOutlined />} placeholder="新密码（至少8位）" />
                    </Form.Item>
                    <Form.Item name="confirm" rules={[{ required: true, message: '请确认新密码' }]}>
                      <Input.Password className="oc-field" prefix={<LockOutlined />} placeholder="确认新密码" />
                    </Form.Item>
                    <Form.Item style={{ marginBottom: 8 }}>
                      <Button type="primary" htmlType="submit" block loading={forgotLoading} className="oc-submit">
                        重置密码
                      </Button>
                    </Form.Item>
                    <Button type="link" block className="oc-auth__link"
                      onClick={() => setForgotStep('email')}>
                      重新发送验证码
                    </Button>
                  </Form>
                )}
              </div>
            ) : (
              /* ---- 登录 / 注册 ---- */
              <div>
                <div className="oc-seg" role="tablist">
                  <span className="oc-seg__thumb" data-index={tab === 'login' ? 0 : 1} />
                  <button type="button" role="tab" className="oc-seg__btn"
                    data-active={tab === 'login'} onClick={() => setTab('login')}>
                    登录
                  </button>
                  <button type="button" role="tab" className="oc-seg__btn"
                    data-active={tab === 'register'} onClick={() => setTab('register')}>
                    注册
                  </button>
                </div>

                {tab === 'login' ? (
                  <Form layout="vertical" onFinish={handleLogin} size="large">
                    <Form.Item name="username" rules={[{ required: true, message: '请输入用户名' }]}>
                      <Input className="oc-field" prefix={<UserOutlined />} placeholder="用户名" />
                    </Form.Item>
                    <Form.Item name="password" rules={[{ required: true, message: '请输入密码' }]}>
                      <Input.Password className="oc-field" prefix={<LockOutlined />} placeholder="密码" />
                    </Form.Item>
                    <Form.Item style={{ marginBottom: 4 }}>
                      <Button type="primary" htmlType="submit" block loading={loginLoading} className="oc-submit">
                        登录
                      </Button>
                    </Form.Item>
                    <Space style={{ width: '100%', justifyContent: 'center' }}>
                      <Button type="link" className="oc-auth__link"
                        onClick={() => { setForgotMode(true); setForgotStep('email'); }}>
                        忘记密码？
                      </Button>
                    </Space>
                  </Form>
                ) : (
                  <Form layout="vertical" onFinish={handleRegister} size="large">
                    <Form.Item name="username" rules={[{ required: true }, { min: 3, message: '用户名至少3位' }]}>
                      <Input className="oc-field" prefix={<UserOutlined />} placeholder="用户名（至少3位）" />
                    </Form.Item>
                    <Form.Item name="display_name" rules={[{ required: true, message: '请输入显示名称' }]}>
                      <Input className="oc-field" prefix={<IdcardOutlined />} placeholder="显示名称" />
                    </Form.Item>
                    <Form.Item name="email" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
                      <Input className="oc-field" prefix={<MailOutlined />} placeholder="邮箱" />
                    </Form.Item>
                    <Form.Item name="password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}>
                      <Input.Password className="oc-field" prefix={<LockOutlined />} placeholder="密码（至少8位）" />
                    </Form.Item>
                    <Form.Item name="confirm" rules={[{ required: true, message: '请确认密码' }]}>
                      <Input.Password className="oc-field" prefix={<LockOutlined />} placeholder="确认密码" />
                    </Form.Item>
                    <Form.Item style={{ marginBottom: 0 }}>
                      <Button type="primary" htmlType="submit" block loading={registerLoading} className="oc-submit">
                        注册账号
                      </Button>
                    </Form.Item>
                  </Form>
                )}
              </div>
            )}

            <div className="oc-auth__card-foot">
              <span>© {year} OpenCert Platform</span>
              <span>服务节点 server-card :1027</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Login;
