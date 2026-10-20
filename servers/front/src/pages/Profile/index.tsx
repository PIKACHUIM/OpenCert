import React, { useState, useEffect } from 'react';
import {
  Tabs, Form, Input, Button, message, Typography, Space, Upload, Card, Descriptions,
  Divider, Row, Col, Statistic, Table, Tag, Modal, InputNumber, Select, Alert, List, Empty,
} from 'antd';
import {
  UserOutlined, LockOutlined, KeyOutlined, LogoutOutlined, UploadOutlined,
  WalletOutlined, PlusOutlined, GiftOutlined, CrownOutlined,
} from '@ant-design/icons';
import {
  getMe, updateMe, changePassword, updatePubkey, logout,
  getBalance, createRecharge, listPaymentOrders, listMyRefunds,
  listPortalPaymentChannels, listMySubscriptions, listPlans, buyPlan, redeemCode,
} from '../../api';
import { useAuthStore } from '../../store/auth';
import { useNavigate, useSearchParams } from 'react-router-dom';
import type { User, UserBalance, PaymentOrder, PortalRefund, Subscription, PromoPlan, PaymentChannel } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text, Paragraph } = Typography;

/**
 * 账号信息管理：账号资料、安全设置、云端公钥，以及合并后的财务与订阅
 * （余额与充值、充值/消费记录、退款工单、订阅套餐购买与兑换码，原「财务支付管理」页面）。
 */
const Profile: React.FC = () => {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') || 'info';
  const { clearAuth, username } = useAuthStore();

  const [user, setUser] = useState<User | null>(null);
  const [infoLoading, setInfoLoading] = useState(false);
  const [pwdLoading, setPwdLoading] = useState(false);
  const [pubkeyLoading, setPubkeyLoading] = useState(false);
  const [infoForm] = Form.useForm();
  const [pwdForm] = Form.useForm();
  const [pubkeyForm] = Form.useForm();

  // ---- 财务与订阅 ----
  const [balance, setBalance] = useState<UserBalance | null>(null);
  const [orders, setOrders] = useState<PaymentOrder[]>([]);
  const [refunds, setRefunds] = useState<PortalRefund[]>([]);
  const [subs, setSubs] = useState<Subscription[]>([]);
  const [plans, setPlans] = useState<PromoPlan[]>([]);
  const [channels, setChannels] = useState<PaymentChannel[]>([]);
  const [rechargeOpen, setRechargeOpen] = useState(false);
  const [rechargeLoading, setRechargeLoading] = useState(false);
  const [redeemValue, setRedeemValue] = useState('');
  const [redeemLoading, setRedeemLoading] = useState(false);
  const [buyPlanTarget, setBuyPlanTarget] = useState<PromoPlan | null>(null);
  const [buyLoading, setBuyLoading] = useState(false);
  const [rechargeForm] = Form.useForm();
  const [buyForm] = Form.useForm();

  useEffect(() => {
    getMe().then((u) => {
      setUser(u);
      infoForm.setFieldsValue({ display_name: u.display_name, email: u.email });
    }).catch(() => {});
  }, []);

  const loadFinance = async () => {
    try {
      const [bal, ord, ref, sub, pl, ch] = await Promise.all([
        getBalance().catch(() => null),
        listPaymentOrders({ page: 1, page_size: 20 }).catch(() => ({ items: [] })),
        listMyRefunds({ page: 1, page_size: 20 }).catch(() => [] as PortalRefund[]),
        listMySubscriptions().catch(() => [] as Subscription[]),
        listPlans().catch(() => [] as PromoPlan[]),
        listPortalPaymentChannels().catch(() => [] as PaymentChannel[]),
      ]);
      setBalance(bal);
      setOrders((ord as any)?.items ?? []);
      setRefunds(ref ?? []);
      setSubs(sub ?? []);
      setPlans(pl ?? []);
      setChannels(ch ?? []);
    } catch { /* 财务接口异常不阻塞资料页 */ }
  };

  useEffect(() => { if (tab === 'finance') loadFinance(); }, [tab]);

  const handleUpdateInfo = async (values: { display_name: string; email: string }) => {
    setInfoLoading(true);
    try {
      const updated = await updateMe(values);
      setUser(updated);
      message.success('个人信息已更新');
    } catch (err: any) { message.error(err.message || '更新失败'); }
    finally { setInfoLoading(false); }
  };

  const handleChangePassword = async (values: { old_password: string; new_password: string; confirm: string }) => {
    if (values.new_password !== values.confirm) { message.error('两次密码不一致'); return; }
    setPwdLoading(true);
    try {
      await changePassword({ old_password: values.old_password, new_password: values.new_password });
      message.success('密码已修改，请重新登录');
      pwdForm.resetFields();
    } catch (err: any) { message.error(err.message || '修改失败'); }
    finally { setPwdLoading(false); }
  };

  const handleUpdatePubkey = async (values: { pubkey_pem: string }) => {
    setPubkeyLoading(true);
    try {
      await updatePubkey(values.pubkey_pem);
      message.success('云端公钥已更新');
      pubkeyForm.resetFields();
    } catch (err: any) { message.error(err.message || '更新失败'); }
    finally { setPubkeyLoading(false); }
  };

  const handleLogout = async () => {
    try { await logout(); } catch {}
    clearAuth();
    navigate('/login', { replace: true });
  };

  const handleRecharge = async (values: { amount: number; channel: string }) => {
    setRechargeLoading(true);
    try {
      const order = await createRecharge({ amount: Math.round(values.amount * 100), channel: values.channel });
      message.success('充值订单已创建');
      if ((order as any).pay_url) window.open((order as any).pay_url, '_blank');
      setRechargeOpen(false); rechargeForm.resetFields(); loadFinance();
    } catch (e: any) { message.error(e.message || '充值失败'); }
    finally { setRechargeLoading(false); }
  };

  const handleRedeem = async () => {
    if (!redeemValue.trim()) return;
    setRedeemLoading(true);
    try {
      const r = await redeemCode(redeemValue.trim());
      message.success(r.grant_type === 'balance'
        ? `已充值 ¥${((r.balance_cents ?? 0) / 100).toFixed(2)}`
        : '订阅套餐已到账');
      setRedeemValue('');
      loadFinance();
    } catch (e: any) { message.error(e.message || '兑换失败'); }
    finally { setRedeemLoading(false); }
  };

  const handleBuyPlan = async (v: any) => {
    if (!buyPlanTarget) return;
    setBuyLoading(true);
    try {
      const order = await buyPlan(buyPlanTarget.code, { applicant_email: v.applicant_email, coupon_code: v.coupon_code });
      message.success('订单已创建，请完成支付');
      setBuyPlanTarget(null);
      buyForm.resetFields();
      navigate(`/checkout/${order.order_no}`);
    } catch (e: any) { message.error(e.message || '下单失败'); }
    finally { setBuyLoading(false); }
  };

  const financeTab = (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} md={8}>
          <Card><Statistic title="可用余额" prefix={<WalletOutlined />} suffix="元"
            value={balance ? (balance.available_cents / 100).toFixed(2) : '—'} valueStyle={{ color: '#1677ff' }} /></Card>
        </Col>
        <Col xs={24} md={8}>
          <Card><Statistic title="累计充值" suffix="元"
            value={balance ? (balance.total_recharge / 100).toFixed(2) : '—'} valueStyle={{ color: '#52c41a' }} /></Card>
        </Col>
        <Col xs={24} md={8}>
          <Card><Statistic title="累计消费" suffix="元"
            value={balance ? (balance.total_consume / 100).toFixed(2) : '—'} valueStyle={{ color: '#fa8c16' }} /></Card>
        </Col>
      </Row>

      <Space style={{ marginBottom: 16 }} wrap>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setRechargeOpen(true)}>充值</Button>
        <Input
          style={{ width: 220 }} placeholder="输入兑换码" value={redeemValue}
          onChange={(e) => setRedeemValue(e.target.value)} onPressEnter={handleRedeem} allowClear
        />
        <Button icon={<GiftOutlined />} loading={redeemLoading} onClick={handleRedeem}>兑换</Button>
      </Space>

      <Card size="small" title={<Space><CrownOutlined />我的订阅</Space>} style={{ marginBottom: 16 }}>
        {subs.length === 0 ? <Empty description="暂无订阅" image={Empty.PRESENTED_IMAGE_SIMPLE} /> : (
          <List
            dataSource={subs}
            renderItem={(s) => (
              <List.Item
                actions={[<Button key="apply" type="primary" size="small"
                  onClick={() => navigate(`/console/apply?subscription=${s.uuid}`)}>去申请</Button>]}
              >
                <List.Item.Meta
                  title={<Space>{s.plan?.name}
                    {s.status === 'active' && new Date(s.ends_at) > new Date()
                      ? <Tag color="green">生效中</Tag> : <Tag>已失效</Tag>}</Space>}
                  description={
                    <Space direction="vertical" size={0}>
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        有效期至 {new Date(s.ends_at).toLocaleDateString('zh-CN')} ·
                        {s.plan?.allow_revoke ? ' 允许自行吊销' : ' 不允许自行吊销'}
                      </Text>
                      {(s.usage ?? []).map((u, i) => (
                        <Text key={i} style={{ fontSize: 12 }}>
                          {u.template_name || u.cert_apply_tmpl_uuid.slice(0, 8)}：剩余 {u.remaining}/{u.quota} 张
                        </Text>
                      ))}
                    </Space>
                  }
                />
              </List.Item>
            )}
          />
        )}
        {plans.length > 0 && (
          <>
            <Divider style={{ margin: '12px 0' }} />
            <Space wrap>
              {plans.map((p) => (
                <Card key={p.uuid} size="small" style={{ width: 260 }}>
                  <Space direction="vertical" size={4} style={{ width: '100%' }}>
                    <Space><Text strong>{p.name}</Text><Tag color="gold">{p.period_days} 天</Tag></Space>
                    <Text style={{ fontSize: 20, color: '#fa8c16' }}>¥{(p.price_cents / 100).toFixed(2)}</Text>
                    {(p.items ?? []).map((it, i) => (
                      <Text key={i} type="secondary" style={{ fontSize: 12 }}>
                        含 {it.quota} 张证书{it.valid_days > 0 ? `（单证 ${it.valid_days} 天）` : ''}
                      </Text>
                    ))}
                    <Text type="secondary" style={{ fontSize: 12 }}>{p.description}</Text>
                    <Button type="primary" block onClick={() => { setBuyPlanTarget(p); buyForm.resetFields(); }}>
                      立即购买
                    </Button>
                  </Space>
                </Card>
              ))}
            </Space>
          </>
        )}
      </Card>

      <Card size="small" title="充值记录" style={{ marginBottom: 16 }}>
        <Table
          rowKey="uuid" size="small" dataSource={orders} pagination={false}
          columns={[
            { title: '订单号', dataIndex: 'uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v?.slice(0, 16)}…</Text> },
            { title: '金额', dataIndex: 'amount', render: (v: number) => `¥${((v ?? 0) / 100).toFixed(2)}` },
            { title: '渠道', dataIndex: 'channel' },
            { title: '状态', dataIndex: 'status', render: (v: string) => <Tag>{v}</Tag> },
            { title: '时间', dataIndex: 'created_at', render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
          ]}
        />
      </Card>

      <Card size="small" title="我的退款工单">
        <Table
          rowKey="uuid" size="small" dataSource={refunds} pagination={false}
          columns={[
            { title: '订单号', dataIndex: 'order_no' },
            { title: '金额', dataIndex: 'amount_cents', render: (v: number) => `¥${((v ?? 0) / 100).toFixed(2)}` },
            { title: '原因', dataIndex: 'reason', ellipsis: true },
            { title: '状态', dataIndex: 'status', render: (v: string) => ({
              pending: <Tag color="orange">待审批</Tag>, paid: <Tag color="green">已退款</Tag>, failed: <Tag color="red">失败</Tag>,
            } as any)[v] ?? <Tag>{v}</Tag> },
            { title: '时间', dataIndex: 'created_at', render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
          ]}
        />
      </Card>

      <Modal open={rechargeOpen} title="账户充值" onCancel={() => setRechargeOpen(false)}
        onOk={() => rechargeForm.submit()} confirmLoading={rechargeLoading} destroyOnClose>
        <Form form={rechargeForm} layout="vertical" onFinish={handleRecharge}>
          <Form.Item label="充值金额（元）" name="amount" rules={[{ required: true }, { type: 'number', min: 1, message: '最低 1 元' }]}>
            <InputNumber min={1} precision={2} style={{ width: '100%' }} addonAfter="元" />
          </Form.Item>
          <Form.Item label="支付渠道" name="channel" rules={[{ required: true, message: '请选择支付渠道' }]}>
            <Select
              placeholder="请选择支付渠道"
              options={channels.length
                ? channels.map((c) => ({ label: c.name, value: c.channel }))
                : [{ label: '默认渠道', value: 'default' }]}
            />
          </Form.Item>
          <Alert type="info" showIcon message="如不便在线支付，可选择线下付款并联系客服确认到账" />
        </Form>
      </Modal>

      <Modal open={!!buyPlanTarget} title={`购买订阅：${buyPlanTarget?.name ?? ''}`}
        onCancel={() => setBuyPlanTarget(null)} onOk={() => buyForm.submit()} confirmLoading={buyLoading} destroyOnClose>
        <Form form={buyForm} layout="vertical" onFinish={handleBuyPlan}
          initialValues={{ applicant_email: user?.email }}>
          <Form.Item label="套餐" ><Input readOnly value={buyPlanTarget?.name} /></Form.Item>
          <Form.Item label="联系邮箱" name="applicant_email" rules={[{ required: true, type: 'email' }]}>
            <Input />
          </Form.Item>
          <Form.Item label="优惠码（可选）" name="coupon_code"><Input placeholder="SAVE10" /></Form.Item>
          <Alert type="info" showIcon message="下单后进入收银台支付，支付完成即自动开通订阅额度" />
        </Form>
      </Modal>
    </div>
  );

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 24px' }}>
        账号信息管理 <HelpLink doc="user-02-buy-and-pay" />
      </Title>
      <Tabs
        activeKey={tab}
        onChange={(k) => setParams(k === 'info' ? {} : { tab: k })}
        items={[
          {
            key: 'info', label: <Space><UserOutlined />基本信息</Space>,
            children: (
              <div style={{ maxWidth: 480 }}>
                {user && (
                  <Descriptions column={1} style={{ marginBottom: 24 }} bordered size="small">
                    <Descriptions.Item label="用户名">{user.display_name || username}</Descriptions.Item>
                    <Descriptions.Item label="邮箱">{user.email}</Descriptions.Item>
                    <Descriptions.Item label="注册时间">{new Date(user.created_at).toLocaleString()}</Descriptions.Item>
                  </Descriptions>
                )}
                <Form form={infoForm} layout="vertical" onFinish={handleUpdateInfo}>
                  <Form.Item label="显示名称" name="display_name" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item label="邮箱" name="email" rules={[{ required: true, type: 'email' }]}><Input /></Form.Item>
                  <Form.Item><Button type="primary" htmlType="submit" loading={infoLoading}>保存修改</Button></Form.Item>
                </Form>
              </div>
            ),
          },
          {
            key: 'password', label: <Space><LockOutlined />安全设置</Space>,
            children: (
              <div style={{ maxWidth: 480 }}>
                <Form form={pwdForm} layout="vertical" onFinish={handleChangePassword}>
                  <Form.Item label="当前密码" name="old_password" rules={[{ required: true }]}><Input.Password /></Form.Item>
                  <Form.Item label="新密码" name="new_password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}><Input.Password placeholder="至少8位" /></Form.Item>
                  <Form.Item label="确认新密码" name="confirm" rules={[{ required: true }]}><Input.Password /></Form.Item>
                  <Form.Item><Button type="primary" htmlType="submit" loading={pwdLoading}>修改密码</Button></Form.Item>
                </Form>
                <Divider />
                <Card size="small" style={{ borderColor: '#ff4d4f' }}>
                  <Title level={5} style={{ color: '#ff4d4f', margin: '0 0 8px' }}>退出登录</Title>
                  <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>退出后需要重新登录才能访问平台。</Text>
                  <Button danger icon={<LogoutOutlined />} onClick={handleLogout}>退出登录</Button>
                </Card>
              </div>
            ),
          },
          {
            key: 'pubkey', label: <Space><KeyOutlined />云端公钥</Space>,
            children: (
              <div style={{ maxWidth: 560 }}>
                <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
                  云端公钥用于加密传输到云端的私钥数据。请上传 PEM 格式的 RSA/EC 公钥。
                </Text>
                <Form form={pubkeyForm} layout="vertical" onFinish={handleUpdatePubkey}>
                  <Form.Item label="公钥（PEM 格式）" name="pubkey_pem" rules={[{ required: true }]}>
                    <Input.TextArea rows={8}
                      placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                      style={{ fontSize: 12 }} />
                  </Form.Item>
                  <Form.Item>
                    <Space>
                      <Button type="primary" htmlType="submit" loading={pubkeyLoading} icon={<UploadOutlined />}>上传公钥</Button>
                      <Upload accept=".pem,.crt,.cer" showUploadList={false}
                        beforeUpload={(file) => {
                          const reader = new FileReader();
                          reader.onload = (e) => { pubkeyForm.setFieldValue('pubkey_pem', e.target?.result as string); };
                          reader.readAsText(file);
                          return false;
                        }}>
                        <Button icon={<UploadOutlined />}>从文件导入</Button>
                      </Upload>
                    </Space>
                  </Form.Item>
                </Form>
              </div>
            ),
          },
          {
            key: 'finance', label: <Space><WalletOutlined />财务与订阅</Space>,
            children: (
              <>
                <Paragraph type="secondary" style={{ marginTop: 0 }}>
                  余额、充值记录、退款工单与订阅套餐（原「财务支付管理」已并入此处）。
                </Paragraph>
                {financeTab}
              </>
            ),
          },
        ]}
      />
    </div>
  );
};

export default Profile;
