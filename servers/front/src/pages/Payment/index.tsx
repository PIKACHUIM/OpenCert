import React, { useState, useEffect } from 'react';
import {
  Tabs, Table, Button, Modal, Form, Input, InputNumber, Select,
  Typography, Space, Tag, Statistic, Row, Col, Card, message,
} from 'antd';
import { WalletOutlined, PlusOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons';
import {
  getBalance, createRecharge, listPaymentOrders, createRefund,
  listPaymentPlugins, createPaymentPlugin, deletePaymentPlugin,
  approveRefund, rejectRefund,
} from '../../api';
import type { UserBalance, PaymentOrder, PaymentPlugin } from '../../types';
import { useAuthStore } from '../../store/auth';
import { useThemeStore } from '../../store/theme';

const { Title, Text } = Typography;
const { Option } = Select;

const statusColor: Record<string, string> = { pending: 'orange', paid: 'green', failed: 'red', refunded: 'blue', refunding: 'purple' };
const statusText: Record<string, string> = { pending: '待支付', paid: '已支付', failed: '失败', refunded: '已退款', refunding: '退款中' };

const Payment: React.FC = () => {
  const { role } = useAuthStore();
  const { darkMode } = useThemeStore();
  const [balance, setBalance] = useState<UserBalance | null>(null);
  const [orders, setOrders] = useState<PaymentOrder[]>([]);
  const [ordersTotal, setOrdersTotal] = useState(0);
  const [ordersPage, setOrdersPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [plugins, setPlugins] = useState<PaymentPlugin[]>([]);
  const [pendingRefunds, setPendingRefunds] = useState<PaymentOrder[]>([]);
  const [rechargeOpen, setRechargeOpen] = useState(false);
  const [rechargeLoading, setRechargeLoading] = useState(false);
  const [refundOpen, setRefundOpen] = useState(false);
  const [refundLoading, setRefundLoading] = useState(false);
  const [pluginOpen, setPluginOpen] = useState(false);
  const [pluginSaving, setPluginSaving] = useState(false);
  const [rechargeForm] = Form.useForm();
  const [refundForm] = Form.useForm();
  const [pluginForm] = Form.useForm();

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const loadAll = async (p = 1) => {
    setLoading(true);
    try {
      const [bal, res, plugs] = await Promise.all([
        getBalance().catch(() => null),
        listPaymentOrders({ page: p, page_size: 20 }),
        listPaymentPlugins().catch(() => []),
      ]);
      if (bal) setBalance(bal);
      setOrders(Array.isArray(res?.items) ? res.items : []);
      setOrdersTotal(res?.total ?? 0);
      const plugArr = Array.isArray(plugs) ? plugs : Array.isArray((plugs as any)?.items) ? (plugs as any).items : [];
      setPlugins(plugArr);
      if (role === 'admin') {
        const refunds = await listPaymentOrders({ page: 1, page_size: 20, status: 'refunding' }).catch(() => ({ items: [] }));
        setPendingRefunds(Array.isArray(refunds?.items) ? refunds.items : []);
      }
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadAll(); }, []);

  const handleRecharge = async (values: { amount: number; channel: string }) => {
    setRechargeLoading(true);
    try {
      const order = await createRecharge({ amount: Math.round(values.amount * 100), channel: values.channel });
      message.success('充值订单已创建');
      if (order.pay_url) window.open(order.pay_url, '_blank');
      setRechargeOpen(false); rechargeForm.resetFields(); loadAll();
    } catch (e: any) { message.error(e.message); }
    finally { setRechargeLoading(false); }
  };

  const handleRefund = async (values: { order_uuid: string; reason: string }) => {
    setRefundLoading(true);
    try {
      await createRefund(values);
      message.success('退款申请已提交，等待管理员审批');
      setRefundOpen(false); refundForm.resetFields();
    } catch (e: any) { message.error(e.message); }
    finally { setRefundLoading(false); }
  };

  const handleCreatePlugin = async (values: any) => {
    setPluginSaving(true);
    try {
      await createPaymentPlugin(values);
      message.success('支付插件已创建');
      setPluginOpen(false); pluginForm.resetFields(); loadAll();
    } catch (e: any) { message.error(e.message); }
    finally { setPluginSaving(false); }
  };

  const orderColumns = [
    { title: '订单号', dataIndex: 'uuid', key: 'uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v.slice(0, 16)}...</Text> },
    { title: '金额', dataIndex: 'amount', key: 'amount', render: (v: number) => `¥${(v / 100).toFixed(2)}` },
    { title: '支付渠道', dataIndex: 'channel', key: 'channel' },
    { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={statusColor[v]}>{statusText[v] || v}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (v: string) => v?.slice(0, 19) },
    {
      title: '操作', key: 'action', render: (_: any, r: PaymentOrder) => (
        r.status === 'paid' ? (
          <Button size="small" onClick={() => { refundForm.setFieldValue('order_uuid', r.uuid); setRefundOpen(true); }}>申请退款</Button>
        ) : null
      ),
    },
  ];

  const pluginColumns = [
    { title: '插件名称', dataIndex: 'name', key: 'name' },
    { title: '插件类型', dataIndex: 'plugin_type', key: 'plugin_type', render: (v: string) => <Tag>{v}</Tag> },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '启用' : '禁用'}</Tag> },
    { title: '排序权重', dataIndex: 'sort_weight', key: 'sort_weight' },
    {
      title: '操作', key: 'action', render: (_: any, r: PaymentPlugin) => (
        <Button size="small" danger onClick={() => deletePaymentPlugin(r.uuid).then(() => { message.success('已删除'); loadAll(); }).catch((e: any) => message.error(e.message))}>删除</Button>
      ),
    },
  ];

  const refundColumns = [
    { title: '订单号', dataIndex: 'uuid', key: 'uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v.slice(0, 16)}...</Text> },
    { title: '金额', dataIndex: 'amount', key: 'amount', render: (v: number) => `¥${(v / 100).toFixed(2)}` },
    { title: '渠道', dataIndex: 'channel', key: 'channel' },
    {
      title: '操作', key: 'action', render: (_: any, r: PaymentOrder) => (
        <Space size={4}>
          <Button size="small" type="primary" icon={<CheckOutlined />} onClick={() => approveRefund(r.uuid).then(() => { message.success('退款已通过'); loadAll(); }).catch((e: any) => message.error(e.message))}>通过</Button>
          <Button size="small" danger icon={<CloseOutlined />} onClick={() => rejectRefund(r.uuid).then(() => { message.success('退款已拒绝'); loadAll(); }).catch((e: any) => message.error(e.message))}>拒绝</Button>
        </Space>
      ),
    },
  ];

  const tabItems = [
    {
      key: 'balance', label: '余额概览',
      children: (
        <div>
          <Row gutter={24} style={{ marginBottom: 24 }}>
            <Col xs={24} sm={8}>
              <Card style={cardStyle}>
                <Statistic title="可用余额" value={balance ? (balance.available / 100).toFixed(2) : '—'}
                  prefix={<WalletOutlined />} suffix="元" valueStyle={{ color: '#1677ff' }} />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card style={cardStyle}>
                <Statistic title="累计充值" value={balance ? (balance.total_recharged / 100).toFixed(2) : '—'}
                  suffix="元" valueStyle={{ color: '#52c41a' }} />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card style={cardStyle}>
                <Statistic title="累计消费" value={balance ? (balance.total_consumed / 100).toFixed(2) : '—'}
                  suffix="元" valueStyle={{ color: '#fa8c16' }} />
              </Card>
            </Col>
          </Row>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setRechargeOpen(true)}>立即充值</Button>
        </div>
      ),
    },
    {
      key: 'orders', label: '充值记录',
      children: (
        <Table rowKey="uuid" columns={orderColumns} dataSource={orders} loading={loading}
          pagination={{ current: ordersPage, total: ordersTotal, pageSize: 20, onChange: (p) => { setOrdersPage(p); loadAll(p); } }} />
      ),
    },
    ...(role === 'admin' ? [
      {
        key: 'plugins', label: '支付插件',
        children: (
          <>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setPluginOpen(true)}>添加支付插件</Button>
            </div>
            <Table rowKey="uuid" columns={pluginColumns} dataSource={plugins} size="small" />
            {pendingRefunds.length > 0 && (
              <>
                <Title level={5} style={{ margin: '24px 0 8px' }}>待审批退款</Title>
                <Table rowKey="uuid" columns={refundColumns} dataSource={pendingRefunds} size="small" pagination={false} />
              </>
            )}
          </>
        ),
      },
    ] : []),
  ];

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 16px' }}>支付与订单</Title>
      <Tabs items={tabItems} />

      {/* 充值弹窗 */}
      <Modal title="立即充值" open={rechargeOpen} onCancel={() => setRechargeOpen(false)} footer={null}>
        <Form form={rechargeForm} layout="vertical" onFinish={handleRecharge} style={{ marginTop: 16 }}>
          <Form.Item label="充值金额（元）" name="amount" rules={[{ required: true }, { type: 'number', min: 1, message: '最低充值 1 元' }]}>
            <InputNumber min={1} precision={2} style={{ width: '100%' }} addonAfter="元" />
          </Form.Item>
          <Form.Item label="支付渠道" name="channel" rules={[{ required: true }]}>
            <Select placeholder="请选择支付渠道">
              {(Array.isArray(plugins) ? plugins : []).filter(p => p.enabled).map(p => <Option key={p.uuid} value={p.plugin_type}>{p.name}</Option>)}
              {(!Array.isArray(plugins) || plugins.length === 0) && <Option value="default">默认渠道</Option>}
            </Select>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setRechargeOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={rechargeLoading}>确认充值</Button></Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 退款弹窗 */}
      <Modal title="申请退款" open={refundOpen} onCancel={() => setRefundOpen(false)} footer={null}>
        <Form form={refundForm} layout="vertical" onFinish={handleRefund} style={{ marginTop: 16 }}>
          <Form.Item label="订单号" name="order_uuid" rules={[{ required: true }]}><Input readOnly /></Form.Item>
          <Form.Item label="退款原因" name="reason" rules={[{ required: true }]}><Input.TextArea rows={3} /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setRefundOpen(false)}>取消</Button><Button type="primary" danger htmlType="submit" loading={refundLoading}>提交申请</Button></Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 添加支付插件 */}
      <Modal title="添加支付插件" open={pluginOpen} onCancel={() => setPluginOpen(false)} footer={null} width={520}>
        <Form form={pluginForm} layout="vertical" onFinish={handleCreatePlugin} style={{ marginTop: 16 }}>
          <Form.Item label="插件名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="插件类型" name="plugin_type" rules={[{ required: true }]}>
            <Select><Option value="alipay">支付宝</Option><Option value="wechat">微信支付</Option><Option value="stripe">Stripe</Option><Option value="custom">自定义</Option></Select>
          </Form.Item>
          <Form.Item label="是否启用" name="enabled" valuePropName="checked" initialValue={true}><input type="checkbox" /></Form.Item>
          <Form.Item label="排序权重" name="sort_weight" initialValue={0}><InputNumber style={{ width: '100%' }} /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setPluginOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={pluginSaving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default Payment;
