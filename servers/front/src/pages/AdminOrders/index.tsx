import React, { useEffect, useState } from 'react';
import {
  Card, Table, Tabs, Button, Space, Tag, Typography, Input, Select, message, Modal, Form, Descriptions,
} from 'antd';
import {
  ShoppingOutlined, ReloadOutlined, SearchOutlined, CheckCircleOutlined, RollbackOutlined,
} from '@ant-design/icons';
import {
  listAdminOrders, confirmOfflinePayment, adminCancelOrder,
  listRefunds, approveRefund, rejectRefund,
} from '../../api';
import type { CertOrder, PortalRefund } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

const ORDER_STATUS: Record<string, { text: string; color: string }> = {
  pending_payment: { text: '待支付', color: 'orange' },
  paid: { text: '已支付', color: 'green' },
  applying: { text: '申请中', color: 'blue' },
  reviewing: { text: '审核中', color: 'purple' },
  issuing: { text: '签发中', color: 'geekblue' },
  completed: { text: '已完成', color: 'success' },
  rejected: { text: '已拒绝', color: 'red' },
  cancelled: { text: '已取消', color: 'default' },
  refunded: { text: '已退款', color: 'cyan' },
};

/** 解析订单规格快照，展示商品名、份数与订阅/优惠信息 */
export const parseSpec = (spec?: string) => {
  try { return spec ? JSON.parse(spec) : {}; } catch { return {} as any; }
};

/** 订单管理：全部订单（含线下到账确认、取消）与退款审批 */
const AdminOrdersPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [orders, setOrders] = useState<CertOrder[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<string>('');
  const [keyword, setKeyword] = useState('');

  const [refunds, setRefunds] = useState<PortalRefund[]>([]);
  const [refundLoading, setRefundLoading] = useState(false);

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [current, setCurrent] = useState<CertOrder | null>(null);
  const [form] = Form.useForm();

  const loadOrders = async (p = page, st = status, kw = keyword) => {
    setLoading(true);
    try {
      const r = await listAdminOrders({ page: p, page_size: 20, status: st || undefined, keyword: kw || undefined });
      setOrders(r.items ?? []);
      setTotal(r.total ?? 0);
    } catch (e: any) { message.error(e.message || '加载订单失败'); }
    finally { setLoading(false); }
  };

  const loadRefunds = async (st?: string) => {
    setRefundLoading(true);
    try {
      const r = await listRefunds({ page: 1, page_size: 50, status: st });
      setRefunds(r.items ?? []);
    } catch (e: any) { message.error(e.message || '加载退款工单失败'); }
    finally { setRefundLoading(false); }
  };

  useEffect(() => { loadOrders(1, '', ''); loadRefunds('pending'); }, []);

  const handleConfirm = async (values: { reference: string }) => {
    if (!current) return;
    try {
      await confirmOfflinePayment(current.order_no || '', values.reference);
      message.success('已确认到账');
      setConfirmOpen(false);
      form.resetFields();
      loadOrders();
    } catch (e: any) { message.error(e.message || '确认失败'); }
  };

  const orderColumns = [
    { title: '订单号', dataIndex: 'order_no', key: 'order_no',
      render: (v: string, r: CertOrder) => (
        <Space direction="vertical" size={0}>
          <Text copyable code style={{ fontSize: 12 }}>{v || r.uuid.slice(0, 8)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{r.username || r.user_uuid?.slice(0, 8)}</Text>
        </Space>
      ) },
    { title: '商品', key: 'product',
      render: (_: any, r: CertOrder) => {
        const spec = parseSpec(r.spec_json);
        return (
          <Space direction="vertical" size={0}>
            <Text>{spec.product_name || r.product_code || '—'}</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {spec.sku_name || r.sku_code || ''}{spec.quantity > 1 ? ` × ${spec.quantity}` : ''}
              {spec.mode === 'subscription' ? ' · 订阅额度' : ''}
            </Text>
          </Space>
        );
      } },
    { title: '金额', key: 'amount',
      render: (_: any, r: CertOrder) => (
        <Space direction="vertical" size={0}>
          <Text>¥{((r.amount_cents ?? 0) / 100).toFixed(2)}</Text>
          {(r.discount_cents ?? 0) > 0 && (
            <Text type="secondary" style={{ fontSize: 12 }}>优惠码 {r.coupon_code} -¥{((r.discount_cents ?? 0) / 100).toFixed(2)}</Text>
          )}
        </Space>
      ) },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (v: string) => {
        const s = ORDER_STATUS[v] ?? { text: v, color: 'default' };
        return <Tag color={s.color}>{s.text}</Tag>;
      } },
    { title: '联系邮箱', dataIndex: 'applicant_email', key: 'applicant_email', width: 180,
      render: (v: string) => v || '—' },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 170,
      render: (_: any, r: CertOrder) => (
        <Space size={4}>
          {r.status === 'pending_payment' && (
            <>
              <Button type="link" size="small" icon={<CheckCircleOutlined />}
                onClick={() => { setCurrent(r); setConfirmOpen(true); }}>确认到账</Button>
              <Button type="link" size="small" danger
                onClick={async () => {
                  try { await adminCancelOrder(r.order_no || ''); message.success('订单已取消'); loadOrders(); }
                  catch (e: any) { message.error(e.message || '取消失败'); }
                }}>取消</Button>
            </>
          )}
          {r.status === 'paid' && (
            <Text type="secondary" style={{ fontSize: 12 }}>等待用户提交申请</Text>
          )}
        </Space>
      ),
    },
  ];

  const refundColumns = [
    { title: '订单号', dataIndex: 'order_no', key: 'order_no',
      render: (v: string) => <Text copyable code style={{ fontSize: 12 }}>{v}</Text> },
    { title: '金额', dataIndex: 'amount_cents', key: 'amount_cents',
      render: (v: number) => `¥${((v ?? 0) / 100).toFixed(2)}` },
    { title: '渠道', dataIndex: 'channel', key: 'channel', render: (v: string) => v || '—' },
    { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (v: string) => ({
        pending: <Tag color="orange">待审批</Tag>,
        paid: <Tag color="green">已退款</Tag>,
        failed: <Tag color="red">失败</Tag>,
      } as any)[v] ?? <Tag>{v}</Tag> },
    { title: '申请时间', dataIndex: 'created_at', key: 'created_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 150,
      render: (_: any, r: PortalRefund) => r.status === 'pending' ? (
        <Space size={4}>
          <Button size="small" type="primary" onClick={async () => {
            try { await approveRefund(r.uuid); message.success('退款已通过'); loadRefunds('pending'); }
            catch (e: any) { message.error(e.message || '操作失败'); }
          }}>通过</Button>
          <Button size="small" danger onClick={async () => {
            try { await rejectRefund(r.uuid, '管理员驳回'); message.success('已拒绝'); loadRefunds('pending'); }
            catch (e: any) { message.error(e.message || '操作失败'); }
          }}>拒绝</Button>
        </Space>
      ) : (r.fail_reason ? <Text type="secondary" style={{ fontSize: 12 }}>{r.fail_reason}</Text> : null),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><ShoppingOutlined /><Title level={4} style={{ margin: 0 }}>订单管理</Title>
          <HelpLink doc="admin-04-products-orders" /></Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={() => { loadOrders(); loadRefunds('pending'); }}>刷新</Button>}
      >
        <Tabs
          items={[
            {
              key: 'orders', label: '全部订单',
              children: (
                <>
                  <Space style={{ marginBottom: 12 }} wrap>
                    <Select
                      allowClear placeholder="订单状态" style={{ width: 150 }}
                      value={status || undefined}
                      onChange={(v) => { setStatus(v ?? ''); setPage(1); loadOrders(1, v ?? '', keyword); }}
                      options={Object.entries(ORDER_STATUS).map(([value, s]) => ({ value, label: s.text }))}
                    />
                    <Input
                      allowClear placeholder="订单号 / 邮箱 / 商品编码" style={{ width: 260 }}
                      prefix={<SearchOutlined />} value={keyword}
                      onChange={(e) => setKeyword(e.target.value)}
                      onPressEnter={() => { setPage(1); loadOrders(1, status, keyword); }}
                    />
                    <Button type="primary" onClick={() => { setPage(1); loadOrders(1, status, keyword); }}>查询</Button>
                  </Space>
                  <Table
                    rowKey="uuid" loading={loading} dataSource={orders} columns={orderColumns as any}
                    pagination={{
                      current: page, total, pageSize: 20,
                      onChange: (p) => { setPage(p); loadOrders(p, status, keyword); },
                    }}
                  />
                </>
              ),
            },
            {
              key: 'refunds', label: '退款审批',
              children: (
                <>
                  <Space style={{ marginBottom: 12 }}>
                    <Button icon={<RollbackOutlined />} onClick={() => loadRefunds('pending')}>待审批</Button>
                    <Button onClick={() => loadRefunds()}>全部工单</Button>
                  </Space>
                  <Table rowKey="uuid" loading={refundLoading} dataSource={refunds} columns={refundColumns as any} />
                </>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        open={confirmOpen} title="确认线下到账" onCancel={() => setConfirmOpen(false)}
        onOk={() => form.submit()} destroyOnClose
      >
        <Descriptions column={1} size="small" style={{ marginBottom: 12 }}>
          <Descriptions.Item label="订单号">{current?.order_no}</Descriptions.Item>
          <Descriptions.Item label="金额">¥{((current?.amount_cents ?? 0) / 100).toFixed(2)}</Descriptions.Item>
        </Descriptions>
        <Form form={form} layout="vertical" onFinish={handleConfirm}>
          <Form.Item name="reference" label="到账凭证号 / 备注"
            rules={[{ required: true, message: '请填写凭证号或备注，便于对账' }]}>
            <Input placeholder="例如：对公转账回单号 20260930001" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AdminOrdersPage;
