import React, { useState, useEffect } from 'react';
import {
  Tabs, Table, Button, Modal, Space,
  Tag, Typography, message, Card, Input,
} from 'antd';
import { useNavigate } from 'react-router-dom';
import { ShoppingCartOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons';
import {
  listCertOrders,
  listCertApplications,
  approveCertApplication, rejectCertApplication,
  requestPortalRefund,
} from '../../api';
import { useAuthStore } from '../../store/auth';
import type { CertOrder, CertApplication } from '../../types';

const { Title, Text } = Typography;

const orderStatusColor: Record<string, string> = {
  pending_payment: 'orange', paid: 'blue', applying: 'cyan',
  reviewing: 'purple', issuing: 'geekblue', completed: 'green',
  rejected: 'red', cancelled: 'default', refunded: 'volcano',
};
const orderStatusText: Record<string, string> = {
  pending_payment: '待支付', paid: '已支付', applying: '申请中',
  reviewing: '审批中', issuing: '签发中', completed: '已完成',
  rejected: '已拒绝', cancelled: '已取消', refunded: '已退款',
};
const appStatusColor: Record<string, string> = { pending: 'orange', approved: 'green', rejected: 'red' };
const appStatusText: Record<string, string> = { pending: '待审批', approved: '已通过', rejected: '已拒绝' };

// ---- 选购入口 Tab ----
//
// 商品（SKU、价格、库存、开通模板）统一由门户与管理端的「商品管理」维护，
// 控制台不再保留第二套选购流程，避免同一商品出现两套价格与规则。
const StoreTab: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Card style={{ maxWidth: 720 }}>
      <Title level={5} style={{ marginTop: 0 }}>选购证书与云卡</Title>
      <Text type="secondary">
        选购、支付与证书签发在同一流程内完成，签发后可随时在本页查看进度。
      </Text>
      <div style={{ marginTop: 20 }}>
        <Space>
          <Button type="primary" icon={<ShoppingCartOutlined />} onClick={() => navigate('/products')}>
            前往产品中心选购
          </Button>
          <Button onClick={() => navigate('/console/products')}>商品管理</Button>
        </Space>
      </div>
    </Card>
  );
};

// ---- 我的订单 Tab ----
const OrdersTab: React.FC = () => {
  const navigate = useNavigate();
  const [orders, setOrders] = useState<CertOrder[]>([]);
  const [refundOpen, setRefundOpen] = useState(false);
  const [refundOrder, setRefundOrder] = useState<CertOrder | null>(null);
  const [refundReason, setRefundReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const load = async (p = 1) => {
    setLoading(true);
    try { const res = await listCertOrders({ page: p, page_size: 20 }); setOrders(Array.isArray(res?.items) ? res.items : []); setTotal(res?.total ?? 0); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  // 证书申请统一走「申请证书」向导（选择订单 → 主体 → 扩展信息 → 确认），此处不再内嵌表单
  useEffect(() => { load(); }, []);

  /** 从规格快照中取出可读的商品名 */
  const specName = (o: CertOrder): string => {
    if (!o.spec_json) return '-';
    try {
      const spec = JSON.parse(o.spec_json);
      return spec.sku_name || spec.product_name || '-';
    } catch { return '-'; }
  };

  const columns = [
    {
      title: '订单号', dataIndex: 'order_no', key: 'order_no', width: 190,
      render: (v: string, r: CertOrder) => (
        v ? <Text copyable style={{ fontSize: 12 }}>{v}</Text>
          : <Text code style={{ fontSize: 11 }}>{r.uuid.slice(0, 12)}…</Text>
      ),
    },
    { title: '商品', key: 'spec', render: (_: any, r: CertOrder) => specName(r) },
    {
      title: '金额', key: 'amount', width: 110,
      render: (_: any, r: CertOrder) => {
        const cents = r.amount_cents ?? r.amount ?? 0;
        return cents === 0 ? <Tag color="green">免费</Tag> : `¥${(cents / 100).toFixed(2)}`;
      },
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (v: string) => <Tag color={orderStatusColor[v]}>{orderStatusText[v] || v}</Tag>,
    },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 160, render: (v: string) => v?.slice(0, 19) },
    {
      title: '操作', key: 'action', width: 200,
      render: (_: any, r: CertOrder) => (
        <Space size={4}>
          {r.status === 'pending_payment' && r.order_no && (
            <Button size="small" type="primary" onClick={() => navigate(`/checkout/${r.order_no}`)}>去支付</Button>
          )}
          {r.status === 'paid' && (
            <>
              <Button size="small" type="primary" onClick={() => navigate(`/console/apply?order_no=${r.order_no}`)}>提交申请</Button>
              <Button size="small" onClick={() => { setRefundOrder(r); setRefundOpen(true); }}>退款</Button>
            </>
          )}
        </Space>
      ),
    },
  ];

  return (
    <>
      <Table rowKey="uuid" columns={columns} dataSource={orders} loading={loading}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); load(p); } }} />
      <Modal
        title="申请退款"
        open={refundOpen}
        onCancel={() => { setRefundOpen(false); setRefundReason(''); }}
        onOk={async () => {
          if (!refundOrder?.order_no) return;
          try {
            await requestPortalRefund(refundOrder.order_no, refundReason || '用户申请退款');
            message.success('退款申请已提交，等待管理员审批');
            setRefundOpen(false); setRefundReason(''); load();
          } catch (e: any) { message.error(e.message); }
        }}
        okText="提交申请"
      >
        <div style={{ marginTop: 12 }}>
          <Text type="secondary" style={{ fontSize: 13 }}>
            订单 {refundOrder?.order_no} 金额 ¥{(((refundOrder?.amount_cents ?? 0)) / 100).toFixed(2)}。
            已进入签发的订单需先取消申请后再退款。
          </Text>
          <Input.TextArea
            style={{ marginTop: 12 }} rows={3} maxLength={200}
            placeholder="请填写退款原因（可选）"
            value={refundReason} onChange={(e) => setRefundReason(e.target.value)}
          />
        </div>
      </Modal>
    </>
  );
};

// ---- 我的申请 Tab ----
const ApplicationsTab: React.FC = () => {
  const { role } = useAuthStore();
  const [apps, setApps] = useState<CertApplication[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [rejectOpen, setRejectOpen] = useState(false);
  const [rejectTarget, setRejectTarget] = useState('');
  const [rejectReason, setRejectReason] = useState('');

  const load = async (p = 1) => {
    setLoading(true);
    try { const res = await listCertApplications({ page: p, page_size: 20 }); setApps(Array.isArray(res?.items) ? res.items : []); setTotal(res?.total ?? 0); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const columns = [
    { title: '申请 UUID', dataIndex: 'uuid', key: 'uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v.slice(0, 16)}...</Text> },
    { title: '关联订单', dataIndex: 'order_uuid', key: 'order_uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v?.slice(0, 12)}...</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={appStatusColor[v]}>{appStatusText[v] || v}</Tag> },
    { title: '拒绝原因', dataIndex: 'reject_reason', key: 'reject_reason', render: (v: string) => v || '-' },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (v: string) => v?.slice(0, 19) },
    ...(role === 'admin' ? [{
      title: '操作', key: 'action', render: (_: any, r: CertApplication) => (
        r.status === 'pending' ? (
          <Space size={4}>
            <Button size="small" type="primary" icon={<CheckOutlined />} onClick={async () => { await approveCertApplication(r.uuid); load(); }}>通过</Button>
            <Button size="small" danger icon={<CloseOutlined />} onClick={() => { setRejectTarget(r.uuid); setRejectOpen(true); }}>拒绝</Button>
          </Space>
        ) : null
      ),
    }] : []),
  ];

  return (
    <>
      <Table rowKey="uuid" columns={columns} dataSource={apps} loading={loading}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); load(p); } }} />
      <Modal title="拒绝申请" open={rejectOpen} onCancel={() => setRejectOpen(false)}
        onOk={async () => { await rejectCertApplication(rejectTarget, rejectReason); setRejectOpen(false); setRejectReason(''); load(); }}
        okText="确认拒绝" okButtonProps={{ danger: true }}>
        <div style={{ marginTop: 16 }}>
          <Text>拒绝原因：</Text>
          <input style={{ width: '100%', marginTop: 8, padding: '4px 8px', border: '1px solid #d9d9d9', borderRadius: 6 }}
            placeholder="请输入拒绝原因" value={rejectReason} onChange={e => setRejectReason(e.target.value)} />
        </div>
      </Modal>
    </>
  );
};

const CertOrders: React.FC = () => (
  <div>
    <Title level={4} style={{ margin: '0 0 16px' }}>证书申请</Title>
    <Tabs items={[
      { key: 'store', label: '证书商店', children: <StoreTab /> },
      { key: 'orders', label: '我的订单', children: <OrdersTab /> },
      { key: 'applications', label: '我的申请', children: <ApplicationsTab /> },
    ]} />
  </div>
);

export default CertOrders;
