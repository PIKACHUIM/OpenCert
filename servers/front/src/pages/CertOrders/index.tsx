import React, { useState, useEffect } from 'react';
import {
  Tabs, Table, Button, Modal, Form, Select, Space,
  Tag, Typography, message, Card, Row, Col,
} from 'antd';
import { ShoppingCartOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons';
import {
  listIssuanceTemplates, createCertOrder, listCertOrders,
  createCertApplication, listCertApplications,
  approveCertApplication, rejectCertApplication,
  listSubjectInfos, listExtensionInfos,
} from '../../api';
import { useAuthStore } from '../../store/auth';
import type { IssuanceTemplate, CertOrder, CertApplication, SubjectInfo, ExtensionInfo } from '../../types';

const { Title, Text } = Typography;
const { Option } = Select;

const KEY_TYPES = ['ec256', 'ec384', 'rsa2048', 'rsa4096'];

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

// ---- 证书商店 Tab ----
const StoreTab: React.FC = () => {
  const [templates, setTemplates] = useState<IssuanceTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [buyOpen, setBuyOpen] = useState(false);
  const [buying, setBuying] = useState(false);
  const [selected, setSelected] = useState<IssuanceTemplate | null>(null);
  const [form] = Form.useForm();

  useEffect(() => {
    setLoading(true);
    listIssuanceTemplates({ page: 1, page_size: 50 })
      .then(r => setTemplates((Array.isArray(r?.items) ? r.items : []).filter((t: IssuanceTemplate) => t.enabled)))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleBuy = async (values: { validity_days: number; key_type: string }) => {
    if (!selected) return;
    setBuying(true);
    try {
      await createCertOrder({ template_uuid: selected.uuid, ...values });
      message.success('订单已创建，请前往「我的订单」完成支付');
      setBuyOpen(false); form.resetFields();
    } catch (e: any) { message.error(e.message); }
    finally { setBuying(false); }
  };

  return (
    <>
      {loading ? <div>加载中...</div> : (
        <Row gutter={[16, 16]}>
          {templates.map(t => (
            <Col xs={24} sm={12} lg={8} key={t.uuid}>
              <Card hoverable style={{ height: '100%' }}
                actions={[
                  <Button type="primary" icon={<ShoppingCartOutlined />} onClick={() => { setSelected(t); setBuyOpen(true); }}>立即购买</Button>
                ]}>
                <Tag color={{ ssl: 'blue', code_sign: 'purple', email: 'green', custom: 'orange' }[t.category] || 'default'} style={{ marginBottom: 8 }}>{t.category}</Tag>
                <Title level={5} style={{ margin: '0 0 8px' }}>{t.name}</Title>
                <Text type="secondary" style={{ fontSize: 13 }}>价格：{t.price === 0 ? '免费' : `¥${(t.price / 100).toFixed(2)}`}</Text><br />
                <Text type="secondary" style={{ fontSize: 13 }}>有效期：{t.validity_options?.join(' / ')} 天</Text><br />
                <Text type="secondary" style={{ fontSize: 13 }}>密钥类型：{t.allowed_key_types?.join(', ')}</Text>
              </Card>
            </Col>
          ))}
          {templates.length === 0 && <Col span={24}><Text type="secondary">暂无可购买的证书模板</Text></Col>}
        </Row>
      )}
      <Modal title={`购买证书 — ${selected?.name}`} open={buyOpen} onCancel={() => setBuyOpen(false)} footer={null}>
        <Form form={form} layout="vertical" onFinish={handleBuy} style={{ marginTop: 16 }}>
          <Form.Item label="有效期" name="validity_days" rules={[{ required: true }]}>
            <Select>{(selected?.validity_options || []).map(d => <Option key={d} value={d}>{d} 天</Option>)}</Select>
          </Form.Item>
          <Form.Item label="密钥类型" name="key_type" rules={[{ required: true }]}>
            <Select>{(selected?.allowed_key_types || KEY_TYPES).map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setBuyOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={buying}>确认购买</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 我的订单 Tab ----
const OrdersTab: React.FC = () => {
  const [orders, setOrders] = useState<CertOrder[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [applyOpen, setApplyOpen] = useState(false);
  const [applying, setApplying] = useState(false);
  const [selectedOrder, setSelectedOrder] = useState<CertOrder | null>(null);
  const [subjectInfos, setSubjectInfos] = useState<SubjectInfo[]>([]);
  const [extensionInfos, setExtensionInfos] = useState<ExtensionInfo[]>([]);
  const [form] = Form.useForm();

  const load = async (p = 1) => {
    setLoading(true);
    try { const res = await listCertOrders({ page: p, page_size: 20 }); setOrders(Array.isArray(res?.items) ? res.items : []); setTotal(res?.total ?? 0); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    listSubjectInfos({ page: 1, page_size: 100 }).then(r => setSubjectInfos((Array.isArray(r?.items) ? r.items : []).filter((s: SubjectInfo) => s.status === 'approved'))).catch(() => {});
    listExtensionInfos({ page: 1, page_size: 100 }).then(r => setExtensionInfos((Array.isArray(r?.items) ? r.items : []).filter((e: ExtensionInfo) => e.status === 'verified'))).catch(() => {});
  }, []);

  const handleApply = async (values: any) => {
    if (!selectedOrder) return;
    setApplying(true);
    try {
      await createCertApplication({ order_uuid: selectedOrder.uuid, subject_info_uuid: values.subject_info_uuid, extension_info_uuids: values.extension_info_uuids || [], key_type: values.key_type });
      message.success('申请已提交，等待管理员审批');
      setApplyOpen(false); form.resetFields(); load();
    } catch (e: any) { message.error(e.message); } finally { setApplying(false); }
  };

  const columns = [
    { title: '订单 UUID', dataIndex: 'uuid', key: 'uuid', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v.slice(0, 16)}...</Text> },
    { title: '关联模板', dataIndex: 'template_name', key: 'template_name', render: (v: string) => v || '-' },
    { title: '金额', dataIndex: 'amount', key: 'amount', render: (v: number) => v === 0 ? '免费' : `¥${(v / 100).toFixed(2)}` },
    { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={orderStatusColor[v]}>{orderStatusText[v] || v}</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at', render: (v: string) => v?.slice(0, 19) },
    {
      title: '操作', key: 'action', render: (_: any, r: CertOrder) => (
        r.status === 'paid' ? (
          <Button size="small" type="primary" onClick={() => { setSelectedOrder(r); setApplyOpen(true); }}>提交申请</Button>
        ) : null
      ),
    },
  ];

  return (
    <>
      <Table rowKey="uuid" columns={columns} dataSource={orders} loading={loading}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); load(p); } }} />
      <Modal title="提交证书申请" open={applyOpen} onCancel={() => setApplyOpen(false)} footer={null} width={520}>
        <Form form={form} layout="vertical" onFinish={handleApply} style={{ marginTop: 16 }}>
          <Form.Item label="选择主体信息（已审核通过）" name="subject_info_uuid" rules={[{ required: true }]}>
            <Select placeholder="请选择主体信息">
              {subjectInfos.map(s => <Option key={s.uuid} value={s.uuid}>{s.template_name} — {Object.values(s.fields || {}).slice(0, 2).join(', ')}</Option>)}
            </Select>
          </Form.Item>
          <Form.Item label="选择扩展信息（已验证，可多选）" name="extension_info_uuids">
            <Select mode="multiple" placeholder="请选择已验证的域名/邮箱/IP">
              {extensionInfos.map(e => <Option key={e.uuid} value={e.uuid}>{e.type}: {e.value}</Option>)}
            </Select>
          </Form.Item>
          <Form.Item label="密钥类型" name="key_type" rules={[{ required: true }]}>
            <Select>{KEY_TYPES.map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setApplyOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={applying}>提交申请</Button></Space>
          </Form.Item>
        </Form>
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
