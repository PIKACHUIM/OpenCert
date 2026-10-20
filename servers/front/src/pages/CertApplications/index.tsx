import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm, Drawer, Descriptions, Steps, Switch, Divider, Empty,
} from 'antd';
import {
  AuditOutlined, ReloadOutlined, CheckOutlined, CloseOutlined,
  FileSearchOutlined, PlusOutlined, UserAddOutlined,
} from '@ant-design/icons';
import {
  listCertApplications, approveCertApplication, rejectCertApplication,
  listUsers, getAdminApplyContext, adminCreateCertApplication,
} from '../../api';
import type { AdminApplyContext, CertApplication, User } from '../../types';
import { useAuthStore } from '../../store/auth';
import AlgorithmSelect from '../../components/AlgorithmSelect';

const { Title, Text } = Typography;

const statusColors: Record<string, string> = {
  pending: 'processing', approved: 'success', rejected: 'error', issued: 'cyan', cancelled: 'default',
};
const statusTexts: Record<string, string> = {
  pending: '待审核', approved: '已通过', rejected: '已拒绝', issued: '已签发', cancelled: '已取消',
};

/** 代办申请抽屉：选客户 → 选来源 → 选/填资料 → 提交 */
const ProxyApplyDrawer: React.FC<{
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}> = ({ open, onClose, onDone }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [userUUID, setUserUUID] = useState<string>('');
  const [ctx, setCtx] = useState<AdminApplyContext | null>(null);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm();

  useEffect(() => {
    if (!open) return;
    listUsers({ page: 1, page_size: 100 })
      .then((r) => setUsers(r.items))
      .catch(() => setUsers([]));
  }, [open]);

  useEffect(() => {
    if (!userUUID) { setCtx(null); return; }
    setLoading(true);
    getAdminApplyContext(userUUID)
      .then((data) => {
        setCtx(data);
        // 默认选中第一个可代办类型
        const first = data.templates?.[0]?.uuid;
        if (first) form.setFieldValue('cert_apply_tmpl_uuid', first);
      })
      .catch((err) => message.error(err.message))
      .finally(() => setLoading(false));
  }, [userUUID, form]);

  const mode = Form.useWatch('mode', form);
  const subjectMode = Form.useWatch('subject_mode', form);

  const handleSubmit = async () => {
    if (!userUUID) { message.warning('请先选择客户'); return; }
    try {
      const values = await form.validateFields();
      setSubmitting(true);
      const payload: any = {
        user_uuid: userUUID,
        skip_approval: !!values.skip_approval,
        key_type: values.key_type || '',
        csr_pem: values.csr_pem || '',
      };
      if (values.mode === 'order') payload.order_no = values.order_no;
      else if (values.mode === 'subscription') payload.subscription_uuid = values.subscription_uuid;
      else payload.cert_apply_tmpl_uuid = values.cert_apply_tmpl_uuid;

      if (values.subject_mode === 'existing') {
        payload.subject_info_uuid = values.subject_info_uuid;
      } else if (values.subject_mode === 'input') {
        payload.subject = {};
        ['CN', 'O', 'OU', 'C'].forEach((k) => {
          if (values[`subject_${k}`]) payload.subject[k] = values[`subject_${k}`];
        });
      }
      if (values.ext_mode === 'existing') {
        payload.extension_info_uuids = values.extension_info_uuids || [];
      } else if (values.ext_mode === 'input' && values.ext_value) {
        payload.extensions = [{ info_type: values.ext_type, value: values.ext_value }];
      }

      const res = await adminCreateCertApplication(payload);
      message.success(res?.message || '申请已提交');
      form.resetFields();
      setCtx(null);
      setUserUUID('');
      onDone();
      onClose();
    } catch (err: any) {
      if (err?.errorFields) return; // 表单校验失败
      message.error(err.message || '提交失败');
    } finally { setSubmitting(false); }
  };

  return (
    <Drawer
      title={<Space><UserAddOutlined />新增申请（代客户提交）</Space>}
      width={720} open={open} onClose={onClose} destroyOnClose
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={submitting} onClick={handleSubmit}>提交申请</Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" initialValues={{
        mode: 'template', subject_mode: 'existing', ext_mode: 'existing', skip_approval: false,
      }}>
        <Form.Item label="客户" required>
          <Select
            showSearch optionFilterProp="label"
            placeholder="搜索并选择要代办的客户"
            value={userUUID || undefined}
            onChange={(v) => setUserUUID(v)}
            options={users.map((u) => ({
              value: u.uuid,
              label: `${u.username}${u.email ? `（${u.email}）` : ''}`,
            }))}
          />
        </Form.Item>

        {loading && <Card loading size="small" />}

        {ctx && (
          <>
            <Form.Item label="申请来源" name="mode">
              <Select
                options={[
                  { value: 'order', label: '该客户的已支付订单' },
                  { value: 'template', label: '直接按证书类型申请' },
                  ...(ctx.subscriptions.some((s) => s.active)
                    ? [{ value: 'subscription', label: '使用订阅额度' }]
                    : []),
                ]}
              />
            </Form.Item>

            {mode === 'order' && (
              <Form.Item label="订单" name="order_no" rules={[{ required: true, message: '请选择订单' }]}>
                <Select
                  placeholder={ctx.orders.length ? '选择订单' : '该客户没有可用的证书订单'}
                  options={ctx.orders.map((o) => ({
                    value: o.order_no,
                    label: `${o.order_no}｜${o.template_name || '证书'}｜${o.status}`,
                  }))}
                />
              </Form.Item>
            )}
            {mode === 'template' && (
              <Form.Item label="证书类型" name="cert_apply_tmpl_uuid" rules={[{ required: true, message: '请选择证书类型' }]}>
                <Select
                  options={ctx.templates.map((t) => ({
                    value: t.uuid,
                    label: `${t.name}${t.require_approval ? '（需审批）' : '（自动签发）'}`,
                  }))}
                />
              </Form.Item>
            )}
            {mode === 'subscription' && (
              <Form.Item label="订阅" name="subscription_uuid" rules={[{ required: true, message: '请选择订阅' }]}>
                <Select
                  options={ctx.subscriptions.filter((s) => s.active).map((s) => ({ value: s.uuid, label: s.plan_name }))}
                />
              </Form.Item>
            )}

            <Divider titlePlacement="start" plain>证书资料</Divider>

            <Form.Item label="主体信息" name="subject_mode">
              <Select
                options={[
                  { value: 'existing', label: '使用客户已通过的主体信息' },
                  { value: 'input', label: '由我直接录入并核定' },
                ]}
              />
            </Form.Item>
            {subjectMode === 'existing' ? (
              <Form.Item label="选择主体信息" name="subject_info_uuid">
                <Select
                  allowClear placeholder={ctx.subject_infos.length ? '选择已通过的主体信息' : '客户暂无已通过的主体信息'}
                  options={ctx.subject_infos.map((s) => ({
                    value: s.uuid,
                    label: Object.entries(s.fields ?? {}).map(([k, v]) => `${k}=${v}`).join(', ') || s.uuid.slice(0, 8),
                  }))}
                />
              </Form.Item>
            ) : (
              <Space style={{ width: '100%' }} size={12} wrap>
                <Form.Item label="CN（通用名称）" name="subject_CN" rules={[{ required: true, message: '请填写 CN' }]}>
                  <Input placeholder="example.com" style={{ width: 220 }} />
                </Form.Item>
                <Form.Item label="组织 O" name="subject_O"><Input style={{ width: 180 }} /></Form.Item>
                <Form.Item label="部门 OU" name="subject_OU"><Input style={{ width: 160 }} /></Form.Item>
                <Form.Item label="国家 C" name="subject_C"><Input maxLength={2} style={{ width: 100 }} placeholder="CN" /></Form.Item>
              </Space>
            )}

            <Form.Item label="扩展信息（域名 / 邮箱 / IP）" name="ext_mode">
              <Select
                options={[
                  { value: 'existing', label: '使用客户已验证的扩展信息' },
                  { value: 'input', label: '由我直接录入并核定' },
                  { value: 'none', label: '不添加（仅用主体信息）' },
                ]}
              />
            </Form.Item>
            {Form.useWatch('ext_mode', form) === 'existing' && (
              <Form.Item label="选择扩展信息" name="extension_info_uuids">
                <Select
                  mode="multiple" allowClear
                  placeholder={ctx.extension_infos.length ? '可多选' : '客户暂无已验证的扩展信息'}
                  options={ctx.extension_infos.map((e) => ({
                    value: e.uuid, label: `${e.type}: ${e.value}`,
                  }))}
                />
              </Form.Item>
            )}
            {Form.useWatch('ext_mode', form) === 'input' && (
              <Space size={12}>
                <Form.Item label="类型" name="ext_type" initialValue="domain">
                  <Select style={{ width: 120 }} options={[
                    { value: 'domain', label: '域名' },
                    { value: 'email', label: '邮箱' },
                    { value: 'ip', label: 'IP' },
                  ]} />
                </Form.Item>
                <Form.Item label="值" name="ext_value"><Input style={{ width: 300 }} placeholder="example.com" /></Form.Item>
              </Space>
            )}

            <Space size={12} style={{ width: '100%' }} align="start">
              <Form.Item label="密钥算法" name="key_type" extra="留空由服务端选择">
                <AlgorithmSelect style={{ width: 220 }} />
              </Form.Item>
              <Form.Item label="跳过审批，直接签发" name="skip_approval" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Space>

            <Form.Item label="自带 CSR（可选，私钥由客户保管）" name="csr_pem">
              <Input.TextArea rows={3} placeholder="-----BEGIN CERTIFICATE REQUEST-----" style={{ fontSize: 12 }} />
            </Form.Item>
          </>
        )}

        {!ctx && !loading && <Empty description="选择客户后加载可用的订单、订阅与资料" />}
      </Form>
    </Drawer>
  );
};

const CertApplicationsPage: React.FC = () => {
  const { role } = useAuthStore();
  const isAdmin = role === 'admin' || role === 'super_admin' || role === 'operator';

  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CertApplication[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [statusFilter, setStatusFilter] = useState<string | undefined>();
  const [detail, setDetail] = useState<CertApplication | null>(null);
  const [rejectOpen, setRejectOpen] = useState<CertApplication | null>(null);
  const [proxyOpen, setProxyOpen] = useState(false);
  const [rejectForm] = Form.useForm();

  const fetchData = async (p = page, ps = pageSize) => {
    setLoading(true);
    try {
      const res = await listCertApplications({ status: statusFilter, page: p, page_size: ps });
      setData(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally { setLoading(false); }
  };

  useEffect(() => { fetchData(page, pageSize); /* eslint-disable-next-line */ }, [page, pageSize, statusFilter]);

  const handleApprove = async (uuid: string) => {
    try {
      await approveCertApplication(uuid);
      message.success('已通过审批，证书将自动签发');
      fetchData();
    } catch (e: any) { message.error(e.message || '审批失败'); }
  };

  const handleReject = async () => {
    if (!rejectOpen) return;
    try {
      const reason = rejectForm.getFieldValue('reason');
      await rejectCertApplication(rejectOpen.uuid, reason);
      message.success('已拒绝');
      setRejectOpen(null);
      rejectForm.resetFields();
      fetchData();
    } catch (e: any) { message.error(e.message || '拒绝失败'); }
  };

  const columns = useMemo(() => [
    {
      title: '申请人', key: 'user', width: 180,
      render: (_: any, r: CertApplication) => (
        <div>
          <Text strong>{r.user_name || '（未知用户）'}</Text>
          {r.on_behalf && <div><Tag color="purple" style={{ marginTop: 4 }}>代办</Tag></div>}
        </div>
      ),
    },
    {
      title: '订单号', dataIndex: 'order_no', key: 'order_no', width: 180,
      render: (v: string) => (v ? <Text copyable={{ text: v }}>{v}</Text> : '-'),
    },
    {
      title: '证书类型', dataIndex: 'template_name', key: 'template_name', width: 170,
      render: (v: string) => v || '-',
    },
    {
      title: '主体', dataIndex: 'subject_summary', key: 'subject_summary', ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '域名 / 标识', dataIndex: 'san_summary', key: 'san_summary', ellipsis: true, width: 220,
      render: (v: string) => v || '-',
    },
    {
      title: '状态', dataIndex: 'status', key: 'status', width: 100,
      render: (v: string) => <Tag color={statusColors[v]}>{statusTexts[v] || v}</Tag>,
    },
    {
      title: '提交时间', dataIndex: 'created_at', key: 'created_at', width: 170,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '-'),
    },
    {
      title: '操作', key: 'actions', width: 220, fixed: 'right' as const,
      render: (_: any, r: CertApplication) => (
        <Space style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" icon={<FileSearchOutlined />} onClick={() => setDetail(r)}>详情</Button>
          {isAdmin && r.status === 'pending' && (
            <>
              <Popconfirm title="确认通过审批？通过后将自动签发证书" onConfirm={() => handleApprove(r.uuid)}>
                <Button type="link" size="small" icon={<CheckOutlined />}>通过</Button>
              </Popconfirm>
              <Button type="link" size="small" danger icon={<CloseOutlined />} onClick={() => setRejectOpen(r)}>拒绝</Button>
            </>
          )}
        </Space>
      ),
    },
  ], [isAdmin]);

  return (
    <div>
      <Card
        title={<Space><AuditOutlined /><Title level={4} style={{ margin: 0 }}>证书申请审核</Title></Space>}
        extra={
          <Space>
            {isAdmin && (
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setProxyOpen(true)}>新增申请</Button>
            )}
            <Select
              style={{ width: 160 }} allowClear placeholder="按状态过滤"
              value={statusFilter} onChange={(v) => { setStatusFilter(v); setPage(1); }}
              options={Object.entries(statusTexts).map(([v, l]) => ({ label: l, value: v }))}
            />
            <Button icon={<ReloadOutlined />} onClick={() => fetchData()}>刷新</Button>
          </Space>
        }
      >
        <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
          通过前请核对主体与域名信息；通过后系统会自动签发证书。
        </Text>
        <Table
          rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          scroll={{ x: 1280 }}
          pagination={{
            current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <ProxyApplyDrawer open={proxyOpen} onClose={() => setProxyOpen(false)} onDone={fetchData} />

      <Modal
        open={!!rejectOpen} title="拒绝证书申请"
        onCancel={() => { setRejectOpen(null); rejectForm.resetFields(); }}
        onOk={handleReject}
      >
        <Form form={rejectForm} layout="vertical">
          <Form.Item name="reason" label="拒绝原因" rules={[{ required: true, message: '请输入拒绝原因' }]}>
            <Input.TextArea rows={3} maxLength={500} placeholder="请说明拒绝原因" />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer width={640} open={!!detail} onClose={() => setDetail(null)} title="证书申请详情">
        {detail && (
          <>
            <Steps
              size="small" style={{ marginBottom: 24 }}
              current={detail.status === 'pending' ? 0 : detail.cert_uuid ? 2 : 1}
              status={detail.status === 'rejected' ? 'error' : 'process'}
              items={[{ title: '提交申请' }, { title: '管理员审批' }, { title: '证书签发' }]}
            />
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="申请人">{detail.user_name || detail.user_uuid}</Descriptions.Item>
              <Descriptions.Item label="证书类型">{detail.template_name || '-'}</Descriptions.Item>
              <Descriptions.Item label="订单号">{detail.order_no || '-'}</Descriptions.Item>
              <Descriptions.Item label="主体">{detail.subject_summary || detail.subject_json || '-'}</Descriptions.Item>
              <Descriptions.Item label="域名 / 标识">{detail.san_summary || detail.san_json || '-'}</Descriptions.Item>
              <Descriptions.Item label="密钥算法">{detail.key_type || '-'}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColors[detail.status]}>{statusTexts[detail.status] || detail.status}</Tag>
              </Descriptions.Item>
              {detail.on_behalf && (
                <Descriptions.Item label="代办">
                  由管理员代为提交{detail.created_by ? `（操作人 ${detail.created_by}）` : ''}
                </Descriptions.Item>
              )}
              {detail.reject_reason && (
                <Descriptions.Item label="拒绝原因"><Text type="danger">{detail.reject_reason}</Text></Descriptions.Item>
              )}
              <Descriptions.Item label="提交时间">
                {detail.created_at ? new Date(detail.created_at).toLocaleString('zh-CN') : '-'}
              </Descriptions.Item>
            </Descriptions>
          </>
        )}
      </Drawer>
    </div>
  );
};

export default CertApplicationsPage;
