import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm, Drawer, Descriptions, Steps,
} from 'antd';
import {
  AuditOutlined, ReloadOutlined, CheckOutlined, CloseOutlined,
  FileSearchOutlined, PlusOutlined,
} from '@ant-design/icons';
import {
  listCertApplications, approveCertApplication, rejectCertApplication,
} from '../../api';
import type { CertApplication } from '../../types';
import { useAuthStore } from '../../store/auth';
import ApplyWizard from '../../components/ApplyWizard';

const { Title, Text } = Typography;

const statusColors: Record<string, string> = {
  pending: 'processing', issuing: 'processing', issuance_failed: 'warning',
  approved: 'success', rejected: 'error', issued: 'cyan', cancelled: 'default',
};
const statusTexts: Record<string, string> = {
  pending: '待审核', issuing: '签发处理中', issuance_failed: '签发失败（需人工核对）',
  approved: '已通过', rejected: '已拒绝', issued: '已签发', cancelled: '已取消',
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
          通过前请核对主体与域名信息；通过后系统会自动签发证书。若签发失败，申请会进入人工核对状态，不会自动重试以避免重复签发。
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

      <ApplyWizard mode="admin" open={proxyOpen} onClose={() => setProxyOpen(false)} onDone={fetchData} />

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
