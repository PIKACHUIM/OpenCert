import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm, Drawer, Descriptions, Alert, Steps,
} from 'antd';
import {
  AuditOutlined, ReloadOutlined, CheckOutlined, CloseOutlined,
  FileSearchOutlined, SearchOutlined,
} from '@ant-design/icons';
import {
  listCertApplications, approveCertApplication, rejectCertApplication,
} from '../../api';
import type { CertApplication } from '../../types';
import { useAuthStore } from '../../store/auth';

const { Title, Text } = Typography;

/**
 * CertApplications 页面：证书申请审核（管理员视角）。
 * - 列表：按状态过滤
 * - 审批：通过 / 拒绝（附原因）
 * - 详情抽屉：展示申请信息、关联订单、主体/扩展信息
 */
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

  const statusColors: Record<string, string> = {
    pending: 'processing', approved: 'success', rejected: 'error',
    issued: 'cyan', cancelled: 'default',
  };
  const statusTexts: Record<string, string> = {
    pending: '待审核', approved: '已通过', rejected: '已拒绝',
    issued: '已签发', cancelled: '已取消',
  };

  const columns = useMemo(() => [
    {
      title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 130, ellipsis: true,
      render: (v: string) => <Text copyable={{ text: v }}>{v.substring(0, 8)}...</Text>,
    },
    { title: '用户', dataIndex: 'user_uuid', key: 'user_uuid', width: 130, ellipsis: true,
      render: (v: string) => <Text copyable={{ text: v }}>{v.substring(0, 8)}...</Text> },
    { title: '订单', dataIndex: 'order_uuid', key: 'order_uuid', width: 130, ellipsis: true,
      render: (v: string) => v ? <Text copyable={{ text: v }}>{v.substring(0, 8)}...</Text> : '-' },
    { title: '主体信息', dataIndex: 'subject_info_uuid', key: 'subject_info_uuid', width: 130, ellipsis: true,
      render: (v: string) => v ? v.substring(0, 8) + '...' : '-' },
    { title: '扩展信息', dataIndex: 'extension_info_uuid', key: 'extension_info_uuid', width: 130, ellipsis: true,
      render: (v: string) => v ? v.substring(0, 8) + '...' : '-' },
    {
      title: '状态', dataIndex: 'status', key: 'status',
      render: (v: string) => <Tag color={statusColors[v]}>{statusTexts[v] || v}</Tag>,
    },
    { title: '拒绝原因', dataIndex: 'reject_reason', key: 'reject_reason', ellipsis: true,
      render: (v: string) => v || '-' },
    { title: '提交时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 260, fixed: 'right' as const,
      render: (_: any, r: CertApplication) => (
        <Space>
          <Button type="link" size="small" icon={<FileSearchOutlined />}
            onClick={() => setDetail(r)}>详情</Button>
          {isAdmin && r.status === 'pending' && (
            <>
              <Popconfirm title="确认通过审批？通过后将自动签发证书" onConfirm={() => handleApprove(r.uuid)}>
                <Button type="link" size="small" icon={<CheckOutlined />}>通过</Button>
              </Popconfirm>
              <Button type="link" size="small" danger icon={<CloseOutlined />}
                onClick={() => setRejectOpen(r)}>拒绝</Button>
            </>
          )}
        </Space>
      ),
    },
  ], [isAdmin]);

  return (
    <div>
      <Card
        title={<Space><AuditOutlined />
          <Title level={4} style={{ margin: 0 }}>证书申请审核</Title></Space>}
        extra={
          <Space>
            <Select
              style={{ width: 160 }} allowClear placeholder="按状态过滤"
              value={statusFilter} onChange={(v) => { setStatusFilter(v); setPage(1); }}
              options={Object.entries(statusTexts).map(([v, l]) => ({ label: l, value: v }))}
            />
            <Button icon={<ReloadOutlined />} onClick={() => fetchData()}>刷新</Button>
          </Space>
        }
      >
        {isAdmin && (
          <Alert
            type="warning" showIcon style={{ marginBottom: 16 }}
            message="审批通过后，系统将自动调用签发引擎为申请人生成证书并写入云端智能卡。请仔细核实主体信息和扩展信息。"
          />
        )}
        <Table
          rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          scroll={{ x: 1200 }}
          pagination={{
            current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      {/* 拒绝弹窗 */}
      <Modal
        open={!!rejectOpen} title="拒绝证书申请"
        onCancel={() => { setRejectOpen(null); rejectForm.resetFields(); }}
        onOk={handleReject} destroyOnClose
      >
        <Form form={rejectForm} layout="vertical">
          <Form.Item name="reason" label="拒绝原因"
            rules={[{ required: true, message: '请输入拒绝原因' }]}>
            <Input.TextArea rows={3} maxLength={500} placeholder="请说明拒绝原因" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 详情抽屉 */}
      <Drawer width={640} open={!!detail} onClose={() => setDetail(null)} title="证书申请详情">
        {detail && (
          <>
            <Steps
              size="small" style={{ marginBottom: 24 }}
              current={
                detail.status === 'pending' ? 0
                : detail.status === 'approved' ? 1
                : detail.status === 'issued' ? 2
                : detail.status === 'rejected' ? 0
                : 0
              }
              status={detail.status === 'rejected' ? 'error' : 'process'}
              items={[
                { title: '提交申请' },
                { title: '管理员审批' },
                { title: '证书签发' },
              ]}
            />
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="申请 UUID">{detail.uuid}</Descriptions.Item>
              <Descriptions.Item label="用户 UUID">{detail.user_uuid}</Descriptions.Item>
              <Descriptions.Item label="订单 UUID">{detail.order_uuid || '-'}</Descriptions.Item>
              <Descriptions.Item label="主体信息 UUID">{detail.subject_info_uuid || '-'}</Descriptions.Item>
              <Descriptions.Item label="扩展信息 UUID">{detail.extension_info_uuid || '-'}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColors[detail.status]}>{statusTexts[detail.status] || detail.status}</Tag>
              </Descriptions.Item>
              {detail.reject_reason && (
                <Descriptions.Item label="拒绝原因">
                  <Text type="danger">{detail.reject_reason}</Text>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="提交时间">
                {new Date(detail.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
              <Descriptions.Item label="更新时间">
                {new Date(detail.updated_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
            </Descriptions>
          </>
        )}
      </Drawer>
    </div>
  );
};

export default CertApplicationsPage;
