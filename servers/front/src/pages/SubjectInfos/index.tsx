import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm, Drawer, Descriptions,
} from 'antd';
import {
  IdcardOutlined, PlusOutlined, ReloadOutlined, CheckOutlined, CloseOutlined, DeleteOutlined,
} from '@ant-design/icons';
import {
  listSubjectInfos, createSubjectInfo, deleteSubjectInfo,
  approveSubjectInfo, rejectSubjectInfo, listSubjectTemplates,
} from '../../api';
import type { SubjectInfo, SubjectTemplate } from '../../types';
import { useAuthStore } from '../../store/auth';

const { Title, Text } = Typography;

/**
 * SubjectInfos 页面：主体信息管理。
 * - 用户自建主体信息（按主体模板填写）
 * - 管理员审核：通过 / 拒绝
 */
const SubjectInfosPage: React.FC = () => {
  const { role } = useAuthStore();
  const isAdmin = role === 'admin' || role === 'super_admin';

  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<SubjectInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const [tmpls, setTmpls] = useState<SubjectTemplate[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();
  const [selectedTmpl, setSelectedTmpl] = useState<SubjectTemplate | null>(null);

  const [detail, setDetail] = useState<SubjectInfo | null>(null);
  const [rejectOpen, setRejectOpen] = useState<SubjectInfo | null>(null);
  const [rejectForm] = Form.useForm();

  const fetchData = async (p = page, ps = pageSize) => {
    setLoading(true);
    try {
      const res = await listSubjectInfos({ page: p, page_size: ps });
      setData(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally { setLoading(false); }
  };

  const fetchTmpls = async () => {
    try { const r = await listSubjectTemplates(); setTmpls(Array.isArray(r) ? r : (r as any)?.items || []); } catch { /* ignore */ }
  };

  useEffect(() => { fetchData(); fetchTmpls(); /* eslint-disable-next-line */ }, []);
  useEffect(() => { fetchData(page, pageSize); /* eslint-disable-next-line */ }, [page, pageSize]);

  const handleCreate = async (values: any) => {
    if (!selectedTmpl) { message.error('请选择主体模板'); return; }
    const fields: Record<string, string> = {};
    selectedTmpl.fields.forEach((f) => { fields[f.name] = values[f.name] || ''; });
    try {
      await createSubjectInfo({ template_uuid: selectedTmpl.uuid, fields });
      message.success('主体信息已提交，等待审核');
      setCreateOpen(false);
      form.resetFields();
      setSelectedTmpl(null);
      fetchData();
    } catch (e: any) { message.error(e.message || '提交失败'); }
  };

  const handleApprove = async (uuid: string) => {
    try { await approveSubjectInfo(uuid); message.success('已通过审核'); fetchData(); }
    catch (e: any) { message.error(e.message || '审核失败'); }
  };

  const handleReject = async () => {
    if (!rejectOpen) return;
    try {
      const reason = rejectForm.getFieldValue('reason');
      await rejectSubjectInfo(rejectOpen.uuid, reason);
      message.success('已拒绝');
      setRejectOpen(null);
      rejectForm.resetFields();
      fetchData();
    } catch (e: any) { message.error(e.message || '拒绝失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteSubjectInfo(uuid); message.success('已删除'); fetchData(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = useMemo(() => [
    {
      title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 120, ellipsis: true,
      render: (v: string) => <Text copyable={{ text: v }}>{v.substring(0, 8)}...</Text>,
    },
    { title: '主体模板', dataIndex: 'template_name', key: 'template_name',
      render: (v: string) => v || <Text type="secondary">-</Text> },
    {
      title: '主要字段', key: 'fields',
      render: (_: any, r: SubjectInfo) => {
        const keys = Object.keys(r.fields || {}).slice(0, 3);
        return (
          <Space size={4} wrap>
            {keys.map((k) => <Tag key={k}>{k}={r.fields[k]}</Tag>)}
            {Object.keys(r.fields || {}).length > 3 && <Tag>...</Tag>}
          </Space>
        );
      },
    },
    {
      title: '状态', dataIndex: 'status', key: 'status',
      render: (v: string) => {
        const colors: Record<string, string> = { pending: 'processing', approved: 'success', rejected: 'error' };
        const texts: Record<string, string> = { pending: '待审核', approved: '已通过', rejected: '已拒绝' };
        return <Tag color={colors[v]}>{texts[v] || v}</Tag>;
      },
    },
    { title: '拒绝原因', dataIndex: 'reject_reason', key: 'reject_reason', ellipsis: true },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 260,
      render: (_: any, r: SubjectInfo) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetail(r)}>详情</Button>
          {isAdmin && r.status === 'pending' && (
            <>
              <Popconfirm title="确认通过审核？" onConfirm={() => handleApprove(r.uuid)}>
                <Button type="link" size="small" icon={<CheckOutlined />}>通过</Button>
              </Popconfirm>
              <Button type="link" size="small" danger icon={<CloseOutlined />} onClick={() => setRejectOpen(r)}>
                拒绝
              </Button>
            </>
          )}
          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], [isAdmin]);

  return (
    <div>
      <Card
        title={<Space><IdcardOutlined />
          <Title level={4} style={{ margin: 0 }}>主体信息管理</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => fetchData()}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新建主体信息</Button>
          </Space>
        }
      >
        <Table
          rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          pagination={{
            current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <Modal
        open={createOpen} title="新建主体信息"
        onCancel={() => { setCreateOpen(false); setSelectedTmpl(null); form.resetFields(); }}
        onOk={() => form.submit()}
        width={640} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}>
          <Form.Item label="主体模板" required>
            <Select
              value={selectedTmpl?.uuid} placeholder="请选择主体模板"
              onChange={(v) => setSelectedTmpl(tmpls.find((t) => t.uuid === v) || null)}
              options={tmpls.map((t) => ({ label: t.name, value: t.uuid }))}
            />
          </Form.Item>
          {selectedTmpl && selectedTmpl.fields.map((f) => (
            <Form.Item
              key={f.name} name={f.name} label={f.name}
              rules={f.required ? [{ required: true, message: `请输入${f.name}` }] : []}
              initialValue={f.default_value}
            >
              <Input maxLength={f.max_length || undefined} placeholder={`模板字段：${f.name}`} />
            </Form.Item>
          ))}
        </Form>
      </Modal>

      <Modal
        open={!!rejectOpen} title="拒绝主体信息"
        onCancel={() => { setRejectOpen(null); rejectForm.resetFields(); }}
        onOk={handleReject} destroyOnClose
      >
        <Form form={rejectForm} layout="vertical">
          <Form.Item name="reason" label="拒绝原因" rules={[{ required: true, message: '请输入拒绝原因' }]}>
            <Input.TextArea rows={3} maxLength={200} />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer width={560} open={!!detail} onClose={() => setDetail(null)} title="主体信息详情">
        {detail && (
          <>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="UUID">{detail.uuid}</Descriptions.Item>
              <Descriptions.Item label="主体模板">{detail.template_name || detail.template_uuid}</Descriptions.Item>
              <Descriptions.Item label="状态"><Tag>{detail.status}</Tag></Descriptions.Item>
              <Descriptions.Item label="拒绝原因">{detail.reject_reason || '-'}</Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {new Date(detail.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
            </Descriptions>
            <div style={{ marginTop: 16 }}>
              <Title level={5}>字段内容</Title>
              <Descriptions column={1} bordered size="small">
                {Object.entries(detail.fields || {}).map(([k, v]) => (
                  <Descriptions.Item key={k} label={k}>{v}</Descriptions.Item>
                ))}
              </Descriptions>
            </div>
          </>
        )}
      </Drawer>
    </div>
  );
};

export default SubjectInfosPage;
