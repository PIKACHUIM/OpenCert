import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Switch, Select,
  message, Popconfirm,
} from 'antd';
import {
  FileTextOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined,
} from '@ant-design/icons';
import { listCertPolicies, saveCertPolicy, deleteCertPolicy } from '../../api';
import type { CertPolicy } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

/**
 * CertPolicies 页面：证书策略（CP）/ 证书实践声明（CPS）等公开文档。
 *
 * 每个策略是一个独立页面：/policy/{path}，以 Markdown 或 HTML 形式返回，
 * 可被颁发模板的证书策略扩展（CPS URI）引用，也可在官网「信任服务」中列出。
 */
const CertPoliciesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CertPolicy[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<CertPolicy | null>(null);
  const [form] = Form.useForm();
  const contentType = Form.useWatch('content_type', form);

  const fetchData = async () => {
    setLoading(true);
    try { setData(await listCertPolicies()); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchData(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ content_type: 'markdown', enabled: true, is_public: true, version: 'v1.0' });
    setOpen(true);
  };

  const openEdit = async (r: CertPolicy) => {
    setEditing(r);
    form.setFieldsValue({ ...r });
    setOpen(true);
  };

  const handleSubmit = async (values: any) => {
    try {
      await saveCertPolicy({ ...values, uuid: editing?.uuid });
      message.success(editing ? '已更新' : '已创建');
      setOpen(false);
      fetchData();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteCertPolicy(uuid); message.success('已删除'); fetchData(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = [
    { title: '策略名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: CertPolicy) => (
        <Space direction="vertical" size={0}>
          <Text strong>{v}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>版本 {r.version || '—'}</Text>
        </Space>
      ) },
    { title: '访问地址', dataIndex: 'path', key: 'path',
      render: (v: string) => <Text copyable code style={{ fontSize: 12 }}>{`/policy/${v}`}</Text> },
    { title: '格式', dataIndex: 'content_type', key: 'content_type', width: 110,
      render: (v: string) => <Tag color={v === 'html' ? 'purple' : 'blue'}>{v}</Tag> },
    { title: '公开', dataIndex: 'is_public', key: 'is_public', width: 100,
      render: (v: boolean) => v ? <Tag color="green">官网可见</Tag> : <Tag>仅内网</Tag> },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 170,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 150,
      render: (_: any, r: CertPolicy) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除此策略页面？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><FileTextOutlined /><Title level={4} style={{ margin: 0 }}>证书策略管理</Title>
          <HelpLink doc="admin-11-ocsp-policy" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchData}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增策略</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          locale={{ emptyText: '还没有证书策略。发布后可对外提供公开链接。' }} />
      </Card>

      <Modal
        open={open} title={editing ? '编辑策略' : '新增策略'}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} destroyOnClose width={820}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="name" label="策略名称" rules={[{ required: true, message: '请输入名称' }]} style={{ flex: 2 }}>
              <Input placeholder="例如：证书实践声明（CPS）" />
            </Form.Item>
            <Form.Item name="version" label="版本" style={{ flex: 1 }}>
              <Input placeholder="v1.0" />
            </Form.Item>
          </Space>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="path" label="访问路径" style={{ flex: 1 }}
              rules={[{ required: true, message: '请输入路径' },
                { pattern: /^[a-z0-9][a-z0-9._-]{0,94}$/, message: '仅小写字母、数字、点、下划线、短横线' }]}
              extra="公开地址：/policy/{路径}">
              <Input placeholder="cps" addonBefore="/policy/" />
            </Form.Item>
            <Form.Item name="content_type" label="内容格式" style={{ flex: 1 }}>
              <Select options={[{ label: 'Markdown', value: 'markdown' }, { label: 'HTML', value: 'html' }]} />
            </Form.Item>
          </Space>
          <Form.Item
            name="content" label="正文"
            rules={[{ required: true, message: '请输入正文' }]}
            extra={contentType === 'html'
              ? 'HTML 内容以严格 CSP 返回（禁止脚本），适合已有排版好的文档'
              : '支持 Markdown 语法，建议包含：适用证书类型、身份验证要求、吊销与退款政策、责任与限制'}
          >
            <Input.TextArea rows={16} style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }} />
          </Form.Item>
          <Space size={24}>
            <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="is_public" label="在官网信任服务中公开" valuePropName="checked"><Switch /></Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  );
};

export default CertPoliciesPage;
