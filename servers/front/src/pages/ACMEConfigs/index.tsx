import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm,
} from 'antd';
import {
  CloudServerOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined,
} from '@ant-design/icons';
import {
  listACMEConfigs, createACMEConfig, updateACMEConfig, deleteACMEConfig,
  listCAs, listIssuanceTemplates,
} from '../../api';
import type { ACMEConfig, CA, IssuanceTemplate } from '../../types';

const { Title, Text } = Typography;

const challengeMeta: Record<string, { color: string; label: string }> = {
  'http-01': { color: 'blue', label: 'HTTP-01' },
  'dns-01': { color: 'green', label: 'DNS-01' },
  'tls-alpn-01': { color: 'purple', label: 'TLS-ALPN-01' },
};

/**
 * ACME 服务配置：绑定 CA 与颁发模板，并选择允许的验证方式。
 * 颁发模板决定签发参数（算法、有效期、资料要求）；CA 与模板必须相互匹配。
 */
const ACMEConfigsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ACMEConfig[]>([]);
  const [cas, setCAs] = useState<CA[]>([]);
  const [tmpls, setTmpls] = useState<IssuanceTemplate[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ACMEConfig | null>(null);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try {
      const r = await listACMEConfigs();
      setData(Array.isArray(r) ? r : (r as any)?.items || []);
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  const fetchOptions = async () => {
    try {
      const [caRes, tmplRes] = await Promise.all([
        listCAs({ page: 1, page_size: 200 }),
        listIssuanceTemplates({ page: 1, page_size: 200 }),
      ]);
      setCAs(Array.isArray(caRes?.items) ? caRes.items : []);
      setTmpls(Array.isArray(tmplRes?.items) ? tmplRes.items : []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetch(); fetchOptions(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ enabled: true, allowed_challenges: ['http-01', 'dns-01'], path: '/acme/default' });
    setOpen(true);
  };

  const openEdit = (r: ACMEConfig) => {
    setEditing(r);
    form.setFieldsValue({
      path: r.path,
      ca_uuid: r.ca_uuid,
      template_uuid: r.template_uuid,
      allowed_challenges: r.allowed_challenges ?? ['http-01', 'dns-01'],
      enabled: r.enabled,
    });
    setOpen(true);
  };

  const handleSubmit = async (values: any) => {
    const payload = {
      path: values.path,
      ca_uuid: values.ca_uuid,
      template_uuid: values.template_uuid,
      enabled: values.enabled !== false,
      allowed_challenges: values.allowed_challenges?.length ? values.allowed_challenges : ['http-01', 'dns-01'],
    } as any;
    try {
      if (editing) {
        await updateACMEConfig(editing.uuid, payload);
        message.success('ACME 配置已更新');
      } else {
        await createACMEConfig(payload);
        message.success('ACME 配置已创建');
      }
      setOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteACMEConfig(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = useMemo(() => [
    { title: '服务路径', dataIndex: 'path', key: 'path',
      render: (v: string) => <Text copyable code>{`/acme/${String(v || '').replace(/^\/?(acme\/)?/, '')}`}</Text> },
    { title: '签发 CA', dataIndex: 'ca_name', key: 'ca_name',
      render: (_: any, r: ACMEConfig) =>
        r.ca_name || cas.find((c) => c.uuid === r.ca_uuid)?.name || '—' },
    { title: '颁发模板', dataIndex: 'template_name', key: 'template_name',
      render: (_: any, r: ACMEConfig) =>
        r.template_name || tmpls.find((t) => t.uuid === r.template_uuid)?.name || '—' },
    {
      title: '允许验证方式', dataIndex: 'allowed_challenges', key: 'allowed_challenges', width: 240,
      render: (v: string[] | undefined) => {
        const items = v && v.length > 0 ? v : ['http-01', 'dns-01'];
        return (
          <Space size={4} wrap>
            {items.map((c) => (
              <Tag key={c} color={challengeMeta[c]?.color || 'default'}>{challengeMeta[c]?.label || c}</Tag>
            ))}
          </Space>
        );
      },
    },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => (v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag>) },
    {
      title: '操作', key: 'actions', width: 150, fixed: 'right' as const,
      render: (_: any, r: ACMEConfig) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除此 ACME 配置？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], [cas, tmpls]);

  return (
    <div>
      <Card
        title={<Space><CloudServerOutlined />
          <Title level={4} style={{ margin: 0 }}>ACME 服务配置</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增配置</Button>
          </Space>
        }
      >
        <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
          ACME 客户端（certbot、acme.sh 等）按这里的路径申请证书；验证方式按需勾选。
        </Text>
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} scroll={{ x: 1000 }} />
      </Card>

      <Modal
        open={open} title={editing ? '编辑 ACME 配置' : '新增 ACME 配置'}
        onCancel={() => { setOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} width={640}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit} initialValues={{ enabled: true }}>
          <Form.Item
            name="path" label="服务路径"
            rules={[
              { required: true, message: '请输入 ACME 服务路径' },
              { pattern: /^\/?[\w\-/]*$/, message: '路径只能包含字母、数字、连字符与斜杠' },
            ]}
            extra="客户端将访问 /acme/<路径>/directory"
          >
            <Input placeholder="default" />
          </Form.Item>
          <Form.Item name="template_uuid" label="颁发模板" rules={[{ required: true, message: '请选择颁发模板' }]}
            extra="决定签发算法、有效期与资料要求">
            <Select
              showSearch optionFilterProp="label"
              options={tmpls.map((t) => ({ label: t.name, value: t.uuid }))} />
          </Form.Item>
          <Form.Item name="ca_uuid" label="签发 CA" rules={[{ required: true, message: '请选择 CA' }]}
            extra="SM2 模板只能用 SM2 CA">
            <Select
              showSearch optionFilterProp="label"
              options={cas.filter((c) => c.status === 'active')
                .map((c) => ({ label: `${c.name}（${c.key_type || '未知算法'}）`, value: c.uuid }))} />
          </Form.Item>
          <Form.Item
            name="allowed_challenges" label="允许的验证方式"
            extra="DNS-01 支持通配符域名；TLS-ALPN-01 适合 80 端口不可用的场景"
          >
            <Select
              mode="multiple" allowClear
              options={[
                { label: 'HTTP-01（80 端口文件校验）', value: 'http-01' },
                { label: 'DNS-01（TXT 记录，支持通配符）', value: 'dns-01' },
                { label: 'TLS-ALPN-01（443 端口 ALPN）', value: 'tls-alpn-01' },
              ]}
            />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default ACMEConfigsPage;
