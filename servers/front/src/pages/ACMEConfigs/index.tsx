import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm, Alert,
} from 'antd';
import {
  CloudServerOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined,
} from '@ant-design/icons';
import {
  listACMEConfigs, createACMEConfig, deleteACMEConfig,
  listCAs, listIssuanceTemplates,
} from '../../api';
import type { ACMEConfig, CA, IssuanceTemplate } from '../../types';

const { Title, Text } = Typography;

/**
 * ACMEConfigs 页面：ACME 服务配置管理。
 * - 配置 ACME 服务的访问路径，绑定 CA 与颁发模板
 * - 支持 HTTP-01 / DNS-01 挑战（后端已实现）
 */
const ACMEConfigsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ACMEConfig[]>([]);
  const [cas, setCAs] = useState<CA[]>([]);
  const [tmpls, setTmpls] = useState<IssuanceTemplate[]>([]);

  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listACMEConfigs(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
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

  const handleCreate = async (values: any) => {
    try {
      await createACMEConfig({
        path: values.path, ca_uuid: values.ca_uuid,
        template_uuid: values.template_uuid, enabled: values.enabled !== false,
        allowed_challenges: values.allowed_challenges && values.allowed_challenges.length > 0
          ? values.allowed_challenges
          : ['http-01', 'dns-01'],
      });
      message.success('ACME 配置已创建');
      setCreateOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteACMEConfig(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = useMemo(() => [
    { title: '服务路径', dataIndex: 'path', key: 'path',
      render: (v: string) => <Text copyable code>{v}</Text> },
    { title: '绑定 CA', dataIndex: 'ca_name', key: 'ca_name',
      render: (_: any, r: ACMEConfig) =>
        r.ca_name || cas.find((c) => c.uuid === r.ca_uuid)?.name || r.ca_uuid.substring(0, 8) },
    { title: '颁发模板', dataIndex: 'template_name', key: 'template_name',
      render: (_: any, r: ACMEConfig) =>
        r.template_name || tmpls.find((t) => t.uuid === r.template_uuid)?.name || r.template_uuid.substring(0, 8) },
    { title: '允许验证方式', dataIndex: 'allowed_challenges', key: 'allowed_challenges',
      render: (v: string[] | undefined) => {
        const items = v && v.length > 0 ? v : ['http-01', 'dns-01'];
        return (
          <Space size={4} wrap>
            {items.map((c) => {
              const colorMap: Record<string, string> = {
                'http-01': 'blue', 'dns-01': 'green', 'tls-alpn-01': 'purple',
              };
              return <Tag key={c} color={colorMap[c] || 'default'}>{c}</Tag>;
            })}
          </Space>
        );
      }
    },
    { title: '启用', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v
        ? <Tag color="success">启用</Tag>
        : <Tag color="default">禁用</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: ACMEConfig) => (
        <Popconfirm title="确认删除此 ACME 配置？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
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
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增配置</Button>
          </Space>
        }
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="ACME 协议（RFC 8555）支持自动化证书申请与续期，可与 certbot、acme.sh 等客户端集成。配置路径示例：/acme/letsencrypt"
        />
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新增 ACME 配置"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate} initialValues={{ enabled: true }}>
          <Form.Item
            name="path" label="服务路径"
            rules={[
              { required: true, message: '请输入 ACME 服务路径' },
              { pattern: /^\/[\w\-/]+$/, message: '路径必须以 / 开头' },
            ]}
            extra="例如：/acme/default；ACME 客户端将访问 <host><path>/directory"
          >
            <Input placeholder="/acme/default" />
          </Form.Item>
          <Form.Item name="ca_uuid" label="绑定 CA" rules={[{ required: true, message: '请选择 CA' }]}>
            <Select options={cas.map((c) => ({ label: c.name, value: c.uuid }))} />
          </Form.Item>
          <Form.Item name="template_uuid" label="颁发模板" rules={[{ required: true, message: '请选择颁发模板' }]}>
            <Select options={tmpls.map((t) => ({ label: t.name, value: t.uuid }))} />
          </Form.Item>
          <Form.Item
            name="allowed_challenges"
            label="允许验证方式"
            initialValue={['http-01', 'dns-01']}
            extra="HTTP-01 通过 80 端口验证；DNS-01 校验 _acme-challenge TXT 记录；TLS-ALPN-01 通过 443 端口 ALPN=acme-tls/1 验证（RFC 8737）。"
          >
            <Select
              mode="multiple"
              allowClear
              options={[
                { label: 'HTTP-01（推荐）', value: 'http-01' },
                { label: 'DNS-01（适合通配符域名）', value: 'dns-01' },
                { label: 'TLS-ALPN-01（适合 80 端口被占用）', value: 'tls-alpn-01' },
              ]}
            />
          </Form.Item>
          <Form.Item name="enabled" label="是否启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default ACMEConfigsPage;
