import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, InputNumber,
  Select, Switch, message, Popconfirm,
} from 'antd';
import {
  StopOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined,
} from '@ant-design/icons';
import {
  listRevocationServices, createRevocationService, deleteRevocationService, listCAs,
} from '../../api';
import type { RevocationService, CA } from '../../types';

const { Title, Text } = Typography;

/**
 * RevocationServices 页面：吊销服务管理。
 * - 针对每个 CA 配置 CRL / OCSP / CAIssuer 三种服务的访问路径和开关
 * - CRL 支持独立的发布周期（分钟）
 */
const RevocationServicesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<RevocationService[]>([]);
  const [cas, setCAs] = useState<CA[]>([]);
  const [caFilter, setCAFilter] = useState<string | undefined>();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listRevocationServices(caFilter); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  const fetchCAs = async () => {
    try {
      const res = await listCAs({ page: 1, page_size: 200 });
      setCAs(Array.isArray(res?.items) ? res.items : []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetchCAs(); }, []);
  useEffect(() => { fetch(); /* eslint-disable-next-line */ }, [caFilter]);

  const handleCreate = async (values: any) => {
    try {
      await createRevocationService({
        ca_uuid: values.ca_uuid, service_type: values.service_type,
        path: values.path, enabled: values.enabled !== false,
        crl_interval_minutes: values.crl_interval_minutes,
      });
      message.success('吊销服务已创建');
      setCreateOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteRevocationService(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const typeColors: Record<string, string> = { crl: 'blue', ocsp: 'green', caissuer: 'purple' };

  const columns = useMemo(() => [
    { title: 'CA', dataIndex: 'ca_name', key: 'ca_name',
      render: (_: any, r: RevocationService) =>
        r.ca_name || cas.find((c) => c.uuid === r.ca_uuid)?.name || r.ca_uuid.substring(0, 8) },
    { title: '类型', dataIndex: 'service_type', key: 'service_type',
      render: (v: string) => <Tag color={typeColors[v] || 'default'}>{v.toUpperCase()}</Tag> },
    { title: '访问路径', dataIndex: 'path', key: 'path',
      render: (v: string) => <Text copyable code>{v}</Text> },
    {
      title: '启用', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v
        ? <Tag color="success">启用</Tag>
        : <Tag color="default">禁用</Tag>,
    },
    { title: 'CRL 周期(分钟)', dataIndex: 'crl_interval_minutes', key: 'crl_interval_minutes',
      render: (v: number) => v || '-' },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: RevocationService) => (
        <Popconfirm title="确认删除此吊销服务？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ], [cas]);

  return (
    <div>
      <Card
        title={<Space><StopOutlined />
          <Title level={4} style={{ margin: 0 }}>吊销服务管理</Title></Space>}
        extra={
          <Space>
            <Select
              style={{ width: 240 }} allowClear placeholder="按 CA 过滤"
              value={caFilter} onChange={setCAFilter}
              options={cas.map((c) => ({ label: c.name, value: c.uuid }))}
            />
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增服务</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新增吊销服务"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}
          initialValues={{ service_type: 'crl', enabled: true, crl_interval_minutes: 1440 }}>
          <Form.Item name="ca_uuid" label="绑定 CA" rules={[{ required: true, message: '请选择 CA' }]}>
            <Select options={cas.map((c) => ({ label: c.name, value: c.uuid }))} />
          </Form.Item>
          <Form.Item name="service_type" label="服务类型" rules={[{ required: true }]}>
            <Select options={[
              { label: 'CRL（证书吊销列表）', value: 'crl' },
              { label: 'OCSP（在线状态查询）', value: 'ocsp' },
              { label: 'CAIssuer（CA 证书下载）', value: 'caissuer' },
            ]} />
          </Form.Item>
          <Form.Item
            name="path" label="访问路径"
            rules={[{ required: true, message: '请输入访问路径' }]}
            extra="CRL: /crl/{ca}；OCSP: /ocsp/{ca}；CAIssuer: /ca-cert/{ca}"
          >
            <Input placeholder="例如：/crl/{ca_uuid} 或 /ocsp/{ca_uuid}" />
          </Form.Item>
          <Form.Item name="enabled" label="是否启用" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item
            name="crl_interval_minutes" label="CRL 发布周期（分钟，仅 CRL 类型生效）"
            tooltip="默认 1440 分钟（1 天），最小 1 分钟"
          >
            <InputNumber min={1} max={10080} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default RevocationServicesPage;
