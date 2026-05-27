import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm,
} from 'antd';
import {
  NumberOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { listOIDs, createOID, deleteOID } from '../../api';
import type { CustomOID } from '../../types';

const { Title, Text } = Typography;

/**
 * OIDs 页面：自定义 OID 管理。
 * - 用于扩展密钥用途、主体字段、EV 策略、ASN.1 扩展
 */
const OIDsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CustomOID[]>([]);
  const [filter, setFilter] = useState<string | undefined>();
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listOIDs(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetch(); }, []);

  const filtered = useMemo(
    () => filter ? data.filter((d) => d.usage_type === filter) : data,
    [data, filter],
  );

  const handleCreate = async (values: any) => {
    try {
      await createOID({
        oid: values.oid, name: values.name,
        description: values.description, usage_type: values.usage_type,
      });
      message.success('OID 已添加');
      setCreateOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '添加失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteOID(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const usageTypeColors: Record<string, string> = {
    ext_key_usage: 'blue',
    subject_field: 'green',
    ev_policy: 'purple',
    asn1_extension: 'orange',
  };
  const usageTypeTexts: Record<string, string> = {
    ext_key_usage: '扩展密钥用途',
    subject_field: '主体字段',
    ev_policy: 'EV 策略',
    asn1_extension: 'ASN.1 扩展',
  };

  const columns = [
    { title: 'OID', dataIndex: 'oid', key: 'oid',
      render: (v: string) => <Text copyable code>{v}</Text> },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '用途类型', dataIndex: 'usage_type', key: 'usage_type',
      render: (v: string) => <Tag color={usageTypeColors[v] || 'default'}>{usageTypeTexts[v] || v}</Tag> },
    { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: CustomOID) => (
        <Popconfirm title="确认删除此 OID？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><NumberOutlined />
          <Title level={4} style={{ margin: 0 }}>自定义 OID 管理</Title></Space>}
        extra={
          <Space>
            <Select
              allowClear placeholder="按用途筛选" style={{ width: 200 }}
              value={filter} onChange={setFilter}
              options={Object.entries(usageTypeTexts).map(([v, l]) => ({ label: l, value: v }))}
            />
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增 OID</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={filtered} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新增 OID"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}
          initialValues={{ usage_type: 'ext_key_usage' }}>
          <Form.Item
            name="oid" label="OID"
            rules={[
              { required: true, message: '请输入 OID' },
              { pattern: /^(\d+\.)+\d+$/, message: 'OID 格式错误，如：1.3.6.1.4.1.311' },
            ]}
          >
            <Input placeholder="1.3.6.1.4.1.311" />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={128} placeholder="例如：msSmartcardLogon" />
          </Form.Item>
          <Form.Item name="usage_type" label="用途类型" rules={[{ required: true }]}>
            <Select options={Object.entries(usageTypeTexts).map(([v, l]) => ({ label: l, value: v }))} />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={3} maxLength={500} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default OIDsPage;
