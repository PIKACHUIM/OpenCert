import React, { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Switch, Space, Tag, message, Popconfirm } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { listIssuanceTemplates, createIssuanceTemplate, deleteIssuanceTemplate } from '../../api';
import type { IssuanceTemplate, CA } from '../../types';

const { Option } = Select;
const KEY_TYPES = ['ec256', 'ec384', 'rsa2048', 'rsa4096', 'ec521'];

// ---- 颁发模板（技术参数：怎么签） ----
const IssuanceTab: React.FC<{ cas: CA[] }> = ({ cas }) => {
  const [data, setData] = useState<IssuanceTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { const r = await listIssuanceTemplates(); setData(Array.isArray(r?.items) ? r.items : []); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '分类', dataIndex: 'category', key: 'category', render: (v: string) => <Tag>{v}</Tag> },
    { title: '可用有效期', dataIndex: 'validity_options', key: 'validity', render: (v: number[]) => (v ?? []).map((d) => `${d}天`).join(' / ') || '—' },
    { title: '可用 CA', dataIndex: 'allowed_ca_uuids', key: 'allowed_ca_uuids',
      render: (v: string[]) => (v ?? []).map((id) => cas.find((c) => c.uuid === id)?.name || id.slice(0, 6)).join('、') || '—' },
    { title: '启用', dataIndex: 'enabled', key: 'enabled', render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '启用' : '禁用'}</Tag> },
    {
      title: '操作', key: 'action', render: (_: any, r: IssuanceTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteIssuanceTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建颁发模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建颁发模板" open={open} onCancel={() => setOpen(false)} footer={null} width={600}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createIssuanceTemplate(v); message.success('创建成功'); setOpen(false); form.resetFields(); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="分类" name="category" rules={[{ required: true }]}>
            <Select><Option value="ssl">SSL</Option><Option value="code_sign">代码签名</Option><Option value="email">邮件</Option><Option value="custom">自定义</Option></Select>
          </Form.Item>
          <Form.Item label="允许的证书有效期（天，可多选）" name="validity_options" initialValue={[365]}>
            <Select mode="tags" placeholder="365 / 90 / 30" />
          </Form.Item>
          <Form.Item label="是否为 CA 证书" name="is_ca" valuePropName="checked" initialValue={false}><Switch /></Form.Item>
          <Form.Item label="允许密钥类型" name="allowed_key_types" initialValue={['ec256', 'rsa2048']}>
            <Select mode="multiple">{KEY_TYPES.map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="可颁发 CA" name="allowed_ca_uuids">
            <Select mode="multiple">{cas.map(c => <Option key={c.uuid} value={c.uuid}>{c.name}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="是否启用" name="enabled" valuePropName="checked" initialValue={true}><Switch /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};
export default IssuanceTab;