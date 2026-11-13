import React, { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Space, Tag, Typography, message, Popconfirm } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { listKeyUsageTemplates, createKeyUsageTemplate, updateKeyUsageTemplate, deleteKeyUsageTemplate } from '../../api';
import type { KeyUsageTemplate } from '../../types';
const { Text } = Typography;
// ---- 密钥用途模板 ----
const keyUsageOptions = [
  { value: 1 << 0, label: '数字签名' },
  { value: 1 << 1, label: '内容承诺' },
  { value: 1 << 2, label: '密钥加密' },
  { value: 1 << 3, label: '数据加密' },
  { value: 1 << 4, label: '密钥协商' },
  { value: 1 << 5, label: '证书签名（CA）' },
  { value: 1 << 6, label: 'CRL 签名（CA）' },
];

const ekuOptions = [
  { value: '1.3.6.1.5.5.7.3.1', label: '服务器认证' },
  { value: '1.3.6.1.5.5.7.3.2', label: '客户端认证' },
  { value: '1.3.6.1.5.5.7.3.3', label: '代码签名' },
  { value: '1.3.6.1.5.5.7.3.4', label: '邮件保护' },
  { value: '1.3.6.1.5.5.7.3.8', label: '时间戳' },
  { value: '1.3.6.1.5.5.7.3.9', label: 'OCSP 签名' },
];

const KeyUsageTab: React.FC = () => {
  const [data, setData] = useState<KeyUsageTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<KeyUsageTemplate | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listKeyUsageTemplates()); }
    catch { /* 忽略 */ } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({ key_usage: 1 | (1 << 2), ext_key_usage: [] });
    setOpen(true);
  };

  const openEdit = (r: KeyUsageTemplate) => {
    setEditing(r);
    // 位掩码 → 勾选项
    const bits = keyUsageOptions.filter((o) => (r.key_usage & o.value) !== 0).map((o) => o.value);
    form.setFieldsValue({ name: r.name, key_usage: bits, ext_key_usage: r.ext_key_usage ?? [] });
    setOpen(true);
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    {
      title: '密钥用法', dataIndex: 'key_usage', key: 'key_usage',
      render: (v: number) => (
        <Space size={4} wrap>
          {keyUsageOptions.filter((o) => (v & o.value) !== 0)
            .map((o) => <Tag key={o.value} color="blue">{o.label}</Tag>)}
        </Space>
      ),
    },
    {
      title: '扩展密钥用法', dataIndex: 'ext_key_usage', key: 'ext_key_usage',
      render: (v: string[]) => (v?.length
        ? v.map((u) => <Tag key={u} style={{ fontSize: 11 }}>{ekuOptions.find((o) => o.value === u)?.label || u}</Tag>)
        : <Text type="secondary">—</Text>),
    },
    {
      title: '操作', key: 'action', width: 150, fixed: 'right' as const,
      render: (_: any, r: KeyUsageTemplate) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="被颁发模板引用时无法删除" onConfirm={async () => {
            try { await deleteKeyUsageTemplate(r.uuid); message.success('已删除'); load(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建密钥用途模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns as any} dataSource={data} loading={loading} size="small" scroll={{ x: 800 }} />
      <Modal title={editing ? '编辑密钥用途模板' : '新建密钥用途模板'} open={open}
        onCancel={() => setOpen(false)} footer={null} width={560}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try {
            const mask = (v.key_usage as number[]).reduce((a, b) => a | b, 0);
            const payload = { name: v.name, key_usage: mask, ext_key_usage: v.ext_key_usage ?? [] };
            if (editing) await updateKeyUsageTemplate(editing.uuid, payload);
            else await createKeyUsageTemplate(payload);
            message.success('已保存'); setOpen(false); form.resetFields(); load();
          } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true, message: '请填写名称' }]}><Input /></Form.Item>
          <Form.Item label="密钥用法" name="key_usage" extra="CA 证书必须包含「证书签名」">
            <Select mode="multiple" options={keyUsageOptions} />
          </Form.Item>
          <Form.Item label="扩展密钥用法" name="ext_key_usage">
            <Select mode="multiple" options={ekuOptions} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={saving}>保存</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};
export default KeyUsageTab;