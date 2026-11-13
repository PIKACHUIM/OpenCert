import React, { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Switch, Space, Typography, message, Popconfirm, Card } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { listExtensionTemplates, createExtensionTemplate, deleteExtensionTemplate, updateExtensionTemplate, listVerifyProviders } from '../../api';
import type { ExtensionTemplate, VerifyProvider } from '../../types';
const { Text } = Typography;
const VERIFY_OPTIONS = [
  { label: '人工审核', value: 'manual' },
  { label: '自动接口（实名认证）', value: 'auto' },
  { label: '免验证', value: 'none' },
];

// ---- 扩展信息模板（按类型的验证策略） ----
const defaultPolicy = (_kind: string, methods: string[]) => ({
  enabled: true, mode: 'auto', methods, validity: '30d',
});

const ExtensionInfoTab: React.FC = () => {
  const [data, setData] = useState<ExtensionTemplate[]>([]);
  const [providers, setProviders] = useState<VerifyProvider[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState<ExtensionTemplate | null>(null);
  const [policy, setPolicy] = useState<any>({
    domain: defaultPolicy('domain', ['dns', 'http']),
    email: defaultPolicy('email', ['email']),
    ip: defaultPolicy('ip', ['http']),
  });
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listExtensionTemplates()); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    listVerifyProviders('email').then((r) => setProviders(r.items)).catch(() => undefined);
  }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    setPolicy({
      domain: defaultPolicy('domain', ['dns', 'http']),
      email: defaultPolicy('email', ['email']),
      ip: defaultPolicy('ip', ['http']),
    });
    setOpen(true);
  };

  const openEdit = (t: ExtensionTemplate) => {
    setEditing(t);
    form.setFieldsValue({ name: t.name });
    try {
      const p = JSON.parse(t.verify_policy || '{}');
      setPolicy({
        domain: { ...defaultPolicy('domain', ['dns', 'http']), ...(p.domain ?? {}) },
        email: { ...defaultPolicy('email', ['email']), ...(p.email ?? {}) },
        ip: { ...defaultPolicy('ip', ['http']), ...(p.ip ?? {}) },
      });
    } catch { /* 保留默认策略 */ }
    setOpen(true);
  };

  const submit = async (v: any) => {
    setSaving(true);
    try {
      const payload = { name: v.name, verify_policy: JSON.stringify(policy) };
      if (editing) await updateExtensionTemplate(editing.uuid, payload as any);
      else await createExtensionTemplate(payload as any);
      message.success('已保存');
      setOpen(false); load();
    } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
  };

  const renderPolicyRow = (key: 'domain' | 'email' | 'ip', title: string, methodOptions: { label: string; value: string }[]) => (
    <Card size="small" title={title} style={{ marginBottom: 8 }}>
      <Space size={12} wrap>
        <Space size={4}>
          <Switch checked={policy[key].enabled} onChange={(v) => setPolicy({ ...policy, [key]: { ...policy[key], enabled: v } })} />
          <Text>允许此类扩展信息</Text>
        </Space>
        <Select value={policy[key].mode} style={{ width: 190 }}
          onChange={(v) => setPolicy({ ...policy, [key]: { ...policy[key], mode: v } })}
          options={VERIFY_OPTIONS} />
        <Select mode="multiple" value={policy[key].methods} style={{ minWidth: 260 }}
          onChange={(v) => setPolicy({ ...policy, [key]: { ...policy[key], methods: v.length ? v : [methodOptions[0].value] } })}
          options={methodOptions} />
        {key === 'email' && (
          <Select allowClear placeholder="邮件接口（缺省用系统 SMTP）" style={{ minWidth: 220 }}
            value={policy[key].provider_uuid || undefined}
            onChange={(v) => setPolicy({ ...policy, [key]: { ...policy[key], provider_uuid: v || '' } })}
            options={providers.map((p) => ({ label: p.name, value: p.uuid }))} />
        )}
        <Input value={policy[key].validity} style={{ width: 110 }} addonBefore="有效期"
          onChange={(e) => setPolicy({ ...policy, [key]: { ...policy[key], validity: e.target.value } })} />
      </Space>
    </Card>
  );

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '验证策略', dataIndex: 'verify_policy', key: 'verify_policy',
      render: (v: string) => {
        try {
          const p = JSON.parse(v || '{}');
          const desc = (k: string, label: string) => p[k]
            ? `${label} ${p[k].enabled ? (p[k].mode === 'auto' ? p[k].methods?.join('/') : p[k].mode === 'manual' ? '人工' : '免验证') : '不支持'}`
            : '';
          return <Text style={{ fontSize: 12 }}>{[desc('domain', '域名'), desc('email', '邮箱'), desc('ip', 'IP')].filter(Boolean).join('；') || '缺省策略'}</Text>;
        } catch { return <Text type="secondary">缺省策略</Text>; }
      } },
    {
      title: '操作', key: 'action', width: 140, render: (_: any, r: ExtensionTemplate) => (
        <Space size={4}>
          <Button size="small" type="link" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除？" onConfirm={async () => {
            try { await deleteExtensionTemplate(r.uuid); load(); } catch (e: any) { message.error(e.message); }
          }}>
            <Button size="small" danger type="link">删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>创建扩展信息模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />

      <Modal title={editing ? '编辑扩展信息模板' : '创建扩展信息模板'} open={open}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={saving} destroyOnClose width={900}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}>
            <Input placeholder="例如：标准 DV 验证" />
          </Form.Item>
          {renderPolicyRow('domain', '域名', [
            { label: 'DNS TXT 记录', value: 'dns' },
            { label: 'HTTP 文件', value: 'http' },
            { label: 'TLS-ALPN（RFC 8737）', value: 'tls' },
          ])}
          {renderPolicyRow('email', '邮箱', [{ label: '邮箱验证码', value: 'email' }])}
          {renderPolicyRow('ip', 'IP 地址', [{ label: 'HTTP 文件', value: 'http' }])}
        </Form>
      </Modal>
    </>
  );
};
export default ExtensionInfoTab;