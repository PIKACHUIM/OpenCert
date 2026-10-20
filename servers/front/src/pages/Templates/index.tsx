import React, { useEffect, useMemo, useState } from 'react';
import {
  Tabs, Table, Button, Modal, Form, Input, Select, InputNumber, Switch, Space, Tag,
  Typography, message, Popconfirm, Checkbox, Tooltip, Card,
} from 'antd';
import { PlusOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons';
import { useSearchParams } from 'react-router-dom';
import {
  listIssuanceTemplates, createIssuanceTemplate, deleteIssuanceTemplate,
  listSubjectTemplates, createSubjectTemplate, deleteSubjectTemplate, updateSubjectTemplate,
  listExtensionTemplates, createExtensionTemplate, deleteExtensionTemplate, updateExtensionTemplate,
  listKeyUsageTemplates, createKeyUsageTemplate, updateKeyUsageTemplate, deleteKeyUsageTemplate,
  listCertExtTemplates, createCertExtTemplate, updateCertExtTemplate, deleteCertExtTemplate,
  listCAs, listSubjectFieldMeta, listVerifyProviders,
  listOIDs, createOID, updateOID, deleteOID,
} from '../../api';
import type {
  IssuanceTemplate, SubjectTemplate, SubjectTemplateField, ExtensionTemplate,
  KeyUsageTemplate, CertExtTemplate, CA, SubjectFieldMeta, VerifyProvider,
} from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

const KEY_TYPES = ['ec256', 'ec384', 'rsa2048', 'rsa4096', 'ec521'];
const VERIFY_OPTIONS = [
  { label: '人工审核', value: 'manual' },
  { label: '自动接口（实名认证）', value: 'auto' },
  { label: '免验证', value: 'none' },
];
const DERIVE_OPTIONS = [
  { label: '不派生（用户填写）', value: '' },
  { label: '取自第一个域名', value: 'first_domain' },
  { label: '取自第一个邮箱', value: 'first_email' },
  { label: '取自第一个 IP', value: 'first_ip' },
];
const FORMAT_OPTIONS = [
  { label: '不限', value: '' },
  { label: '国家代码（2 位大写）', value: 'country' },
  { label: '邮箱', value: 'email' },
  { label: '域名', value: 'domain' },
  { label: '纯数字', value: 'digits' },
  { label: '统一社会信用代码', value: 'uscc' },
];

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

// ---- 主体模板（字段、验证方式、派生、有效期） ----
const emptyField = (): SubjectTemplateField => ({
  key: 'CN', required: true, min_len: 0, max_len: 64, format: '', pattern: '', verify: 'manual', derive: '', default: '', help: '',
});

const SubjectTab: React.FC = () => {
  const [data, setData] = useState<SubjectTemplate[]>([]);
  const [meta, setMeta] = useState<SubjectFieldMeta[]>([]);
  const [providers, setProviders] = useState<VerifyProvider[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editing, setEditing] = useState<SubjectTemplate | null>(null);
  const [fields, setFields] = useState<SubjectTemplateField[]>([emptyField()]);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listSubjectTemplates()); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    listSubjectFieldMeta().then(setMeta).catch(() => undefined);
    listVerifyProviders('identity').then((r) => setProviders(r.items)).catch(() => undefined);
  }, []);

  const setField = (i: number, patch: Partial<SubjectTemplateField>) => {
    const nf = [...fields];
    nf[i] = { ...nf[i], ...patch };
    if (patch.derive) nf[i].verify = 'none';
    setFields(nf);
  };

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    setFields([emptyField()]);
    form.setFieldsValue({ verify_validity: '365d' });
    setOpen(true);
  };

  const openEdit = (t: SubjectTemplate) => {
    setEditing(t);
    form.setFieldsValue({
      name: t.name, description: t.description, verify_provider_uuid: t.verify_provider_uuid,
      verify_validity: t.verify_validity || '365d',
    });
    setFields((t.fields ?? []).length ? t.fields : [emptyField()]);
    setOpen(true);
  };

  const submit = async (v: any) => {
    if (fields.some((f) => !f.key)) { message.error('存在未选择字段名的行'); return; }
    if (new Set(fields.map((f) => f.key)).size !== fields.length) { message.error('字段不能重复'); return; }
    setSaving(true);
    try {
      const payload = {
        name: v.name, description: v.description,
        fields, verify_provider_uuid: v.verify_provider_uuid || '',
        verify_validity: v.verify_validity || '365d',
      };
      if (editing) await updateSubjectTemplate(editing.uuid, payload as any);
      else await createSubjectTemplate(payload as any);
      message.success('已保存');
      setOpen(false); load();
    } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '字段', dataIndex: 'fields', key: 'fields',
      render: (fs: SubjectTemplateField[]) => (
        <Space size={4} wrap>
          {(fs ?? []).map((f) => (
            <Tag key={f.key} color={f.derive ? 'purple' : f.verify === 'auto' ? 'blue' : f.verify === 'none' ? 'default' : 'orange'}>
              {f.key}{f.required ? '*' : ''}{f.derive ? '（派生）' : ''}
            </Tag>
          ))}
        </Space>
      ) },
    { title: '验证方式', key: 'mode',
      render: (_: any, r: SubjectTemplate) => {
        const has = (m: string) => (r.fields ?? []).some((f) => f.verify === m && !f.derive);
        return <Space size={4}>
          {has('manual') && <Tag color="orange">人工</Tag>}
          {has('auto') && <Tag color="blue">实名接口</Tag>}
          {!has('manual') && !has('auto') && <Tag>免验证</Tag>}
        </Space>;
      } },
    { title: '有效期', dataIndex: 'verify_validity', key: 'verify_validity', render: (v: string) => v || '365d' },
    {
      title: '操作', key: 'action', width: 140, render: (_: any, r: SubjectTemplate) => (
        <Space size={4}>
          <Button size="small" type="link" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除？" onConfirm={async () => {
            try { await deleteSubjectTemplate(r.uuid); load(); } catch (e: any) { message.error(e.message); }
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
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>创建主体模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />

      <Modal title={editing ? '编辑主体模板' : '创建主体模板'} open={open}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={saving} destroyOnClose width={980}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item label="名称" name="name" rules={[{ required: true }]} style={{ flex: 2 }}>
              <Input placeholder="例如：SSL DV 主体" />
            </Form.Item>
            <Form.Item label="审核/认证有效期" name="verify_validity" style={{ flex: 1 }}
              extra="1d/7d/30d/365d；0 表示长期有效">
              <Input />
            </Form.Item>
            <Form.Item label="实名认证接口" name="verify_provider_uuid" style={{ flex: 2 }}
              extra="存在「自动接口」字段时必选">
              <Select allowClear options={providers.map((p) => ({ label: p.name, value: p.uuid }))} />
            </Form.Item>
          </Space>
          <Form.Item label="说明" name="description"><Input /></Form.Item>

          <Text strong>字段列表</Text>
          <div style={{ marginTop: 8 }}>
            {fields.map((f, i) => (
              <Card key={i} size="small" style={{ marginBottom: 8 }}>
                <Space size={8} wrap align="baseline">
                  <Select
                    value={f.key} style={{ width: 220 }} showSearch optionFilterProp="label"
                    onChange={(v) => setField(i, { key: v })}
                    options={meta.map((m) => ({ label: m.label, value: m.key }))}
                  />
                  <Checkbox checked={f.required} onChange={(e) => setField(i, { required: e.target.checked })}>必填</Checkbox>
                  <Tooltip title="长度范围（字符）">
                    <Space size={4}>
                      <InputNumber min={0} value={f.min_len} placeholder="最短"
                        onChange={(v) => setField(i, { min_len: v ?? 0 })} style={{ width: 90 }} />
                      <Text>~</Text>
                      <InputNumber min={0} value={f.max_len} placeholder="最长"
                        onChange={(v) => setField(i, { max_len: v ?? 0 })} style={{ width: 90 }} />
                    </Space>
                  </Tooltip>
                  <Select value={f.format || ''} style={{ width: 190 }}
                    onChange={(v) => setField(i, { format: v })} options={FORMAT_OPTIONS} />
                  <Input value={f.pattern} placeholder="自定义正则（可选）" style={{ width: 200 }}
                    onChange={(e) => setField(i, { pattern: e.target.value })} />
                  <Select value={f.verify} style={{ width: 180 }} disabled={!!f.derive}
                    onChange={(v) => setField(i, { verify: v as any })} options={VERIFY_OPTIONS} />
                  <Select value={f.derive || ''} style={{ width: 190 }}
                    onChange={(v) => setField(i, { derive: v as any })} options={DERIVE_OPTIONS} />
                  <Input value={f.default} placeholder="默认值" style={{ width: 130 }}
                    onChange={(e) => setField(i, { default: e.target.value })} />
                  <Input value={f.help} placeholder="填写提示" style={{ width: 160 }}
                    onChange={(e) => setField(i, { help: e.target.value })} />
                  <Button size="small" danger icon={<DeleteOutlined />}
                    onClick={() => setFields(fields.filter((_, j) => j !== i))} />
                </Space>
              </Card>
            ))}
          </div>
          <Button size="small" icon={<PlusOutlined />} onClick={() => setFields([...fields, emptyField()])}>添加字段</Button>
          <Paragraph type="secondary" style={{ marginTop: 12, fontSize: 12 }}>
            提示：证书主体为纯派生字段时（如 CN 取自第一个域名），申请向导会跳过主体信息填写；仅派生字段缺失来源时会提示用户先添加对应扩展信息。
          </Paragraph>
        </Form>
      </Modal>
    </>
  );
};

// ---- 扩展信息模板（按类型的验证策略） ----
const defaultPolicy = (_kind: string, methods: string[]) => ({
  enabled: true, mode: 'auto', methods, validity: '30d',
});

const ExtensionTab: React.FC = () => {
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

// ---- 证书拓展模板 ----
const CertExtTab: React.FC = () => {
  const [data, setData] = useState<CertExtTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<CertExtTemplate | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listCertExtTemplates()); }
    catch { /* 忽略 */ } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    setOpen(true);
  };

  const openEdit = (r: CertExtTemplate) => {
    setEditing(r);
    form.setFieldsValue({
      name: r.name,
      crl_distribution_points: (r.crl_distribution_points ?? []).join('\n'),
      ocsp_servers: (r.ocsp_servers ?? []).join('\n'),
      aia_issuers: (r.aia_issuers ?? []).join('\n'),
      ct_servers: (r.ct_servers ?? []).join('\n'),
      ev_policy_oid: r.ev_policy_oid,
    });
    setOpen(true);
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: 'CRL 分发点', dataIndex: 'crl_distribution_points', key: 'crl', render: (v: string[]) => v?.length || 0 },
    { title: 'OCSP 服务器', dataIndex: 'ocsp_servers', key: 'ocsp', render: (v: string[]) => v?.length || 0 },
    { title: 'AIA 颁发者', dataIndex: 'aia_issuers', key: 'aia', render: (v: string[]) => v?.length || 0 },
    { title: 'CT 服务器', dataIndex: 'ct_servers', key: 'ct', render: (v: string[]) => v?.length || 0 },
    {
      title: 'EV 策略 OID', dataIndex: 'ev_policy_oid', key: 'ev',
      render: (v: string) => (v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : '-'),
    },
    {
      title: '操作', key: 'action', width: 150, fixed: 'right' as const,
      render: (_: any, r: CertExtTemplate) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="被颁发模板引用时无法删除" onConfirm={async () => {
            try { await deleteCertExtTemplate(r.uuid); message.success('已删除'); load(); }
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
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建证书拓展模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns as any} dataSource={data} loading={loading} size="small" scroll={{ x: 900 }} />
      <Modal title={editing ? '编辑证书拓展模板' : '新建证书拓展模板'} open={open}
        onCancel={() => setOpen(false)} footer={null} width={600}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try {
            const split = (s?: string) => (s ? s.split('\n').map((x: string) => x.trim()).filter(Boolean) : []);
            const payload = {
              name: v.name,
              crl_distribution_points: split(v.crl_distribution_points),
              ocsp_servers: split(v.ocsp_servers),
              aia_issuers: split(v.aia_issuers),
              ct_servers: split(v.ct_servers),
              ev_policy_oid: v.ev_policy_oid || undefined,
            };
            if (editing) await updateCertExtTemplate(editing.uuid, payload);
            else await createCertExtTemplate(payload);
            message.success('已保存'); setOpen(false); form.resetFields(); load();
          } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true, message: '请填写名称' }]}><Input /></Form.Item>
          <Form.Item label="CRL 分发点（每行一个 URL）" name="crl_distribution_points" extra="签发时写入证书，客户端据此下载吊销列表">
            <Input.TextArea rows={2} placeholder="http://crl.example.com/ca.crl" />
          </Form.Item>
          <Form.Item label="OCSP 服务器（每行一个 URL）" name="ocsp_servers">
            <Input.TextArea rows={2} placeholder="http://ocsp.example.com" />
          </Form.Item>
          <Form.Item label="AIA 颁发者（每行一个 URL）" name="aia_issuers" extra="指向 CA 证书，便于客户端补链">
            <Input.TextArea rows={2} placeholder="http://ca.example.com/ca.crt" />
          </Form.Item>
          <Form.Item label="CT 服务器（每行一个 URL）" name="ct_servers">
            <Input.TextArea rows={2} placeholder="https://ct.example.com/logs/1" />
          </Form.Item>
          <Form.Item label="EV 策略 OID（可选）" name="ev_policy_oid">
            <Input placeholder="2.23.140.1.1" />
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

// ---- 自定义 OID（由原「证书 OIDS 管理」并入） ----
const OidTab: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any[]>([]);
  const [filter, setFilter] = useState<string | undefined>();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<any | null>(null);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { setData(await listOIDs() as any); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };
  useEffect(() => { fetch(); }, []);

  const usageTexts: Record<string, string> = {
    ext_key_usage: '扩展密钥用途', subject_field: '主体字段', ev_policy: 'EV 策略', asn1_extension: 'ASN.1 扩展',
  };
  const filtered = useMemo(
    () => (filter ? data.filter((d) => d.usage_type === filter) : data),
    [data, filter],
  );

  return (
    <>
      <Space style={{ marginBottom: 12 }}>
        <Select allowClear placeholder="按用途筛选" style={{ width: 200 }} value={filter} onChange={setFilter}
          options={Object.entries(usageTexts).map(([v, l]) => ({ label: l, value: v }))} />
        <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>
          新增 OID
        </Button>
      </Space>
      <Table rowKey="uuid" loading={loading} dataSource={filtered} size="small"
        columns={[
          { title: 'OID', dataIndex: 'oid_value', key: 'oid_value',
            render: (v: string, r: any) => <Text copyable code>{v || r.oid}</Text> },
          { title: '名称', dataIndex: 'name', key: 'name' },
          { title: '用途类型', dataIndex: 'usage_type', key: 'usage_type',
            render: (v: string) => <Tag>{usageTexts[v] || v}</Tag> },
          { title: 'ASN.1 类型', dataIndex: 'asn1_type', key: 'asn1_type',
            render: (v: string) => v || '—' },
          {
            title: '关键扩展', dataIndex: 'is_critical', key: 'is_critical', width: 100,
            render: (v: boolean) => (v ? <Tag color="orange">是</Tag> : <Tag>否</Tag>),
          },
          { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
          {
            title: '操作', key: 'actions', width: 150, fixed: 'right' as const,
            render: (_: any, r: any) => (
              <Space size={4} style={{ whiteSpace: 'nowrap' }}>
                <Button type="link" size="small" onClick={() => {
                  setEditing(r);
                  form.setFieldsValue({
                    oid: r.oid_value || r.oid, name: r.name, usage_type: r.usage_type,
                    asn1_type: r.asn1_type || 'UTF8String', is_critical: !!r.is_critical,
                    description: r.description,
                  });
                  setOpen(true);
                }}>编辑</Button>
                <Popconfirm title="被模板引用时无法删除" onConfirm={async () => {
                  try { await deleteOID(r.uuid); fetch(); }
                  catch (e: any) { message.error(e.message); }
                }}>
                  <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
                </Popconfirm>
              </Space>
            ),
          },
        ] as any} />

      <Modal open={open} title={editing ? '编辑 OID' : '新增 OID'}
        onCancel={() => { setOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} width={560}>
        <Form form={form} layout="vertical" initialValues={{ usage_type: 'ext_key_usage', asn1_type: 'UTF8String' }}
          onFinish={async (v) => {
            try {
              const payload = {
                oid: v.oid, name: v.name, description: v.description,
                usage_type: v.usage_type, asn1_type: v.asn1_type, is_critical: !!v.is_critical,
              } as any;
              if (editing) await updateOID(editing.uuid, payload);
              else await createOID(payload);
              message.success('已保存');
              setOpen(false); form.resetFields(); fetch();
            } catch (e: any) { message.error(e.message || '保存失败'); }
          }}>
          <Form.Item name="oid" label="OID" rules={[{ required: true, message: '请输入 OID' },
            { pattern: /^(\d+\.)+\d+$/, message: 'OID 格式错误，如：1.3.6.1.4.1.311' }]}>
            <Input placeholder="1.3.6.1.4.1.311" />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={128} placeholder="例如：msSmartcardLogon" />
          </Form.Item>
          <Form.Item name="usage_type" label="用途类型" rules={[{ required: true }]}>
            <Select options={Object.entries(usageTexts).map(([v, l]) => ({ label: l, value: v }))} />
          </Form.Item>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="asn1_type" label="ASN.1 类型" style={{ flex: 1 }}
              extra="仅在证书拓展模板中作为自定义扩展使用时生效">
              <Select options={['UTF8String', 'PrintableString', 'IA5String', 'OCTET STRING', 'INTEGER', 'BOOLEAN', 'NULL']
                .map((v) => ({ label: v, value: v }))} />
            </Form.Item>
            <Form.Item name="is_critical" label="标记为关键扩展" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3} maxLength={500} /></Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 主页面 ----
const Templates: React.FC = () => {
  const [cas, setCAs] = useState<CA[]>([]);
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') || 'issuance';

  useEffect(() => {
    listCAs({ page: 1, page_size: 100 }).then(r => setCAs(Array.isArray(r?.items) ? r.items : [])).catch(() => {});
  }, []);

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 16px' }}>
        证书模板 <HelpLink doc="admin-03-ca-templates" /> <HelpLink doc="admin-13-identity-verification" label="身份认证文档" />
      </Title>
      <Tabs
        activeKey={tab}
        onChange={(k) => setParams({ tab: k })}
        items={[
          { key: 'issuance', label: '颁发模板', children: <IssuanceTab cas={cas} /> },
          { key: 'subject', label: '主体模板', children: <SubjectTab /> },
          { key: 'extension', label: '扩展信息模板', children: <ExtensionTab /> },
          { key: 'key_usage', label: '密钥用途模板', children: <KeyUsageTab /> },
          { key: 'cert_ext', label: '证书拓展模板', children: <CertExtTab /> },
          { key: 'oids', label: '自定义 OID', children: <OidTab /> },
        ]}
      />
    </div>
  );
};

export default Templates;
