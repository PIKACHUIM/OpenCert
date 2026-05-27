import React, { useState, useEffect } from 'react';
import {
  Tabs, Table, Button, Modal, Form, Input, Select, InputNumber,
  Switch, Space, Tag, Typography, message, Popconfirm, Checkbox,
} from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import {
  listIssuanceTemplates, createIssuanceTemplate, deleteIssuanceTemplate,
  listSubjectTemplates, createSubjectTemplate, deleteSubjectTemplate,
  listExtensionTemplates, createExtensionTemplate, deleteExtensionTemplate,
  listKeyUsageTemplates, createKeyUsageTemplate, deleteKeyUsageTemplate,
  listCertExtTemplates, createCertExtTemplate, deleteCertExtTemplate,
  listKeyStorageTemplates, createKeyStorageTemplate, deleteKeyStorageTemplate,
  listCAs,
} from '../../api';
import type {
  IssuanceTemplate, SubjectTemplate, ExtensionTemplate,
  KeyUsageTemplate, CertExtTemplate, KeyStorageTemplate, CA,
} from '../../types';

const { Title, Text } = Typography;
const { Option } = Select;

const KEY_TYPES = ['ec256', 'ec384', 'rsa2048', 'rsa4096', 'ec521'];

// ---- 颁发模板 ----
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
    { title: '启用', dataIndex: 'enabled', key: 'enabled', render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '启用' : '禁用'}</Tag> },
    { title: '定价', dataIndex: 'price', key: 'price', render: (v: number) => v === 0 ? '免费' : `¥${(v / 100).toFixed(2)}` },
    { title: '库存', dataIndex: 'stock', key: 'stock', render: (v: number) => v === -1 ? '无限' : v },
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
      <Modal title="创建颁发模板" open={open} onCancel={() => setOpen(false)} footer={null} width={560}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createIssuanceTemplate(v); message.success('创建成功'); setOpen(false); form.resetFields(); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="分类" name="category" rules={[{ required: true }]}>
            <Select><Option value="ssl">SSL</Option><Option value="code_sign">代码签名</Option><Option value="email">邮件</Option><Option value="custom">自定义</Option></Select>
          </Form.Item>
          <Form.Item label="是否为 CA 证书" name="is_ca" valuePropName="checked" initialValue={false}><Switch /></Form.Item>
          <Form.Item label="允许密钥类型" name="allowed_key_types">
            <Select mode="multiple">{KEY_TYPES.map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="可颁发 CA" name="allowed_ca_uuids">
            <Select mode="multiple">{cas.map(c => <Option key={c.uuid} value={c.uuid}>{c.name}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="定价（分，0=免费）" name="price" initialValue={0}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="库存（-1=无限）" name="stock" initialValue={-1}><InputNumber min={-1} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="是否启用" name="enabled" valuePropName="checked" initialValue={true}><Switch /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 主体模板 ----
const SubjectTab: React.FC = () => {
  const [data, setData] = useState<SubjectTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [fields, setFields] = useState([{ name: '', required: false, default_value: '', max_length: 128 }]);
  const [form] = Form.useForm();

  const load = async () => { setLoading(true); try { const r = await listSubjectTemplates(); setData(Array.isArray(r) ? r : (r as any).items || []); } catch {} finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '字段数量', dataIndex: 'fields', key: 'fields', render: (v: any[]) => v?.length || 0 },
    {
      title: '操作', key: 'action', render: (_: any, r: SubjectTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteSubjectTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建主体模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建主体模板" open={open} onCancel={() => setOpen(false)} footer={null} width={600}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createSubjectTemplate({ name: v.name, fields }); message.success('创建成功'); setOpen(false); form.resetFields(); setFields([{ name: '', required: false, default_value: '', max_length: 128 }]); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <div style={{ marginBottom: 8 }}><Text strong>字段列表</Text></div>
          {fields.map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8, alignItems: 'center' }}>
              <Input placeholder="字段名" value={f.name} onChange={e => { const nf = [...fields]; nf[i].name = e.target.value; setFields(nf); }} style={{ flex: 2 }} />
              <Checkbox checked={f.required} onChange={e => { const nf = [...fields]; nf[i].required = e.target.checked; setFields(nf); }}>必填</Checkbox>
              <Input placeholder="默认值" value={f.default_value} onChange={e => { const nf = [...fields]; nf[i].default_value = e.target.value; setFields(nf); }} style={{ flex: 2 }} />
              <InputNumber placeholder="最大长度" value={f.max_length} onChange={v => { const nf = [...fields]; nf[i].max_length = v || 128; setFields(nf); }} style={{ width: 90 }} />
              <Button size="small" danger onClick={() => setFields(fields.filter((_, j) => j !== i))}>删除</Button>
            </div>
          ))}
          <Button size="small" onClick={() => setFields([...fields, { name: '', required: false, default_value: '', max_length: 128 }])}>+ 添加字段</Button>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right', marginTop: 16 }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 扩展信息模板 ----
const ExtensionTab: React.FC = () => {
  const [data, setData] = useState<ExtensionTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => { setLoading(true); try { const r = await listExtensionTemplates(); setData(Array.isArray(r) ? r : (r as any).items || []); } catch {} finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '最大 DNS', dataIndex: 'max_dns', key: 'max_dns' },
    { title: '最大邮箱', dataIndex: 'max_email', key: 'max_email' },
    { title: '最大 IP', dataIndex: 'max_ip', key: 'max_ip' },
    { title: '需要验证', dataIndex: 'require_verify', key: 'require_verify', render: (v: boolean) => <Tag color={v ? 'blue' : 'default'}>{v ? '是' : '否'}</Tag> },
    {
      title: '操作', key: 'action', render: (_: any, r: ExtensionTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteExtensionTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建扩展信息模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建扩展信息模板" open={open} onCancel={() => setOpen(false)} footer={null}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createExtensionTemplate(v); message.success('创建成功'); setOpen(false); form.resetFields(); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="最大 DNS 数量" name="max_dns" initialValue={10}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="最大邮箱数量" name="max_email" initialValue={5}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="最大 IP 数量" name="max_ip" initialValue={5}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="最大 URI 数量" name="max_uri" initialValue={5}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item label="需要验证" name="require_verify" valuePropName="checked" initialValue={true}><Switch /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 密钥用途模板 ----
const KeyUsageTab: React.FC = () => {
  const [data, setData] = useState<KeyUsageTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => { setLoading(true); try { const r = await listKeyUsageTemplates(); setData(Array.isArray(r) ? r : (r as any).items || []); } catch {} finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '扩展密钥用法', dataIndex: 'ext_key_usage', key: 'ext_key_usage', render: (v: string[]) => v?.map(u => <Tag key={u} style={{ fontSize: 11 }}>{u}</Tag>) },
    {
      title: '操作', key: 'action', render: (_: any, r: KeyUsageTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteKeyUsageTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建密钥用途模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建密钥用途模板" open={open} onCancel={() => setOpen(false)} footer={null} width={520}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createKeyUsageTemplate({ ...v, key_usage: 0 }); message.success('创建成功'); setOpen(false); form.resetFields(); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="扩展密钥用法" name="ext_key_usage">
            <Select mode="multiple">
              <Option value="1.3.6.1.5.5.7.3.1">服务器认证</Option>
              <Option value="1.3.6.1.5.5.7.3.2">客户端认证</Option>
              <Option value="1.3.6.1.5.5.7.3.3">代码签名</Option>
              <Option value="1.3.6.1.5.5.7.3.4">邮件保护</Option>
              <Option value="1.3.6.1.5.5.7.3.8">时间戳</Option>
              <Option value="1.3.6.1.5.5.7.3.9">OCSP 签名</Option>
            </Select>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
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
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => { setLoading(true); try { const r = await listCertExtTemplates(); setData(Array.isArray(r) ? r : (r as any).items || []); } catch {} finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: 'CRL 分发点', dataIndex: 'crl_distribution_points', key: 'crl', render: (v: string[]) => v?.length || 0 },
    { title: 'OCSP 服务器', dataIndex: 'ocsp_servers', key: 'ocsp', render: (v: string[]) => v?.length || 0 },
    { title: 'CT 服务器', dataIndex: 'ct_servers', key: 'ct', render: (v: string[]) => v?.length || 0 },
    { title: 'EV 策略 OID', dataIndex: 'ev_policy_oid', key: 'ev', render: (v: string) => v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : '-' },
    {
      title: '操作', key: 'action', render: (_: any, r: CertExtTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteCertExtTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建证书拓展模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建证书拓展模板" open={open} onCancel={() => setOpen(false)} footer={null} width={560}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try {
            await createCertExtTemplate({
              name: v.name,
              crl_distribution_points: v.crl_distribution_points ? v.crl_distribution_points.split('\n').map((s: string) => s.trim()).filter(Boolean) : [],
              ocsp_servers: v.ocsp_servers ? v.ocsp_servers.split('\n').map((s: string) => s.trim()).filter(Boolean) : [],
              aia_issuers: v.aia_issuers ? v.aia_issuers.split('\n').map((s: string) => s.trim()).filter(Boolean) : [],
              ct_servers: v.ct_servers ? v.ct_servers.split('\n').map((s: string) => s.trim()).filter(Boolean) : [],
              ev_policy_oid: v.ev_policy_oid || undefined,
            });
            message.success('创建成功'); setOpen(false); form.resetFields(); load();
          } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="CRL 分发点（每行一个 URL）" name="crl_distribution_points"><Input.TextArea rows={3} placeholder="http://crl.example.com/ca.crl" /></Form.Item>
          <Form.Item label="OCSP 服务器（每行一个 URL）" name="ocsp_servers"><Input.TextArea rows={2} placeholder="http://ocsp.example.com" /></Form.Item>
          <Form.Item label="AIA 颁发者（每行一个 URL）" name="aia_issuers"><Input.TextArea rows={2} placeholder="http://ca.example.com/ca.crt" /></Form.Item>
          <Form.Item label="CT 服务器（每行一个 URL）" name="ct_servers"><Input.TextArea rows={2} placeholder="https://ct.googleapis.com/logs/argon2024" /></Form.Item>
          <Form.Item label="EV 策略 OID（可选）" name="ev_policy_oid"><Input placeholder="2.23.140.1.1" /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 密钥存储类型模板 ----
const KeyStorageTab: React.FC = () => {
  const [data, setData] = useState<KeyStorageTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [hasVirtual, setHasVirtual] = useState(false);
  const [secLevel, setSecLevel] = useState<string>('medium');
  const [cloudBackup, setCloudBackup] = useState(false);
  const [form] = Form.useForm();

  const load = async () => { setLoading(true); try { const r = await listKeyStorageTemplates(); setData(Array.isArray(r) ? r : (r as any).items || []); } catch {} finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    {
      title: '允许存储方式', key: 'storage', render: (_: any, r: KeyStorageTemplate) => (
        <Space wrap size={4}>
          {r.allow_file_download && <Tag color="blue">文件下载</Tag>}
          {r.allow_cloud_card && <Tag color="purple">云端智能卡</Tag>}
          {r.allow_physical_card && <Tag color="green">实体智能卡</Tag>}
          {r.allow_virtual_card && <Tag color="orange">虚拟智能卡</Tag>}
        </Space>
      ),
    },
    { title: '安全等级', dataIndex: 'virtual_card_security', key: 'security', render: (v: string) => ({ high: '高', medium: '中', low: '低' }[v] || v) },
    { title: '云端备份', dataIndex: 'cloud_backup', key: 'cloud_backup', render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '是' : '否'}</Tag> },
    { title: '最大下发次数', dataIndex: 'max_reissue_count', key: 'max_reissue_count', render: (v: number) => v === -1 ? '无限' : v },
    {
      title: '操作', key: 'action', render: (_: any, r: KeyStorageTemplate) => (
        <Popconfirm title="确认删除？" onConfirm={async () => { await deleteKeyStorageTemplate(r.uuid); load(); }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>创建密钥存储模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading} size="small" />
      <Modal title="创建密钥存储类型模板" open={open}
        onCancel={() => { setOpen(false); form.resetFields(); setHasVirtual(false); setSecLevel('medium'); setCloudBackup(false); }}
        footer={null} width={560}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try {
            await createKeyStorageTemplate({
              name: v.name,
              allow_file_download: v.storage_modes?.includes('file') || false,
              allow_cloud_card: v.storage_modes?.includes('cloud') || false,
              allow_physical_card: v.storage_modes?.includes('physical') || false,
              allow_virtual_card: v.storage_modes?.includes('virtual') || false,
              virtual_card_security: v.virtual_card_security || 'medium',
              allow_reimport: secLevel !== 'high' ? (v.allow_reimport || false) : false,
              cloud_backup: v.cloud_backup || false,
              allow_reissue: v.allow_reissue || false,
              max_reissue_count: v.allow_reissue ? (v.max_reissue_count || -1) : 0,
            });
            message.success('创建成功'); setOpen(false); form.resetFields(); setHasVirtual(false); setSecLevel('medium'); setCloudBackup(false); load();
          } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="存储方式" name="storage_modes" rules={[{ required: true, message: '请选择至少一种存储方式' }]}>
            <Checkbox.Group onChange={(v) => setHasVirtual(v.includes('virtual'))} options={[
              { label: '文件下载', value: 'file' },
              { label: '云端智能卡', value: 'cloud' },
              { label: '实体智能卡', value: 'physical' },
              { label: '虚拟智能卡', value: 'virtual' },
            ]} />
          </Form.Item>
          {hasVirtual && (
            <Form.Item label="虚拟卡安全等级" name="virtual_card_security" initialValue="medium">
              <Select onChange={setSecLevel}>
                <Option value="high">高安全性（不可重新导入）</Option>
                <Option value="medium">中安全性</Option>
                <Option value="low">低安全性</Option>
              </Select>
            </Form.Item>
          )}
          <Form.Item label="允许重新导入" name="allow_reimport" valuePropName="checked" initialValue={false}>
            <Switch disabled={secLevel === 'high'} />
          </Form.Item>
          <Form.Item label="云端备份私钥" name="cloud_backup" valuePropName="checked" initialValue={false}>
            <Switch onChange={setCloudBackup} />
          </Form.Item>
          {cloudBackup && (
            <>
              <Form.Item label="支持重新下发" name="allow_reissue" valuePropName="checked" initialValue={false}><Switch /></Form.Item>
              <Form.Item label="最大下发次数（-1=无限）" name="max_reissue_count" initialValue={-1}><InputNumber min={-1} style={{ width: '100%' }} /></Form.Item>
            </>
          )}
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 主页面 ----
const Templates: React.FC = () => {
  const [cas, setCAs] = useState<CA[]>([]);
  useEffect(() => { listCAs({ page: 1, page_size: 100 }).then(r => setCAs(Array.isArray(r?.items) ? r.items : [])).catch(() => {}); }, []);

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 16px' }}>模板管理</Title>
      <Tabs items={[
        { key: 'issuance', label: '颁发模板', children: <IssuanceTab cas={cas} /> },
        { key: 'subject', label: '主体模板', children: <SubjectTab /> },
        { key: 'extension', label: '扩展信息模板', children: <ExtensionTab /> },
        { key: 'key_usage', label: '密钥用途模板', children: <KeyUsageTab /> },
        { key: 'cert_ext', label: '证书拓展模板', children: <CertExtTab /> },
        { key: 'key_storage', label: '密钥存储类型模板', children: <KeyStorageTab /> },
      ]} />
    </div>
  );
};

export default Templates;
