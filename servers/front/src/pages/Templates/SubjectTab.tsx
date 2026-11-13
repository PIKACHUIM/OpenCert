import React, { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, InputNumber, Space, Tag, Typography, message, Popconfirm, Checkbox, Tooltip, Card } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { listSubjectTemplates, createSubjectTemplate, deleteSubjectTemplate, updateSubjectTemplate, listSubjectFieldMeta, listVerifyProviders } from '../../api';
import type { SubjectTemplate, SubjectTemplateField, SubjectFieldMeta, VerifyProvider } from '../../types';
const { Text, Paragraph } = Typography;
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
export default SubjectTab;