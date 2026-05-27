import React, { useState, useEffect } from 'react';
import {
  Tabs, Table, Button, Modal, Form, Input, Select, Space,
  Tag, Typography, message, Popconfirm, Alert,
} from 'antd';
import { PlusOutlined, DeleteOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons';
import {
  listSubjectInfos, createSubjectInfo, approveSubjectInfo, rejectSubjectInfo, deleteSubjectInfo,
  listExtensionInfos, createExtensionInfo, verifyDNS, verifyEmail, deleteExtensionInfo,
  listSubjectTemplates,
} from '../../api';
import { useAuthStore } from '../../store/auth';
import type { SubjectInfo, ExtensionInfo, SubjectTemplate } from '../../types';

const { Title, Text } = Typography;
const { Option } = Select;

const statusColor: Record<string, string> = { pending: 'orange', approved: 'green', rejected: 'red', verified: 'green', expired: 'orange' };
const statusText: Record<string, string> = { pending: '待审核', approved: '已通过', rejected: '已拒绝', verified: '已验证', expired: '已过期' };

// ---- 主体信息 Tab ----
const SubjectInfoTab: React.FC = () => {
  const { role } = useAuthStore();
  const [data, setData] = useState<SubjectInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [templates, setTemplates] = useState<SubjectTemplate[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<SubjectTemplate | null>(null);
  const [form] = Form.useForm();

  const load = async (p = 1) => {
    setLoading(true);
    try { const res = await listSubjectInfos({ page: p, page_size: 20 }); setData(Array.isArray(res?.items) ? res.items : []); setTotal(res?.total ?? 0); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    listSubjectTemplates().then(res => setTemplates(Array.isArray(res) ? res : [])).catch(() => {});
  }, []);

  const handleCreate = async (values: any) => {
    if (!selectedTemplate) return;
    setSaving(true);
    try {
      const fields: Record<string, string> = {};
      selectedTemplate.fields.forEach(f => { if (values[`field_${f.name}`]) fields[f.name] = values[`field_${f.name}`]; });
      await createSubjectInfo({ template_uuid: selectedTemplate.uuid, fields });
      message.success('主体信息已提交，等待审核');
      setOpen(false); form.resetFields(); setSelectedTemplate(null); load();
    } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
  };

  const columns = [
    { title: '关联模板', dataIndex: 'template_name', key: 'template_name', render: (v: string) => v || '-' },
    {
      title: '字段摘要', dataIndex: 'fields', key: 'fields',
      render: (v: Record<string, string>) => Object.entries(v || {}).slice(0, 3).map(([k, val]) => `${k}: ${val}`).join(' | '),
    },
    { title: '审核状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={statusColor[v]}>{statusText[v] || v}</Tag> },
    {
      title: '操作', key: 'action', render: (_: any, r: SubjectInfo) => (
        <Space size={4}>
          {role === 'admin' && r.status === 'pending' && (
            <>
              <Button size="small" type="primary" icon={<CheckOutlined />} onClick={async () => { await approveSubjectInfo(r.uuid); load(); }}>通过</Button>
              <Button size="small" danger icon={<CloseOutlined />} onClick={async () => { await rejectSubjectInfo(r.uuid, '管理员拒绝'); load(); }}>拒绝</Button>
            </>
          )}
          <Popconfirm title="确认删除？" onConfirm={async () => { await deleteSubjectInfo(r.uuid); load(); }}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>添加主体信息</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); load(p); } }} />
      <Modal title="添加主体信息" open={open} onCancel={() => { setOpen(false); form.resetFields(); setSelectedTemplate(null); }} footer={null} width={520}>
        <Form form={form} layout="vertical" onFinish={handleCreate} style={{ marginTop: 16 }}>
          <Form.Item label="选择主体模板" name="template_uuid" rules={[{ required: true }]}>
            <Select placeholder="请选择主体模板" onChange={(uuid) => setSelectedTemplate(templates.find(t => t.uuid === uuid) || null)}>
              {templates.map(t => <Option key={t.uuid} value={t.uuid}>{t.name}</Option>)}
            </Select>
          </Form.Item>
          {selectedTemplate?.fields.map(f => (
            <Form.Item key={f.name} label={f.name} name={`field_${f.name}`}
              rules={[{ required: f.required, message: `请输入 ${f.name}` }]}
              initialValue={f.default_value}>
              <Input maxLength={f.max_length} placeholder={f.default_value || `请输入 ${f.name}`} />
            </Form.Item>
          ))}
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>提交</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};

// ---- 扩展信息 Tab ----
const ExtensionInfoTab: React.FC = () => {
  const [data, setData] = useState<ExtensionInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [verifyEmailOpen, setVerifyEmailOpen] = useState(false);
  const [verifyTarget, setVerifyTarget] = useState<ExtensionInfo | null>(null);
  const [emailCode, setEmailCode] = useState('');
  const [form] = Form.useForm();

  const load = async (p = 1) => {
    setLoading(true);
    try { const res = await listExtensionInfos({ page: p, page_size: 20 }); setData(Array.isArray(res?.items) ? res.items : []); setTotal(res?.total ?? 0); }
    catch (e: any) { message.error(e.message); } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const columns = [
    { title: '类型', dataIndex: 'type', key: 'type', render: (v: string) => <Tag>{{ domain: '域名', email: '邮箱', ip: 'IP' }[v] || v}</Tag> },
    { title: '值', dataIndex: 'value', key: 'value', render: (v: string) => <Text code>{v}</Text> },
    { title: '验证方式', dataIndex: 'verify_method', key: 'verify_method', render: (v: string) => ({ dns: 'DNS TXT', email: '邮件验证码', none: '无需验证' }[v] || v) },
    { title: '验证状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={statusColor[v]}>{statusText[v] || v}</Tag> },
    { title: '有效期', dataIndex: 'expires_at', key: 'expires_at', render: (v: string) => v?.slice(0, 10) || '-' },
    {
      title: '操作', key: 'action', render: (_: any, r: ExtensionInfo) => (
        <Space size={4}>
          {r.status === 'pending' && r.verify_method === 'dns' && (
            <Button size="small" type="primary" onClick={async () => {
              try { await verifyDNS(r.uuid); message.success('DNS 验证成功'); load(); }
              catch (e: any) { message.error(e.message || 'DNS 验证失败，请确认 TXT 记录已生效'); }
            }}>验证 DNS</Button>
          )}
          {r.status === 'pending' && r.verify_method === 'email' && (
            <Button size="small" type="primary" onClick={() => { setVerifyTarget(r); setVerifyEmailOpen(true); }}>输入验证码</Button>
          )}
          <Popconfirm title="确认删除？" onConfirm={async () => { await deleteExtensionInfo(r.uuid); load(); }}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>添加扩展信息</Button>
      </div>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading}
        expandable={{
          expandedRowRender: (r: ExtensionInfo) => r.verify_method === 'dns' && r.status === 'pending' ? (
            <Alert type="info" message="DNS 验证说明"
              description={<>请添加 TXT 记录：<Text code>_opencert.{r.value} TXT opencert-verify={r.verify_token || '（请刷新获取）'}</Text></>} />
          ) : null,
        }}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); load(p); } }} />
      <Modal title="添加扩展信息" open={open} onCancel={() => { setOpen(false); form.resetFields(); }} footer={null}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try { await createExtensionInfo(v); message.success('扩展信息已添加，请完成验证'); setOpen(false); form.resetFields(); load(); }
          catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="类型" name="type" rules={[{ required: true }]}>
            <Select><Option value="domain">域名</Option><Option value="email">邮箱</Option><Option value="ip">IP 地址</Option></Select>
          </Form.Item>
          <Form.Item label="值" name="value" rules={[{ required: true }]}><Input placeholder="example.com / user@example.com / 192.168.1.1" /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={saving}>添加</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
      <Modal title="邮箱验证" open={verifyEmailOpen} onCancel={() => setVerifyEmailOpen(false)}
        onOk={async () => {
          if (!verifyTarget) return;
          try { await verifyEmail(verifyTarget.uuid, emailCode); message.success('邮箱验证成功'); setVerifyEmailOpen(false); setEmailCode(''); load(); }
          catch (e: any) { message.error(e.message || '验证码错误'); }
        }} okText="验证">
        <div style={{ marginTop: 16 }}>
          <Text>请输入发送到 <Text strong>{verifyTarget?.value}</Text> 的验证码：</Text>
          <Input style={{ marginTop: 12 }} value={emailCode} onChange={e => setEmailCode(e.target.value)} placeholder="请输入验证码" maxLength={8} />
        </div>
      </Modal>
    </>
  );
};

const Identity: React.FC = () => (
  <div>
    <Title level={4} style={{ margin: '0 0 16px' }}>身份信息管理</Title>
    <Tabs items={[
      { key: 'subject', label: '主体信息', children: <SubjectInfoTab /> },
      { key: 'extension', label: '扩展信息（域名/邮箱/IP）', children: <ExtensionInfoTab /> },
    ]} />
  </div>
);

export default Identity;
