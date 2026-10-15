import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, message,
  Popconfirm, Alert, Descriptions,
} from 'antd';
import {
  IdcardOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, SafetyOutlined, EditOutlined,
} from '@ant-design/icons';
import {
  listSubjectInfos, createSubjectInfo, resubmitSubjectInfo, deleteSubjectInfo,
  startSubjectIdentity, listSubjectTemplates,
} from '../../api';
import type { SubjectInfo, SubjectTemplate, SubjectTemplateField } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

const STATUS: Record<string, { text: string; color: string }> = {
  pending: { text: '待人工审核', color: 'orange' },
  verifying: { text: '待实名认证', color: 'purple' },
  approved: { text: '已通过', color: 'green' },
  rejected: { text: '已驳回', color: 'red' },
};

const VERIFY_TEXT: Record<string, string> = {
  manual: '人工审核', auto: '实名认证', none: '免验证',
};

/**
 * 证书主体信息：提交证书主体字段（CN/O/OU/C…）并跟踪审核/实名认证状态。
 *
 * 字段、验证方式（人工/自动实名接口/免验证、派生）与有效期由主体模板决定；
 * 审核通过后在有效期内可直接用于证书申请，过期需重新提交。
 */
const SubjectInfosPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<SubjectInfo[]>([]);
  const [templates, setTemplates] = useState<SubjectTemplate[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<SubjectInfo | null>(null);
  const [tmplUUID, setTmplUUID] = useState<string>('');
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      const r = await listSubjectInfos({ page: 1, page_size: 100 });
      setData(r.items ?? []);
      setTemplates(await listSubjectTemplates().catch(() => []));
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const currentFields: SubjectTemplateField[] = useMemo(() => {
    const t = templates.find((x) => x.uuid === tmplUUID);
    return (t?.fields ?? []).filter((f) => !f.derive);
  }, [templates, tmplUUID]);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    const first = templates[0]?.uuid ?? '';
    setTmplUUID(first);
    form.setFieldsValue({ subject_tmpl_uuid: first });
    setOpen(true);
  };

  const openEdit = (r: SubjectInfo) => {
    setEditing(r);
    setTmplUUID(r.template_uuid);
    form.resetFields();
    form.setFieldsValue({ subject_tmpl_uuid: r.template_uuid, ...r.fields });
    setOpen(true);
  };

  const submit = async (v: any) => {
    const fields: Record<string, string> = {};
    currentFields.forEach((f) => {
      const val = v[f.key];
      if (val !== undefined && val !== null && val !== '') fields[f.key] = String(val);
    });
    try {
      if (editing) {
        await resubmitSubjectInfo(editing.uuid, fields);
        message.success('已重新提交，等待验证');
      } else {
        const info = await createSubjectInfo({ template_uuid: tmplUUID, fields });
        message.success(info.status === 'approved' ? '已通过验证' : '已提交，等待验证');
      }
      setOpen(false);
      load();
    } catch (e: any) { message.error(e.message || '提交失败'); }
  };

  const handleIdentity = async (r: SubjectInfo) => {
    try {
      const { redirect_url } = await startSubjectIdentity(r.uuid, '/console/subject-infos');
      window.location.href = redirect_url;
    } catch (e: any) { message.error(e.message || '实名认证接口不可用，请等待人工审核'); }
  };

  const columns = [
    { title: '主体内容', dataIndex: 'fields', key: 'fields',
      render: (fields: Record<string, string>) => (
        <Space direction="vertical" size={0}>
          {Object.entries(fields ?? {}).map(([k, v]) => (
            <Text key={k} style={{ fontSize: 12 }}>{k} = {v}</Text>
          ))}
        </Space>
      ) },
    { title: '模板', dataIndex: 'template_uuid', key: 'template_uuid',
      render: (v: string) => templates.find((t) => t.uuid === v)?.name || (v ? v.slice(0, 8) : '—') },
    { title: '验证方式', dataIndex: 'verify_mode', key: 'verify_mode', width: 110,
      render: (v: string) => <Tag>{VERIFY_TEXT[v] ?? v ?? '人工审核'}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 130,
      render: (v: string, r: SubjectInfo) => {
        const s = STATUS[v] ?? { text: v, color: 'default' };
        return (
          <Space direction="vertical" size={0}>
            <Tag color={s.color}>{s.text}</Tag>
            {r.reject_reason && <Text type="danger" style={{ fontSize: 12 }}>{r.reject_reason}</Text>}
            {r.expires_at && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                有效期至 {new Date(r.expires_at).toLocaleDateString('zh-CN')}
              </Text>
            )}
          </Space>
        );
      } },
    {
      title: '操作', key: 'actions', width: 220,
      render: (_: any, r: SubjectInfo) => (
        <Space size={4}>
          {r.status === 'verifying' && (
            <Button type="link" size="small" icon={<SafetyOutlined />} onClick={() => handleIdentity(r)}>实名认证</Button>
          )}
          {(r.status === 'rejected' || (r.status === 'approved' && r.expires_at && new Date(r.expires_at) < new Date())) && (
            <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>修改并重提</Button>
          )}
          <Popconfirm title="删除后不可恢复，确认？" onConfirm={async () => {
            try { await deleteSubjectInfo(r.uuid); message.success('已删除'); load(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><IdcardOutlined /><Title level={4} style={{ margin: 0 }}>证书主体信息</Title>
          <HelpLink doc="user-03-apply-certificate" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建主体信息</Button>
          </Space>
        }
      >
        <Alert type="info" showIcon style={{ marginBottom: 16 }}
          message="主体信息按主体模板验证：人工审核 / 实名认证接口 / 免验证"
          description="审核或认证通过后在有效期内可直接用于证书申请；过期或被驳回可修改后重新提交。域名/邮箱证书的主体字段可配置为「派生」，无需在此填写。" />
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal open={open} title={editing ? '修改并重新提交主体信息' : '新建主体信息'}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} destroyOnClose width={620}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Form.Item name="subject_tmpl_uuid" label="主体模板" rules={[{ required: true, message: '请选择主体模板' }]}
            extra="模板决定需要填写的字段与验证方式">
            <Select
              disabled={!!editing}
              onChange={(v) => {
                setTmplUUID(v);
                const t = templates.find((x) => x.uuid === v);
                if (t) {
                  const init: Record<string, string> = {};
                  (t.fields ?? []).forEach((f) => { if (f.default) init[f.key] = f.default; });
                  form.setFieldsValue(init);
                }
              }}
              options={templates.map((t) => ({ label: t.name, value: t.uuid }))}
            />
          </Form.Item>
          {currentFields.map((f) => (
            <Form.Item
              key={f.key} name={f.key} label={`${f.label || f.key}（${f.key}）`}
              rules={f.required ? [{ required: true, message: `请填写${f.label || f.key}` }] : undefined}
              extra={[
                f.min_len || f.max_len ? `长度 ${f.min_len || 1}-${f.max_len || 128}` : '',
                f.format ? `格式：${f.format}` : '',
                f.verify === 'auto' ? '需实名认证' : f.verify === 'manual' ? '需管理员审核' : '免验证',
                f.help || '',
              ].filter(Boolean).join(' · ') || undefined}
            >
              <Input maxLength={f.max_len || 128} placeholder={f.default ? `默认值 ${f.default}` : ''} />
            </Form.Item>
          ))}
          {currentFields.length === 0 && (
            <Descriptions column={1} size="small">
              <Descriptions.Item>
                该模板字段全部由扩展信息派生，无需填写；请在申请证书时添加对应域名/邮箱。
              </Descriptions.Item>
            </Descriptions>
          )}
        </Form>
      </Modal>
    </div>
  );
};

export default SubjectInfosPage;
