import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm, Alert, InputNumber, Tooltip,
} from 'antd';
import { AppstoreOutlined, PlusOutlined, ReloadOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import {
  listCertApplyTemplates, saveCertApplyTemplate, deleteCertApplyTemplate,
  listIssuanceTemplates, listSubjectTemplates, listExtensionTemplates, listCAs,
} from '../../api';
import type {
  CertApplyTemplateInfo, IssuanceTemplate, SubjectTemplate, ExtensionTemplate, CA,
} from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

/**
 * 证书开通模板（原「证书申请模板」）。
 *
 * 职责：面向用户与商品的**开通规则**——绑定颁发模板（怎么签）+ 主体模板与扩展信息模板（要什么资料、
 * 怎么审核）+ 是否人工审批 + 是否允许续期 + 可选密钥算法。
 *
 * 价格与库存、SAN 数量/格式限制属于商品规格（销售管理 → 销售商品管理）；
 * 技术签发参数（CA、有效期候选、KU/EKU、扩展）属于颁发模板。
 */
const CertApplyTemplatesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CertApplyTemplateInfo[]>([]);
  const [issuance, setIssuance] = useState<IssuanceTemplate[]>([]);
  const [subjects, setSubjects] = useState<SubjectTemplate[]>([]);
  const [extensions, setExtensions] = useState<ExtensionTemplate[]>([]);
  const [cas, setCAs] = useState<CA[]>([]);

  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<CertApplyTemplateInfo | null>(null);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listCertApplyTemplates()); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  const loadOptions = async () => {
    try {
      const [is, sub, ext, ca] = await Promise.all([
        listIssuanceTemplates({ page: 1, page_size: 200 }),
        listSubjectTemplates(),
        listExtensionTemplates(),
        listCAs({ page: 1, page_size: 200 }),
      ]);
      setIssuance(is.items ?? []);
      setSubjects(sub ?? []);
      setExtensions(ext ?? []);
      setCAs(ca.items ?? []);
    } catch { /* 选项失败不阻塞列表 */ }
  };

  useEffect(() => { load(); loadOptions(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      enabled: true, require_approval: true, allow_renewal: true,
      allowed_key_types: ['ec256', 'rsa2048'], valid_days: 365,
    });
    setOpen(true);
  };

  const openEdit = (r: CertApplyTemplateInfo) => {
    setEditing(r);
    let keyTypes: string[] = ['ec256', 'rsa2048'];
    try { keyTypes = JSON.parse(r.allowed_key_types || '[]'); } catch { /* 保持默认 */ }
    form.setFieldsValue({ ...r, allowed_key_types: keyTypes });
    setOpen(true);
  };

  const submit = async (v: any) => {
    try {
      const payload = { ...v, allowed_key_types: JSON.stringify(v.allowed_key_types ?? []) };
      await saveCertApplyTemplate(editing ? { ...payload, uuid: editing.uuid } : payload);
      message.success('已保存');
      setOpen(false);
      load();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteCertApplyTemplate(uuid); message.success('已删除'); load(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const nameOf = <T extends { uuid: string; name: string }>(list: T[], uuid: string) =>
    list.find((x) => x.uuid === uuid)?.name || (uuid ? uuid.slice(0, 8) : '—');

  const columns = [
    { title: '模板名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: CertApplyTemplateInfo) => (
        <Space direction="vertical" size={0}>
          <Text strong>{v}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{r.description || '—'}</Text>
        </Space>
      ) },
    { title: '颁发模板', dataIndex: 'issuance_tmpl_uuid', key: 'issuance_tmpl_uuid',
      render: (v: string) => nameOf(issuance, v) },
    { title: '主体模板', dataIndex: 'subject_tmpl_uuid', key: 'subject_tmpl_uuid',
      render: (v: string) => v ? nameOf(subjects, v) : <Tag>未绑定（DV 简化）</Tag> },
    { title: '扩展信息模板', dataIndex: 'extension_tmpl_uuid', key: 'extension_tmpl_uuid',
      render: (v: string) => v ? nameOf(extensions, v) : <Tag>缺省策略</Tag> },
    { title: '有效期', dataIndex: 'valid_days', key: 'valid_days',
      render: (v: number) => (v > 0 ? `${v} 天` : '按颁发模板') },
    { title: '审批', dataIndex: 'require_approval', key: 'require_approval',
      render: (v: boolean) => v ? <Tag color="orange">人工审批</Tag> : <Tag color="green">自动开通</Tag> },
    { title: '状态', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    {
      title: '操作', key: 'actions', width: 150,
      render: (_: any, r: CertApplyTemplateInfo) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="被商品规格或订单引用时无法删除，只能停用" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><AppstoreOutlined /><Title level={4} style={{ margin: 0 }}>证书开通模板</Title>
          <HelpLink doc="admin-03-ca-templates" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => { load(); loadOptions(); }}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新开通模板</Button>
          </Space>
        }
      >
        <Alert type="info" showIcon style={{ marginBottom: 16 }}
          message="开通模板＝怎么申请（资料与审批）：绑定颁发模板 + 主体模板 + 扩展信息模板；价格与库存、SAN 数量在商品规格中配置" />
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal open={open} title={editing ? '编辑证书开通模板' : '新建证书开通模板'}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} destroyOnClose width={720}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="name" label="模板名称" style={{ flex: 2 }} rules={[{ required: true, message: '请输入名称' }]}>
              <Input placeholder="例如：SSL DV 自动开通" />
            </Form.Item>
            <Form.Item name="valid_days" label="证书有效期（天）" style={{ flex: 1 }}
              extra={<Tooltip title="0 表示使用颁发模板的首个有效期候选">说明</Tooltip>}>
              <InputNumber min={0} max={3650} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item name="issuance_tmpl_uuid" label="颁发模板（怎么签）"
            rules={[{ required: true, message: '请选择颁发模板' }]}
            extra="决定 CA 候选、有效期候选、密钥算法白名单、KU/EKU、证书扩展与密钥存储">
            <Select
              showSearch optionFilterProp="label"
              options={issuance.map((t) => ({ label: `${t.name}（${t.category}）`, value: t.uuid }))}
            />
          </Form.Item>

          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="subject_tmpl_uuid" label="主体模板（身份资料）" style={{ flex: 1 }}
              extra="决定用户填写哪些主体字段、如何验证（人工/实名接口/免验证）与有效期">
              <Select allowClear options={subjects.map((t) => ({ label: t.name, value: t.uuid }))} />
            </Form.Item>
            <Form.Item name="extension_tmpl_uuid" label="扩展信息模板（域名/邮箱/IP）" style={{ flex: 1 }}
              extra="决定扩展信息的验证方式（DNS/HTTP/TLS/邮箱验证码/人工）与验证有效期">
              <Select allowClear options={extensions.map((t) => ({ label: t.name, value: t.uuid }))} />
            </Form.Item>
          </Space>

          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="ca_uuid" label="指定签发 CA" style={{ flex: 1 }}
              extra="留空时使用颁发模板的首个 CA">
              <Select allowClear options={cas.map((c) => ({ label: c.name, value: c.uuid }))} />
            </Form.Item>
            <Form.Item name="allowed_key_types" label="可选密钥算法" style={{ flex: 2 }}>
              <Select mode="multiple" options={['ec256', 'ec384', 'rsa2048', 'rsa4096'].map((k) => ({ label: k, value: k }))} />
            </Form.Item>
          </Space>

          <Space size={24}>
            <Form.Item name="require_approval" label="需要人工审批" valuePropName="checked"
              extra="关闭＝提交后自动签发（资料仍需通过审核/验证）">
              <Switch />
            </Form.Item>
            <Form.Item name="allow_renewal" label="允许续期" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
          </Space>

          <Form.Item name="description" label="说明"><Input.TextArea rows={2} /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CertApplyTemplatesPage;
