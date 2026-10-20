import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm,
} from 'antd';
import { AppstoreOutlined, PlusOutlined, ReloadOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import {
  listCertApplyTemplates, saveCertApplyTemplate, deleteCertApplyTemplate, listIssuanceTemplates,
} from '../../api';
import type { CertApplyTemplateInfo, IssuanceTemplate } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

const modeText: Record<string, string> = {
  order: '购买订单',
  self: '自助申请',
  subscription: '订阅额度',
};

const parseModes = (v: CertApplyTemplateInfo['apply_modes']): string[] => {
  if (Array.isArray(v)) return v;
  if (!v) return ['order', 'self', 'subscription'];
  try { return JSON.parse(v); } catch { return ['order', 'self', 'subscription']; }
};

/**
 * 证书开通模板：只管业务规则。
 *
 * 关联哪个颁发模板、是否需要审批、是否允许续期、可申请方式、启用与说明。
 * CA、有效期、密钥算法、资料要求都由颁发模板提供，这里只读展示（标注"继承自颁发模板"）。
 */
const CertApplyTemplatesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CertApplyTemplateInfo[]>([]);
  const [issuance, setIssuance] = useState<IssuanceTemplate[]>([]);
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
      const is = await listIssuanceTemplates({ page: 1, page_size: 200 });
      setIssuance(is.items ?? []);
    } catch { /* 选项失败不阻塞列表 */ }
  };

  useEffect(() => { load(); loadOptions(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      enabled: true, require_approval: true, allow_renewal: true,
      apply_modes: ['order', 'self', 'subscription'],
    });
    setOpen(true);
  };

  const openEdit = (r: CertApplyTemplateInfo) => {
    setEditing(r);
    form.setFieldsValue({
      name: r.name,
      issuance_tmpl_uuid: r.issuance_tmpl_uuid,
      enabled: r.enabled,
      require_approval: r.require_approval,
      allow_renewal: r.allow_renewal,
      apply_modes: parseModes(r.apply_modes),
      description: r.description,
    });
    setOpen(true);
  };

  const submit = async (v: any) => {
    try {
      await saveCertApplyTemplate(editing ? { ...v, uuid: editing.uuid } : v);
      message.success('已保存');
      setOpen(false);
      load();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteCertApplyTemplate(uuid); message.success('已删除'); load(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = [
    {
      title: '模板名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: CertApplyTemplateInfo) => (
        <Space direction="vertical" size={0}>
          <Text strong>{v}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{r.description || '—'}</Text>
        </Space>
      ),
    },
    {
      title: '颁发模板', dataIndex: 'issuance_tmpl_uuid', key: 'issuance_tmpl_uuid', width: 200,
      render: (v: string) => issuance.find((t) => t.uuid === v)?.name || (v ? v.slice(0, 8) : '—'),
    },
    {
      title: '可申请方式', key: 'apply_modes', width: 220,
      render: (_: any, r: CertApplyTemplateInfo) => (
        <Space size={4} wrap>
          {parseModes(r.apply_modes).map((m) => <Tag key={m}>{modeText[m] || m}</Tag>)}
        </Space>
      ),
    },
    {
      title: '继承的技术配置', key: 'inherited',
      render: (_: any, r: CertApplyTemplateInfo) => {
        const inh = r.inherited;
        if (!inh) return <Text type="secondary">颁发模板缺失</Text>;
        const days = inh.valid_days?.length ? `有效期 ${inh.valid_days.join('/')} 天` : '有效期不限制';
        const algs = inh.allowed_key_types?.length ? inh.allowed_key_types.join('、') : '算法未限制';
        return (
          <Space direction="vertical" size={0}>
            <Text style={{ fontSize: 12 }}>{days}（默认 {inh.default_valid_days || '-'} 天）</Text>
            <Text style={{ fontSize: 12 }}>{algs}</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>继承自颁发模板</Text>
          </Space>
        );
      },
    },
    {
      title: '审批', dataIndex: 'require_approval', key: 'require_approval', width: 110,
      render: (v: boolean) => (v ? <Tag color="orange">人工审批</Tag> : <Tag color="green">自动签发</Tag>),
    },
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => (v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag>),
    },
    {
      title: '操作', key: 'actions', width: 150, fixed: 'right' as const,
      render: (_: any, r: CertApplyTemplateInfo) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="被商品规格或订单引用时无法删除，只能停用" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const selectedIssuance = Form.useWatch('issuance_tmpl_uuid', form);
  const inherited = issuance.find((t) => t.uuid === selectedIssuance);

  return (
    <div>
      <Card
        title={<Space><AppstoreOutlined /><Title level={4} style={{ margin: 0 }}>证书开通模板</Title>
          <HelpLink doc="admin-03-ca-templates" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => { load(); loadOptions(); }}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建开通模板</Button>
          </Space>
        }
      >
        <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>
          开通模板只决定"怎么申请"：关联哪个颁发模板、是否审批、是否可续期、允许哪些申请方式。
        </Text>
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} scroll={{ x: 1180 }} />
      </Card>

      <Modal open={open} title={editing ? '编辑证书开通模板' : '新建证书开通模板'}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} width={720}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="例如：SSL DV 自动开通" />
          </Form.Item>

          <Form.Item name="issuance_tmpl_uuid" label="颁发模板"
            rules={[{ required: true, message: '请选择颁发模板' }]}
            extra="CA、有效期、密钥算法与资料要求都由颁发模板决定">
            <Select
              showSearch optionFilterProp="label"
              options={issuance.map((t) => ({ label: t.name, value: t.uuid }))}
            />
          </Form.Item>

          {inherited && (
            <Card size="small" style={{ marginBottom: 16, background: '#fafafa' }}>
              <Text type="secondary" style={{ fontSize: 12 }}>继承自颁发模板（不可在此修改）</Text>
              <div style={{ marginTop: 8 }}>
                <Space size={8} wrap>
                  <Tag>有效期：{inherited.validity_options?.length ? inherited.validity_options.join(' / ') + ' 天' : '不限制'}</Tag>
                  <Tag>默认：{inherited.default_valid_days || '-'} 天</Tag>
                  <Tag>算法：{inherited.allowed_key_types?.length ? inherited.allowed_key_types.join('、') : '未限制'}</Tag>
                  <Tag color={inherited.is_ca ? 'purple' : 'default'}>{inherited.is_ca ? 'CA 证书' : '终端证书'}</Tag>
                </Space>
              </div>
            </Card>
          )}

          <Form.Item name="apply_modes" label="可申请方式"
            extra="面向用户的入口限制：购买订单 / 自助申请 / 订阅额度">
            <Select mode="multiple" options={[
              { label: '购买订单', value: 'order' },
              { label: '自助申请', value: 'self' },
              { label: '订阅额度', value: 'subscription' },
            ]} />
          </Form.Item>

          <Space size={24}>
            <Form.Item name="require_approval" label="需要人工审批" valuePropName="checked"
              extra="关闭＝资料通过后自动签发">
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
