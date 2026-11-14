import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Button, Card, Drawer, Form, Input, InputNumber, Modal, Popconfirm,
  Select, Space, Switch, Table, Tag, Tooltip, Typography, message,
} from 'antd';
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined, UnorderedListOutlined } from '@ant-design/icons';
import {
  createAdminProduct, createAdminSKU, deleteAdminProduct, deleteAdminSKU,
  listAdminProducts, listAdminSKUs, updateAdminProduct, updateAdminSKU,
  listCertApplyTemplates, listAdminCloudCardTemplates, createAdminCloudCardTemplate,
  updateAdminCloudCardTemplate, deleteAdminCloudCardTemplate, listStorageZones,
} from '../../../api';
import type {
  CloudCardTemplate, DeliveryMode, PortalProduct, PortalProductSKU, ProductView,
  CertApplyTemplateInfo, StorageZone,
} from '../../../types';

const { Title, Text } = Typography;

const CATEGORY_OPTIONS = [
  { value: 'ssl', label: 'SSL/TLS 证书' },
  { value: 'codesign', label: '代码签名证书' },
  { value: 'email', label: '邮件证书' },
  { value: 'docsign', label: '文档签名证书' },
  { value: 'cloudcard', label: '云端智能卡' },
];

const DELIVERY_OPTIONS: { value: DeliveryMode; label: string }[] = [
  { value: 'cloud_card', label: '云端智能卡' },
  { value: 'download', label: '文件下载' },
  { value: 'physical_card', label: '实体智能卡（设备 CSR）' },
  { value: 'virtual_card', label: '本地虚拟卡（设备 CSR）' },
  { value: 'csr', label: '自备 CSR' },
];

/** JSON 数组字符串 <-> 多行文本 */
const jsonToLines = (raw: string): string => {
  if (!raw) return '';
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.join('\n') : '';
  } catch {
    return '';
  }
};
const linesToJson = (text?: string): string => {
  const items = (text || '').split('\n').map((s) => s.trim()).filter(Boolean);
  return JSON.stringify(items);
};
/** 多行文本 -> 字符串数组（邮箱/域名后缀） */
const linesToArray = (text?: string): string[] =>
  (text || '').split('\n').map((s) => s.trim()).filter(Boolean);

/**
 * 控制台 - 商品管理。
 *
 * 商品负责"卖什么"，规格（SKU）负责价格、库存、时长与开通模板，
 * 证书开通仍复用"证书申请模板"，此处只做引用。
 */
const ConsoleProducts: React.FC = () => {
  const [views, setViews] = useState<ProductView[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [editing, setEditing] = useState<PortalProduct | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  // 规格管理
  const [skuProduct, setSkuProduct] = useState<PortalProduct | null>(null);
  const [skus, setSkus] = useState<PortalProductSKU[]>([]);
  const [skusLoading, setSkusLoading] = useState(false);
  const [skuEditing, setSkuEditing] = useState<PortalProductSKU | null>(null);
  const [skuModalOpen, setSkuModalOpen] = useState(false);
  const [skuForm] = Form.useForm();
  const [applyTemplates, setApplyTemplates] = useState<CertApplyTemplateInfo[]>([]);
  const [cloudCardTemplates, setCloudCardTemplates] = useState<CloudCardTemplate[]>([]);
  const [storageZones, setStorageZones] = useState<StorageZone[]>([]);
  const [templateManagerOpen, setTemplateManagerOpen] = useState(false);
  const [templateFormOpen, setTemplateFormOpen] = useState(false);
  const [templateEditing, setTemplateEditing] = useState<CloudCardTemplate | null>(null);
  const [templateSaving, setTemplateSaving] = useState(false);
  const [templateForm] = Form.useForm();

  const loadCloudCardTemplates = useCallback(async () => {
    try {
      const [templates, zones] = await Promise.all([listAdminCloudCardTemplates(), listStorageZones()]);
      setCloudCardTemplates(templates);
      setStorageZones(zones);
    } catch (e: any) {
      message.error(e?.message || '加载云卡开通模板失败');
    }
  }, []);

  useEffect(() => {
    listCertApplyTemplates().then(setApplyTemplates).catch(() => undefined);
    loadCloudCardTemplates();
  }, [loadCloudCardTemplates]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setViews(await listAdminProducts());
    } catch (e: any) {
      setError(e?.message || '加载商品失败');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadSKUs = useCallback(async (productUUID: string) => {
    setSkusLoading(true);
    try {
      setSkus(await listAdminSKUs(productUUID));
    } catch (e: any) {
      message.error(e?.message || '加载规格失败');
    } finally {
      setSkusLoading(false);
    }
  }, []);

  const openCloudCardTemplateForm = (template?: CloudCardTemplate) => {
    setTemplateEditing(template ?? null);
    templateForm.resetFields();
    if (template) {
      templateForm.setFieldsValue({
        ...template,
        reminder_days: template.reminder_days.join(', '),
      });
    } else {
      templateForm.setFieldsValue({
        certificate_limit: 10, pin_min_length: 6, reminder_enabled: true,
        reminder_days: '7, 0', enabled: true,
        storage_zone_uuid: storageZones.find((zone) => zone.status === 'active')?.uuid,
      });
    }
    setTemplateFormOpen(true);
  };

  const saveCloudCardTemplate = async () => {
    try {
      const values = await templateForm.validateFields();
      const reminderDays: number[] = Array.from(new Set<number>(
        (values.reminder_days || '').split(/[ ,\n]+/).map((value: string) => Number(value)).filter(Number.isInteger),
      ));
      setTemplateSaving(true);
      const payload: Partial<CloudCardTemplate> = {
        name: values.name,
        description: values.description || '',
        storage_zone_uuid: values.storage_zone_uuid,
        certificate_limit: values.certificate_limit,
        pin_min_length: values.pin_min_length,
        reminder_enabled: !!values.reminder_enabled,
        reminder_days: [...new Set(reminderDays)],
        enabled: !!values.enabled,
      };
      if (templateEditing) {
        await updateAdminCloudCardTemplate(templateEditing.uuid, payload);
        message.success('云卡开通模板已更新');
      } else {
        await createAdminCloudCardTemplate(payload);
        message.success('云卡开通模板已创建');
      }
      setTemplateFormOpen(false);
      setTemplateEditing(null);
      await loadCloudCardTemplates();
    } catch (e: any) {
      if (e?.errorFields) return;
      message.error(e?.message || '保存云卡开通模板失败');
    } finally {
      setTemplateSaving(false);
    }
  };

  const removeCloudCardTemplate = async (uuid: string) => {
    try {
      await deleteAdminCloudCardTemplate(uuid);
      message.success('云卡开通模板已删除');
      await loadCloudCardTemplates();
    } catch (e: any) {
      message.error(e?.message || '删除失败');
    }
  };

  // ---- 商品编辑 ----

  const openProductModal = (p?: PortalProduct) => {
    setEditing(p ?? null);
    form.resetFields();
    if (p) {
      form.setFieldsValue({
        ...p,
        features: jsonToLines(p.features),
        highlights: jsonToLines(p.highlights),
      });
    } else {
      form.setFieldsValue({ category: 'ssl', visible: false, enabled: true, sort_weight: 0 });
    }
    setModalOpen(true);
  };

  const submitProduct = async () => {
    try {
      const v = await form.validateFields();
      setSaving(true);
      const payload: Partial<PortalProduct> = {
        code: v.code,
        name: v.name,
        category: v.category,
        level: v.level || '',
        summary: v.summary || '',
        description: v.description || '',
        features: linesToJson(v.features),
        highlights: linesToJson(v.highlights),
        badge: v.badge || '',
        cover_image: v.cover_image || '',
        sort_weight: v.sort_weight ?? 0,
        visible: !!v.visible,
        enabled: !!v.enabled,
      };
      if (editing) {
        await updateAdminProduct(editing.uuid, payload);
        message.success('商品已更新');
      } else {
        await createAdminProduct(payload);
        message.success('商品已创建');
      }
      setModalOpen(false);
      setEditing(null);
      form.resetFields();
      await load();
    } catch (e: any) {
      if (e?.message) message.error(e.message);
    } finally {
      setSaving(false);
    }
  };

  const removeProduct = async (uuid: string) => {
    try {
      await deleteAdminProduct(uuid);
      message.success('商品已删除');
      await load();
    } catch (e: any) {
      message.error(e?.message || '删除失败');
    }
  };

  // ---- 规格编辑 ----

  const openSkuModal = (s?: PortalProductSKU) => {
    setSkuEditing(s ?? null);
    skuForm.resetFields();
    let sanPolicy: any = { max_dns: 1, max_email: 0, max_ip: 0, allow_wildcard: false, ip_versions: ['v4', 'v6'] };
    if (s?.san_policy) { try { sanPolicy = { ...sanPolicy, ...JSON.parse(s.san_policy) }; } catch { /* 保持默认 */ } }
    if (s) {
      skuForm.setFieldsValue({
        ...s, key_types: jsonToLines(s.key_types),
        san_policy: sanPolicy,
        email_suffixes: (sanPolicy.email_suffixes ?? []).join('\n'),
        dns_suffixes: (sanPolicy.dns_suffixes ?? []).join('\n'),
      });
    } else {
      skuForm.setFieldsValue({
        delivery_mode: skuProduct?.category === 'cloudcard' ? 'cloud_card' : 'download',
        currency: 'CNY',
        stock: -1,
        min_qty: 1,
        max_qty: 10,
        duration_months: 12,
        san_included: 1,
        enabled: true,
        sort_weight: 0,
        price_cents: 0,
        key_types: 'ec256\nrsa2048',
        san_policy: sanPolicy,
        cloud_card_tmpl_uuid: skuProduct?.category === 'cloudcard'
          ? cloudCardTemplates.find((template) => template.enabled)?.uuid : undefined,
        cloud_card_operation: 'activation',
      });
    }
    setSkuModalOpen(true);
  };

  const submitSKU = async () => {
    if (!skuProduct) return;
    try {
      const v = await skuForm.validateFields();
      const isCloudCard = skuProduct.category === 'cloudcard';
      const payload: Partial<PortalProductSKU> = {
        product_uuid: skuProduct.uuid,
        code: v.code,
        name: v.name,
        price_cents: v.price_cents ?? 0,
        currency: v.currency || 'CNY',
        stock: v.stock ?? -1,
        min_qty: v.min_qty ?? 1,
        max_qty: v.max_qty ?? 10,
        duration_months: v.duration_months ?? 12,
        delivery_mode: v.delivery_mode,
        key_types: linesToJson(v.key_types),
        san_included: isCloudCard ? 0 : (v.san_policy?.max_dns ?? v.san_included ?? 0),
        san_policy: isCloudCard ? '{}' : JSON.stringify({
          max_dns: v.san_policy?.max_dns ?? 0,
          max_email: v.san_policy?.max_email ?? 0,
          max_ip: v.san_policy?.max_ip ?? 0,
          allow_wildcard: !!v.san_policy?.allow_wildcard,
          ip_versions: v.san_policy?.ip_versions ?? ['v4', 'v6'],
          email_suffixes: linesToArray(v.email_suffixes),
          dns_suffixes: linesToArray(v.dns_suffixes),
        }),
        cert_apply_tmpl_uuid: isCloudCard ? '' : (v.cert_apply_tmpl_uuid || ''),
        cloud_card_tmpl_uuid: isCloudCard ? (v.cloud_card_tmpl_uuid || '') : '',
        cloud_card_operation: isCloudCard ? (v.cloud_card_operation || 'activation') : '',
        enabled: !!v.enabled,
        sort_weight: v.sort_weight ?? 0,
      };
      if (skuEditing) {
        await updateAdminSKU(skuEditing.uuid, payload);
        message.success('规格已更新');
      } else {
        await createAdminSKU(payload);
        message.success('规格已创建');
      }
      setSkuModalOpen(false);
      setSkuEditing(null);
      await loadSKUs(skuProduct.uuid);
      await load();
    } catch (e: any) {
      if (e?.message) message.error(e.message);
    }
  };

  const removeSKU = async (uuid: string) => {
    if (!skuProduct) return;
    try {
      await deleteAdminSKU(uuid);
      message.success('规格已删除');
      await loadSKUs(skuProduct.uuid);
      await load();
    } catch (e: any) {
      message.error(e?.message || '删除失败');
    }
  };

  const columns = [
    {
      title: '商品', dataIndex: 'name', key: 'name',
      render: (_: any, row: ProductView) => (
        <Space direction="vertical" size={0}>
          <Space size={6}>
            <Text strong>{row.product.name}</Text>
            {row.product.badge && <Tag color="gold" style={{ margin: 0 }}>{row.product.badge}</Tag>}
          </Space>
          <Text type="secondary" style={{ fontSize: 12 }}>{row.product.code}</Text>
        </Space>
      ),
    },
    {
      title: '分类', dataIndex: ['product', 'category'], key: 'category', width: 140,
      render: (v: string, row: ProductView) => (
        <Space size={4}>
          <Tag>{CATEGORY_OPTIONS.find((c) => c.value === v)?.label ?? v}</Tag>
          {row.product.level && <Tag bordered={false}>{row.product.level.toUpperCase()}</Tag>}
        </Space>
      ),
    },
    {
      title: '规格', key: 'skus', width: 220,
      render: (_: any, row: ProductView) => {
        if (row.skus.length === 0) return <Text type="secondary">未配置</Text>;
        const prices = row.skus.map((s) => s.price_cents / 100);
        return (
          <Space direction="vertical" size={0}>
            <Text style={{ fontSize: 13 }}>{row.skus.length} 个规格</Text>
            <Text type="secondary" style={{ fontSize: 12 }}>
              ¥{Math.min(...prices)} - ¥{Math.max(...prices)}
            </Text>
          </Space>
        );
      },
    },
    {
      title: '前台可见', dataIndex: ['product', 'visible'], key: 'visible', width: 100,
      render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '已发布' : '未发布'}</Tag>,
    },
    {
      title: '可售', dataIndex: ['product', 'enabled'], key: 'enabled', width: 90,
      render: (v: boolean) => <Tag color={v ? 'blue' : 'red'}>{v ? '启用' : '停用'}</Tag>,
    },
    {
      title: '操作', key: 'action', width: 190, fixed: 'right' as const,
      render: (_: any, row: ProductView) => (
        <Space size={4}>
          <Tooltip title="规格管理">
            <Button
              size="small" icon={<UnorderedListOutlined />}
              onClick={() => { setSkuProduct(row.product); loadSKUs(row.product.uuid); }}
            />
          </Tooltip>
          <Tooltip title="编辑">
            <Button size="small" icon={<EditOutlined />} onClick={() => openProductModal(row.product)} />
          </Tooltip>
          <Popconfirm title="删除商品及其全部规格？" onConfirm={() => removeProduct(row.product.uuid)}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const skuColumns = [
    { title: '规格名称', dataIndex: 'name', key: 'name' },
    { title: '编码', dataIndex: 'code', key: 'code', render: (v: string) => <Text code style={{ fontSize: 12 }}>{v}</Text> },
    {
      title: '价格', dataIndex: 'price_cents', key: 'price', width: 110,
      render: (v: number, row: PortalProductSKU) => `¥${(v / 100).toFixed(2)} / ${row.duration_months}月`,
    },
    {
      title: '库存', dataIndex: 'stock', key: 'stock', width: 90,
      render: (v: number) => (v < 0 ? <Tag>不限</Tag> : v === 0 ? <Tag color="red">售罄</Tag> : v),
    },
    {
      title: '交付', dataIndex: 'delivery_mode', key: 'delivery_mode', width: 120,
      render: (v: string) => DELIVERY_OPTIONS.find((d) => d.value === v)?.label ?? v,
    },
    {
      title: skuProduct?.category === 'cloudcard' ? '云卡权益' : '证书开通模板',
      key: 'tmpl', width: 170,
      render: (_: unknown, row: PortalProductSKU) => {
        const uuid = skuProduct?.category === 'cloudcard' ? row.cloud_card_tmpl_uuid : row.cert_apply_tmpl_uuid;
        const templateName = cloudCardTemplates.find((template) => template.uuid === uuid)?.name;
        const applyName = applyTemplates.find((template) => template.uuid === uuid)?.name;
        const name = skuProduct?.category === 'cloudcard' ? templateName : applyName;
        if (!name) return <Tag color="orange">未关联</Tag>;
        if (skuProduct?.category === 'cloudcard') {
          return <Space size={4}><Tag color="green">{name}</Tag><Tag>{row.cloud_card_operation === 'renewal' ? '续费' : '开通'}</Tag></Space>;
        }
        return <Tag color="green">{name}</Tag>;
      },
    },
    {
      title: '启用', dataIndex: 'enabled', key: 'enabled', width: 80,
      render: (v: boolean) => <Tag color={v ? 'blue' : 'default'}>{v ? '启用' : '停用'}</Tag>,
    },
    {
      title: '操作', key: 'action', width: 110,
      render: (_: any, row: PortalProductSKU) => (
        <Space size={4}>
          <Button size="small" icon={<EditOutlined />} onClick={() => openSkuModal(row)} />
          <Popconfirm title="删除该规格？" onConfirm={() => removeSKU(row.uuid)}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <Title level={4} style={{ margin: 0 }}>商品管理</Title>
          <Text type="secondary" style={{ fontSize: 13 }}>
            配置前台可售商品、价格、库存与服务时长，并关联开通模板
          </Text>
        </div>
        <Space>
          <Button icon={<UnorderedListOutlined />} onClick={() => setTemplateManagerOpen(true)}>云卡开通模板</Button>
          <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openProductModal()}>
            新建商品
          </Button>
        </Space>
      </div>

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      <Card styles={{ body: { padding: 0 } }}>
        <Table
          rowKey={(r) => r.product.uuid}
          columns={columns}
          dataSource={views}
          loading={loading}
          scroll={{ x: 1000 }}
          pagination={false}
        />
      </Card>

      {/* 商品编辑 */}
      <Modal
        title={editing ? '编辑商品' : '新建商品'}
        open={modalOpen}
        onOk={submitProduct}
        onCancel={() => { setModalOpen(false); setEditing(null); }}
        confirmLoading={saving}
        okText={editing ? '保存' : '创建'}
        width={640}
      >
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="name" label="商品名称" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input placeholder="例如：标准 SSL 证书" />
            </Form.Item>
            <Form.Item
              name="code" label="商品编码" rules={[{ required: true }]}
              extra="用于对外访问地址，创建后请勿修改" style={{ flex: 1 }}
            >
              <Input placeholder="ssl-standard" />
            </Form.Item>
          </Space>

          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="category" label="商品分类" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Select options={CATEGORY_OPTIONS} />
            </Form.Item>
            <Form.Item name="level" label="等级标识" extra="如 dv / ov / ev" style={{ flex: 1 }}>
              <Input placeholder="dv" />
            </Form.Item>
            <Form.Item name="badge" label="角标" style={{ flex: 1 }}>
              <Input placeholder="推荐 / 新品" />
            </Form.Item>
          </Space>

          <Form.Item name="summary" label="一句话卖点">
            <Input placeholder="为网站提供加密传输与身份证明" />
          </Form.Item>

          <Form.Item name="description" label="详细说明">
            <Input.TextArea rows={3} placeholder="面向客户的产品说明" />
          </Form.Item>

          <Form.Item name="features" label="包含权益" extra="每行一条">
            <Input.TextArea rows={4} placeholder={'域名验证\n证书链完整\n技术支持'} />
          </Form.Item>

          <Form.Item name="highlights" label="服务说明" extra="每行一条，展示在详情页侧栏">
            <Input.TextArea rows={3} placeholder={'有效期以所选套餐为准\n审核通过后自动签发'} />
          </Form.Item>

          <Space size={16}>
            <Form.Item name="sort_weight" label="排序权重" initialValue={0}>
              <InputNumber min={0} max={9999} />
            </Form.Item>
            <Form.Item name="visible" label="前台可见" valuePropName="checked">
              <Switch checkedChildren="已发布" unCheckedChildren="未发布" />
            </Form.Item>
            <Form.Item name="enabled" label="允许购买" valuePropName="checked">
              <Switch checkedChildren="启用" unCheckedChildren="停用" />
            </Form.Item>
          </Space>
        </Form>
      </Modal>

      {/* 云卡服务策略管理 */}
      <Modal
        title="云卡开通模板"
        open={templateManagerOpen}
        onCancel={() => setTemplateManagerOpen(false)}
        footer={<Button type="primary" icon={<PlusOutlined />} onClick={() => openCloudCardTemplateForm()}>新建模板</Button>}
        width={900}
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="云卡模板决定服务端存储区域、证书容量、PIN 强度与到期通知；购买期限由 SKU 配置。"
        />
        <Table
          rowKey="uuid"
          dataSource={cloudCardTemplates}
          pagination={false}
          size="small"
          columns={[
            { title: '模板', dataIndex: 'name', key: 'name' },
            { title: '存储区域', key: 'zone', render: (_: unknown, row: CloudCardTemplate) => storageZones.find((zone) => zone.uuid === row.storage_zone_uuid)?.name || '不可用' },
            { title: '证书容量', dataIndex: 'certificate_limit', key: 'capacity', render: (value: number) => value < 0 ? '不限' : `${value} 张` },
            { title: '提醒', key: 'reminders', render: (_: unknown, row: CloudCardTemplate) => row.reminder_enabled ? row.reminder_days.map((day) => day === 0 ? '到期当天' : `提前 ${day} 天`).join('、') : '关闭' },
            { title: '状态', dataIndex: 'enabled', key: 'enabled', render: (value: boolean) => <Tag color={value ? 'green' : 'default'}>{value ? '启用' : '停用'}</Tag> },
            {
              title: '操作', key: 'action', width: 110,
              render: (_: unknown, row: CloudCardTemplate) => (
                <Space size={4}>
                  <Button size="small" icon={<EditOutlined />} onClick={() => openCloudCardTemplateForm(row)} />
                  <Popconfirm title="模板仍被商品或云卡引用时不可删除" onConfirm={() => removeCloudCardTemplate(row.uuid)}>
                    <Button size="small" danger icon={<DeleteOutlined />} />
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Modal>

      <Modal
        title={templateEditing ? '编辑云卡开通模板' : '新建云卡开通模板'}
        open={templateFormOpen}
        onOk={saveCloudCardTemplate}
        onCancel={() => { setTemplateFormOpen(false); setTemplateEditing(null); }}
        confirmLoading={templateSaving}
        okText={templateEditing ? '保存' : '创建'}
        width={620}
      >
        <Form form={templateForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入模板名称' }]}>
            <Input maxLength={80} />
          </Form.Item>
          <Form.Item name="description" label="说明"><Input.TextArea rows={2} maxLength={300} /></Form.Item>
          <Form.Item name="storage_zone_uuid" label="私钥存储区域" rules={[{ required: true, message: '请选择存储区域' }]}>
            <Select
              showSearch optionFilterProp="label"
              options={storageZones.filter((zone) => zone.status === 'active').map((zone) => ({ value: zone.uuid, label: zone.name }))}
            />
          </Form.Item>
          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="certificate_limit" label="证书容量" extra="-1 表示不限" rules={[{ required: true }]} style={{ flex: 1 }}>
              <InputNumber min={-1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="pin_min_length" label="PIN 最小长度" rules={[{ required: true }]} style={{ flex: 1 }}>
              <InputNumber min={6} max={64} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Form.Item name="reminder_enabled" label="到期邮件提醒" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="关闭" />
          </Form.Item>
          <Form.Item name="reminder_days" label="提醒时间（天）" extra="逗号分隔；0 表示到期当天，例如 7, 0">
            <Input placeholder="7, 0" />
          </Form.Item>
          <Form.Item name="enabled" label="允许购买" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 规格管理 */}
      <Drawer
        title={skuProduct ? `规格管理 · ${skuProduct.name}` : '规格管理'}
        open={!!skuProduct}
        onClose={() => setSkuProduct(null)}
        width={880}
        extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => openSkuModal()}>新增规格</Button>}
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="规格决定前台价格、库存、服务时长与开通策略"
          description={skuProduct?.category === 'cloudcard'
            ? '云卡规格必须关联启用的云卡开通模板；用户不能自行覆盖模板指定的私钥存储区域。'
            : '证书类规格需要关联「证书申请模板」才能购买；签发参数与安全级别由关联模板约束。'}
        />
        <Table
          rowKey="uuid"
          columns={skuColumns}
          dataSource={skus}
          loading={skusLoading}
          pagination={false}
          size="small"
          scroll={{ x: 800 }}
        />
      </Drawer>

      {/* 规格编辑 */}
      <Modal
        title={skuEditing ? '编辑规格' : '新增规格'}
        open={skuModalOpen}
        onOk={submitSKU}
        onCancel={() => { setSkuModalOpen(false); setSkuEditing(null); }}
        okText={skuEditing ? '保存' : '创建'}
        width={620}
      >
        <Form form={skuForm} layout="vertical" style={{ marginTop: 16 }}>
          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="name" label="规格名称" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input placeholder="标准版" />
            </Form.Item>
            <Form.Item name="code" label="规格编码" rules={[{ required: true }]} style={{ flex: 1 }}>
              <Input placeholder="ssl-standard-1y" />
            </Form.Item>
          </Space>

          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="price_cents" label="价格（分）" rules={[{ required: true }]} style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} placeholder="6800 = ¥68.00" />
            </Form.Item>
            <Form.Item name="currency" label="币种" style={{ flex: 1 }}>
              <Select options={[{ value: 'CNY', label: 'CNY' }]} />
            </Form.Item>
            <Form.Item name="duration_months" label="服务期（月）" rules={[{ required: true, message: '请输入服务期（月）' }]} style={{ flex: 1 }}>
              <InputNumber min={1} max={120} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item name="stock" label="库存" extra="-1 表示不限" style={{ flex: 1 }}>
              <InputNumber min={-1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="min_qty" label="起购数量" style={{ flex: 1 }}>
              <InputNumber min={1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="max_qty" label="限购数量" style={{ flex: 1 }}>
              <InputNumber min={1} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Space size={12} style={{ display: 'flex' }} align="start">
            <Form.Item
              name="delivery_mode" label="交付方式" style={{ flex: 1 }}
              extra={skuProduct?.category === 'cloudcard'
                ? '云卡商品只用于开通或续费云端智能卡。'
                : '本地实体/虚拟卡规格要求设备生成 CSR；SKU 只收证书费用，不包含卡片或 TPM 硬件。'}
            >
              <Select options={skuProduct?.category === 'cloudcard'
                ? DELIVERY_OPTIONS.filter((option) => option.value === 'cloud_card') : DELIVERY_OPTIONS} />
            </Form.Item>
            <Form.Item name="sort_weight" label="排序权重" style={{ flex: 1 }}>
              <InputNumber min={0} max={9999} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          {skuProduct?.category === 'cloudcard' ? (
            <>
              <Form.Item
                name="cloud_card_tmpl_uuid" label="云卡开通模板"
                rules={[{ required: true, message: '请选择云卡开通模板' }]}
                extra="服务期、存储区域、证书容量和到期提醒由该模板及此规格共同决定"
              >
                <Select
                  showSearch optionFilterProp="label"
                  options={cloudCardTemplates.map((template) => ({
                    label: `${template.name}${template.enabled ? '' : '（停用）'}`,
                    value: template.uuid,
                    disabled: !template.enabled,
                  }))}
                />
              </Form.Item>
              <Form.Item name="cloud_card_operation" label="权益用途" rules={[{ required: true, message: '请选择该规格的用途' }]}>
                <Select options={[
                  { value: 'activation', label: '新开云端智能卡' },
                  { value: 'renewal', label: '续费已有同模板云卡' },
                ]} />
              </Form.Item>
              <Alert type="info" showIcon message="续费规格只延长用户已有同模板云卡的服务期，不会创建新卡；到期后暂停敏感操作，证书与审计数据保留。" />
            </>
          ) : (
            <>
              <Form.Item name="key_types" label="支持的密钥算法" extra="每行一个，如 ec256 / rsa2048">
                <Input.TextArea rows={2} />
              </Form.Item>
              <Form.Item
                name="cert_apply_tmpl_uuid" label="关联证书开通模板"
                rules={[{ required: true, message: '请选择证书开通模板' }]}
                extra="决定申请资料要求与审批策略；签发参数由关联颁发模板统一约束"
              >
                <Select
                  showSearch optionFilterProp="label"
                  options={applyTemplates.map((t) => ({ label: `${t.name}${t.require_approval ? '（人工审批）' : '（自动开通）'}`, value: t.uuid }))}
                />
              </Form.Item>
              <Alert type="info" showIcon style={{ marginBottom: 12 }}
                message="单张证书的 SAN 限制（本规格内每次申请生效）" />
              <Space size={12} style={{ display: 'flex' }} align="start">
                <Form.Item name={['san_policy', 'max_dns']} label="域名数量" style={{ flex: 1 }}>
                  <InputNumber min={0} max={999} style={{ width: '100%' }} />
                </Form.Item>
                <Form.Item name={['san_policy', 'max_email']} label="邮箱数量" style={{ flex: 1 }}>
                  <InputNumber min={0} max={999} style={{ width: '100%' }} />
                </Form.Item>
                <Form.Item name={['san_policy', 'max_ip']} label="IP 数量" style={{ flex: 1 }}>
                  <InputNumber min={0} max={999} style={{ width: '100%' }} />
                </Form.Item>
              </Space>
              <Space size={24} style={{ display: 'flex' }}>
                <Form.Item name={['san_policy', 'allow_wildcard']} label="允许通配符域名" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name={['san_policy', 'ip_versions']} label="允许的 IP 版本">
                  <Select mode="multiple" style={{ minWidth: 180 }}
                    options={[{ label: 'IPv4', value: 'v4' }, { label: 'IPv6', value: 'v6' }]} />
                </Form.Item>
              </Space>
              <Space size={12} style={{ display: 'flex' }} align="start">
                <Form.Item name="email_suffixes" label="允许的邮箱后缀" style={{ flex: 1 }} extra="每行一个，如 corp.com；留空不限">
                  <Input.TextArea rows={2} />
                </Form.Item>
                <Form.Item name="dns_suffixes" label="允许的域名后缀" style={{ flex: 1 }} extra="每行一个，如 example.com；留空不限">
                  <Input.TextArea rows={2} />
                </Form.Item>
              </Space>
            </>
          )}

          <Form.Item name="enabled" label="启用该规格" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="停用" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default ConsoleProducts;
