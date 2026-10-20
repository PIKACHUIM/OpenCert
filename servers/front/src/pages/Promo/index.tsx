import React, { useEffect, useState } from 'react';
import {
  Card, Table, Tabs, Button, Space, Tag, Typography, Modal, Form, Input, InputNumber,
  Select, Switch, message, Popconfirm, Alert, DatePicker,
} from 'antd';
import {
  GiftOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined, TagsOutlined,
} from '@ant-design/icons';
import {
  listCoupons, saveCoupon, deleteCoupon,
  listPlans, savePlan, deletePlan,
  listAdminSubscriptions, grantSubscription, cancelSubscription,
  listRedeemCodes, generateRedeemCodes, setRedeemEnabled,
  listCertApplyTemplates,
} from '../../api';
import type { Coupon, PromoPlan, Subscription, RedeemCode, CertApplyTemplateInfo } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

/**
 * 订阅优惠管理：优惠码、订阅套餐、订阅实例、兑换码。
 *
 * - 优惠码：下单抵扣（满减/折扣），可限制适用商品、总量与每人次数、有效期；
 * - 订阅套餐：周期内可用指定证书开通模板申请若干张证书，可设置单证有效期、
 *   是否允许吊销、吊销后是否释放额度；
 * - 订阅实例：购买的套餐订单支付后自动开通，也可由管理员直接发放；
 * - 兑换码：兑换订阅套餐或账户余额（批量生成，可导出）。
 */
const PromoPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [coupons, setCoupons] = useState<Coupon[]>([]);
  const [plans, setPlans] = useState<PromoPlan[]>([]);
  const [subs, setSubs] = useState<Subscription[]>([]);
  const [codes, setCodes] = useState<RedeemCode[]>([]);
  const [tmpls, setTmpls] = useState<CertApplyTemplateInfo[]>([]);

  const [couponOpen, setCouponOpen] = useState(false);
  const [planOpen, setPlanOpen] = useState(false);
  const [grantOpen, setGrantOpen] = useState(false);
  const [codeOpen, setCodeOpen] = useState(false);
  const [editingCoupon, setEditingCoupon] = useState<Coupon | null>(null);
  const [editingPlan, setEditingPlan] = useState<PromoPlan | null>(null);
  const [generated, setGenerated] = useState<RedeemCode[]>([]);

  const [couponForm] = Form.useForm();
  const [planForm] = Form.useForm();
  const [grantForm] = Form.useForm();
  const [codeForm] = Form.useForm();

  const loadAll = async () => {
    setLoading(true);
    try {
      const [c, p, s, r] = await Promise.all([
        listCoupons().catch(() => []),
        listPlans(true).catch(() => []),
        listAdminSubscriptions().catch(() => []),
        listRedeemCodes().catch(() => []),
      ]);
      setCoupons(c); setPlans(p); setSubs(s); setCodes(r);
      const t = await listCertApplyTemplates().catch(() => ({ items: [] as CertApplyTemplateInfo[] }));
      setTmpls((t as any).items ?? []);
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadAll(); }, []);

  const reload = () => loadAll();

  // ---- 优惠码 ----
  const openCoupon = (c?: Coupon) => {
    setEditingCoupon(c ?? null);
    couponForm.resetFields();
    couponForm.setFieldsValue(c ? {
      ...c,
      valid_range: c.valid_from || c.valid_until ? [c.valid_from, c.valid_until] : undefined,
    } : { discount_type: 'amount', total_limit: -1, per_user_limit: 1, enabled: true });
    setCouponOpen(true);
  };

  const submitCoupon = async (v: any) => {
    try {
      const [valid_from, valid_until] = v.valid_range ?? [];
      await saveCoupon({
        ...v, uuid: editingCoupon?.uuid, valid_from, valid_until, product_codes: v.product_codes ?? [],
      } as any);
      message.success('已保存');
      setCouponOpen(false); reload();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  // ---- 套餐 ----
  const openPlan = (p?: PromoPlan) => {
    setEditingPlan(p ?? null);
    planForm.resetFields();
    planForm.setFieldsValue(p ?? {
      period_days: 365, visible: true, enabled: true, allow_revoke: true, revoke_release_quota: false,
      items: [{ quota: 1, valid_days: 365 }],
    });
    setPlanOpen(true);
  };

  const submitPlan = async (v: any) => {
    try {
      await savePlan({ ...v, uuid: editingPlan?.uuid } as any);
      message.success('已保存');
      setPlanOpen(false); reload();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const tmplName = (uuid: string) => tmpls.find((t) => t.uuid === uuid)?.name || uuid?.slice(0, 8) || '—';

  const couponColumns = [
    { title: '优惠码', dataIndex: 'code', key: 'code', render: (v: string) => <Text copyable code>{v}</Text> },
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '优惠', key: 'discount',
      render: (_: any, r: Coupon) => r.discount_type === 'amount'
        ? `立减 ¥${(r.discount_value / 100).toFixed(2)}`
        : `${r.discount_value}% 折扣${r.max_discount_cents > 0 ? `（封顶 ¥${(r.max_discount_cents / 100).toFixed(2)}）` : ''}` },
    { title: '门槛', dataIndex: 'min_amount_cents', key: 'min_amount_cents',
      render: (v: number) => v > 0 ? `满 ¥${(v / 100).toFixed(2)}` : '无门槛' },
    { title: '适用商品', dataIndex: 'product_codes', key: 'product_codes',
      render: (v: string[]) => (v && v.length ? v.join('、') : '全部商品') },
    { title: '用量', key: 'usage',
      render: (_: any, r: Coupon) => (
        <Text>{r.used_count} / {r.total_limit < 0 ? '不限' : r.total_limit}
          {r.per_user_limit > 0 ? `（每人 ${r.per_user_limit} 次）` : ''}</Text>
      ) },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    {
      title: '操作', key: 'actions', width: 140,
      render: (_: any, r: Coupon) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openCoupon(r)}>编辑</Button>
          <Popconfirm title="确认删除？已使用的优惠码建议改为停用" onConfirm={async () => {
            try { await deleteCoupon(r.uuid); message.success('已删除'); reload(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const planColumns = [
    { title: '套餐', key: 'name',
      render: (_: any, r: PromoPlan) => (
        <Space direction="vertical" size={0}>
          <Text strong>{r.name}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{r.code} · {r.period_days} 天</Text>
        </Space>
      ) },
    { title: '价格', dataIndex: 'price_cents', key: 'price_cents',
      render: (v: number) => `¥${(v / 100).toFixed(2)}` },
    { title: '包含额度', dataIndex: 'items', key: 'items',
      render: (items: PromoPlan['items']) => (
        <Space direction="vertical" size={0}>
          {(items ?? []).map((it, i) => (
            <Text key={i} style={{ fontSize: 12 }}>
              {tmplName(it.cert_apply_tmpl_uuid)} × {it.quota} 张{it.valid_days > 0 ? `（单证 ${it.valid_days} 天）` : ''}
            </Text>
          ))}
        </Space>
      ) },
    { title: '吊销策略', key: 'revoke',
      render: (_: any, r: PromoPlan) => (
        <Space direction="vertical" size={0}>
          <Tag color={r.allow_revoke ? 'green' : 'red'}>{r.allow_revoke ? '允许自行吊销' : '不允许自行吊销'}</Tag>
          {r.allow_revoke && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              {r.revoke_release_quota ? '吊销后释放额度' : '吊销后不释放额度'}
            </Text>
          )}
        </Space>
      ) },
    { title: '状态', key: 'status',
      render: (_: any, r: PromoPlan) => (
        <Space size={4}>
          {r.visible ? <Tag color="blue">前台可见</Tag> : <Tag>仅内部</Tag>}
          {r.enabled ? <Tag color="success">可售</Tag> : <Tag>停用</Tag>}
        </Space>
      ) },
    {
      title: '操作', key: 'actions', width: 140,
      render: (_: any, r: PromoPlan) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openPlan(r)}>编辑</Button>
          <Popconfirm title="确认删除？已有订阅的套餐只能停用" onConfirm={async () => {
            try { await deletePlan(r.uuid); message.success('已删除'); reload(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const subColumns = [
    { title: '用户', dataIndex: 'username', key: 'username',
      render: (v: string, r: Subscription) => v || r.user_uuid?.slice(0, 8) },
    { title: '套餐', key: 'plan',
      render: (_: any, r: Subscription) => (
        <Space direction="vertical" size={0}>
          <Text>{r.plan?.name || r.plan_uuid?.slice(0, 8)}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>来源：{{
            order: '购买订单', redeem: '兑换码', admin: '管理员发放',
          }[r.source] ?? r.source}</Text>
        </Space>
      ) },
    { title: '有效期', key: 'period',
      render: (_: any, r: Subscription) => (
        <Text style={{ fontSize: 12 }}>
          {new Date(r.starts_at).toLocaleDateString('zh-CN')} ~ {new Date(r.ends_at).toLocaleDateString('zh-CN')}
        </Text>
      ) },
    { title: '额度使用', key: 'usage',
      render: (_: any, r: Subscription) => (
        <Space direction="vertical" size={0}>
          {(r.usage ?? []).map((u, i) => (
            <Text key={i} style={{ fontSize: 12 }}>
              {u.template_name || tmplName(u.cert_apply_tmpl_uuid)}：{u.used}/{u.quota}（余 {u.remaining}）
            </Text>
          ))}
        </Space>
      ) },
    { title: '状态', key: 'status', width: 110,
      render: (_: any, r: Subscription) => {
        const active = r.status === 'active' && new Date(r.ends_at) > new Date();
        return active ? <Tag color="green">生效中</Tag>
          : <Tag color="default">{r.status === 'cancelled' ? '已终止' : '已过期'}</Tag>;
      } },
    {
      title: '操作', key: 'actions', width: 100,
      render: (_: any, r: Subscription) => (
        <Popconfirm title="终止后用户将无法再使用该订阅额度，确认？" onConfirm={async () => {
          try { await cancelSubscription(r.uuid); message.success('已终止'); reload(); }
          catch (e: any) { message.error(e.message || '操作失败'); }
        }}>
          <Button type="link" size="small" danger>终止</Button>
        </Popconfirm>
      ),
    },
  ];

  const codeColumns = [
    { title: '兑换码', dataIndex: 'code', key: 'code', render: (v: string) => <Text copyable code>{v}</Text> },
    { title: '批次', dataIndex: 'batch_name', key: 'batch_name', render: (v: string) => v || '—' },
    { title: '权益', key: 'grant',
      render: (_: any, r: RedeemCode) => r.grant_type === 'plan'
        ? `订阅套餐：${plans.find((p) => p.uuid === r.plan_uuid)?.name || r.plan_uuid?.slice(0, 8)}`
        : `余额 ¥${((r.balance_cents ?? 0) / 100).toFixed(2)}` },
    { title: '使用', key: 'usage', render: (_: any, r: RedeemCode) => `${r.used_count}/${r.max_uses}` },
    { title: '有效期', dataIndex: 'valid_until', key: 'valid_until',
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '长期有效') },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 110,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    {
      title: '操作', key: 'actions', width: 100,
      render: (_: any, r: RedeemCode) => (
        <Button type="link" size="small" onClick={async () => {
          try { await setRedeemEnabled(r.uuid, !r.enabled); reload(); }
          catch (e: any) { message.error(e.message || '操作失败'); }
        }}>{r.enabled ? '停用' : '启用'}</Button>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><GiftOutlined /><Title level={4} style={{ margin: 0 }}>订阅优惠管理</Title>
          <HelpLink doc="admin-12-promo-subscription" /></Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={reload}>刷新</Button>}
      >
        <Tabs
          items={[
            {
              key: 'coupons', label: '优惠码',
              children: (
                <>
                  <Alert type="info" showIcon style={{ marginBottom: 12 }}
                    message="优惠码在用户下单时抵扣金额；订单取消后次数自动归还" />
                  <Space style={{ marginBottom: 12 }}>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => openCoupon()}>新增优惠码</Button>
                  </Space>
                  <Table rowKey="uuid" loading={loading} dataSource={coupons} columns={couponColumns as any} />
                </>
              ),
            },
            {
              key: 'plans', label: '订阅套餐',
              children: (
                <>
                  <Space style={{ marginBottom: 12 }}>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => openPlan()}>新增套餐</Button>
                    <Button icon={<TagsOutlined />} onClick={() => { grantForm.resetFields(); setGrantOpen(true); }}>发放订阅</Button>
                  </Space>
                  <Table rowKey="uuid" loading={loading} dataSource={plans} columns={planColumns as any} />
                </>
              ),
            },
            {
              key: 'subscriptions', label: '订阅实例',
              children: <Table rowKey="uuid" loading={loading} dataSource={subs} columns={subColumns as any} />,
            },
            {
              key: 'codes', label: '兑换码',
              children: (
                <>
                  <Space style={{ marginBottom: 12 }}>
                    <Button type="primary" icon={<PlusOutlined />}
                      onClick={() => { codeForm.resetFields(); setGenerated([]); codeForm.setFieldsValue({ grant_type: 'balance', max_uses: 1, count: 10 }); setCodeOpen(true); }}>
                      批量生成
                    </Button>
                  </Space>
                  <Table rowKey="uuid" loading={loading} dataSource={codes} columns={codeColumns as any} />
                </>
              ),
            },
          ]}
        />
      </Card>

      {/* 优惠码编辑 */}
      <Modal open={couponOpen} title={editingCoupon ? '编辑优惠码' : '新增优惠码'}
        onCancel={() => setCouponOpen(false)} onOk={() => couponForm.submit()} destroyOnClose width={620}>
        <Form form={couponForm} layout="vertical" onFinish={submitCoupon}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="code" label="优惠码" style={{ flex: 1 }} extra="留空自动生成">
              <Input placeholder="SAVE10" />
            </Form.Item>
            <Form.Item name="name" label="名称" style={{ flex: 1 }}>
              <Input placeholder="新用户立减" />
            </Form.Item>
          </Space>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="discount_type" label="优惠类型" style={{ flex: 1 }} rules={[{ required: true }]}>
              <Select options={[
                { label: '立减金额（分）', value: 'amount' },
                { label: '折扣（减免百分比）', value: 'percent' },
              ]} />
            </Form.Item>
            <Form.Item name="discount_value" label="优惠值" style={{ flex: 1 }}
              rules={[{ required: true, message: '请输入优惠值' }]}
              extra="立减填分（100 = 1 元）；折扣填 1-100 的百分比">
              <InputNumber min={1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="max_discount_cents" label="折扣封顶（分）" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="min_amount_cents" label="订单门槛（分）" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="total_limit" label="总可用次数" style={{ flex: 1 }} extra="-1 表示不限">
              <InputNumber min={-1} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="per_user_limit" label="每人次数" style={{ flex: 1 }} extra="0 表示不限">
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Form.Item name="product_codes" label="适用商品编码" extra="留空表示全部商品">
            <Select mode="tags" placeholder="例如：ssl-std" />
          </Form.Item>
          <Form.Item name="valid_range" label="有效期">
            <DatePicker.RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      {/* 套餐编辑 */}
      <Modal open={planOpen} title={editingPlan ? '编辑套餐' : '新增套餐'}
        onCancel={() => setPlanOpen(false)} onOk={() => planForm.submit()} destroyOnClose width={760}>
        <Form form={planForm} layout="vertical" onFinish={submitPlan}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="code" label="套餐编码" style={{ flex: 1 }} rules={[{ required: true, message: '请输入编码' }]}>
              <Input placeholder="team-yearly" />
            </Form.Item>
            <Form.Item name="name" label="套餐名称" style={{ flex: 1 }} rules={[{ required: true, message: '请输入名称' }]}>
              <Input placeholder="团队年包" />
            </Form.Item>
          </Space>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="period_days" label="订阅周期（天）" style={{ flex: 1 }} rules={[{ required: true }]}>
              <InputNumber min={1} max={3650} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="price_cents" label="价格（分）" style={{ flex: 1 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="sort_weight" label="排序权重" style={{ flex: 1 }}>
              <InputNumber style={{ width: '100%' }} />
            </Form.Item>
          </Space>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Form.List name="items">
            {(fields, { add, remove }) => (
              <>
                <Text strong>证书额度</Text>
                {fields.map((field) => (
                  <Space key={field.key} size={12} style={{ display: 'flex', marginTop: 8 }} align="baseline">
                    <Form.Item name={[field.name, 'cert_apply_tmpl_uuid']} rules={[{ required: true, message: '请选择证书类型' }]}
                      style={{ flex: 2, marginBottom: 0 }}>
                      <Select placeholder="证书开通模板" options={tmpls.map((t) => ({ label: t.name, value: t.uuid }))} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'quota']} rules={[{ required: true, message: '数量' }]} style={{ flex: 1, marginBottom: 0 }}>
                      <InputNumber min={1} placeholder="张数" style={{ width: '100%' }} />
                    </Form.Item>
                    <Form.Item name={[field.name, 'valid_days']} style={{ flex: 1, marginBottom: 0 }}
                      extra="0 = 按开通模板">
                      <InputNumber min={0} placeholder="单证有效期(天)" style={{ width: '100%' }} />
                    </Form.Item>
                    <Button type="link" danger onClick={() => remove(field.name)}>删除</Button>
                  </Space>
                ))}
                <Button type="dashed" block icon={<PlusOutlined />} style={{ marginTop: 8 }} onClick={() => add({ quota: 1, valid_days: 365 })}>
                  添加额度项
                </Button>
              </>
            )}
          </Form.List>
          <Space size={24} style={{ marginTop: 16 }}>
            <Form.Item name="allow_revoke" label="允许用户自行吊销" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="revoke_release_quota" label="吊销后释放额度" valuePropName="checked"><Switch /></Form.Item>
          </Space>
          <Space size={24}>
            <Form.Item name="visible" label="前台可见" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
          </Space>
        </Form>
      </Modal>

      {/* 发放订阅 */}
      <Modal open={grantOpen} title="发放订阅" onCancel={() => setGrantOpen(false)}
        onOk={() => grantForm.submit()} destroyOnClose>
        <Form form={grantForm} layout="vertical" onFinish={async (v: any) => {
          try {
            await grantSubscription(v.username, v.plan_uuid, v.remark);
            message.success('已发放');
            setGrantOpen(false); reload();
          } catch (e: any) { message.error(e.message || '发放失败'); }
        }}>
          <Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input placeholder="用户名（非邮箱）" />
          </Form.Item>
          <Form.Item name="plan_uuid" label="订阅套餐" rules={[{ required: true, message: '请选择套餐' }]}>
            <Select options={plans.map((p) => ({ label: `${p.name}（${p.period_days} 天）`, value: p.uuid }))} />
          </Form.Item>
          <Form.Item name="remark" label="备注"><Input /></Form.Item>
        </Form>
      </Modal>

      {/* 生成兑换码 */}
      <Modal open={codeOpen} title="批量生成兑换码" onCancel={() => setCodeOpen(false)}
        onOk={() => codeForm.submit()} destroyOnClose width={560} footer={generated.length ? null : undefined}>
        {generated.length > 0 ? (
          <div>
            <Alert type="success" showIcon style={{ marginBottom: 12 }} message={`已生成 ${generated.length} 个兑换码`} />
            <Input.TextArea rows={10} readOnly value={generated.map((c) => c.code).join('\n')} />
            <div style={{ marginTop: 12, textAlign: 'right' }}>
              <Button onClick={() => { setGenerated([]); reload(); }}>完成</Button>
            </div>
          </div>
        ) : (
          <Form form={codeForm} layout="vertical" onFinish={async (v: any) => {
            try {
              const list = await generateRedeemCodes({
                batch_name: v.batch_name, grant_type: v.grant_type, plan_uuid: v.plan_uuid,
                balance_cents: v.balance_cents, max_uses: v.max_uses, count: v.count,
                valid_until: v.valid_until ? new Date(v.valid_until).toISOString() : undefined,
              } as any);
              setGenerated(list);
              message.success(`已生成 ${list.length} 个`);
            } catch (e: any) { message.error(e.message || '生成失败'); }
          }}>
            <Form.Item name="grant_type" label="兑换权益" rules={[{ required: true }]}>
              <Select options={[
                { label: '订阅套餐', value: 'plan' },
                { label: '账户余额', value: 'balance' },
              ]} />
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(p, c) => p.grant_type !== c.grant_type}>
              {({ getFieldValue }) => getFieldValue('grant_type') === 'plan' ? (
                <Form.Item name="plan_uuid" label="套餐" rules={[{ required: true, message: '请选择套餐' }]}>
                  <Select options={plans.map((p) => ({ label: p.name, value: p.uuid }))} />
                </Form.Item>
              ) : (
                <Form.Item name="balance_cents" label="兑换金额（分）" rules={[{ required: true, message: '请输入金额' }]}>
                  <InputNumber min={1} style={{ width: '100%' }} />
                </Form.Item>
              )}
            </Form.Item>
            <Space size={16} style={{ display: 'flex' }}>
              <Form.Item name="batch_name" label="批次名称" style={{ flex: 1 }}>
                <Input placeholder="2026 双十一" />
              </Form.Item>
              <Form.Item name="max_uses" label="每码可用次数" style={{ flex: 1 }}>
                <InputNumber min={1} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="count" label="生成数量" style={{ flex: 1 }}>
                <InputNumber min={1} max={1000} style={{ width: '100%' }} />
              </Form.Item>
            </Space>
            <Form.Item name="valid_until" label="有效期">
              <DatePicker showTime style={{ width: '100%' }} />
            </Form.Item>
          </Form>
        )}
      </Modal>
    </div>
  );
};

export default PromoPage;
