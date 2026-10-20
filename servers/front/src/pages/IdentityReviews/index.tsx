import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Tabs, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Row, Col, Popconfirm, Empty,
} from 'antd';
import {
  AuditOutlined, CheckOutlined, CloseOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined,
  MailOutlined, SafetyCertificateOutlined, GlobalOutlined, EditOutlined, StarOutlined,
  SendOutlined, ApiOutlined,
} from '@ant-design/icons';
import {
  listIdentityReviews, approveSubjectInfo, rejectSubjectInfo,
  approveExtensionInfo, rejectExtensionInfo,
  listVerifyProviders, saveVerifyProvider, deleteVerifyProvider, testVerifyProvider,
  setDefaultVerifyProvider, listExtensionTemplates, listSubjectTemplates,
} from '../../api';
import type { SubjectInfo, ExtensionInfo, VerifyProvider, VerifyProviderDriver } from '../../types';
import HelpLink from '../../components/HelpLink';
import ProviderConfigForm from '../../components/ProviderConfigForm';

const { Title, Text, Paragraph } = Typography;

/** 后端 API 地址，用于生成第三方回调地址 */
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:1027';

const kindMeta: Record<string, { label: string; icon: React.ReactNode; color: string; hint: string }> = {
  email: {
    label: '邮件接口', icon: <MailOutlined />, color: 'blue',
    hint: '发送邮箱验证码与业务通知。可把其中一个设为系统默认发信接口。',
  },
  domain: {
    label: '域名验证接口', icon: <GlobalOutlined />, color: 'green',
    hint: '证明申请人对域名的控制权。在扩展信息模板中选择使用哪个接口。',
  },
  identity: {
    label: '实名认证接口', icon: <SafetyCertificateOutlined />, color: 'purple',
    hint: '用户完成实名核验后自动更新审核状态。在主体模板中选择使用哪个接口。',
  },
};

/** 认证接口分组表格 */
const ProviderSection: React.FC<{
  kind: 'email' | 'domain' | 'identity';
  providers: VerifyProvider[];
  onEdit: (p?: VerifyProvider) => void;
  onTest: (p: VerifyProvider) => void;
  onDefault: (p: VerifyProvider) => void;
  onDelete: (p: VerifyProvider) => void;
  onCopyCallback: (p: VerifyProvider) => void;
}> = ({ kind, providers, onEdit, onTest, onDefault, onDelete, onCopyCallback }) => {
  const meta = kindMeta[kind];
  const columns = [
    {
      title: '接口名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: VerifyProvider) => (
        <Space direction="vertical" size={0}>
          <Space size={6}>
            <Text strong>{v}</Text>
            {r.is_default && <Tag color="blue">默认</Tag>}
          </Space>
          <Text type="secondary" style={{ fontSize: 12 }}>{r.driver}</Text>
        </Space>
      ),
    },
    ...(kind === 'identity'
      ? [{
        title: '回调地址', key: 'callback', width: 200,
        render: (_: any, r: VerifyProvider) => (
          <Button type="link" size="small" onClick={() => onCopyCallback(r)}>复制回调地址</Button>
        ),
      }]
      : []),
    {
      title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => (v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag>),
    },
    {
      title: '操作', key: 'actions', width: 260, fixed: 'right' as const,
      render: (_: any, r: VerifyProvider) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => onEdit(r)}>编辑</Button>
          <Button type="link" size="small" icon={<SendOutlined />} onClick={() => onTest(r)}>测试</Button>
          {!r.is_default && r.enabled && (
            <Button type="link" size="small" icon={<StarOutlined />} onClick={() => onDefault(r)}>设为默认</Button>
          )}
          <Popconfirm title="被模板引用时无法删除" onConfirm={() => onDelete(r)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Card
      size="small"
      style={{ marginBottom: 16 }}
      title={<Space>{meta.icon}<Text strong>{meta.label}</Text>
        <Tag color={meta.color}>{providers.length}</Tag></Space>}
      extra={<Button size="small" type="primary" icon={<PlusOutlined />} onClick={() => onEdit(undefined)}>新增</Button>}
    >
      <Paragraph type="secondary" style={{ fontSize: 12, marginTop: -4 }}>{meta.hint}</Paragraph>
      {providers.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={`还没有${meta.label}`} />
      ) : (
        <Table rowKey="uuid" dataSource={providers} columns={columns as any} size="small" pagination={false} scroll={{ x: 760 }} />
      )}
    </Card>
  );
};

/** 身份认证审核：待审核（人工） + 自动审核（认证接口配置） */
const IdentityReviewsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [subjectReviews, setSubjectReviews] = useState<SubjectInfo[]>([]);
  const [extensionReviews, setExtensionReviews] = useState<ExtensionInfo[]>([]);
  const [reviewKind, setReviewKind] = useState<'subject' | 'extension'>('subject');
  const [reviewStatus, setReviewStatus] = useState('pending');

  const [providers, setProviders] = useState<VerifyProvider[]>([]);
  const [drivers, setDrivers] = useState<VerifyProviderDriver[]>([]);
  const [providerOpen, setProviderOpen] = useState(false);
  const [editingProvider, setEditingProvider] = useState<VerifyProvider | null>(null);
  const [providerForm] = Form.useForm();
  const [testTarget, setTestTarget] = useState<VerifyProvider | null>(null);
  const [testForm] = Form.useForm();
  const [rejectTarget, setRejectTarget] = useState<{ kind: 'subject' | 'extension'; uuid: string } | null>(null);
  const [rejectForm] = Form.useForm();

  const [extTmpls, setExtTmpls] = useState<any[]>([]);
  const [subjTmpls, setSubjTmpls] = useState<any[]>([]);

  const loadReviews = async (kind = reviewKind, status = reviewStatus) => {
    setLoading(true);
    try {
      const list = await listIdentityReviews(kind, status);
      if (kind === 'subject') setSubjectReviews(list);
      else setExtensionReviews(list);
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  const loadProviders = async () => {
    try {
      const r = await listVerifyProviders();
      setProviders(r.items);
      setDrivers(r.drivers);
    } catch { /* 接口未启用时忽略 */ }
  };

  useEffect(() => {
    loadReviews('subject', 'pending');
    loadReviews('extension', 'reviewing');
    loadProviders();
    listExtensionTemplates().then(setExtTmpls).catch(() => undefined);
    listSubjectTemplates().then(setSubjTmpls).catch(() => undefined);
  }, []);

  const grouped = useMemo(() => ({
    email: providers.filter((p) => p.kind === 'email'),
    domain: providers.filter((p) => p.kind === 'domain'),
    identity: providers.filter((p) => p.kind === 'identity'),
  }), [providers]);

  /** 被模板引用的接口不能删除，这里给管理员看得懂的提示 */
  const usagesOf = (p: VerifyProvider) => [
    ...subjTmpls.filter((t: any) => t.verify_provider_uuid === p.uuid).map((t: any) => `主体模板「${t.name}」`),
    ...extTmpls.filter((t: any) => (t.verify_policy ?? '').includes(p.uuid)).map((t: any) => `扩展模板「${t.name}」`),
  ];

  const openProvider = (p?: VerifyProvider, kind?: 'email' | 'domain' | 'identity') => {
    setEditingProvider(p ?? null);
    providerForm.resetFields();
    if (p) {
      providerForm.setFieldsValue({ ...p, config: { ...p.config } });
    } else {
      const k = kind || 'email';
      const first = drivers.find((d) => d.kind === k);
      providerForm.setFieldsValue({ kind: k, driver: first?.driver, enabled: true, config: {} });
    }
    setProviderOpen(true);
  };

  const submitProvider = async (v: any) => {
    try {
      // 明文值才提交；脱敏占位符由服务端保留原密钥
      const config: Record<string, string> = {};
      Object.entries(v.config ?? {}).forEach(([k, val]) => {
        if (val !== undefined && val !== null && val !== '') config[k] = String(val);
      });
      await saveVerifyProvider({ ...v, uuid: editingProvider?.uuid, config });
      message.success('已保存');
      setProviderOpen(false);
      loadProviders();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDefault = async (p: VerifyProvider) => {
    try {
      await setDefaultVerifyProvider(p.uuid);
      message.success(`已将「${p.name}」设为默认`);
      loadProviders();
    } catch (e: any) { message.error(e.message || '设置失败'); }
  };

  const handleCopyCallback = async (p: VerifyProvider) => {
    const url = `${API_BASE.replace(/\/$/, '')}/api/identity/callback/${p.uuid}`;
    try {
      await navigator.clipboard.writeText(url);
      message.success('回调地址已复制');
    } catch {
      Modal.info({ title: '回调地址', content: url });
    }
  };

  const subjectColumns = [
    { title: '申请人', dataIndex: 'username', key: 'username',
      render: (v: string, r: SubjectInfo) => v || r.user_uuid?.slice(0, 8) },
    { title: '模板', dataIndex: 'template_name', key: 'template_name', render: (v: string) => v || '—' },
    { title: '主体内容', dataIndex: 'fields', key: 'fields',
      render: (fields: Record<string, string>) => (
        <Space direction="vertical" size={0}>
          {Object.entries(fields ?? {}).map(([k, v]) => (
            <Text key={k} style={{ fontSize: 12 }}>{k} = {v}</Text>
          ))}
        </Space>
      ) },
    { title: '验证方式', dataIndex: 'verify_mode', key: 'verify_mode', width: 110,
      render: (v: string) => ({
        manual: <Tag color="orange">人工审核</Tag>,
        auto: <Tag color="purple">实名认证</Tag>,
        none: <Tag>免验证</Tag>,
      } as any)[v] ?? <Tag>{v}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 110,
      render: (v: string) => ({
        pending: <Tag color="orange">待审核</Tag>,
        verifying: <Tag color="purple">待实名</Tag>,
        approved: <Tag color="green">已通过</Tag>,
        rejected: <Tag color="red">已驳回</Tag>,
      } as any)[v] ?? <Tag>{v}</Tag> },
    { title: '提交时间', dataIndex: 'created_at', key: 'created_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 150,
      render: (_: any, r: SubjectInfo) => (r.status === 'pending' || r.status === 'verifying') ? (
        <Space size={4}>
          <Button type="link" size="small" icon={<CheckOutlined />} onClick={async () => {
            try { await approveSubjectInfo(r.uuid); message.success('已通过'); loadReviews(); }
            catch (e: any) { message.error(e.message || '操作失败'); }
          }}>通过</Button>
          <Button type="link" size="small" danger icon={<CloseOutlined />}
            onClick={() => { setRejectTarget({ kind: 'subject', uuid: r.uuid }); rejectForm.resetFields(); }}>驳回</Button>
        </Space>
      ) : (r.reject_reason ? <Text type="secondary" style={{ fontSize: 12 }}>{r.reject_reason}</Text> : null),
    },
  ];

  const extensionColumns = [
    { title: '申请人', dataIndex: 'username', key: 'username',
      render: (v: string, r: ExtensionInfo) => v || r.user_uuid?.slice(0, 8) },
    { title: '类型', dataIndex: 'type', key: 'type', width: 90,
      render: (v: string) => ({ domain: '域名', email: '邮箱', ip: 'IP' } as any)[v] ?? v },
    { title: '值', dataIndex: 'value', key: 'value', render: (v: string) => <Text copyable>{v}</Text> },
    { title: '验证方式', dataIndex: 'verify_method', key: 'verify_method', width: 110,
      render: (v: string) => ({
        txt: <Tag>DNS TXT</Tag>, http: <Tag>HTTP 文件</Tag>, tls: <Tag>TLS-ALPN</Tag>, email: <Tag>邮箱验证码</Tag>,
      } as any)[v] ?? <Tag>{v}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 110,
      render: (v: string) => ({
        pending: <Tag color="orange">待自助验证</Tag>,
        reviewing: <Tag color="purple">待人工审核</Tag>,
        verified: <Tag color="green">已验证</Tag>,
        rejected: <Tag color="red">已驳回</Tag>,
      } as any)[v] ?? <Tag>{v}</Tag> },
    { title: '提交时间', dataIndex: 'created_at', key: 'created_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 150,
      render: (_: any, r: ExtensionInfo) => (r.status === 'reviewing' || r.status === 'pending') ? (
        <Space size={4}>
          <Button type="link" size="small" icon={<CheckOutlined />} onClick={async () => {
            try { await approveExtensionInfo(r.uuid); message.success('已通过'); loadReviews(); }
            catch (e: any) { message.error(e.message || '操作失败'); }
          }}>通过</Button>
          <Button type="link" size="small" danger icon={<CloseOutlined />}
            onClick={() => { setRejectTarget({ kind: 'extension', uuid: r.uuid }); rejectForm.resetFields(); }}>驳回</Button>
        </Space>
      ) : (r.reject_reason ? <Text type="secondary" style={{ fontSize: 12 }}>{r.reject_reason}</Text> : null),
    },
  ];

  // 编辑弹窗里可选的驱动：只显示当前类型的
  const watchedKind = Form.useWatch('kind', providerForm);
  const driverOptions = drivers
    .filter((d) => !watchedKind || d.kind === watchedKind)
    .map((d) => ({
      label: `${d.name} · ${kindMeta[d.kind]?.label ?? d.kind}`,
      value: d.driver,
      disabled: !d.available,
    }));

  return (
    <div>
      <Card
        title={<Space><AuditOutlined /><Title level={4} style={{ margin: 0 }}>身份认证审核</Title>
          <HelpLink doc="admin-13-identity-verification" /></Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={() => { loadReviews(); loadProviders(); }}>刷新</Button>}
      >
        <Tabs
          items={[
            {
              key: 'pending', label: '待审核（人工）',
              children: (
                <>
                  <Space style={{ marginBottom: 12 }} wrap>
                    <Select value={reviewKind} style={{ width: 180 }}
                      onChange={(v) => {
                        setReviewKind(v);
                        const st = v === 'subject' ? 'pending' : 'reviewing';
                        setReviewStatus(st);
                        loadReviews(v, st);
                      }}
                      options={[
                        { label: '主体信息', value: 'subject' },
                        { label: '扩展信息（域名/邮箱/IP）', value: 'extension' },
                      ]} />
                    <Select value={reviewStatus} style={{ width: 140 }}
                      onChange={(v) => { setReviewStatus(v); loadReviews(reviewKind, v); }}
                      options={[
                        { label: '待处理', value: reviewKind === 'subject' ? 'pending' : 'reviewing' },
                        { label: '已通过', value: 'approved' },
                        { label: '已驳回', value: 'rejected' },
                        { label: '全部', value: '' },
                      ]} />
                  </Space>
                  {reviewKind === 'subject'
                    ? <Table rowKey="uuid" loading={loading} dataSource={subjectReviews} columns={subjectColumns as any} />
                    : <Table rowKey="uuid" loading={loading} dataSource={extensionReviews} columns={extensionColumns as any} />}
                </>
              ),
            },
            {
              key: 'auto', label: '自动审核（认证接口）',
              children: (
                <Row gutter={16}>
                  <Col xs={24} xl={18}>
                    <ProviderSection kind="email" providers={grouped.email}
                      onEdit={(p) => openProvider(p, 'email')}
                      onTest={(p) => { setTestTarget(p); testForm.resetFields(); }}
                      onDefault={handleDefault}
                      onCopyCallback={handleCopyCallback}
                      onDelete={async (p) => {
                        const used = usagesOf(p);
                        if (used.length) { message.warning(`该接口正被 ${used.join('、')} 使用，请先修改模板`); return; }
                        try { await deleteVerifyProvider(p.uuid); message.success('已删除'); loadProviders(); }
                        catch (e: any) { message.error(e.message || '删除失败'); }
                      }} />
                    <ProviderSection kind="domain" providers={grouped.domain}
                      onEdit={(p) => openProvider(p, 'domain')}
                      onTest={(p) => { setTestTarget(p); testForm.resetFields(); }}
                      onDefault={handleDefault}
                      onCopyCallback={handleCopyCallback}
                      onDelete={async (p) => {
                        const used = usagesOf(p);
                        if (used.length) { message.warning(`该接口正被 ${used.join('、')} 使用，请先修改模板`); return; }
                        try { await deleteVerifyProvider(p.uuid); message.success('已删除'); loadProviders(); }
                        catch (e: any) { message.error(e.message || '删除失败'); }
                      }} />
                    <ProviderSection kind="identity" providers={grouped.identity}
                      onEdit={(p) => openProvider(p, 'identity')}
                      onTest={(p) => { setTestTarget(p); testForm.resetFields(); }}
                      onDefault={handleDefault}
                      onCopyCallback={handleCopyCallback}
                      onDelete={async (p) => {
                        const used = usagesOf(p);
                        if (used.length) { message.warning(`该接口正被 ${used.join('、')} 使用，请先修改模板`); return; }
                        try { await deleteVerifyProvider(p.uuid); message.success('已删除'); loadProviders(); }
                        catch (e: any) { message.error(e.message || '删除失败'); }
                      }} />
                  </Col>
                  <Col xs={24} xl={6}>
                    <Card size="small" title={<Space><ApiOutlined />怎么用</Space>}>
                      <Paragraph style={{ fontSize: 13, marginBottom: 8 }}>
                        邮件接口：在「主体模板 / 扩展信息模板」的邮箱验证中选择，或在「系统设置 - 系统邮件」中设为默认发信接口。
                      </Paragraph>
                      <Paragraph style={{ fontSize: 13, marginBottom: 8 }}>
                        域名接口：在扩展信息模板中为域名验证选择要使用的接口。
                      </Paragraph>
                      <Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
                        实名接口：在主体模板中为需要实名的字段选择接口；用户完成后审核状态会自动更新。
                      </Paragraph>
                    </Card>
                  </Col>
                </Row>
              ),
            },
          ]}
        />
      </Card>

      {/* 认证接口编辑 */}
      <Modal open={providerOpen} title={editingProvider ? '编辑认证接口' : '新增认证接口'}
        onCancel={() => setProviderOpen(false)} onOk={() => providerForm.submit()} width={680}>
        <Form form={providerForm} layout="vertical" onFinish={submitProvider}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="name" label="接口名称" style={{ flex: 1 }} rules={[{ required: true, message: '请输入名称' }]}>
              <Input placeholder="例如：企业邮箱 SMTP" />
            </Form.Item>
            <Form.Item name="kind" label="用途" style={{ flex: 1 }} rules={[{ required: true }]}>
              <Select
                disabled={!!editingProvider}
                onChange={() => {
                  const first = drivers.find((d) => d.kind === providerForm.getFieldValue('kind'));
                  providerForm.setFieldsValue({ driver: first?.driver, config: {} });
                }}
                options={[
                  { label: '邮件发送', value: 'email' },
                  { label: '域名验证', value: 'domain' },
                  { label: '实名认证', value: 'identity' },
                ]} />
            </Form.Item>
          </Space>
          <Form.Item name="driver" label="驱动" rules={[{ required: true, message: '请选择驱动' }]}>
            <Select
              disabled={!!editingProvider}
              onChange={() => providerForm.setFieldsValue({ config: {} })}
              options={driverOptions} />
          </Form.Item>
          <ProviderConfigForm drivers={drivers} kind={watchedKind} />
          <Form.Item name="enabled" label="启用" valuePropName="checked" style={{ marginTop: 12 }}>
            <Switch />
          </Form.Item>
        </Form>
      </Modal>

      {/* 连通性测试：邮件发信 / 域名解析 / 实名配置检查 */}
      <Modal open={!!testTarget} title={`测试接口 — ${testTarget?.name ?? ''}`} onCancel={() => setTestTarget(null)}
        onOk={() => testForm.submit()} destroyOnClose>
        <Form form={testForm} layout="vertical" onFinish={async (v: any) => {
          try {
            const payload = testTarget?.kind === 'email'
              ? { to: v.to }
              : testTarget?.kind === 'domain'
                ? { domain: v.domain, dry_run: !!v.dry_run }
                : { dry_run: true };
            const res = await testVerifyProvider(testTarget!.uuid, payload as any);
            Modal.info({
              title: '测试结果',
              content: (
                <div style={{ fontSize: 13 }}>
                  {res?.message && <Paragraph>{res.message}</Paragraph>}
                  {res?.method && (
                    <Paragraph type="secondary">
                      方式 {res.method}｜端口 {res.port}｜前缀 {res.record_prefix || res.path_prefix}
                    </Paragraph>
                  )}
                </div>
              ),
            });
            setTestTarget(null);
          } catch (e: any) { message.error(e.message || '测试失败'); }
        }}>
          {testTarget?.kind === 'email' && (
            <Form.Item name="to" label="接收邮箱" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
              <Input placeholder="you@example.com" />
            </Form.Item>
          )}
          {testTarget?.kind === 'domain' && (
            <>
              <Form.Item name="domain" label="测试域名" extra="留空只检查配置是否生效，不发起真实解析">
                <Input placeholder="example.com" />
              </Form.Item>
              <Form.Item name="dry_run" label="只检查配置" valuePropName="checked" initialValue={false}>
                <Switch />
              </Form.Item>
            </>
          )}
          {testTarget?.kind === 'identity' && (
            <Paragraph type="secondary">
              实名认证需要用户本人配合，这里只检查必填项是否配置完整。
            </Paragraph>
          )}
        </Form>
      </Modal>

      {/* 驳回原因 */}
      <Modal open={!!rejectTarget} title="驳回" onCancel={() => setRejectTarget(null)}
        onOk={() => rejectForm.submit()} destroyOnClose>
        <Form form={rejectForm} layout="vertical" onFinish={async (v: any) => {
          if (!rejectTarget) return;
          try {
            if (rejectTarget.kind === 'subject') await rejectSubjectInfo(rejectTarget.uuid, v.reason);
            else await rejectExtensionInfo(rejectTarget.uuid, v.reason);
            message.success('已驳回');
            setRejectTarget(null);
            loadReviews();
          } catch (e: any) { message.error(e.message || '驳回失败'); }
        }}>
          <Form.Item name="reason" label="驳回原因" rules={[{ required: true, message: '请填写驳回原因' }]}>
            <Input.TextArea rows={3} maxLength={200} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default IdentityReviewsPage;
