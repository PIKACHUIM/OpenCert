import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Tabs, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Alert, Row, Col, List, Popconfirm, Tooltip,
} from 'antd';
import {
  AuditOutlined, CheckOutlined, CloseOutlined, ReloadOutlined, PlusOutlined, DeleteOutlined,
  ApiOutlined, MailOutlined, SafetyCertificateOutlined, GlobalOutlined, EditOutlined,
} from '@ant-design/icons';
import {
  listIdentityReviews, approveSubjectInfo, rejectSubjectInfo,
  approveExtensionInfo, rejectExtensionInfo,
  listVerifyProviders, saveVerifyProvider, deleteVerifyProvider, testVerifyProvider,
  listExtensionTemplates, listSubjectTemplates,
} from '../../api';
import type { SubjectInfo, ExtensionInfo, VerifyProvider, VerifyProviderDriver } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text, Paragraph } = Typography;

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

  const driverOf = (p: VerifyProvider) =>
    drivers.find((d) => d.kind === p.kind && d.driver === p.driver);

  const openProvider = (p?: VerifyProvider) => {
    setEditingProvider(p ?? null);
    providerForm.resetFields();
    if (p) {
      providerForm.setFieldsValue({ ...p, config: { ...p.config } });
    } else {
      providerForm.setFieldsValue({ kind: 'email', enabled: true, config: {} });
    }
    setProviderOpen(true);
  };

  const submitProvider = async (v: any) => {
    try {
      // 明文值才提交；脱敏占位符由服务端保留原密钥
      const config: Record<string, string> = {};
      Object.entries(v.config ?? {}).forEach(([k, val]) => { if (val !== undefined && val !== null && val !== '') config[k] = String(val); });
      await saveVerifyProvider({ ...v, uuid: editingProvider?.uuid, config });
      message.success('已保存');
      setProviderOpen(false);
      loadProviders();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const providerColumns = useMemo(() => [
    { title: '接口名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: VerifyProvider) => (
        <Space direction="vertical" size={0}>
          <Text strong>{v}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>{driverOf(r)?.name || r.driver}</Text>
        </Space>
      ) },
    { title: '用途', dataIndex: 'kind', key: 'kind', width: 130,
      render: (v: string) => v === 'email'
        ? <Tag icon={<MailOutlined />} color="blue">邮箱验证码</Tag>
        : <Tag icon={<SafetyCertificateOutlined />} color="purple">实名认证</Tag> },
    { title: '被引用', key: 'used',
      render: (_: any, r: VerifyProvider) => {
        const used = [
          ...subjTmpls.filter((t: any) => t.verify_provider_uuid === r.uuid).map((t: any) => `主体模板「${t.name}」`),
          ...extTmpls.filter((t: any) => (t.verify_policy ?? '').includes(r.uuid)).map((t: any) => `扩展模板「${t.name}」`),
        ];
        return used.length ? <Text style={{ fontSize: 12 }}>{used.join('、')}</Text> : <Text type="secondary">—</Text>;
      } },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    {
      title: '操作', key: 'actions', width: 200,
      render: (_: any, r: VerifyProvider) => (
        <Space size={4}>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openProvider(r)}>编辑</Button>
          {r.kind === 'email' && (
            <Button type="link" size="small" onClick={() => { setTestTarget(r); testForm.resetFields(); }}>测试</Button>
          )}
          <Popconfirm title="确认删除？被模板引用时无法删除" onConfirm={async () => {
            try { await deleteVerifyProvider(r.uuid); message.success('已删除'); loadProviders(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], [drivers, subjTmpls, extTmpls]);

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

  const selectedDriver = drivers.find(
    (d) => d.kind === providerForm.getFieldValue('kind') && d.driver === providerForm.getFieldValue('driver'),
  );

  return (
    <div>
      <Card
        title={<Space><AuditOutlined /><Title level={4} style={{ margin: 0 }}>身份认证审核</Title>
          <HelpLink doc="admin-13-identity-review" /></Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={() => loadReviews()}>刷新</Button>}
      >
        <Tabs
          items={[
            {
              key: 'pending', label: '待审核（人工）',
              children: (
                <>
                  <Alert type="info" showIcon style={{ marginBottom: 12 }}
                    message="主体信息与扩展信息的审核队列（验证方式与有效期规则见帮助文档）" />
                  <Space style={{ marginBottom: 12 }} wrap>
                    <Select value={reviewKind} style={{ width: 160 }}
                      onChange={(v) => { setReviewKind(v); setReviewStatus(v === 'subject' ? 'pending' : 'reviewing'); loadReviews(v, v === 'subject' ? 'pending' : 'reviewing'); }}
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
                <Row gutter={[16, 16]}>
                  <Col xs={24} lg={16}>
                    <Space style={{ marginBottom: 12 }}>
                      <Button type="primary" icon={<PlusOutlined />} onClick={() => openProvider()}>新增认证接口</Button>
                    </Space>
                    <Table rowKey="uuid" dataSource={providers} columns={providerColumns as any} size="small" />
                  </Col>
                  <Col xs={24} lg={8}>
                    <Card size="small" title="内置验证方式" style={{ marginBottom: 16 }}>
                      <List
                        size="small"
                        dataSource={[
                          { icon: <GlobalOutlined />, title: '域名所有权', desc: 'DNS TXT 记录 / HTTP 文件 / TLS-ALPN（RFC 8737），在扩展信息模板中按类型启停' },
                          { icon: <MailOutlined />, title: '邮箱所有权', desc: '发送 6 位验证码，可选择下方任一邮件接口（未指定时使用系统 SMTP）' },
                          { icon: <ApiOutlined />, title: '个人实名', desc: '跳转第三方实名页面，完成后以 HMAC 签名回调本平台' },
                          { icon: <ApiOutlined />, title: '企业实名', desc: '同个人实名，回调结果由管理员按需复核主体字段' },
                        ]}
                        renderItem={(item) => (
                          <List.Item>
                            <List.Item.Meta avatar={item.icon} title={item.title} description={item.desc} />
                          </List.Item>
                        )}
                      />
                    </Card>
                    <Alert type="warning" showIcon
                      message="第三方实名接口为插件位"
                      description={
                        <Paragraph style={{ marginBottom: 0, fontSize: 13 }}>
                          支付宝身份验证、微信/腾讯云实名核身的驱动已登记但尚未接入（需商户资质与官方接口联调）。
                          当前可通过「通用实名回调」对接任意自建或第三方实名服务：平台跳转实名页面，
                          对方完成核验后回调 /api/identity/callback/&#123;providerUUID&#125;，签名头 X-Signature = hex(HMAC-SHA256(secret, body))。
                        </Paragraph>
                      } />
                  </Col>
                </Row>
              ),
            },
          ]}
        />
      </Card>

      {/* 认证接口编辑 */}
      <Modal open={providerOpen} title={editingProvider ? '编辑认证接口' : '新增认证接口'}
        onCancel={() => setProviderOpen(false)} onOk={() => providerForm.submit()} destroyOnClose width={640}>
        <Form form={providerForm} layout="vertical" onFinish={submitProvider}>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="name" label="接口名称" style={{ flex: 1 }} rules={[{ required: true, message: '请输入名称' }]}>
              <Input placeholder="例如：企业邮箱 SMTP" />
            </Form.Item>
            <Form.Item name="kind" label="类型" style={{ flex: 1 }} rules={[{ required: true }]}>
              <Select options={[
                { label: '邮件发送（邮箱验证码）', value: 'email' },
                { label: '实名认证（跳转回调）', value: 'identity' },
              ]} />
            </Form.Item>
          </Space>
          <Form.Item name="driver" label="驱动" rules={[{ required: true, message: '请选择驱动' }]}>
            <Select
              onChange={() => providerForm.setFieldsValue({ config: {} })}
              options={drivers.map((d) => ({
                label: `${d.name}${d.available ? '' : '（未接入）'} · ${d.kind === 'email' ? '邮件' : '实名'}`,
                value: d.driver,
                disabled: !d.available,
              }))}
            />
          </Form.Item>
          {selectedDriver && (
            <>
              <Alert type={selectedDriver.available ? 'info' : 'warning'} showIcon style={{ marginBottom: 12 }}
                message={selectedDriver.description} />
              {selectedDriver.fields.map((f) => (
                <Form.Item key={f.key} name={['config', f.key]} label={f.label}
                  rules={f.required ? [{ required: true, message: `请填写${f.label}` }] : undefined}
                  extra={f.help} tooltip={f.secret ? '已保存的密钥显示为 ******，保持不变即保留原值' : undefined}>
                  {f.secret ? <Input.Password placeholder="******" /> : <Input />}
                </Form.Item>
              ))}
            </>
          )}
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      {/* 邮件接口测试 */}
      <Modal open={!!testTarget} title="发送测试邮件" onCancel={() => setTestTarget(null)}
        onOk={() => testForm.submit()} destroyOnClose>
        <Form form={testForm} layout="vertical" onFinish={async (v: any) => {
          try {
            await testVerifyProvider(testTarget!.uuid, v.to);
            message.success('测试邮件已发送');
            setTestTarget(null);
          } catch (e: any) { message.error(e.message || '发送失败'); }
        }}>
          <Form.Item name="to" label="接收邮箱" rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
            <Input placeholder="you@example.com" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 驳回原因 */}
      <Modal open={!!rejectTarget} title="驳回" onCancel={() => setRejectTarget(null)}
        onOk={() => rejectForm.submit()} destroyOnClose>
        <Form form={rejectForm} layout="vertical" onFinish={async (v: any) => {
          try {
            if (rejectTarget!.kind === 'subject') await rejectSubjectInfo(rejectTarget!.uuid, v.reason);
            else await rejectExtensionInfo(rejectTarget!.uuid, v.reason);
            message.success('已驳回');
            setRejectTarget(null);
            loadReviews();
          } catch (e: any) { message.error(e.message || '操作失败'); }
        }}>
          <Tooltip title="原因会展示给用户，用户可修改资料后重新提交验证">
            <Form.Item name="reason" label="驳回原因" rules={[{ required: true, message: '请填写驳回原因' }]}>
              <Input.TextArea rows={3} placeholder="例如：证件照片不清晰 / 域名与主体不一致" />
            </Form.Item>
          </Tooltip>
        </Form>
      </Modal>
    </div>
  );
};

export default IdentityReviewsPage;
