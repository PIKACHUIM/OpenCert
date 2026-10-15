import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Steps, Button, Space, Typography, Select, Table, Tag, Alert, Form, Input, Radio,
  Descriptions, Result, message, Empty, Spin, Modal, List,
} from 'antd';
import {
  SolutionOutlined, IdcardOutlined, LinkOutlined, CheckCircleOutlined, PlusOutlined,
  ReloadOutlined, SafetyCertificateOutlined,
} from '@ant-design/icons';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  getApplyContext, getCapabilities, createSubjectInfo, createExtensionInfo,
  verifyDNS, verifyHTTP, verifyTLS, verifyEmail, renewExtensionInfo,
  submitApplication, listMySubscriptions,
} from '../../api';
import type { ApplyContext, ExtensionInfo, Subscription } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text, Paragraph } = Typography;

/** 验证方式文案 */
const VERIFY_TEXT: Record<string, string> = {
  manual: '人工审核', auto: '实名认证接口', none: '免验证',
};

type SourceOption = {
  key: string;
  kind: 'order' | 'self' | 'subscription';
  label: string;
  sub?: string;
  params: { order_no?: string; tmpl?: string; subscription?: string };
};

/**
 * 申请证书向导：选择订单/额度 → 主体信息 → 扩展信息（域名/邮箱/IP 验证）→ 确认提交。
 *
 * 是否自动开通由证书开通模板的「是否需要审批」决定：
 * 无需审批时服务端在提交后立即签发并跳转申请详情，否则提示证书审核中。
 */
const ApplyWizard: React.FC = () => {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [ctx, setCtx] = useState<ApplyContext | null>(null);
  const [source, setSource] = useState<SourceOption | null>(null);
  const [sources, setSources] = useState<SourceOption[]>([]);

  const [subjectChoice, setSubjectChoice] = useState<string>('');
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [newSubjectOpen, setNewSubjectOpen] = useState(false);
  const [subjectForm] = Form.useForm();

  const [picked, setPicked] = useState<string[]>([]);
  const [addOpen, setAddOpen] = useState(false);
  const [addForm] = Form.useForm();
  const [addResult, setAddResult] = useState<{ info: ExtensionInfo; instructions?: string } | null>(null);

  const [keyType, setKeyType] = useState('');
  const [cardUUID, setCardUUID] = useState('');
  const [csrPEM, setCsrPEM] = useState('');
  const [result, setResult] = useState<{ auto_issued: boolean; message: string; app: any } | null>(null);

  // ---- 加载可选来源 ----
  const loadSources = async () => {
    setLoading(true);
    try {
      const [caps, mySubs] = await Promise.all([
        getCapabilities(),
        listMySubscriptions().catch(() => [] as Subscription[]),
      ]);
      const list: SourceOption[] = [];
      (caps.cert_order_quotas ?? []).forEach((q) => {
        list.push({
          key: `order:${q.order_no}`, kind: 'order',
          label: `${q.product_name || '证书订单'} ${q.sku_name ? `· ${q.sku_name}` : ''}`,
          sub: `订单 ${q.order_no} · 剩余 ${q.remaining}/${q.quantity} 份`,
          params: { order_no: q.order_no },
        });
      });
      (caps.self_apply_templates ?? []).forEach((t) => {
        list.push({
          key: `self:${t.uuid}`, kind: 'self', label: `自助申请 · ${t.name}`,
          sub: t.require_approval ? '需人工审批' : '自动开通',
          params: { tmpl: t.uuid },
        });
      });
      mySubs.filter((s) => s.status === 'active').forEach((s) => {
        (s.usage ?? []).filter((u) => u.remaining > 0).forEach((u) => {
          list.push({
            key: `sub:${s.uuid}:${u.cert_apply_tmpl_uuid}`, kind: 'subscription',
            label: `订阅额度 · ${u.template_name || u.cert_apply_tmpl_uuid.slice(0, 8)}`,
            sub: `剩余 ${u.remaining} 张 · 到期 ${new Date(s.ends_at).toLocaleDateString('zh-CN')}`,
            params: { subscription: s.uuid, tmpl: u.cert_apply_tmpl_uuid },
          });
        });
      });
      setSources(list);

      // URL 指定来源时直接进入下一步
      const qOrder = params.get('order_no');
      const qTmpl = params.get('tmpl');
      const qSub = params.get('subscription');
      const matched = list.find((x) =>
        (qOrder && x.params.order_no === qOrder) ||
        (qSub && x.params.subscription === qSub && x.params.tmpl === qTmpl) ||
        (!qOrder && !qSub && qTmpl && x.params.tmpl === qTmpl));
      if (matched) {
        setSource(matched);
        await loadContext(matched);
        setStep(1);
      }
    } catch (e: any) { message.error(e.message || '加载可申请额度失败'); }
    finally { setLoading(false); }
  };

  const loadContext = async (s: SourceOption) => {
    setLoading(true);
    try {
      const c = await getApplyContext(s.params);
      setCtx(c);
      setKeyType(c.source.key_types?.[0] ?? '');
      setCardUUID(c.cards?.[0]?.uuid ?? '');
      // 优先选择可用主体信息
      const usable = (c.subject_infos ?? []).find((i) => i.status === 'approved' &&
        (!i.expires_at || new Date(i.expires_at) > new Date()));
      setSubjectChoice(usable?.uuid ?? '');
      if (usable) setSubjectValues(usable.fields ?? {});
      setPicked((c.extension_infos ?? []).filter((e) => e.usable).map((e) => e.uuid));
      return c;
    } catch (e: any) {
      message.error(e.message || '加载申请要求失败');
      return null;
    } finally { setLoading(false); }
  };

  useEffect(() => { loadSources(); }, []);

  const pickedExtensions = useMemo(
    () => (ctx?.extension_infos ?? []).filter((e) => picked.includes(e.uuid)),
    [ctx, picked],
  );

  const policy = ctx?.extension.policy;

  // ---- 提交主体信息（新建） ----
  const submitNewSubject = async (v: any) => {
    try {
      const fields: Record<string, string> = {};
      (ctx?.subject.fields ?? []).forEach((f) => {
        const val = v[`f_${f.key}`];
        if (val !== undefined && val !== null && val !== '') fields[f.key] = String(val);
      });
      const info = await createSubjectInfo({ template_uuid: ctx!.subject.template_uuid, fields });
      message.success(info.status === 'approved' ? '主体信息已通过验证' : '主体信息已提交，等待验证');
      setSubjectChoice(info.uuid);
      setNewSubjectOpen(false);
      subjectForm.resetFields();
      await loadContext(source!);
    } catch (e: any) { message.error(e.message || '提交失败'); }
  };

  // ---- 提交扩展信息（新建） ----
  const submitNewExtension = async (v: any) => {
    try {
      const info = await createExtensionInfo({
        type: v.type, value: v.value, verify_method: v.verify_method, tmpl_uuid: ctx!.extension.template_uuid,
      });
      const resp: any = info as any;
      setAddResult({ info, instructions: resp?.instructions });
      message.success(info.status === 'verified' ? '已通过验证' : '已创建，请按提示完成验证');
      await loadContext(source!);
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const runVerify = async (id: string, method: string) => {
    try {
      if (method === 'txt') await verifyDNS(id);
      else if (method === 'http') await verifyHTTP(id);
      else if (method === 'tls') await verifyTLS(id);
      message.success('验证通过');
      await loadContext(source!);
    } catch (e: any) { message.error(e.message || '验证未通过'); }
  };

  // ---- 提交申请 ----
  const doSubmit = async () => {
    if (!source) return;
    setLoading(true);
    try {
      const r = await submitApplication({
        ...source.params,
        subject_info_uuid: subjectChoice || undefined,
        extension_info_uuids: picked,
        key_type: keyType,
        card_uuid: cardUUID || undefined,
        csr_pem: csrPEM || undefined,
      });
      setResult({ auto_issued: r.auto_issued, message: r.message, app: r.application });
      setStep(3);
    } catch (e: any) { message.error(e.message || '提交失败'); }
    finally { setLoading(false); }
  };

  const needSubject = ctx?.subject.required ?? false;
  const subjectOk = !needSubject || (() => {
    const info = (ctx?.subject_infos ?? []).find((i) => i.uuid === subjectChoice);
    return !!info && info.status === 'approved' && (!info.expires_at || new Date(info.expires_at) > new Date());
  })();
  const sanPolicy = ctx?.source.san_policy;
  const sanCount = {
    dns: pickedExtensions.filter((e) => e.type === 'domain').length,
    email: pickedExtensions.filter((e) => e.type === 'email').length,
    ip: pickedExtensions.filter((e) => e.type === 'ip').length,
  };

  const renderSourceStep = () => (
    <div>
      {sources.length === 0 ? (
        <Empty description="暂无可申请的证书额度">
          <Space>
            <Button type="primary" onClick={() => navigate('/products')}>去产品中心选购</Button>
            <Button onClick={() => navigate('/console/profile')}>查看订阅与兑换</Button>
          </Space>
        </Empty>
      ) : (
        <List
          dataSource={sources}
          renderItem={(item) => (
            <List.Item
              actions={[<Button key="go" type="primary" onClick={async () => {
                setSource(item);
                const c = await loadContext(item);
                if (c) setStep(1);
              }}>选择</Button>]}
            >
              <List.Item.Meta
                avatar={<SafetyCertificateOutlined style={{ fontSize: 20, color: '#1677ff' }} />}
                title={item.label}
                description={item.sub}
              />
            </List.Item>
          )}
        />
      )}
    </div>
  );

  const renderSubjectStep = () => (
    <div>
      <Alert
        type="info" showIcon style={{ marginBottom: 16 }}
        message={`证书开通模板：${ctx?.source.template?.name ?? '—'}`}
        description={ctx?.subject.template_uuid ? (
          <Space direction="vertical" size={2} style={{ fontSize: 13 }}>
            <Text>主体模板：{ctx.subject.template_name}（验证方式：{VERIFY_TEXT[ctx.subject.verify_mode] ?? ctx.subject.verify_mode}）</Text>
            {ctx.subject.validity && <Text type="secondary">审核/认证有效期：{ctx.subject.validity}</Text>}
            {ctx.subject.verify_mode === 'auto' && <Text type="secondary">提交后需完成实名认证，认证通过即生效</Text>}
          </Space>
        ) : '该证书类型未绑定主体模板，将直接以第一个已验证的域名/邮箱作为通用名称（CN）'}
      />

      {needSubject && (
        <>
          <Radio.Group value={subjectChoice} onChange={(e) => {
            setSubjectChoice(e.target.value);
            const info = (ctx?.subject_infos ?? []).find((i) => i.uuid === e.target.value);
            setSubjectValues(info?.fields ?? {});
          }} style={{ width: '100%' }}>
            <Space direction="vertical" style={{ width: '100%' }}>
              {(ctx?.subject_infos ?? []).map((info) => (
                <Radio key={info.uuid} value={info.uuid} style={{ width: '100%' }}>
                  <Space direction="vertical" size={0}>
                    {Object.entries(info.fields ?? {}).map(([k, v]) => (
                      <Text key={k} style={{ fontSize: 13 }}>{k} = {v}</Text>
                    ))}
                    <Space size={4}>
                      {info.status === 'approved'
                        ? <Tag color="green">已通过</Tag>
                        : info.status === 'verifying' ? <Tag color="purple">待实名认证</Tag>
                        : info.status === 'pending' ? <Tag color="orange">待审核</Tag> : <Tag color="red">已驳回</Tag>}
                      {info.expires_at && (
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          有效期至 {new Date(info.expires_at).toLocaleDateString('zh-CN')}
                        </Text>
                      )}
                      {info.reject_reason && <Text type="danger" style={{ fontSize: 12 }}>{info.reject_reason}</Text>}
                    </Space>
                  </Space>
                </Radio>
              ))}
            </Space>
          </Radio.Group>
          <Button icon={<PlusOutlined />} style={{ marginTop: 12 }} onClick={() => setNewSubjectOpen(true)}>
            新建主体信息
          </Button>
          <div style={{ marginTop: 12 }}>
            <Button onClick={() => navigate('/console/subject-infos')}>管理主体信息</Button>
          </div>
        </>
      )}

      <Modal open={newSubjectOpen} title="填写主体信息" onCancel={() => setNewSubjectOpen(false)}
        onOk={() => subjectForm.submit()} destroyOnClose width={560}>
        <Form form={subjectForm} layout="vertical" onFinish={submitNewSubject}>
          {(ctx?.subject.fields ?? []).map((f) => (
            <Form.Item
              key={f.key} name={`f_${f.key}`} label={`${f.label || f.key}（${f.key}）`}
              rules={f.required ? [{ required: true, message: `请填写${f.label || f.key}` }] : undefined}
              extra={[
                f.derive ? `由扩展信息自动派生（${f.derive === 'first_domain' ? '第一个域名' : f.derive === 'first_email' ? '第一个邮箱' : '第一个 IP'}）` : '',
                f.verify === 'auto' ? '需完成实名认证' : f.verify === 'manual' ? '需管理员审核' : '免验证',
                f.pattern ? `格式：${f.pattern}` : '',
                f.help || '',
              ].filter(Boolean).join(' · ') || undefined}
            >
              <Input
                placeholder={f.default ? `默认值 ${f.default}` : ''}
                maxLength={f.max_len || 128}
                disabled={!!f.derive}
              />
            </Form.Item>
          ))}
        </Form>
      </Modal>
    </div>
  );

  const renderExtensionStep = () => (
    <div>
      <Alert
        type="info" showIcon style={{ marginBottom: 16 }}
        message="扩展信息（SAN）：域名 / 邮箱 / IP 的所有权验证"
        description={
          <Space direction="vertical" size={2} style={{ fontSize: 13 }}>
            {sanPolicy && (
              <Text>
                本证书允许：域名 {sanPolicy.max_dns} 个（含 {sanCount.dns} 个）
                {sanPolicy.max_email > 0 ? ` · 邮箱 ${sanPolicy.max_email} 个（含 ${sanCount.email} 个）` : ''}
                {sanPolicy.max_ip > 0 ? ` · IP ${sanPolicy.max_ip} 个（含 ${sanCount.ip} 个）` : ''}
                {sanPolicy.allow_wildcard ? ' · 支持通配符' : ''}
                {sanPolicy.ip_versions?.length ? ` · ${sanPolicy.ip_versions.join('/').toUpperCase()}` : ''}
              </Text>
            )}
            <Text type="secondary">
              验证方式：{policy ? `域名 ${policy.domain.methods.join('/')}；邮箱 ${policy.email.methods.join('/')}；IP ${policy.ip.methods.join('/')}` : '—'}
              （模板策略：{policy ? { manual: '人工审核', auto: '自动验证', none: '免验证' }[policy.domain.mode] : '—'}）
            </Text>
            <Text type="secondary">已验证且未过期的扩展信息可直接勾选复用</Text>
          </Space>
        }
      />

      <Table
        rowKey="uuid"
        size="small"
        dataSource={ctx?.extension_infos ?? []}
        rowSelection={{
          selectedRowKeys: picked,
          onChange: (keys) => setPicked(keys as string[]),
          getCheckboxProps: (r: ExtensionInfo) => ({ disabled: !r.usable }),
        }}
        columns={[
          { title: '类型', dataIndex: 'type', width: 80,
            render: (v: string) => ({ domain: '域名', email: '邮箱', ip: 'IP' } as any)[v] ?? v },
          { title: '值', dataIndex: 'value' },
          { title: '验证方式', dataIndex: 'verify_method', width: 110 },
          { title: '状态', dataIndex: 'status', width: 120,
            render: (v: string, r: ExtensionInfo) => (
              <Space direction="vertical" size={0}>
                {r.usable ? <Tag color="green">可复用</Tag>
                  : v === 'pending' ? <Tag color="orange">待验证</Tag>
                  : v === 'reviewing' ? <Tag color="purple">待人工审核</Tag>
                  : v === 'verified' ? <Tag color="red">需重新验证</Tag>
                  : <Tag color="red">已驳回</Tag>}
                {r.policy_error && <Text type="secondary" style={{ fontSize: 12 }}>{r.policy_error}</Text>}
              </Space>
            ) },
          { title: '有效期', dataIndex: 'expires_at', width: 130,
            render: (v: string) => (v ? new Date(v).toLocaleDateString('zh-CN') : '—') },
          {
            title: '操作', key: 'actions', width: 150,
            render: (_: any, r: ExtensionInfo) => r.usable ? null : (
              <Space size={2}>
                {r.status === 'pending' && r.verify_method === 'email' && (
                  <Button type="link" size="small" onClick={() => {
                    const code = window.prompt(`请输入发送到 ${r.value} 的验证码`);
                    if (code) verifyEmail(r.uuid, code).then(() => {
                      message.success('邮箱验证通过'); loadContext(source!);
                    }).catch((e: any) => message.error(e.message));
                  }}>输入验证码</Button>
                )}
                {r.status === 'pending' && r.verify_method !== 'email' && (
                  <Button type="link" size="small" onClick={() => runVerify(r.uuid, r.verify_method)}>立即验证</Button>
                )}
                {r.status === 'verified' && (
                  <Button type="link" size="small" onClick={async () => {
                    try {
                      await renewExtensionInfo(r.uuid, undefined, ctx?.extension.template_uuid);
                      message.success('已按当前证书要求重新发起验证');
                      await loadContext(source!);
                    } catch (e: any) { message.error(e.message || '操作失败'); }
                  }}>重新验证</Button>
                )}
              </Space>
            ),
          },
        ]}
        pagination={false}
      />

      <Space style={{ marginTop: 12 }}>
        <Button icon={<PlusOutlined />} onClick={() => { addForm.resetFields(); setAddResult(null); setAddOpen(true); }}>
          添加域名 / 邮箱 / IP
        </Button>
        <Button onClick={() => navigate('/console/extension-infos')}>管理扩展信息</Button>
        <Button icon={<ReloadOutlined />} onClick={() => loadContext(source!)}>刷新状态</Button>
      </Space>

      <Modal open={addOpen} title="添加扩展信息" onCancel={() => setAddOpen(false)}
        onOk={() => (addResult ? setAddOpen(false) : addForm.submit())} destroyOnClose width={560}
        footer={addResult ? [
          <Button key="close" type="primary" onClick={() => setAddOpen(false)}>完成</Button>,
        ] : undefined}>
        {addResult ? (
          <Alert
            type={addResult.info.status === 'verified' ? 'success' : 'info'} showIcon
            message={addResult.info.status === 'verified' ? '已通过验证' : '请完成验证'}
            description={<Paragraph style={{ marginBottom: 0 }} copyable>{addResult.instructions}</Paragraph>}
          />
        ) : (
          <Form form={addForm} layout="vertical" onFinish={submitNewExtension}
            initialValues={{ type: 'domain', verify_method: 'dns' }}>
            <Form.Item name="type" label="类型" rules={[{ required: true }]}>
              <Select
                options={[
                  { label: '域名', value: 'domain', disabled: !!policy && !policy.domain.enabled },
                  { label: '邮箱', value: 'email', disabled: !!policy && !policy.email.enabled },
                  { label: 'IP 地址', value: 'ip', disabled: !!policy && !policy.ip.enabled },
                ]}
              />
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(p, c) => p.type !== c.type}>
              {({ getFieldValue }) => {
                const t = getFieldValue('type');
                const methods = t === 'domain' ? policy?.domain.methods : t === 'email' ? policy?.email.methods : policy?.ip.methods;
                return (
                  <>
                    <Form.Item name="value" label={t === 'email' ? '邮箱地址' : t === 'ip' ? 'IP 地址' : '域名'}
                      rules={[{ required: true, message: '请输入值' }]}>
                      <Input placeholder={t === 'email' ? 'user@example.com' : t === 'ip' ? '192.0.2.10' : 'example.com 或 *.example.com'} />
                    </Form.Item>
                    {t !== 'email' && (
                      <Form.Item name="verify_method" label="验证方式" initialValue={methods?.[0]}>
                        <Select options={(methods ?? []).map((m) => ({
                          value: m,
                          label: m === 'dns' ? 'DNS TXT 记录' : m === 'http' ? 'HTTP 文件' : 'TLS-ALPN（RFC 8737）',
                        }))} />
                      </Form.Item>
                    )}
                  </>
                );
              }}
            </Form.Item>
          </Form>
        )}
      </Modal>
    </div>
  );

  const renderConfirmStep = () => (
    <div>
      <Descriptions bordered size="small" column={1} style={{ marginBottom: 16 }}>
        <Descriptions.Item label="申请来源">
          {source?.label}（{source?.sub}）
        </Descriptions.Item>
        <Descriptions.Item label="证书类型">{ctx?.source.template?.name ?? '—'}</Descriptions.Item>
        <Descriptions.Item label="有效期">
          {ctx?.source.valid_days ? `${ctx.source.valid_days} 天` : '按模板缺省'}
        </Descriptions.Item>
        <Descriptions.Item label="是否需要审批">
          {ctx?.source.template?.require_approval ? '需要人工审批' : '自动开通'}
        </Descriptions.Item>
        <Descriptions.Item label="主体信息">
          {Object.keys(subjectValues).length
            ? Object.entries(subjectValues).map(([k, v]) => `${k}=${v}`).join('，')
            : '（由扩展信息派生 / 无需填写）'}
        </Descriptions.Item>
        <Descriptions.Item label="SAN">
          {pickedExtensions.length ? pickedExtensions.map((e) => e.value).join('，') : '（无）'}
        </Descriptions.Item>
      </Descriptions>

      <Form layout="vertical">
        <Form.Item label="密钥算法" extra="密钥在云端智能卡或托管容器内生成，私钥不出服务端">
          <Select
            value={keyType || undefined}
            onChange={setKeyType}
            options={(ctx?.source.key_types ?? []).map((k) => ({ label: k, value: k }))}
          />
        </Form.Item>
        {(ctx?.source.delivery_mode === 'cloud_card') && (
          <Form.Item label="签发到智能卡" required extra="该证书可通过智能卡远程签名/解密">
            {ctx?.cards?.length ? (
              <Select value={cardUUID} onChange={setCardUUID}
                options={(ctx?.cards ?? []).map((c) => ({ label: c.card_name, value: c.uuid }))} />
            ) : (
              <Alert type="warning" showIcon message="暂无智能卡"
                description={<Button type="link" onClick={() => navigate('/console/cards')}>前往开通智能卡</Button>} />
            )}
          </Form.Item>
        )}
        <Form.Item label="自带 CSR（可选）" extra="提交后将使用您的公钥签发，私钥不进入服务端；CSR 中的名称需在本次申请中通过验证">
          <Input.TextArea rows={4} value={csrPEM} onChange={(e) => setCsrPEM(e.target.value)}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----" />
        </Form.Item>
      </Form>

      {!subjectOk && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }}
          message="主体信息尚未通过审核，暂时无法提交"
          description="请等待人工审核或完成实名认证，审核通过后可继续提交。" />
      )}
      <Button type="primary" size="large" disabled={!subjectOk} loading={loading} onClick={doSubmit}>
        确认并提交申请
      </Button>
    </div>
  );

  const renderResultStep = () => (
    <Result
      status={result?.auto_issued ? 'success' : 'info'}
      icon={result?.auto_issued ? <CheckCircleOutlined /> : <SolutionOutlined />}
      title={result?.auto_issued ? '证书已签发' : '证书审核中'}
      subTitle={result?.auto_issued
        ? '证书已签发并存入您的托管容器或智能卡，可立即下载或使用。'
        : '申请已提交，审核通过后将自动签发；可在「我的证书申请」中查看进度。'}
      extra={[
        <Button type="primary" key="apps" onClick={() => navigate('/console/apply-records')}>查看我的申请</Button>,
        <Button key="certs" onClick={() => navigate('/console/certs')}>我的证书</Button>,
        <Button key="again" onClick={() => {
          setResult(null); setStep(0); setPicked([]); setCsrPEM(''); loadSources();
        }}>再申请一张</Button>,
      ]}
    />
  );

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 8px' }}>
        申请证书 <HelpLink doc="user-03-apply-certificate" />
      </Title>
      <Text type="secondary">选择订单或订阅额度 → 确认主体信息 → 添加并验证域名/邮箱/IP → 提交</Text>

      <Card style={{ marginTop: 16 }}>
        <Steps
          current={step}
          items={[
            { title: '选择来源', icon: <SolutionOutlined /> },
            { title: '主体信息', icon: <IdcardOutlined /> },
            { title: '扩展信息', icon: <LinkOutlined /> },
            { title: '确认提交', icon: <CheckCircleOutlined /> },
          ]}
          style={{ marginBottom: 24 }}
        />

        {loading && !ctx ? <Spin /> : (
          <>
            {step === 0 && renderSourceStep()}
            {step === 1 && renderSubjectStep()}
            {step === 2 && renderExtensionStep()}
            {step === 3 && (result ? renderResultStep() : renderConfirmStep())}
          </>
        )}

        {step > 0 && step < 3 && (
          <Space style={{ marginTop: 24 }}>
            <Button onClick={() => setStep(step - 1)}>上一步</Button>
            <Button type="primary" onClick={() => setStep(step + 1)}
              disabled={step === 1 && needSubject && !subjectChoice}>
              下一步
            </Button>
          </Space>
        )}
        {step === 0 && null}
      </Card>
    </div>
  );
};

export default ApplyWizard;
