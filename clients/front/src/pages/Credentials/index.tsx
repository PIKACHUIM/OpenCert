import React, { useEffect, useMemo, useState } from 'react';
import {
  Card as ACard, Tabs, Select, Form, Input, Button, Table, Tag, Popconfirm,
  message, Space, Typography, Alert, Modal,
} from 'antd';
import {
  UserOutlined, FileTextOutlined, CreditCardOutlined,
  LockOutlined, DeleteOutlined, PlusOutlined, EyeOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import PageHeader from '../../components/PageHeader';
import {
  getCards, getCerts, deleteCert, createCredential, getCredentialSecret, type CredentialPayload,
} from '../../api';
import type { Card, Certificate } from '../../types';

const { Text } = Typography;

// 将任意字符串/对象编码为 base64 (UTF-8 安全)。
const toB64 = (s: string): string => {
  // 先编码为 UTF-8 再 btoa，避免中文导致 InvalidCharacterError
  return btoa(unescape(encodeURIComponent(s)));
};

type CredType = 'login' | 'note' | 'payment' | 'text';

/**
 * 共享的"卡片选择 + 卡片密码"区域。
 */
// 将 base64 解码为字符串（UTF-8 安全）
const fromB64 = (s: string): string => {
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch {
    return s;
  }
};

// 解析 public_meta（cert_content 字段，base64 编码的 JSON）
const parseMeta = (certContent: Uint8Array | string | null | undefined): Record<string, string> => {
  try {
    if (!certContent) return {};
    const raw = typeof certContent === 'string' ? certContent : String.fromCharCode(...certContent);
    return JSON.parse(fromB64(raw));
  } catch {
    return {};
  }
};

// 根据 cert_type 将解密后的 JSON 渲染为可读内容
const renderSecretContent = (certType: CredType, secretJson: string) => {
  try {
    const obj = JSON.parse(secretJson);
    if (certType === 'login') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {obj.password !== undefined && <div><strong>密码：</strong><Typography.Text copyable code>{obj.password}</Typography.Text></div>}
        </div>
      );
    }
    if (certType === 'note') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {obj.title && <div><strong>标题：</strong>{obj.title}</div>}
          {obj.content && <div><strong>内容：</strong><pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{obj.content}</pre></div>}
        </div>
      );
    }
    if (certType === 'payment') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {obj.card_number && <div><strong>卡号：</strong><Typography.Text copyable code>{obj.card_number}</Typography.Text></div>}
          {obj.expiry && <div><strong>有效期：</strong>{obj.expiry}</div>}
          {obj.cvv && <div><strong>CVV：</strong><Typography.Text copyable code>{obj.cvv}</Typography.Text></div>}
        </div>
      );
    }
    if (certType === 'text') {
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {obj.label && <div><strong>标签：</strong>{obj.label}</div>}
          {obj.secret && <div><strong>内容：</strong><Typography.Text copyable code>{obj.secret}</Typography.Text></div>}
        </div>
      );
    }
    // 其他类型直接展示 JSON
    return <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{JSON.stringify(obj, null, 2)}</pre>;
  } catch {
    return <Typography.Text copyable>{secretJson}</Typography.Text>;
  }
};

/**
 * 通用列表 + 删除 + 查看：5 类凭据共用，按 cert_type 过滤。
 */
const CredentialList: React.FC<{
  certs: Certificate[];
  cardUUID: string;
  certType: CredType;
  onChanged: () => void;
}> = ({ certs, cardUUID, certType, onChanged }) => {
  const { t } = useTranslation();
  const [viewModal, setViewModal] = useState<{ open: boolean; cert: Certificate | null }>({ open: false, cert: null });
  const [pinInput, setPinInput] = useState('');
  const [secretContent, setSecretContent] = useState<string | null>(null);
  const [viewLoading, setViewLoading] = useState(false);

  const data = useMemo(
    () => certs.filter((c) => c.cert_type === certType),
    [certs, certType],
  );

  const handleView = (row: Certificate) => {
    setViewModal({ open: true, cert: row });
    setPinInput('');
    setSecretContent(null);
  };

  const handleDecrypt = async () => {
    if (!viewModal.cert || !pinInput) { message.warning('请输入卡片密码'); return; }
    setViewLoading(true);
    try {
      const b64 = await getCredentialSecret(cardUUID, viewModal.cert.uuid, pinInput);
      setSecretContent(fromB64(b64));
    } catch (e: any) {
      message.error(e?.response?.data?.message || e?.message || '解密失败');
    } finally {
      setViewLoading(false);
    }
  };

  // 根据 certType 决定展示哪些公开字段列
  const metaColumns = useMemo(() => {
    if (certType === 'login') return [
      { title: '网站', key: 'site', ellipsis: true, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.site || '-' },
      { title: '用户名', key: 'username', width: 140, ellipsis: true, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.username || '-' },
    ];
    if (certType === 'note') return [
      { title: '标题', key: 'title', ellipsis: true, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.title || '-' },
    ];
    if (certType === 'payment') return [
      { title: '持卡人', key: 'cardholder', width: 120, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.cardholder || '-' },
      { title: '银行', key: 'bank', width: 100, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.bank || '-' },
      { title: '尾号', key: 'last4', width: 80, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.last4 || '-' },
    ];
    if (certType === 'text') return [
      { title: '标签', key: 'label', ellipsis: true, render: (_: unknown, row: Certificate) => parseMeta(row.cert_content as any)?.label || '-' },
    ];
    return [];
  }, [certType]);

  const columns = [
    { title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 400, ellipsis: true },
    ...metaColumns,
    { title: t('credentials.common.remark'), dataIndex: 'remark', key: 'remark', ellipsis: true },
    { title: t('credentials.common.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 300 },
    {
      title: t('credentials.common.actions'),
      key: 'actions',
      width: 160,
      render: (_: unknown, row: Certificate) => (
        <Space size="small">
          <Button size="small" icon={<EyeOutlined />} onClick={() => handleView(row)}>
            查看
          </Button>
          <Popconfirm
            title={t('credentials.common.deleteConfirm')}
            onConfirm={async () => {
              try {
                await deleteCert(cardUUID, row.uuid);
                message.success('OK');
                onChanged();
              } catch (e: any) {
                message.error(e?.message || 'failed');
              }
            }}
          >
            <Button danger size="small" icon={<DeleteOutlined />}>
              {t('credentials.common.delete')}
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <Table
        rowKey="uuid"
        size="small"
        pagination={{ pageSize: 10 }}
        dataSource={data}
        columns={columns as any}
      />

      {/* 查看凭据弹窗 */}
      <Modal
        title="查看凭据内容"
        open={viewModal.open}
        onCancel={() => { setViewModal({ open: false, cert: null }); setSecretContent(null); setPinInput(''); }}
        footer={null}
        width={480}
        destroyOnHidden
      >
        {/* 公开信息区域（无需密码） */}
        {viewModal.cert && (() => {
          const meta = parseMeta(viewModal.cert.cert_content as any);
          const metaItems = Object.entries(meta).filter(([, v]) => v);
          if (metaItems.length === 0) return null;
          return (
            <div style={{ marginBottom: 16, padding: '12px 16px', background: '#f5f5f5', borderRadius: 6 }}>
              <div style={{ fontWeight: 600, marginBottom: 8, color: '#666' }}>公开信息</div>
              {metaItems.map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
                  <Text type="secondary" style={{ minWidth: 60 }}>{k}：</Text>
                  <Text copyable>{v}</Text>
                </div>
              ))}
            </div>
          );
        })()}
        {!secretContent ? (
          <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
            <Alert type="warning" showIcon title="需要输入卡片密码才能查看私密内容" />
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="请输入卡片密码"
              value={pinInput}
              onChange={(e) => setPinInput(e.target.value)}
              onPressEnter={handleDecrypt}
              autoComplete="current-password"
            />
            <Button type="primary" loading={viewLoading} onClick={handleDecrypt} block>
              解密查看
            </Button>
          </Space>
        ) : (
          <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
            {renderSecretContent(certType, secretContent)}
            <Button onClick={() => setSecretContent(null)} block>重新输入密码</Button>
          </Space>
        )}
      </Modal>
    </>
  );
};

/* ---------- 各 Tab 表单：复用 createCredential ---------- */

const LoginForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  // 优先使用表单内输入的密码，其次使用外部传入的密码
  return (
    <Form form={form} layout="vertical" initialValues={{ _card_password: cardPassword }} onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      const pwd = v._card_password || cardPassword;
      if (!pwd) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ site: v.site, username: v.username, url: v.url });
        const secret = JSON.stringify({ password: v.password });
        const payload: CredentialPayload = {
          cert_type: 'login',
          key_type: 'login-v1',
          public_meta: toB64(meta),
          secret_data: toB64(secret),
          card_password: pwd,
          remark: v.remark,
        };
        await createCredential(cardUUID, payload);
        message.success(t('credentials.common.createSuccess'));
        form.resetFields();
        onCreated();
      } catch (e: any) {
        message.error(e?.response?.data?.message || e?.message || t('credentials.common.createFailed'));
      } finally {
        setLoading(false);
      }
    }}>
      <Alert type="info" showIcon title={t('credentials.login.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="site" label={t('credentials.login.site')} rules={[{ required: true }]}>
        <Input placeholder={t('credentials.login.sitePh')} />
      </Form.Item>
      <Form.Item name="username" label={t('credentials.login.username')} rules={[{ required: true }]}>
        <Input prefix={<UserOutlined />} />
      </Form.Item>
      <Form.Item name="password" label={t('credentials.login.password')} rules={[{ required: true }]}>
        <Input.Password autoComplete="new-password" />
      </Form.Item>
      <Form.Item name="url" label={t('credentials.login.url')}>
        <Input />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
      </Form.Item>
      <Form.Item name="_card_password" label={t('credentials.common.cardPassword')} rules={[{ required: true, message: '请输入卡片密码' }]}>
        <Input.Password prefix={<LockOutlined />} placeholder={t('credentials.common.cardPassword')} autoComplete="current-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>{t('credentials.common.create')}</Button>
    </Form>
  );
};

const NoteForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  return (
    <Form form={form} layout="vertical" initialValues={{ _card_password: cardPassword }} onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      const pwd = v._card_password || cardPassword;
      if (!pwd) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ title: v.title });
        const secret = JSON.stringify({ title: v.title, content: v.content });
        await createCredential(cardUUID, {
          cert_type: 'note', key_type: 'note-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: pwd, remark: v.remark,
        });
        message.success(t('credentials.common.createSuccess'));
        form.resetFields();
        onCreated();
      } catch (e: any) {
        message.error(e?.response?.data?.message || e?.message || t('credentials.common.createFailed'));
      } finally {
        setLoading(false);
      }
    }}>
      <Alert type="info" showIcon title={t('credentials.note.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="title" label={t('credentials.note.noteTitle')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="content" label={t('credentials.note.content')} rules={[{ required: true }]}>
        <Input.TextArea rows={6} />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
      </Form.Item>
      <Form.Item name="_card_password" label={t('credentials.common.cardPassword')} rules={[{ required: true, message: '请输入卡片密码' }]}>
        <Input.Password prefix={<LockOutlined />} placeholder={t('credentials.common.cardPassword')} autoComplete="current-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>{t('credentials.common.create')}</Button>
    </Form>
  );
};

const PaymentForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  return (
    <Form form={form} layout="vertical" initialValues={{ _card_password: cardPassword }} onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      const pwd = v._card_password || cardPassword;
      if (!pwd) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ cardholder: v.cardholder, bank: v.bank, last4: (v.card_number || '').slice(-4) });
        const secret = JSON.stringify({ card_number: v.card_number, expiry: v.expiry, cvv: v.cvv });
        await createCredential(cardUUID, {
          cert_type: 'payment', key_type: 'card-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: pwd, remark: v.remark,
        });
        message.success(t('credentials.common.createSuccess'));
        form.resetFields();
        onCreated();
      } catch (e: any) {
        message.error(e?.response?.data?.message || e?.message || t('credentials.common.createFailed'));
      } finally {
        setLoading(false);
      }
    }}>
      <Alert type="info" showIcon title={t('credentials.payment.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="cardholder" label={t('credentials.payment.cardholder')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="card_number" label={t('credentials.payment.cardNumber')} rules={[{ required: true }]}>
        <Input prefix={<CreditCardOutlined />} maxLength={19} />
      </Form.Item>
      <Space>
        <Form.Item name="expiry" label={t('credentials.payment.expiry')} rules={[{ required: true }]}>
          <Input placeholder="MM/YY" maxLength={5} />
        </Form.Item>
        <Form.Item name="cvv" label={t('credentials.payment.cvv')} rules={[{ required: true }]}>
          <Input.Password maxLength={4} autoComplete="new-password" />
        </Form.Item>
      </Space>
      <Form.Item name="bank" label={t('credentials.payment.bank')}>
        <Input />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
      </Form.Item>
      <Form.Item name="_card_password" label={t('credentials.common.cardPassword')} rules={[{ required: true, message: '请输入卡片密码' }]}>
        <Input.Password prefix={<LockOutlined />} placeholder={t('credentials.common.cardPassword')} autoComplete="current-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>{t('credentials.common.create')}</Button>
    </Form>
  );
};

const TextForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  return (
    <Form form={form} layout="vertical" initialValues={{ _card_password: cardPassword }} onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      const pwd = v._card_password || cardPassword;
      if (!pwd) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ label: v.label });
        const secret = JSON.stringify({ label: v.label, secret: v.secret });
        await createCredential(cardUUID, {
          cert_type: 'text', key_type: 'text-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: pwd, remark: v.remark,
        });
        message.success(t('credentials.common.createSuccess'));
        form.resetFields();
        onCreated();
      } catch (e: any) {
        message.error(e?.response?.data?.message || e?.message || t('credentials.common.createFailed'));
      } finally {
        setLoading(false);
      }
    }}>
      <Alert type="info" showIcon title={t('credentials.text.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="label" label={t('credentials.text.label')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="secret" label={t('credentials.text.secret')} rules={[{ required: true }]}>
        <Input.TextArea rows={4} />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
      </Form.Item>
      <Form.Item name="_card_password" label={t('credentials.common.cardPassword')} rules={[{ required: true, message: '请输入卡片密码' }]}>
        <Input.Password prefix={<LockOutlined />} placeholder={t('credentials.common.cardPassword')} autoComplete="current-password" />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>{t('credentials.common.create')}</Button>
    </Form>
  );
};

/* ---------- 主页面 ---------- */
const CredentialsPage: React.FC = () => {
  const { t } = useTranslation();
  const [cards, setCards] = useState<Card[]>([]);
  const [cardUUID, setCardUUID] = useState<string>('');
  const [cardPassword, setCardPassword] = useState<string>('');
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<CredType>('login');

  const loadCards = async () => {
    try {
      const data = await getCards();
      const list = Array.isArray(data) ? data : (data as any)?.items || [];
      // 仅本地卡片且启用了安全凭据功能的卡片
      const local = list.filter((c: Card) => c.slot_type === 'local' && c.credential_enabled);
      setCards(local);
      if (local.length > 0 && !cardUUID) setCardUUID(local[0].uuid);
    } catch {
      setCards([]);
    }
  };

  const loadCerts = async () => {
    if (!cardUUID) { setCerts([]); return; }
    setLoading(true);
    try {
      const list = await getCerts(cardUUID);
      setCerts(list);
    } catch {
      setCerts([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadCards(); }, []);
  useEffect(() => { loadCerts(); }, [cardUUID]);

  const renderTabContent = (kind: CredType) => (
    <ACard size="small" loading={loading}>
      <CredentialList certs={certs} cardUUID={cardUUID} certType={kind} onChanged={loadCerts} />
    </ACard>
  );

  return (
    <div>
      <PageHeader
        icon={<LockOutlined />}
        title={t('credentials.title')}
        tags={
          <Space size={8}>
            <Tag color="blue">本地加密存储</Tag>
            <Select
              size="small"
              style={{ width: 260 }}
              placeholder={t('credentials.common.selectCard')}
              value={cardUUID || undefined}
              onChange={setCardUUID}
              options={cards.map((c) => ({ label: c.card_name, value: c.uuid }))}
            />
          </Space>
        }
        extra={
          <Space size={8}>
            <Input.Password
              prefix={<LockOutlined />}
              placeholder={t('credentials.common.cardPassword')}
              size="small"
              style={{ width: 200 }}
              value={cardPassword}
              onChange={(e) => setCardPassword(e.target.value)}
              autoComplete="new-password"
            />
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateModalOpen(true)} size="small">
              {t('credentials.common.create')}
            </Button>
          </Space>
        }
      />

      <Tabs
        activeKey={activeTab}
        onChange={(k) => setActiveTab(k as CredType)}
        items={[
          { key: 'login', label: <span><UserOutlined /> {t('credentials.tabs.login')}</span>, children: renderTabContent('login') },
          { key: 'note', label: <span><FileTextOutlined /> {t('credentials.tabs.note')}</span>, children: renderTabContent('note') },
          { key: 'payment', label: <span><CreditCardOutlined /> {t('credentials.tabs.payment')}</span>, children: renderTabContent('payment') },
          { key: 'text', label: <span><FileTextOutlined /> {t('credentials.tabs.text')}</span>, children: renderTabContent('text') },
        ]}
      />

      {/* 创建凭据模态框 */}
      <Modal
        title={t('credentials.common.create')}
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        footer={null}
        width={560}
        destroyOnHidden
      >
        {activeTab === 'login' && <LoginForm cardUUID={cardUUID} cardPassword={cardPassword} onCreated={() => { loadCerts(); setCreateModalOpen(false); }} />}
        {activeTab === 'note' && <NoteForm cardUUID={cardUUID} cardPassword={cardPassword} onCreated={() => { loadCerts(); setCreateModalOpen(false); }} />}
        {activeTab === 'payment' && <PaymentForm cardUUID={cardUUID} cardPassword={cardPassword} onCreated={() => { loadCerts(); setCreateModalOpen(false); }} />}
        {activeTab === 'text' && <TextForm cardUUID={cardUUID} cardPassword={cardPassword} onCreated={() => { loadCerts(); setCreateModalOpen(false); }} />}
      </Modal>
    </div>
  );
};

export default CredentialsPage;
