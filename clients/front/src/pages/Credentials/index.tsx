import React, { useEffect, useMemo, useState } from 'react';
import {
  Card as ACard, Tabs, Select, Form, Input, Button, Table, Tag, Popconfirm,
  message, Space, Typography, Alert, Modal,
} from 'antd';
import {
  KeyOutlined, UserOutlined, FileTextOutlined, CreditCardOutlined,
  LockOutlined, DeleteOutlined, PlusOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import PageHeader from '../../components/PageHeader';
import {
  getCards, getCerts, deleteCert, createCredential, type CredentialPayload,
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
const CardPicker: React.FC<{
  cards: Card[];
  cardUUID: string;
  onCardChange: (uuid: string) => void;
  cardPassword: string;
  onPasswordChange: (v: string) => void;
}> = ({ cards, cardUUID, onCardChange, cardPassword, onPasswordChange }) => {
  const { t } = useTranslation();
  return (
    <Space wrap style={{ marginBottom: 16 }}>
      <span>{t('credentials.common.card')}:</span>
      <Select
        style={{ width: 260 }}
        placeholder={t('credentials.common.selectCard')}
        value={cardUUID || undefined}
        onChange={onCardChange}
        options={cards.map((c) => ({ label: c.card_name, value: c.uuid }))}
      />
      <Input.Password
        prefix={<LockOutlined />}
        placeholder={t('credentials.common.cardPassword')}
        style={{ width: 220 }}
        value={cardPassword}
        onChange={(e) => onPasswordChange(e.target.value)}
        autoComplete="new-password"
      />
    </Space>
  );
};

/**
 * 通用列表 + 删除：5 类凭据共用，按 cert_type 过滤。
 */
const CredentialList: React.FC<{
  certs: Certificate[];
  cardUUID: string;
  certType: CredType;
  onChanged: () => void;
}> = ({ certs, cardUUID, certType, onChanged }) => {
  const { t } = useTranslation();
  const data = useMemo(
    () => certs.filter((c) => c.cert_type === certType),
    [certs, certType],
  );

  const columns = [
    { title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 280, ellipsis: true },
    { title: t('credentials.common.type'), dataIndex: 'key_type', key: 'key_type', width: 140 },
    { title: t('credentials.common.remark'), dataIndex: 'remark', key: 'remark' },
    { title: t('credentials.common.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 200 },
    {
      title: t('credentials.common.actions'),
      key: 'actions',
      width: 120,
      render: (_: unknown, row: Certificate) => (
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
      ),
    },
  ];

  return (
    <Table
      rowKey="uuid"
      size="small"
      pagination={{ pageSize: 10 }}
      dataSource={data}
      columns={columns as any}
    />
  );
};

/* ---------- 各 Tab 表单：复用 createCredential ---------- */

const LoginForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  return (
    <Form form={form} layout="vertical" onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      if (!cardPassword) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ site: v.site, username: v.username, url: v.url });
        const secret = JSON.stringify({ password: v.password });
        const payload: CredentialPayload = {
          cert_type: 'login',
          key_type: 'login-v1',
          public_meta: toB64(meta),
          secret_data: toB64(secret),
          card_password: cardPassword,
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
      <Alert type="info" showIcon message={t('credentials.login.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="site" label={t('credentials.login.site')} rules={[{ required: true }]}>
        <Input placeholder={t('credentials.login.sitePh')} />
      </Form.Item>
      <Form.Item name="username" label={t('credentials.login.username')} rules={[{ required: true }]}>
        <Input prefix={<UserOutlined />} />
      </Form.Item>
      <Form.Item name="password" label={t('credentials.login.password')} rules={[{ required: true }]}>
        <Input.Password />
      </Form.Item>
      <Form.Item name="url" label={t('credentials.login.url')}>
        <Input />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
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
    <Form form={form} layout="vertical" onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      if (!cardPassword) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ title: v.title });
        const secret = JSON.stringify({ title: v.title, content: v.content });
        await createCredential(cardUUID, {
          cert_type: 'note', key_type: 'note-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: cardPassword, remark: v.remark,
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
      <Alert type="info" showIcon message={t('credentials.note.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="title" label={t('credentials.note.noteTitle')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="content" label={t('credentials.note.content')} rules={[{ required: true }]}>
        <Input.TextArea rows={6} />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
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
    <Form form={form} layout="vertical" onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      if (!cardPassword) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ cardholder: v.cardholder, bank: v.bank, last4: (v.card_number || '').slice(-4) });
        const secret = JSON.stringify({ card_number: v.card_number, expiry: v.expiry, cvv: v.cvv });
        await createCredential(cardUUID, {
          cert_type: 'payment', key_type: 'card-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: cardPassword, remark: v.remark,
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
      <Alert type="info" showIcon message={t('credentials.payment.tip')} style={{ marginBottom: 12 }} />
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
          <Input.Password maxLength={4} />
        </Form.Item>
      </Space>
      <Form.Item name="bank" label={t('credentials.payment.bank')}>
        <Input />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
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
    <Form form={form} layout="vertical" onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      if (!cardPassword) { message.warning(t('credentials.common.cardPassword')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ label: v.label });
        const secret = JSON.stringify({ label: v.label, secret: v.secret });
        await createCredential(cardUUID, {
          cert_type: 'text', key_type: 'text-v1',
          public_meta: toB64(meta), secret_data: toB64(secret),
          card_password: cardPassword, remark: v.remark,
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
      <Alert type="info" showIcon message={t('credentials.text.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="label" label={t('credentials.text.label')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="secret" label={t('credentials.text.secret')} rules={[{ required: true }]}>
        <Input.TextArea rows={4} />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
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
      // 仅本地卡片支持安全凭据
      const local = list.filter((c: Card) => c.slot_type === 'local');
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

  const renderTabContent = (kind: CredType, FormComp: React.FC<any>) => (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { setActiveTab(kind); setCreateModalOpen(true); }}>
          {t('credentials.common.create')}
        </Button>
      </div>
      <ACard size="small" loading={loading}>
        <CredentialList certs={certs} cardUUID={cardUUID} certType={kind} onChanged={loadCerts} />
      </ACard>
    </Space>
  );

  return (
    <div>
      <PageHeader
        icon={<LockOutlined />}
        title={t('credentials.title')}
        tags={<Tag color="blue">本地加密存储</Tag>}
      />

      <CardPicker
        cards={cards}
        cardUUID={cardUUID}
        onCardChange={setCardUUID}
        cardPassword={cardPassword}
        onPasswordChange={setCardPassword}
      />

      <Tabs
        items={[
          { key: 'login', label: <span><UserOutlined /> {t('credentials.tabs.login')}</span>, children: renderTabContent('login', LoginForm) },
          { key: 'note', label: <span><FileTextOutlined /> {t('credentials.tabs.note')}</span>, children: renderTabContent('note', NoteForm) },
          { key: 'payment', label: <span><CreditCardOutlined /> {t('credentials.tabs.payment')}</span>, children: renderTabContent('payment', PaymentForm) },
          { key: 'text', label: <span><FileTextOutlined /> {t('credentials.tabs.text')}</span>, children: renderTabContent('text', TextForm) },
        ]}
      />

      {/* 创建凭据模态框 */}
      <Modal
        title={t('credentials.common.create')}
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        footer={null}
        width={560}
        destroyOnClose
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
