import React, { useEffect, useMemo, useState } from 'react';
import {
  Card as ACard, Select, Form, Input, Button, Table, Popconfirm,
  message, Space, Typography, Alert, Modal, Tag, Tooltip,
} from 'antd';
import {
  KeyOutlined, LockOutlined, DeleteOutlined, PlusOutlined, ReloadOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import PageHeader from '../../components/PageHeader';
import {
  getCards, getCerts, deleteCert, createCredential, type CredentialPayload,
} from '../../api';
import type { Card, Certificate } from '../../types';

const { Text } = Typography;

const toB64 = (s: string): string => btoa(unescape(encodeURIComponent(s)));

/** 生成随机 base64url 字符串（n 字节） */
const randomBase64url = (n: number): string => {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/** 生成 UUID v4 */
const randomUUID = (): string => crypto.randomUUID();

const FidoPage: React.FC = () => {
  const { t } = useTranslation();
  const [cards, setCards] = useState<Card[]>([]);
  const [cardUUID, setCardUUID] = useState<string>('');
  const [cardPassword, setCardPassword] = useState<string>('');
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);

  const loadCards = async () => {
    try {
      const data = await getCards();
      const list = Array.isArray(data) ? data : (data as any)?.items || [];
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

  const fidoData = useMemo(
    () => certs.filter((c) => c.cert_type === 'fido'),
    [certs],
  );

  const columns = [
    { title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 280, ellipsis: true },
    { title: t('credentials.common.type'), dataIndex: 'key_type', key: 'key_type', width: 140 },
    { title: t('credentials.common.remark'), dataIndex: 'remark', key: 'remark' },
{ title: t('credentials.common.createdAt'), dataIndex: 'created_at', key: 'created_at', width: 300 },
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
              loadCerts();
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
    <div>
      <PageHeader
        icon={<KeyOutlined />}
        title={t('credentials.fido-umdf.pageTitle')}
        tags={
          <Space size={8}>
            <Tag color="green">FIDO2/WebAuthn</Tag>
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

      {/* 列表 */}
      <ACard size="small" loading={loading}>
        <Table
          rowKey="uuid"
          size="small"
          pagination={{ pageSize: 10 }}
          dataSource={fidoData}
          columns={columns as any}
        />
      </ACard>

      {/* 新增模态框 */}
      <Modal
        title={t('credentials.fido-umdf.pageTitle')}
        open={createModalOpen}
        onCancel={() => setCreateModalOpen(false)}
        footer={null}
        width={560}
        destroyOnHidden
      >
        <FidoForm
          cardUUID={cardUUID}
          cardPassword={cardPassword}
          onCreated={() => { loadCerts(); setCreateModalOpen(false); }}
        />
      </Modal>
    </div>
  );
};

/* FIDO 新增表单 */
const FidoForm: React.FC<{ cardUUID: string; cardPassword: string; onCreated: () => void }> = ({ cardUUID, cardPassword, onCreated }) => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  return (
    <Form form={form} layout="vertical" onFinish={async (v) => {
      if (!cardUUID) { message.warning(t('credentials.common.noCard')); return; }
      setLoading(true);
      try {
        const meta = JSON.stringify({ rp_id: v.rp_id, user_name: v.user_name, user_handle: v.user_handle, credential_id: v.credential_id });
        const secret = v.private_key_pem ? v.private_key_pem : '';
        const payload: CredentialPayload = {
          cert_type: 'fido',
          key_type: 'fido2',
          public_meta: toB64(meta),
          secret_data: secret ? toB64(secret) : undefined,
          card_password: secret ? cardPassword : undefined,
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
<Alert type="info" showIcon title={t('credentials.fido-umdf.tip')} style={{ marginBottom: 12 }} />
      <Form.Item name="rp_id" label={t('credentials.fido-umdf.rpId')} rules={[{ required: true }]}>
        <Input placeholder={t('credentials.fido-umdf.rpIdPh')} />
      </Form.Item>
      <Form.Item name="user_name" label={t('credentials.fido-umdf.userName')} rules={[{ required: true }]}>
        <Input />
      </Form.Item>
      <Form.Item name="user_handle" label={t('credentials.fido-umdf.userHandle')}>
        <Space.Compact style={{ width: '100%' }}>
          <Form.Item name="user_handle" noStyle>
            <Input placeholder="留空则随机生成" />
          </Form.Item>
          <Tooltip title="随机生成 User Handle">
            <Button
              icon={<ReloadOutlined />}
              onClick={() => form.setFieldValue('user_handle', randomBase64url(16))}
            />
          </Tooltip>
        </Space.Compact>
      </Form.Item>
      <Form.Item name="credential_id" label={t('credentials.fido-umdf.credentialId')} rules={[{ required: true }]}>
        <Space.Compact style={{ width: '100%' }}>
          <Form.Item name="credential_id" noStyle>
            <Input placeholder="Credential ID" />
          </Form.Item>
          <Tooltip title="随机生成 Credential ID">
            <Button
              icon={<ReloadOutlined />}
              onClick={() => form.setFieldValue('credential_id', randomUUID())}
            />
          </Tooltip>
        </Space.Compact>
      </Form.Item>
      <Form.Item name="private_key_pem" label={t('credentials.fido-umdf.privateKeyPem')}>
        <Input.TextArea rows={4} placeholder="-----BEGIN PRIVATE KEY-----..." />
      </Form.Item>
      <Form.Item name="remark" label={t('credentials.common.remark')}>
        <Input />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={loading}>{t('credentials.common.create')}</Button>
    </Form>
  );
};

export default FidoPage;
