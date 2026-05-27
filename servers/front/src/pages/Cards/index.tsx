import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, InputNumber,
  message, Popconfirm, Drawer, Descriptions, Select, Tabs, Alert,
} from 'antd';
import {
  CreditCardOutlined, PlusOutlined, DeleteOutlined, LockOutlined, UnlockOutlined,
  SafetyOutlined, ReloadOutlined, KeyOutlined,
} from '@ant-design/icons';
import {
  listCards, createCard, deleteCard, getCard, listCardCerts,
  verifyCardPIN, logoutCardPINSession, unlockCardWithPUK, resetCardWithAdminKey,
  listStorageZones,
} from '../../api';
import type { Card as CardModel, Certificate, StorageZone } from '../../types';

const { Title, Text } = Typography;

/**
 * Cards 页面：云端智能卡管理。
 * - 列表 + 新建 + 删除
 * - 详情抽屉：展示卡片信息、证书列表、PIN/PUK/AdminKey 操作
 */
const CardsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [cards, setCards] = useState<CardModel[]>([]);
  const [zones, setZones] = useState<StorageZone[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [currentCard, setCurrentCard] = useState<CardModel | null>(null);
  const [cardCerts, setCardCerts] = useState<Certificate[]>([]);

  // PIN/PUK/Admin 弹窗
  const [pinOpen, setPinOpen] = useState(false);
  const [pukOpen, setPukOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [pinSession, setPinSession] = useState<string>('');

  const fetchCards = async () => {
    setLoading(true);
    try {
      const data = await listCards();
      setCards(data);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  const fetchZones = async () => {
    try {
      const data = await listStorageZones();
      setZones(Array.isArray(data) ? data : (data as any)?.items || []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetchCards(); fetchZones(); }, []);

  const openDetail = async (c: CardModel) => {
    setCurrentCard(c);
    setDrawerOpen(true);
    setPinSession('');
    try {
      const [card, certs] = await Promise.all([getCard(c.uuid), listCardCerts(c.uuid)]);
      setCurrentCard(card);
      setCardCerts(certs);
    } catch (e: any) {
      message.error(e.message || '加载详情失败');
    }
  };

  const handleCreate = async (values: any) => {
    try {
      await createCard({
        card_name: values.card_name,
        remark: values.remark,
        storage_zone_uuid: values.storage_zone_uuid,
        pin: values.pin,
        puk: values.puk,
        admin_key: values.admin_key,
        pin_retries: values.pin_retries || 3,
      });
      message.success('智能卡创建成功');
      setCreateOpen(false);
      form.resetFields();
      fetchCards();
    } catch (e: any) {
      message.error(e.message || '创建失败');
    }
  };

  const handleDelete = async (uuid: string) => {
    try {
      await deleteCard(uuid);
      message.success('已删除');
      fetchCards();
    } catch (e: any) {
      message.error(e.message || '删除失败');
    }
  };

  const columns = useMemo(() => [
    { title: '卡片名称', dataIndex: 'card_name', key: 'card_name',
      render: (v: string) => <Space><CreditCardOutlined />{v}</Space> },
    { title: '备注', dataIndex: 'remark', key: 'remark', ellipsis: true },
    { title: '存储区域', dataIndex: 'storage_zone_uuid', key: 'storage_zone_uuid',
      render: (v: string) => zones.find((z) => z.uuid === v)?.name || <Text type="secondary">-</Text> },
    { title: 'PIN 状态', key: 'pin_status',
      render: (_: any, r: CardModel) => r.pin_locked
        ? <Tag icon={<LockOutlined />} color="error">已锁定</Tag>
        : <Tag icon={<UnlockOutlined />} color="success">正常（{r.pin_failed_count}/{r.pin_retries}）</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 260,
      render: (_: any, r: CardModel) => (
        <Space>
          <Button type="link" onClick={() => openDetail(r)}>详情</Button>
          <Popconfirm title="确认删除此卡片？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], [zones]);

  return (
    <div>
      <Card
        title={<Space><CreditCardOutlined /><Title level={4} style={{ margin: 0 }}>个人业务</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchCards}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
              新建智能卡
            </Button>
          </Space>
        }
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="云端智能卡支持 PIN/PUK/Admin Key 三级密钥保护；PIN 错误超过限制后会被锁定，使用 PUK 解锁，Admin Key 可重置 PIN/PUK。"
        />
        <Table rowKey="uuid" loading={loading} dataSource={cards} columns={columns as any} />
      </Card>

      {/* 新建卡片 */}
      <Modal
        open={createOpen} title="新建智能卡"
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}>
          <Form.Item name="card_name" label="卡片名称" rules={[{ required: true, message: '请输入卡片名称' }]}>
            <Input placeholder="例如：服务器证书卡" maxLength={64} />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input.TextArea rows={2} maxLength={200} />
          </Form.Item>
          <Form.Item name="storage_zone_uuid" label="存储区域">
            <Select allowClear placeholder="选择存储区域（可选）"
              options={zones.map((z) => ({ label: z.name, value: z.uuid }))} />
          </Form.Item>
          <Form.Item name="pin" label="PIN 码" rules={[{ min: 4, max: 32 }]}>
            <Input.Password placeholder="4-32 位字符；签名/解密/导入证书时需要" />
          </Form.Item>
          <Form.Item name="puk" label="PUK 码" rules={[{ min: 8, max: 32 }]}>
            <Input.Password placeholder="8-32 位字符；PIN 锁定后用于解锁" />
          </Form.Item>
          <Form.Item name="admin_key" label="Admin Key" rules={[{ min: 16, max: 64 }]}>
            <Input.Password placeholder="16-64 位字符；可重置 PIN 和 PUK" />
          </Form.Item>
          <Form.Item name="pin_retries" label="PIN 错误重试次数" initialValue={3}>
            <InputNumber min={1} max={10} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 详情抽屉 */}
      <Drawer
        width={720} open={drawerOpen} onClose={() => setDrawerOpen(false)}
        title={currentCard ? `卡片详情：${currentCard.card_name}` : '卡片详情'}
      >
        {currentCard && (
          <>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="UUID">{currentCard.uuid}</Descriptions.Item>
              <Descriptions.Item label="卡片名称">{currentCard.card_name}</Descriptions.Item>
              <Descriptions.Item label="备注">{currentCard.remark || '-'}</Descriptions.Item>
              <Descriptions.Item label="存储区域">
                {zones.find((z) => z.uuid === currentCard.storage_zone_uuid)?.name || '默认'}
              </Descriptions.Item>
              <Descriptions.Item label="PIN 状态">
                {currentCard.pin_locked
                  ? <Tag color="error" icon={<LockOutlined />}>已锁定</Tag>
                  : <Tag color="success" icon={<UnlockOutlined />}>
                      正常（已连续失败 {currentCard.pin_failed_count}/{currentCard.pin_retries}）
                    </Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {new Date(currentCard.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
              {pinSession && (
                <Descriptions.Item label="PIN 会话">
                  <Tag color="processing">已验证</Tag>
                  <Button type="link" size="small" onClick={async () => {
                    try { await logoutCardPINSession(currentCard.uuid); setPinSession(''); message.success('已登出 PIN 会话'); }
                    catch (e: any) { message.error(e.message); }
                  }}>登出</Button>
                </Descriptions.Item>
              )}
            </Descriptions>

            <Space style={{ marginTop: 16 }} wrap>
              <Button icon={<SafetyOutlined />} onClick={() => setPinOpen(true)}>验证 PIN</Button>
              <Button icon={<UnlockOutlined />} onClick={() => setPukOpen(true)}>PUK 解锁</Button>
              <Button icon={<KeyOutlined />} onClick={() => setAdminOpen(true)}>Admin Key 重置</Button>
            </Space>

            <Tabs
              style={{ marginTop: 16 }}
              items={[
                {
                  key: 'certs', label: `卡内证书（${cardCerts.length}）`,
                  children: (
                    <Table
                      size="small" rowKey="uuid" dataSource={cardCerts}
                      columns={[
                        { title: 'UUID', dataIndex: 'uuid', key: 'uuid', ellipsis: true, width: 120 },
                        { title: '类型', dataIndex: 'cert_type', key: 'cert_type' },
                        { title: '密钥类型', dataIndex: 'key_type', key: 'key_type' },
                        { title: '备注', dataIndex: 'remark', key: 'remark' },
                        {
                          title: '状态', dataIndex: 'status', key: 'status',
                          render: (v: string) => <Tag>{v || '-'}</Tag>,
                        },
                      ] as any}
                    />
                  ),
                },
              ]}
            />
          </>
        )}
      </Drawer>

      {/* 验证 PIN */}
      <PINModal
        open={pinOpen}
        title="验证 PIN 码"
        fields={[{ name: 'pin', label: 'PIN 码', required: true }]}
        onCancel={() => setPinOpen(false)}
        onOk={async (v) => {
          if (!currentCard) return;
          try {
            const res = await verifyCardPIN(currentCard.uuid, { pin: v.pin });
            setPinSession(res.session_token);
            message.success(`PIN 验证成功，会话有效 ${res.expires_in} 秒`);
            setPinOpen(false);
            await openDetail(currentCard);
          } catch (e: any) { message.error(e.message || 'PIN 验证失败'); }
        }}
      />
      {/* PUK 解锁 */}
      <PINModal
        open={pukOpen}
        title="PUK 解锁并重置 PIN"
        fields={[
          { name: 'puk', label: 'PUK 码', required: true },
          { name: 'new_pin', label: '新 PIN 码', required: true },
        ]}
        onCancel={() => setPukOpen(false)}
        onOk={async (v) => {
          if (!currentCard) return;
          try {
            await unlockCardWithPUK(currentCard.uuid, { puk: v.puk, new_pin: v.new_pin });
            message.success('PUK 解锁成功，PIN 已重置');
            setPukOpen(false);
            await openDetail(currentCard);
          } catch (e: any) { message.error(e.message || 'PUK 解锁失败'); }
        }}
      />
      {/* Admin Key 重置 */}
      <PINModal
        open={adminOpen}
        title="Admin Key 重置 PIN/PUK"
        fields={[
          { name: 'admin_key', label: 'Admin Key', required: true },
          { name: 'new_pin', label: '新 PIN 码', required: false },
          { name: 'new_puk', label: '新 PUK 码', required: false },
        ]}
        onCancel={() => setAdminOpen(false)}
        onOk={async (v) => {
          if (!currentCard) return;
          try {
            await resetCardWithAdminKey(currentCard.uuid, {
              admin_key: v.admin_key, new_pin: v.new_pin, new_puk: v.new_puk,
            });
            message.success('Admin Key 重置成功');
            setAdminOpen(false);
            await openDetail(currentCard);
          } catch (e: any) { message.error(e.message || 'Admin Key 重置失败'); }
        }}
      />
    </div>
  );
};

interface PINField { name: string; label: string; required: boolean }

const PINModal: React.FC<{
  open: boolean; title: string; fields: PINField[];
  onOk: (values: any) => void; onCancel: () => void;
}> = ({ open, title, fields, onOk, onCancel }) => {
  const [f] = Form.useForm();
  return (
    <Modal open={open} title={title} onCancel={onCancel} onOk={() => f.submit()} destroyOnClose>
      <Form form={f} layout="vertical" onFinish={onOk}>
        {fields.map((fd) => (
          <Form.Item
            key={fd.name} name={fd.name} label={fd.label}
            rules={fd.required ? [{ required: true, message: `请输入${fd.label}` }] : []}
          >
            <Input.Password autoComplete="off" />
          </Form.Item>
        ))}
      </Form>
    </Modal>
  );
};

export default CardsPage;
