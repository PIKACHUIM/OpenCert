import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input,
  Select, Popconfirm, message, Tooltip, Card, Drawer, Descriptions,
  Empty, Radio, Alert, DatePicker, Switch, Checkbox,
} from 'antd';
import {
  PlusOutlined, DeleteOutlined, ReloadOutlined,
  KeyOutlined, SafetyCertificateOutlined, EyeOutlined, LockOutlined,
  ExportOutlined, ImportOutlined, CheckCircleOutlined, CloseCircleOutlined,
  UndoOutlined, CreditCardOutlined, EditOutlined, PoweroffOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import { getCards, createCard, deleteCard, getCerts, generateKey, deleteCert, getUsers, resetCardPIN, exportCardDownload, restoreCard, updateCard } from '../../api';
import type { Card as CardType, Certificate, User, CreateCardRequest } from '../../types';
import { useAppStore } from '../../store/appStore';
import { useAuthStore } from '../../store/auth';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

// 密钥类型选项
const KEY_TYPE_OPTIONS = [
  { value: 'ec256', label: 'EC P-256' },
  { value: 'ec384', label: 'EC P-384' },
  { value: 'ec521', label: 'EC P-521' },
  { value: 'rsa2048', label: 'RSA 2048' },
  { value: 'rsa4096', label: 'RSA 4096' },
];

// 安全等级颜色和标签
// 说明：当前实现里只有 slot_type=tpmsc 是真正的硬件保护（密钥落在 Windows TPM）；
// 本地卡的 medium 仅在导出私钥时增加 ADMINKEY 校验，加密强度与 low 一致；
// 本地卡的 high 暂未启用 TPM Provider，后端会拒绝创建。
const securityLevelConfig: Record<string, { color: string; label: string; desc: string }> = {
  high: { color: 'red', label: '高', desc: '硬件 TPM 保护，私钥永不可导出（仅 TPM 智能卡支持）' },
  medium: { color: 'orange', label: '中', desc: '软件加密 + ADMINKEY 校验，可导出私钥需 ADMINKEY' },
  low: { color: 'green', label: '低', desc: '仅 PIN/卡密码软件加密，可凭密码导出' },
};

// Slot 类型颜色
const slotColor = (t: string) =>
  t === 'cloud' ? 'purple' : t === 'tpm2' ? 'cyan' : t === 'tpmsc' ? 'magenta' : 'green';

// Slot 类型中文标签
const slotLabel = (t: string) => {
  switch (t) {
    case 'cloud': return '云端智能卡';
    case 'tpm2': return 'TPM2 硬件卡';
    case 'tpmsc': return 'TPM 智能卡';
    default: return '本地智能卡';
  }
};

const Cards: React.FC = () => {
  const { darkMode } = useAppStore();
  const accounts = useAuthStore((s) => s.accounts);
  const activeUUID = useAuthStore((s) => s.activeUUID);
  const activeAccount = accounts.find((a) => a.user_uuid === activeUUID) || null;
  const [cards, setCards] = useState<CardType[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [users, setUsers] = useState<User[]>([]);
  const [filterMode, setFilterMode] = useState<'active' | 'all'>('active');

  // PIN 重置弹窗
  const [pinResetOpen, setPinResetOpen] = useState(false);
  const [pinResetCard, setPinResetCard] = useState<CardType | null>(null);
  const [pinResetForm] = Form.useForm();
  const [pinResetting, setPinResetting] = useState(false);

  // 创建卡片后一次性显示 PUK/AdminKey
  const [credsModal, setCredsModal] = useState<{ puk: string; admin_key: string; pin: string; instance_id?: string; reader_name?: string; output?: string } | null>(null);

  // 导出卡片弹窗
  const [exportOpen, setExportOpen] = useState(false);
  const [exportCard, setExportCard] = useState<CardType | null>(null);
  const [exportForm] = Form.useForm();
  const [exporting, setExporting] = useState(false);

  // 恢复卡片弹窗
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [restoreForm] = Form.useForm();
  const [restoring, setRestoring] = useState(false);

  // 新建卡片弹窗
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm] = Form.useForm();
  const [creating, setCreating] = useState(false);
  const [createSlotType, setCreateSlotType] = useState<string>('local');

  // 证书抽屉
  const [certDrawerOpen, setCertDrawerOpen] = useState(false);
  const [selectedCard, setSelectedCard] = useState<CardType | null>(null);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [certsLoading, setCertsLoading] = useState(false);

  // 密钥生成弹窗
  const [keygenOpen, setKeygenOpen] = useState(false);
  const [keygenForm] = Form.useForm();
  const [keygening, setKeygening] = useState(false);

  // 删除卡片弹窗
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteCard2, setDeleteCard2] = useState<CardType | null>(null);
  const [deleteForm] = Form.useForm();
  const [deleting, setDeleting] = useState(false);

  // 修改卡片弹窗
  const [editOpen, setEditOpen] = useState(false);
  const [editCard, setEditCard] = useState<CardType | null>(null);
  const [editForm] = Form.useForm();
  const [editing, setEditing] = useState(false);

  const load = async (p = page) => {
    setLoading(true);
    try {
      const params: any = { page: p, page_size: 10 };
      if (filterMode === 'active' && activeAccount) {
        params.user_uuid = activeAccount.user_uuid;
      }
      const res = await getCards(params);
      const items = res?.items;
      setCards(Array.isArray(items) ? items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    try {
      const res = await getUsers({ page: 1, page_size: 100 });
      const items = res?.items;
      setUsers(Array.isArray(items) ? items : []);
    } catch {}
  };

  const loadCerts = async (cardUUID: string) => {
    setCertsLoading(true);
    try {
      const res = await getCerts(cardUUID);
      setCerts(Array.isArray(res) ? res : []);
    } catch (e: any) {
      message.error(e.message);
    } finally {
      setCertsLoading(false);
    }
  };

  useEffect(() => { load(); loadUsers(); }, [filterMode]);

  const handleCreate = async () => {
    try {
      const values = await createForm.validateFields();
      setCreating(true);
      const result: any = await createCard(values as CreateCardRequest);
      message.success('卡片已创建');
      setCreateOpen(false);
      createForm.resetFields();
      // 一次性显示自动生成的 PUK / AdminKey
      if (result?.puk || result?.admin_key) {
        setCredsModal({
          puk: result.puk || '',
          admin_key: result.admin_key || '',
          pin: result.pin || '',
          instance_id: result.instance_id || '',
          reader_name: result.reader_name || '',
          output: result.output || '',
        });
      }
      load();
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setCreating(false);
    }
  };

  // PIN 修改/重置
  const handlePinReset = async () => {
    if (!pinResetCard) return;
    try {
      const values = await pinResetForm.validateFields();
      setPinResetting(true);
      if (values.method === 'pin') {
        // 使用当前 PIN 修改 PIN（传 old_pin + new_pin）
        await resetCardPIN(pinResetCard.uuid, { old_pin: values.secret, new_pin: values.new_pin });
      } else if (values.method === 'puk') {
        await resetCardPIN(pinResetCard.uuid, { puk: values.secret, new_pin: values.new_pin });
      } else {
        await resetCardPIN(pinResetCard.uuid, { admin_key: values.secret, new_pin: values.new_pin });
      }
      message.success('PIN 已更新');
      setPinResetOpen(false);
      pinResetForm.resetFields();
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setPinResetting(false);
    }
  };

  // 备份卡片
  const handleExport = async () => {
    if (!exportCard || !activeAccount) return;
    try {
      const values = await exportForm.validateFields();
      setExporting(true);
      await exportCardDownload(exportCard.uuid, {
        user_uuid: activeAccount.user_uuid,
        user_password: values.user_password,
        password: values.password,
        admin_key: values.admin_key,
      });
      message.success('卡片备份成功');
      setExportOpen(false);
      exportForm.resetFields();
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setExporting(false);
    }
  };

  // 恢复卡片
  const handleRestore = async () => {
    if (!activeAccount) return;
    try {
      const values = await restoreForm.validateFields();
      setRestoring(true);
      // 读取文件并转 base64
      const file = values.ocs_file?.[0]?.originFileObj;
      if (!file) { message.error('请选择 .ocs 文件'); return; }
      const reader = new FileReader();
      reader.onload = async () => {
        try {
          const b64 = btoa(reader.result as string);
          await restoreCard({
            ocs_data: b64,
            password: values.password,
            user_uuid: activeAccount.user_uuid,
            user_password: values.user_password,
          });
          message.success('卡片恢复成功');
          setRestoreOpen(false);
          restoreForm.resetFields();
          load();
        } catch (e: any) {
          message.error(e.message || '恢复失败');
        } finally {
          setRestoring(false);
        }
      };
      reader.readAsBinaryString(file);
    } catch (e: any) {
      if (e.message) message.error(e.message);
      setRestoring(false);
    }
  };

  const handleDelete = async (uuid: string) => {
    if (!deleteCard2 || !activeAccount) return;
    try {
      const values = await deleteForm.validateFields();
      setDeleting(true);
      await deleteCard(uuid, {
        user_uuid: activeAccount.user_uuid,
        user_password: values.user_password,
      });
      message.success('卡片已删除');
      setDeleteOpen(false);
      deleteForm.resetFields();
      load();
    } catch (e: any) {
      message.error(e.message);
    } finally {
      setDeleting(false);
    }
  };

  const openCerts = (card: CardType) => {
    setSelectedCard(card);
    setCertDrawerOpen(true);
    loadCerts(card.uuid);
  };

  const handleKeygen = async () => {
    if (!selectedCard) return;
    try {
      const values = await keygenForm.validateFields();
      setKeygening(true);
      await generateKey(selectedCard.uuid, values);
      message.success('密钥对已生成');
      setKeygenOpen(false);
      keygenForm.resetFields();
      loadCerts(selectedCard.uuid);
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setKeygening(false);
    }
  };

  const handleDeleteCert = async (certUUID: string) => {
    if (!selectedCard) return;
    try {
      await deleteCert(selectedCard.uuid, certUUID);
      message.success('证书已删除');
      loadCerts(selectedCard.uuid);
    } catch (e: any) {
      message.error(e.message);
    }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const columns = [
    {
      title: '卡片信息',
      dataIndex: 'card_name',
      width: 220,
      render: (_: string, record: CardType) => {
        const isExpired = record.expires_at && dayjs(record.expires_at).isBefore(dayjs());
        const isDisabled = record.enabled === false;
        return (
          <div>
            <Space size={4}>
              <SafetyCertificateOutlined style={{ color: slotColor(record.slot_type) === 'purple' ? '#722ed1' : slotColor(record.slot_type) === 'cyan' ? '#13c2c2' : '#52c41a' }} />
              <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{record.card_name}</Text>
              {isDisabled ? (
                <Tag color="red" style={{ fontSize: 10 }}>已禁用</Tag>
              ) : isExpired ? (
                <Tag color="orange" style={{ fontSize: 10 }}>已过期</Tag>
              ) : (
                <Tag color="green" style={{ fontSize: 10 }}>已启用</Tag>
              )}
            </Space>
            <div style={{ marginTop: 2 }}>
              <Text copyable={{ text: record.uuid }} style={{ fontSize: 11, fontFamily: 'monospace', color: darkMode ? '#8b949e' : '#999' }}>
                UUID: {record.uuid}
              </Text>
            </div>
          </div>
        );
      },
    },
    {
      title: '安全等级',
      width: 60,
      render: (_: any, record: CardType) => {
        const cfg = securityLevelConfig[record.security_level] || securityLevelConfig.low;
        return (
<Space orientation="vertical" size={2}>
            <Tag color={slotColor(record.slot_type)}>{slotLabel(record.slot_type)}</Tag>
            <Tooltip title={cfg.desc}>
              <Tag color={cfg.color}>安全性: {cfg.label}</Tag>
            </Tooltip>
          </Space>
        );
      },
    },
    {
      title: '凭据状态',
      width:140,
      render: (_: any, record: CardType) => {
        const canExport = record.security_level !== 'high';
        const canRestore = record.slot_type === 'local';
        const user = users.find((u) => u.uuid === record.user_uuid);
        return (
          <Space size={[4, 4]} wrap>
            <Tooltip title="PIN 密钥"><Tag icon={<CheckCircleOutlined />} color="green" style={{ fontSize: 10 }}>PIN</Tag></Tooltip>
            <Tooltip title="PUK 密钥"><Tag icon={<CheckCircleOutlined />} color="green" style={{ fontSize: 10 }}>PUK</Tag></Tooltip>
            <Tooltip title={record.security_level === 'low' ? '有AdminKey' : '有AdminKey'}>
              <Tag icon={record.security_level === 'low' ? <CloseCircleOutlined /> : <CheckCircleOutlined />} color={record.security_level === 'low' ? 'default' : 'purple'} style={{ fontSize: 10 }}>ADK</Tag>
            </Tooltip>
            <Tooltip title={record.security_level === 'low' ? '无TPM保护' : 'TPM保护中'}>
              <Tag icon={record.security_level === 'low' ? <CloseCircleOutlined /> : <CheckCircleOutlined />} color={record.security_level === 'low' ? 'default' : 'purple'} style={{ fontSize: 10 }}>TPM</Tag>
            </Tooltip>
            <Tag color={canExport ? 'green' : 'default'} style={{ fontSize: 10 }}>
              {canExport ? '可导出' : '不可导出'}
            </Tag>
            <Tag color={canRestore ? 'blue' : 'default'} style={{ fontSize: 10 }}>
              {canRestore ? '可恢复' : '不可恢复'}
            </Tag>

          </Space>
        );
      },
    },
    {
      title: '有效期',
      width: 140,
      render: (_: any, record: CardType) => {
        const isExpired = record.expires_at && dayjs(record.expires_at).isBefore(dayjs());
        return (
          <div>
            <div>
              <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>
                创建日期: {dayjs(record.created_at).format('YYYY-MM-DD')}
              </Text>
            </div>
            <div>
              <Text style={{ fontSize: 12, color: isExpired ? '#ff4d4f' : (darkMode ? '#8b949e' : '#999') }}>
                过期时间: {record.expires_at ? `${dayjs(record.expires_at).format('YYYY-MM-DD')}` : '永不过期'}
              </Text>
              {isExpired && <Tag color="red" style={{ marginLeft: 4, fontSize: 10 }}>已过期</Tag>}
            </div>
          </div>
        );
      },
    },

    {
      title: '凭据统计',
      width: 40,
      render: (_: any, record: CardType) => {
        const stats = record.cert_stats;
        if (!stats || (stats.x509 === 0 && stats.fido === 0 && stats.totp === 0 && stats.creds === 0)) {
          return <Text type="secondary" style={{ fontSize: 12 }}>暂无凭据</Text>;
        }
        return (
          <Space size={4} wrap>
            {stats.x509 > 0 && <Tag color="blue">X509: {stats.x509}</Tag>}
            {stats.fido > 0 && <Tag color="green">FIDO: {stats.fido}</Tag>}
            {stats.totp > 0 && <Tag color="orange">TOTP: {stats.totp}</Tag>}
            {stats.creds > 0 && <Tag color="purple">凭据: {stats.creds}</Tag>}
          </Space>
        );
      },
    },
    {
      title: '凭据详情',
      width: 40,
      render: (_: any, record: CardType) => {
        const recordUser = users.find((u) => u.uuid === record.user_uuid);
        const hasCloud = record.cloud_url || record.cloud_card_uuid;
        const isCloudUser = recordUser?.user_type === 'cloud';
        return (
          <div>
            {recordUser && (
              <div>
                <Tag color={isCloudUser ? 'purple' : 'cyan'} style={{ fontSize: 10 }}>
                  {isCloudUser ? '☁️ 云端' : '🖥️ 本地'} {recordUser.display_name}
                </Tag>
              </div>
            )}
            {hasCloud && (
              <div style={{ marginTop: recordUser ? 4 : 0 }}>
                {record.cloud_url && (
                  <div>
                    <Text copyable={{ text: record.cloud_url }} style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#666' }}>
                      {record.cloud_url.length > 22 ? record.cloud_url.slice(0, 22) + '...' : record.cloud_url}
                    </Text>
                  </div>
              )}
              {record.cloud_card_uuid && (
                  <div style={{ marginTop: 2 }}>
                    <Text copyable={{ text: record.cloud_card_uuid }} style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>
                      {record.cloud_card_uuid.slice(0, 8)}...
                    </Text>
                  </div>
              )}
              </div>
            )}
          </div>
        );
      },
    },
    {
      title: '备注信息',
      dataIndex: 'remark',
      width: 120,
      render: (v: string) => (
        <div style={{ color: darkMode ? '#8b949e' : '#999', fontSize: 12, wordBreak: 'break-all', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
          {v || '-'}
        </div>
      ),
    },
    {
      title: '卡片操作',
      width: 240,
      render: (_: any, record: CardType) => (
        <Space size={4} wrap>
          <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => openCerts(record)}>
            详情
          </Button>
          <Button
            type="link" size="small" icon={<EditOutlined />}
            onClick={() => {
              setEditCard(record);
              editForm.setFieldsValue({
                remark: record.remark || '',
                expires_at: record.expires_at ? dayjs(record.expires_at) : null,
                never_expire: !record.expires_at,
                fido_enabled: !!record.fido_enabled,
                totp_enabled: !!record.totp_enabled,
                credential_enabled: !!record.credential_enabled,
                pin_timeout: record.pin_timeout ?? 900,
              });
              setEditOpen(true);
            }}
          >
            修改
          </Button>
          <Button
            type="link" size="small" icon={<KeyOutlined />}
            onClick={() => { setSelectedCard(record); setKeygenOpen(true); }}
          >
            密钥
          </Button>
          <Button
            type="link" size="small" icon={<PoweroffOutlined />}
            style={{ color: record.enabled === false ? '#52c41a' : '#fa8c16' }}
            onClick={async () => {
              try {
                const newEnabled = record.enabled === false;
                await updateCard(record.uuid, { enabled: newEnabled } as any);
                message.success(newEnabled ? '卡片已启用' : '卡片已禁用');
                load();
              } catch (e: any) { message.error(e.message); }
            }}
          >
            {record.enabled === false ? '启用' : '禁用'}
          </Button>
          <Button
            type="link" size="small" icon={<LockOutlined />}
            onClick={() => { setPinResetCard(record); setPinResetOpen(true); }}
          >
            密码
          </Button>
          <Button
            type="link" size="small" icon={<ExportOutlined />}
            disabled={record.security_level === 'high'}
            onClick={() => { setExportCard(record); setExportOpen(true); }}
          >
            备份
          </Button>
          <Button
            type="link" size="small" icon={<UndoOutlined />}
            onClick={() => { setSelectedCard(record); setRestoreOpen(true); }}
          >
            恢复
          </Button>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}
            onClick={() => { setDeleteCard2(record); setDeleteOpen(true); }}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ];

  const certColumns = [
    {
      title: '证书名称',
      dataIndex: 'common_name',
      width: 280,
      render: (v: string) => <Text style={{ fontSize: 12 }}>{v || '-'}</Text>,
    },
    {
      title: '类型',
      dataIndex: 'cert_type',
      width: 80,
      render: (v: string) => <Tag>{v || 'x509'}</Tag>,
    },
    {
      title: '备注',
      dataIndex: 'remark',
      render: (v: string) => <Text style={{ fontSize: 12 }}>{v || '-'}</Text>,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 150,
      render: (v: string) => (
        <Text style={{ fontSize: 12, color: '#999' }}>{dayjs(v).format('YY-MM-DD HH:mm')}</Text>
      ),
    },
    {
      title: '操作',
      width: 80,
      render: (_: any, record: Certificate) => (
        <Popconfirm
          title="确认删除此证书？"
          onConfirm={() => handleDeleteCert(record.uuid)}
          okText="删除" cancelText="取消" okButtonProps={{ danger: true }}
        >
          <Button type="text" size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={<CreditCardOutlined />}
        title="智能卡片管理"
        tags={
          <Radio.Group value={filterMode} onChange={(e) => { setFilterMode(e.target.value); setPage(1); }} size="small" buttonStyle="solid">
            <Radio.Button value="active">当前账号</Radio.Button>
            <Radio.Button value="all">全部已登录</Radio.Button>
          </Radio.Group>
        }
        extra={
          <>
            <Button icon={<ReloadOutlined />} onClick={() => load()} size="small">刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)} size="small">
              新建卡片
            </Button>
            <Button icon={<UndoOutlined />} onClick={() => setRestoreOpen(true)} size="small">
              恢复卡片
            </Button>
          </>
        }
      />

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table
          dataSource={cards}
          columns={columns}
          rowKey="uuid"
          loading={loading}
          pagination={{
            current: page,
            total,
            pageSize: 10,
            onChange: (p) => { setPage(p); load(p); },
            showTotal: (t) => `共 ${t} 条`,
          }}
        />
      </Card>

      {/* 新建卡片弹窗 */}
      <Modal
        title="新建卡片"
        open={createOpen}
        onOk={handleCreate}
        onCancel={() => { setCreateOpen(false); createForm.resetFields(); setCreateSlotType('local'); }}
        okText="创建" cancelText="取消"
        confirmLoading={creating}
        width={480}
      >
        <Form form={createForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="card_name" label="卡片名称" initialValue="OpenCert SmartCard" rules={[{ required: true, message: '请输入卡片名称' }]}>
            <Input placeholder="智能卡的名称" />
          </Form.Item>
          <Form.Item name="slot_type" label="Slot类型" initialValue="local" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'local', label: '本地 (本地数据库)' },
                { value: 'tpmsc', label: 'TPM 虚拟智能卡 (Windows TPM)' },
                // { value: 'cloud', label: '云端 (云端数据库)' },
              ]}
              onChange={(val) => {
                setCreateSlotType(val);
                if (val === 'tpmsc') {
                  createForm.setFieldsValue({ security_level: 'high' });
                }
              }}
            />
          </Form.Item>
          {createSlotType === 'tpmsc' && (
            <Alert
              message="TPM 虚拟智能卡（需要管理员权限）"
              description="创建后默认 PIN 为 12345678，请在创建成功后立即通过 Windows 修改 PIN。密钥由 TPM 硬件保护，永远不可导出。"
              type="warning" showIcon style={{ marginBottom: 16 }}
            />
          )}
          <Form.Item name="user_uuid" label="所属用户" rules={[{ required: true, message: '请选择用户' }]}>
            <Select
              options={users.map((u) => ({ value: u.uuid, label: u.display_name }))}
              placeholder="选择所属用户"
            />
          </Form.Item>
          <Form.Item name="security_level" label="安全等级" initialValue="low" rules={[{ required: true }]}
            tooltip={createSlotType === 'tpmsc' ? 'TPM 虚拟智能卡固定为高安全性' : undefined}
          >
            <Select
              disabled={createSlotType === 'tpmsc'}
              options={[
                { value: 'low', label: '低安全性 — 密钥可被用户导出 (Local数据库)' },
                { value: 'medium', label: '中安全性 — 密钥可被管理恢复 (TPM协助加密)' },
                { value: 'high', label: '高安全性 — 密钥永远无法导出 (TPM片上生成)' },
              ]}
            />
          </Form.Item>
          <Form.Item name="pin" label="卡片 PIN" rules={[
            { required: true, message: '请输入 PIN 码' },
            { min: 8, message: 'PIN 最少 8 位（Microsoft TPM 要求）' },
          ]} tooltip="PIN 用于加密保护卡片主密钥，是日常使用卡片的核心凭据。TPM 虚拟智能卡要求最少 8 位">
            <Input.Password placeholder="设置卡片密码" />
          </Form.Item>
          <Form.Item name="user_password" label="用户密码" rules={[{ required: true, message: '请输入用户密码' }]} tooltip="验证用户身份">
            <Input.Password placeholder="输入当前用户密码" />
          </Form.Item>
          <Form.Item name="remark" label="卡片备注">
            <Input.TextArea rows={2} placeholder="卡片备注信息" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 卡片详情抽屉 */}
      <Drawer
        title={
          <Space>
            <SafetyCertificateOutlined />
            <span>{selectedCard?.card_name} — 卡片详情</span>
{selectedCard && <Tag color={slotColor(selectedCard.slot_type)}>{slotLabel(selectedCard.slot_type)}</Tag>}
            {selectedCard && selectedCard.enabled === false && <Tag color="red">已禁用</Tag>}
            {selectedCard && selectedCard.expires_at && dayjs(selectedCard.expires_at).isBefore(dayjs()) && <Tag color="red">已过期</Tag>}
          </Space>
        }
        open={certDrawerOpen}
        onClose={() => setCertDrawerOpen(false)}
        width={750}
        extra={
          <Button
            type="primary" size="small" icon={<KeyOutlined />}
            onClick={() => setKeygenOpen(true)}
          >
            生成密钥对
          </Button>
        }
      >
        {selectedCard && (
          <>
            {/* 卡片状态警告 */}
            {(selectedCard.enabled === false || (selectedCard.expires_at && dayjs(selectedCard.expires_at).isBefore(dayjs()))) && (
              <Alert
                message="此卡片当前不可用"
                description={selectedCard.enabled === false ? '卡片已被禁用，其证书不会显示在用户证书管理中，也不会注册到系统。' : '卡片已过期，其证书不会显示在用户证书管理中，也不会注册到系统。'}
                type="warning" showIcon style={{ marginBottom: 16 }}
              />
            )}

            <Descriptions size="small" style={{ marginBottom: 16 }} column={2}>
              <Descriptions.Item label="UUID">
                <Text copyable style={{ fontSize: 12 }}>{selectedCard.uuid}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="安全等级">
                {(() => {
                  const cfg = securityLevelConfig[selectedCard.security_level] || securityLevelConfig.low;
                  return <Tag color={cfg.color}>{cfg.label} - {cfg.desc}</Tag>;
                })()}
              </Descriptions.Item>
              <Descriptions.Item label="卡片类型">
<Tag color={slotColor(selectedCard.slot_type)}>{slotLabel(selectedCard.slot_type)}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                <Text style={{ fontSize: 12 }}>{dayjs(selectedCard.created_at).format('YYYY-MM-DD HH:mm:ss')}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="有效期至">
                <Space>
                  <Text style={{ fontSize: 12 }}>
                    {selectedCard.expires_at ? dayjs(selectedCard.expires_at).format('YYYY-MM-DD') : '永不过期'}
                  </Text>
                  {selectedCard.expires_at && dayjs(selectedCard.expires_at).isBefore(dayjs()) && <Tag color="red" style={{ fontSize: 10 }}>已过期</Tag>}
                  <Button
                    type="link" size="small" icon={<EditOutlined />}
                    onClick={() => {
                      setEditCard(selectedCard);
                      editForm.setFieldsValue({
                        remark: selectedCard.remark || '',
                        expires_at: selectedCard.expires_at ? dayjs(selectedCard.expires_at) : null,
                        never_expire: !selectedCard.expires_at,
                        fido_enabled: !!selectedCard.fido_enabled,
                        totp_enabled: !!selectedCard.totp_enabled,
                        credential_enabled: !!selectedCard.credential_enabled,
                        pin_timeout: selectedCard.pin_timeout ?? 900,
                      });
                      setEditOpen(true);
                    }}
                  >
                    修改
                  </Button>
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="卡片状态">
                <Switch
                  checked={selectedCard.enabled !== false}
                  checkedChildren="启用"
                  unCheckedChildren="禁用"
                  onChange={async (checked) => {
                    try {
                      await updateCard(selectedCard.uuid, { enabled: checked } as any);
                      selectedCard.enabled = checked;
                      message.success(checked ? '卡片已启用' : '卡片已禁用');
                      load();
                    } catch (e: any) { message.error(e.message); }
                  }}
                />
              </Descriptions.Item>
              <Descriptions.Item label="卡片备注">
                <Text style={{ fontSize: 12 }}>{selectedCard.remark || '-'}</Text>
              </Descriptions.Item>
              {selectedCard.cloud_url && (
                <Descriptions.Item label="云地址">
                  <Text copyable style={{ fontSize: 12 }}>{selectedCard.cloud_url}</Text>
                </Descriptions.Item>
              )}
              {selectedCard.cloud_card_uuid && (
                <Descriptions.Item label="云卡片 UUID">
                  <Text copyable style={{ fontSize: 12 }}>{selectedCard.cloud_card_uuid}</Text>
                </Descriptions.Item>
              )}
            </Descriptions>

            <Typography.Title level={5} style={{ marginTop: 8, marginBottom: 8, color: darkMode ? '#c9d1d9' : undefined }}>
              证书列表
            </Typography.Title>
          </>
        )}

        {certs.length === 0 && !certsLoading ? (
          <Empty description="暂无证书，点击「生成密钥对」创建" />
        ) : (
          <Table
            dataSource={certs}
            columns={certColumns}
            rowKey="uuid"
            loading={certsLoading}
            pagination={false}
            size="small"
          />
        )}
      </Drawer>

      {/* PIN 重置弹窗 */}
      <Modal
        title="修改 / 重置 PIN"
        open={pinResetOpen}
        onOk={handlePinReset}
        onCancel={() => { setPinResetOpen(false); pinResetForm.resetFields(); }}
        okText="确认" cancelText="取消"
        confirmLoading={pinResetting}
        width={420}
      >
        <Form form={pinResetForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="method" label="验证方式" initialValue="pin" rules={[{ required: true }]}>
            <Select options={[
              { value: 'pin', label: '使用当前 PIN 修改' },
              { value: 'puk', label: '使用 PUK 重置' },
              { value: 'admin', label: '使用 Admin Key 重置' },
            ]} />
          </Form.Item>
          <Form.Item name="secret" label="当前 PIN / PUK / Admin Key" rules={[{ required: true, message: '请输入凭据' }]}>
            <Input.Password placeholder="输入当前 PIN、PUK 或 Admin Key" />
          </Form.Item>
          <Form.Item name="new_pin" label="新 PIN" rules={[{ required: true, message: '请输入新 PIN' }]}>
            <Input.Password placeholder="设置新的 PIN" />
          </Form.Item>
        </Form>
      </Modal>

      {/* PUK/AdminKey 一次性显示弹窗 */}
      <Modal
        title="⚠️ 请妥善保存以下凭据"
        open={!!credsModal}
        onOk={() => setCredsModal(null)}
        onCancel={() => setCredsModal(null)}
        okText="我已记录" cancelText="关闭"
        width={480}
      >
        <Alert
          message="以下凭据仅显示一次，请立即抄写或保存到安全位置！"
          type="warning" showIcon style={{ marginBottom: 16 }}
        />
        {credsModal?.pin && (
          <Descriptions column={1} bordered size="small" style={{ marginBottom: 8 }}>
            <Descriptions.Item label="PIN">
              <Typography.Text copyable strong style={{ fontSize: 16 }}>{credsModal.pin}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        )}
        {credsModal?.puk && (
          <Descriptions column={1} bordered size="small" style={{ marginBottom: 8 }}>
            <Descriptions.Item label="PUK（可重置 PIN）">
              <Typography.Text copyable strong style={{ fontSize: 16 }}>{credsModal.puk}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        )}
        {credsModal?.admin_key && (
          <Descriptions column={1} bordered size="small" style={{ marginBottom: 8 }}>
            <Descriptions.Item label="Admin Key（最高权限）">
              <Typography.Text copyable strong style={{ fontSize: 16 }}>{credsModal.admin_key}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        )}
        {credsModal?.reader_name && (
          <Descriptions column={1} bordered size="small" style={{ marginBottom: 8 }}>
            <Descriptions.Item label="虚拟读卡器名称">
              <Typography.Text copyable style={{ fontSize: 14 }}>{credsModal.reader_name}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        )}
        {credsModal?.instance_id && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="设备实例 ID">
              <Typography.Text copyable style={{ fontSize: 14 }}>{credsModal.instance_id}</Typography.Text>
            </Descriptions.Item>
          </Descriptions>
        )}
        {credsModal?.output && (
          <div style={{ marginTop: 12 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>命令行输出：</Typography.Text>
            <pre style={{ background: '#f5f5f5', padding: 8, borderRadius: 4, fontSize: 11, maxHeight: 200, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {credsModal.output}
            </pre>
          </div>
        )}
      </Modal>

      {/* 密钥生成弹窗 */}
      <Modal
        title={
          <Space>
            <KeyOutlined />
            <span>生成密钥对 — {selectedCard?.card_name}</span>
          </Space>
        }
        open={keygenOpen}
        onOk={handleKeygen}
        onCancel={() => { setKeygenOpen(false); keygenForm.resetFields(); }}
        okText="生成" cancelText="取消"
        confirmLoading={keygening}
        width={420}
      >
        <Form form={keygenForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="key_type" label="密钥类型" initialValue="ec256" rules={[{ required: true }]}>
            <Select options={KEY_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item name="card_password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码' }]}>
            <Input.Password placeholder="验证卡片身份" />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="例如：TLS 签名密钥" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 备份卡片弹窗 */}
      <Modal
        title="备份智能卡"
        open={exportOpen}
        onOk={handleExport}
        onCancel={() => { setExportOpen(false); exportForm.resetFields(); }}
        okText="备份" cancelText="取消"
        confirmLoading={exporting}
        width={420}
      >
        <Alert
          message={exportCard?.security_level === 'medium'
            ? '中安全性卡片需要 Admin Key 验证后才能备份'
            : '请输入卡片密码以备份'}
          type="info" showIcon style={{ marginBottom: 16 }}
        />
        <Form form={exportForm} layout="vertical">
          <Form.Item name="confirm_uuid" label="请输入卡片 UUID 以确认" rules={[
            { required: true, message: '请输入卡片 UUID' },
            { validator: (_, value) => value === exportCard?.uuid ? Promise.resolve() : Promise.reject('UUID 不匹配') },
          ]}>
            <div style={{ marginBottom: 4, padding: '4px 8px', background: '#f5f5f5', borderRadius: 4 }}>
              <Text copyable style={{ fontSize: 12, fontFamily: 'monospace' }}>{exportCard?.uuid}</Text>
            </div>
            <Input placeholder={exportCard?.uuid} style={{ fontFamily: 'monospace', fontSize: 12 }} />
          </Form.Item>
          <Form.Item name="user_password" label="当前用户密码" rules={[{ required: true, message: '请输入用户密码' }]}>
            <Input.Password placeholder="验证当前用户身份" />
          </Form.Item>
          {exportCard?.security_level === 'medium' ? (
            <Form.Item name="admin_key" label="Admin Key" rules={[{ required: true, message: '请输入 Admin Key' }]}>
              <Input.Password placeholder="输入 Admin Key" />
            </Form.Item>
          ) : (
            <Form.Item name="password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码' }]}>
              <Input.Password placeholder="输入卡片密码" />
            </Form.Item>
          )}
        </Form>
      </Modal>

      {/* 恢复卡片弹窗 */}
      <Modal
        title="恢复智能卡"
        open={restoreOpen}
        onOk={handleRestore}
        onCancel={() => { setRestoreOpen(false); restoreForm.resetFields(); }}
        okText="恢复" cancelText="取消"
        confirmLoading={restoring}
        width={480}
      >
        <Form form={restoreForm} layout="vertical">
          {selectedCard && (
            <Form.Item name="confirm_uuid" label="请输入卡片 UUID 以确认恢复" rules={[
              { required: true, message: '请输入卡片 UUID' },
              { validator: (_, value) => value === selectedCard?.uuid ? Promise.resolve() : Promise.reject('UUID 不匹配') },
            ]}>
              <div style={{ marginBottom: 4, padding: '4px 8px', background: '#f5f5f5', borderRadius: 4 }}>
                <Text copyable style={{ fontSize: 12, fontFamily: 'monospace' }}>{selectedCard.uuid}</Text>
              </div>
              <Input placeholder={selectedCard?.uuid} style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </Form.Item>
          )}
          <Form.Item name="ocs_file" label="选择 .ocs 备份文件" rules={[{ required: true, message: '请选择文件' }]}
            valuePropName="fileList" getValueFromEvent={(e: any) => e?.fileList}
          >
            <Input type="file" accept=".ocs" />
          </Form.Item>
          <Form.Item name="password" label="备份解密密码" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password placeholder="输入备份时设置的密码" />
          </Form.Item>
          <Form.Item name="user_password" label="当前用户密码" rules={[{ required: true, message: '请输入用户密码' }]}>
            <Input.Password placeholder="验证当前用户身份" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 删除卡片确认弹窗 */}
      <Modal
        title="确认删除卡片"
        open={deleteOpen}
        onOk={() => deleteCard2 && handleDelete(deleteCard2.uuid)}
        onCancel={() => { setDeleteOpen(false); deleteForm.resetFields(); }}
        okText="删除" cancelText="取消"
        okButtonProps={{ danger: true }}
        confirmLoading={deleting}
        width={420}
      >
        <Alert
          message={`确认删除卡片「${deleteCard2?.card_name}」？此操作将同时删除所有证书，不可恢复。`}
          type="error" showIcon style={{ marginBottom: 16 }}
        />
        <Form form={deleteForm} layout="vertical">
          <Form.Item name="confirm_uuid" label="请输入卡片 UUID 以确认" rules={[
            { required: true, message: '请输入卡片 UUID' },
            { validator: (_, value) => value === deleteCard2?.uuid ? Promise.resolve() : Promise.reject('UUID 不匹配') },
          ]}>
            <div style={{ marginBottom: 4, padding: '4px 8px', background: '#f5f5f5', borderRadius: 4 }}>
              <Text copyable style={{ fontSize: 12, fontFamily: 'monospace' }}>{deleteCard2?.uuid}</Text>
            </div>
            <Input placeholder={deleteCard2?.uuid} style={{ fontFamily: 'monospace', fontSize: 12 }} />
          </Form.Item>
          <Form.Item name="user_password" label="当前用户密码" rules={[{ required: true, message: '请输入用户密码' }]}>
            <Input.Password placeholder="验证当前用户身份" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 修改卡片弹窗 */}
      <Modal
        title={`修改卡片 — ${editCard?.card_name}`}
        open={editOpen}
        onOk={async () => {
          if (!editCard) return;
          try {
            const values = await editForm.validateFields();
            setEditing(true);
            const updateData: any = { remark: values.remark };
            if (values.never_expire) {
              updateData.expires_at = '';
            } else if (values.expires_at) {
              updateData.expires_at = values.expires_at.format('YYYY-MM-DD');
            }
            updateData.fido_enabled = !!values.fido_enabled;
            updateData.totp_enabled = !!values.totp_enabled;
            updateData.credential_enabled = !!values.credential_enabled;
            updateData.pin_timeout = values.pin_timeout ?? 900;
            await updateCard(editCard.uuid, updateData);
            message.success('卡片已更新');
            setEditOpen(false);
            editForm.resetFields();
            load();
          } catch (e: any) {
            if (e.message) message.error(e.message);
          } finally {
            setEditing(false);
          }
        }}
        onCancel={() => { setEditOpen(false); editForm.resetFields(); }}
        okText="保存" cancelText="取消"
        confirmLoading={editing}
        width={480}
      >
        <Form form={editForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="remark" label="备注">
            <Input.TextArea rows={2} placeholder="卡片备注信息" />
          </Form.Item>
          <Form.Item name="never_expire" valuePropName="checked">
            <Checkbox>永不过期</Checkbox>
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.never_expire !== cur.never_expire}>
            {({ getFieldValue }) => !getFieldValue('never_expire') && (
              <Form.Item name="expires_at" label="有效期">
                <DatePicker style={{ width: '100%' }} placeholder="选择过期日期" />
              </Form.Item>
            )}
          </Form.Item>
          <Form.Item label="生成密钥对">
            <Button
              type="dashed" icon={<KeyOutlined />}
              onClick={() => { setSelectedCard(editCard); setKeygenOpen(true); }}
            >
              为此卡片生成新密钥对
            </Button>
          </Form.Item>
          <Form.Item label="功能开关" style={{ marginBottom: 8 }}>
            <Space direction="vertical" size={8} style={{ width: '100%' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text>FIDO2/WebAuthn</Text>
                <Form.Item name="fido_enabled" valuePropName="checked" noStyle>
                  <Switch size="small" />
                </Form.Item>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text>TOTP 动态口令</Text>
                <Form.Item name="totp_enabled" valuePropName="checked" noStyle>
                  <Switch size="small" />
                </Form.Item>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text>安全凭据</Text>
                <Form.Item name="credential_enabled" valuePropName="checked" noStyle>
                  <Switch size="small" />
                </Form.Item>
              </div>
            </Space>
          </Form.Item>
          <Form.Item name="pin_timeout" label="记住密码时间">
            <Select
              options={[
                { label: '不记住', value: 0 },
                { label: '5 分钟', value: 300 },
                { label: '15 分钟', value: 900 },
                { label: '30 分钟', value: 1800 },
                { label: '60 分钟', value: 3600 },
                { label: '3 小时', value: 10800 },
                { label: '6 小时', value: 21600 },
                { label: '24 小时', value: 86400 },
                { label: '72 小时', value: 259200 },
                { label: '7 天', value: 604800 },
                { label: '30 天', value: 2592000 },
                { label: '永久', value: -1 },
              ]}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default Cards;
