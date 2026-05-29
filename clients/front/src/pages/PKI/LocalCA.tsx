import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Tabs,
  Popconfirm, message, Tooltip, Card, Row, Col, Divider,
  Drawer, Descriptions, List, Empty,
} from 'antd';
import {
  DeleteOutlined, ReloadOutlined, BankOutlined,
  ImportOutlined, DownloadOutlined, StopOutlined, EyeOutlined,
  CopyOutlined, SafetyCertificateOutlined, CreditCardOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import { getLocalCAs, importLocalCA, revokeLocalCA, deleteLocalCA, exportLocalCA, getCards, getPKICerts, getCerts } from '../../api';
import type { LocalCA, ImportCARequest, Card as CardType } from '../../types';
import { useAppStore } from '../../store/appStore';
import dayjs from 'dayjs';

const { Text } = Typography;
const { TextArea } = Input;

/** 计算剩余有效期的友好文本 */
const getValidityText = (notAfter: string): { text: string; color: string } => {
  const end = dayjs(notAfter);
  const now = dayjs();
  if (end.isBefore(now)) return { text: '已过期', color: '#ff4d4f' };
  const days = end.diff(now, 'day');
  if (days <= 30) return { text: `${days} 天`, color: '#fa8c16' };
  if (days <= 365) return { text: `${Math.floor(days / 30)} 个月`, color: '#52c41a' };
  const years = Math.floor(days / 365);
  const months = Math.floor((days % 365) / 30);
  return { text: months > 0 ? `${years} 年 ${months} 月` : `${years} 年`, color: '#52c41a' };
};

const LocalCAPage: React.FC = () => {
  const { darkMode } = useAppStore();
  const [list, setList] = useState<LocalCA[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [cards, setCards] = useState<CardType[]>([]);

  const [importOpen, setImportOpen] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importForm] = Form.useForm();

  // 查看详情
  const [viewOpen, setViewOpen] = useState(false);
  const [viewRecord, setViewRecord] = useState<LocalCA | null>(null);

  // 导入 Tab 切换
  const [importTab, setImportTab] = useState<'pem' | 'existing'>('pem');
  // 从已有证书选择
  interface ExistingCert { uuid: string; cn: string; certPEM: string; source: string; hasKey: boolean; cardUUID?: string; cardName?: string; notAfter?: string; }
  const [existingCerts, setExistingCerts] = useState<ExistingCert[]>([]);
  const [selectedExistingCert, setSelectedExistingCert] = useState<ExistingCert | null>(null);
  const [loadingExisting, setLoadingExisting] = useState(false);

  const load = async (p = page) => {
    setLoading(true);
    try {
      const res = await getLocalCAs({ page: p, page_size: 10 });
      setList(res.items);
      setTotal(res.total);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    getCards({ page: 1, page_size: 100 }).then((r) => setCards(r.items)).catch(() => {});
  }, []);

  const handleImport = async () => {
    try {
      const values = await importForm.validateFields();
      setImporting(true);
      await importLocalCA(values as ImportCARequest);
      message.success('CA 已导入');
      setImportOpen(false);
      importForm.resetFields();
      load();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setImporting(false); }
  };

  // 从已有证书导入为 CA
  const handleImportFromCert = async () => {
    if (!selectedExistingCert) {
      message.warning('请先选择一个证书');
      return;
    }
    try {
      setImporting(true);
      await importLocalCA({
        cert_pem: selectedExistingCert.certPEM,
        card_uuid: selectedExistingCert.cardUUID,
      } as ImportCARequest);
      message.success('CA 已从已有证书导入');
      setImportOpen(false);
      setSelectedExistingCert(null);
      setExistingCerts([]);
      setImportTab('pem');
      load();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setImporting(false); }
  };

  // 加载 PKI 证书列表（证书签发管理中的）
  const loadPKICerts = async () => {
    setLoadingExisting(true);
    try {
      const res = await getPKICerts({ page: 1, page_size: 100 });
      const items = (res?.items || [])
        .filter((c: any) => c.cert_pem && !c.revoked)
        .map((c: any) => ({
          uuid: c.uuid,
          cn: c.common_name || '未知',
          certPEM: c.cert_pem,
          source: 'PKI 证书',
          hasKey: c.has_private_key,
          cardUUID: c.card_uuid,
          cardName: c.card_uuid ? getCardName(c.card_uuid) || undefined : undefined,
          notAfter: c.not_after,
        }));
      setExistingCerts(items);
      if (items.length === 0) message.info('没有可用的 PKI 证书');
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoadingExisting(false); }
  };

  // 加载智能卡证书列表
  const loadCardCerts = async () => {
    setLoadingExisting(true);
    try {
      const allCerts: ExistingCert[] = [];
      for (const card of cards) {
        try {
          const res = await getCerts(card.uuid);
          const items = (res || [])
            .filter((c: any) => c.cert_type === 'x509' && c.cert_content)
            .map((c: any) => ({
              uuid: c.uuid,
              cn: c.remark || c.uuid.slice(0, 8),
              certPEM: typeof c.cert_content === 'string' ? c.cert_content : '',
              source: `智能卡`,
              hasKey: !!(c.private_data || c.tpm_wrapped_blob),
              cardUUID: card.uuid,
              cardName: card.card_name,
              notAfter: undefined,
            }));
          allCerts.push(...items);
        } catch { /* skip */ }
      }
      setExistingCerts(allCerts);
      if (allCerts.length === 0) message.info('没有可用的智能卡证书');
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoadingExisting(false); }
  };

  /** 获取卡片名称 */
  const getCardName = (cardUUID?: string) => {
    if (!cardUUID) return null;
    const card = cards.find((c) => c.uuid === cardUUID);
    return card ? card.card_name : cardUUID.slice(0, 8);
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const columns = [
    {
      title: '通用名称 (CN)',
      dataIndex: 'common_name',
      ellipsis: true,
      render: (v: string, r: LocalCA) => (
        <Space>
          <BankOutlined style={{ color: r.revoked ? '#ff4d4f' : '#52c41a' }} />
          <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{v}</Text>
        </Space>
      ),
    },
    {
      title: '组织 / 国家',
      width: 130,
      render: (_: any, r: LocalCA) => (
        <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>
          {[r.organization, r.country].filter(Boolean).join(' / ') || '-'}
        </Text>
      ),
    },
    {
      title: '密钥类型',
      dataIndex: 'key_type',
      width: 120,
      render: (v: string) => <Tag color="blue">{v?.toUpperCase()}</Tag>,
    },
    {
      title: '有效期',
      width: 200,
      render: (_: any, r: LocalCA) => {
        const expired = dayjs(r.not_after).isBefore(dayjs());
        return (
          <Text style={{ fontSize: 12, color: expired ? '#ff4d4f' : darkMode ? '#8b949e' : '#666' }}>
            {dayjs(r.not_before).format('YYYY-MM-DD')} ~ {dayjs(r.not_after).format('YYYY-MM-DD')}
          </Text>
        );
      },
    },
    {
      title: '剩余',
      width: 90,
      render: (_: any, r: LocalCA) => {
        const { text, color } = getValidityText(r.not_after);
        return <Text style={{ fontSize: 12, color }}>{text}</Text>;
      },
    },
    {
      title: '已签发',
      dataIndex: 'issued_count',
      width: 100,
      render: (v: number) => <Tag>{v ?? 0}</Tag>,
    },
    {
      title: '私钥',
      dataIndex: 'has_priv_key',
      width: 90,
      render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '有' : '无'}</Tag>,
    },
    {
      title: '密钥',
      width: 90,
      render: (_: any, r: LocalCA) => (
        <Tag color={r.card_uuid ? 'purple' : 'green'}>
          {r.card_uuid ? '智能卡' : '数据库'}
        </Tag>
      ),
    },
    {
      title: '状态',
      width: 75,
      render: (_: any, r: LocalCA) => {
        if (r.revoked) return <Tag color="red">已吊销</Tag>;
        if (dayjs(r.not_after).isBefore(dayjs())) return <Tag color="orange">已过期</Tag>;
        return <Tag color="green">有效</Tag>;
      },
    },
    {
      title: '操作',
      width: 190,
      fixed: 'right' as const,
      render: (_: any, record: LocalCA) => (
        <Space>
          <Tooltip title="查看详情">
            <Button type="text" size="small" icon={<EyeOutlined />}
              onClick={() => { setViewRecord(record); setViewOpen(true); }} />
          </Tooltip>
          <Tooltip title="导出证书">
            <Button type="text" size="small" icon={<DownloadOutlined />}
              onClick={() => exportLocalCA(record.uuid, 'pem', record.name).catch((e) => message.error(e.message))} />
          </Tooltip>
          <Tooltip title="导出证书链">
            <Button type="text" size="small" icon={<DownloadOutlined />}
              onClick={() => exportLocalCA(record.uuid, 'chain', record.name).catch((e) => message.error(e.message))}>
              链
            </Button>
          </Tooltip>
          {!record.revoked && (
            <Popconfirm title="确认吊销此 CA？吊销后无法签发新证书。"
              onConfirm={() => revokeLocalCA(record.uuid).then(() => { message.success('已吊销'); load(); }).catch((e) => message.error(e.message))}
              okText="吊销" cancelText="取消" okButtonProps={{ danger: true }}>
              <Tooltip title="吊销">
                <Button type="text" size="small" danger icon={<StopOutlined />} />
              </Tooltip>
            </Popconfirm>
          )}
          <Popconfirm title="确认删除此 CA？"
            onConfirm={() => deleteLocalCA(record.uuid).then(() => { message.success('已删除'); load(); }).catch((e) => message.error(e.message))}
            okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
            <Tooltip title="删除">
              <Button type="text" size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={<BankOutlined />}
        title="本地颁发机构"
        extra={
          <>
            <Button icon={<ReloadOutlined />} onClick={() => load()} size="small">刷新</Button>
            <Button type="primary" icon={<ImportOutlined />} onClick={() => setImportOpen(true)} size="small">导入 CA</Button>
          </>
        }
      />

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table dataSource={list} columns={columns} rowKey="uuid" loading={loading}
          scroll={{ x: 1200 }}
          pagination={{ current: page, total, pageSize: 10, onChange: (p) => { setPage(p); load(p); }, showTotal: (t) => `共 ${t} 条` }} />
      </Card>

      {/* 查看详情抽屉 */}
      <Drawer title={<Space><EyeOutlined />CA 详情 — {viewRecord?.common_name}</Space>}
        open={viewOpen} onClose={() => setViewOpen(false)} width={600}
        extra={
          <Space>
            <Button size="small" icon={<CopyOutlined />} onClick={() => {
              if (viewRecord?.cert_pem) { navigator.clipboard.writeText(viewRecord.cert_pem); message.success('证书已复制'); }
            }}>复制证书</Button>
            <Button size="small" icon={<DownloadOutlined />}
              onClick={() => viewRecord && exportLocalCA(viewRecord.uuid, 'pem', viewRecord.name).catch((e) => message.error(e.message))}>
              导出
            </Button>
          </Space>
        }>
        {viewRecord && (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="通用名称 (CN)">{viewRecord.common_name}</Descriptions.Item>
              <Descriptions.Item label="组织 (O)">{viewRecord.organization || '-'}</Descriptions.Item>
              <Descriptions.Item label="国家 (C)">{viewRecord.country || '-'}</Descriptions.Item>
              <Descriptions.Item label="密钥类型"><Tag color="blue">{viewRecord.key_type?.toUpperCase()}</Tag></Descriptions.Item>
              <Descriptions.Item label="含私钥">
                <Tag color={viewRecord.has_priv_key ? 'green' : 'default'}>{viewRecord.has_priv_key ? '是' : '否'}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="密钥存储">
                <Tag color={viewRecord.card_uuid ? 'purple' : 'green'}>
                  {viewRecord.card_uuid ? `智能卡 (${getCardName(viewRecord.card_uuid)})` : '数据库'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                {viewRecord.revoked
                  ? <Tag color="red">已吊销</Tag>
                  : dayjs(viewRecord.not_after).isBefore(dayjs())
                    ? <Tag color="orange">已过期</Tag>
                    : <Tag color="green">有效</Tag>
                }
              </Descriptions.Item>
              <Descriptions.Item label="生效时间">{dayjs(viewRecord.not_before).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
              <Descriptions.Item label="过期时间">{dayjs(viewRecord.not_after).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
              <Descriptions.Item label="剩余有效期">
                {(() => { const { text, color } = getValidityText(viewRecord.not_after); return <Text style={{ color }}>{text}</Text>; })()}
              </Descriptions.Item>
              <Descriptions.Item label="已签发证书">{viewRecord.issued_count ?? 0} 张</Descriptions.Item>
              <Descriptions.Item label="创建时间" span={2}>{dayjs(viewRecord.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
            </Descriptions>
            {viewRecord.cert_pem && (
              <>
                <Divider style={{ margin: '8px 0' }} />
                <Text type="secondary" style={{ fontSize: 12 }}>CA 证书（PEM）</Text>
                <TextArea value={viewRecord.cert_pem} rows={12} readOnly
                  style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 8 }} />
              </>
            )}
            {viewRecord.chain_pem && (
              <>
                <Divider style={{ margin: '8px 0' }} />
                <Text type="secondary" style={{ fontSize: 12 }}>证书链（PEM）</Text>
                <TextArea value={viewRecord.chain_pem} rows={6} readOnly
                  style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 8 }} />
              </>
            )}
          </>
        )}
      </Drawer>

      {/* 导入 CA 弹窗 */}
      <Modal title={<Space><ImportOutlined />导入 CA 证书</Space>} open={importOpen}
        onOk={importTab === 'pem' ? handleImport : handleImportFromCert}
        onCancel={() => { setImportOpen(false); importForm.resetFields(); setImportTab('pem'); setExistingCerts([]); }}
        okText="导入" cancelText="取消" confirmLoading={importing} width={640}>
        <Tabs activeKey={importTab} onChange={(k) => setImportTab(k as any)} items={[
          {
            key: 'pem',
            label: '粘贴 PEM',
            children: (
              <Form form={importForm} layout="vertical" style={{ marginTop: 8 }}>
                <Form.Item name="cert_pem" label="CA 证书（PEM 格式）" rules={[{ required: true }]}>
                  <TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    style={{ fontFamily: 'monospace', fontSize: 12 }} />
                </Form.Item>
                <Form.Item name="key_pem" label="CA 私钥（PEM 格式，可选）">
                  <TextArea rows={5} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;（有私钥才能用此 CA 签发证书）"
                    style={{ fontFamily: 'monospace', fontSize: 12 }} />
                </Form.Item>
                <Form.Item name="chain_pem" label="证书链（PEM 格式，可选）">
                  <TextArea rows={4} placeholder="中间 CA 证书链（可选）"
                    style={{ fontFamily: 'monospace', fontSize: 12 }} />
                </Form.Item>
                <Form.Item name="card_uuid" label="私钥存储智能卡（可选）">
                  <Select allowClear placeholder="若私钥需存储到智能卡，请选择"
                    options={cards.map((c) => ({ value: c.uuid, label: `${c.card_name} (${c.slot_type})` }))} />
                </Form.Item>
              </Form>
            ),
          },
          {
            key: 'existing',
            label: '从已有证书选择',
            children: (
              <div style={{ marginTop: 8 }}>
                <Space style={{ marginBottom: 12 }}>
                  <Button size="small" icon={<SafetyCertificateOutlined />}
                    onClick={loadPKICerts} loading={loadingExisting}>
                    加载 PKI 证书
                  </Button>
                  <Button size="small" icon={<CreditCardOutlined />}
                    onClick={loadCardCerts} loading={loadingExisting}>
                    加载智能卡证书
                  </Button>
                </Space>
                {existingCerts.length === 0 ? (
                  <Empty description="点击上方按钮加载可选的 CA 证书" style={{ margin: '24px 0' }} />
                ) : (
                  <List
                    size="small"
                    dataSource={existingCerts}
                    style={{ maxHeight: 300, overflow: 'auto' }}
                    renderItem={(item) => (
                      <List.Item
                        onClick={() => setSelectedExistingCert(item)}
                        style={{
                          cursor: 'pointer', borderRadius: 6, padding: '8px 12px',
                          background: selectedExistingCert?.uuid === item.uuid
                            ? (darkMode ? 'rgba(22,119,255,0.15)' : 'rgba(22,119,255,0.06)')
                            : undefined,
                          border: selectedExistingCert?.uuid === item.uuid
                            ? '1px solid rgba(22,119,255,0.4)'
                            : '1px solid transparent',
                        }}
                      >
                        <List.Item.Meta
                          avatar={<BankOutlined style={{ color: '#1677ff', fontSize: 18 }} />}
                          title={<Text style={{ color: darkMode ? '#c9d1d9' : '#333' }}>{item.cn}</Text>}
                          description={
                            <Space size={8} style={{ fontSize: 11 }}>
                              <Tag color="blue">{item.source}</Tag>
                              {item.hasKey && <Tag color="green">含私钥</Tag>}
                              {item.cardName && <Tag color="purple">{item.cardName}</Tag>}
                              <Text type="secondary">{item.notAfter ? `有效期至 ${dayjs(item.notAfter).format('YYYY-MM-DD')}` : ''}</Text>
                            </Space>
                          }
                        />
                      </List.Item>
                    )}
                  />
                )}
              </div>
            ),
          },
        ]} />
      </Modal>
    </div>
  );
};

export default LocalCAPage;
