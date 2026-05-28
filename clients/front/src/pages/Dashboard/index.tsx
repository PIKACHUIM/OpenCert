// Dashboard 多账号聚合视图：
//   - 统计卡片：智能卡 / 证书 / TOTP / FIDO / 安全凭据
//   - 最近的智能卡列表
//   - 最近的证书列表
//   - TOTP 实时验证码
//   - FIDO 凭据列表
//   - 安全凭据列表
import React, { useEffect, useState, useCallback, memo } from 'react';
import {
  Row, Col, Card, Statistic, Table, Tag, Typography, Space, Spin, Alert,
  Button, Tooltip, Progress, message, Segmented, Empty, List, Badge,
} from 'antd';
import {
  CreditCardOutlined, SafetyCertificateOutlined,
  ClockCircleOutlined, CopyOutlined,
  SyncOutlined, AppstoreOutlined, UnorderedListOutlined, KeyOutlined,
  LockOutlined, IdcardOutlined, DashboardOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import { useAppStore } from '../../store/appStore';
import { useAuthStore } from '../../store/auth';
import { getCards, getCerts, getTOTPList, getTOTPCode } from '../../api';
import type { Card as CardType, Certificate, TOTPEntry } from '../../types';
import dayjs from 'dayjs';

const { Text } = Typography;

// ---- TOTP 行组件 ----
interface TOTPRowData extends TOTPEntry {
  code?: string;
  remaining?: number;
  ownerName?: string;
}

const TOTPGridCard = memo<{ item: TOTPRowData; darkMode: boolean }>(({ item, darkMode }) => {
  const isExpiring = (item.remaining ?? 30) <= 5;
  const pct = ((item.remaining ?? 30) / (item.period || 30)) * 100;
  const handleCopy = () => {
    if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('验证码已复制'));
  };
  return (
    <Card
      size="small" hoverable onClick={handleCopy}
      style={{
        background: darkMode ? '#161b22' : '#fff',
        border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
        borderRadius: 10, textAlign: 'center',
      }}
      bodyStyle={{ padding: '14px 10px' }}
    >
      <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{item.issuer}</Text>
      <div style={{ margin: '4px 0' }}>
        <Text style={{
          fontSize: 20, fontWeight: 700, letterSpacing: 3,
          color: isExpiring ? '#ff4d4f' : (darkMode ? '#c9d1d9' : '#333'),
        }}>
          {item.code || '------'}
        </Text>
      </div>
      <Space size={4}>
        <Text style={{ fontSize: 11, color: darkMode ? '#6e7681' : '#bbb' }}>{item.account}</Text>
        <Progress type="circle" size={14} percent={pct} showInfo={false} strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'} />
      </Space>
    </Card>
  );
});

// ---- 主组件 ----
const Dashboard: React.FC = () => {
  const { connected, slots, darkMode } = useAppStore();
  const accounts = useAuthStore((s) => s.accounts);

  const [cards, setCards] = useState<CardType[]>([]);
  const [certItems, setCertItems] = useState<{ cert: Certificate; cardName: string; ownerName: string }[]>([]);
  const [totpItems, setTotpItems] = useState<TOTPRowData[]>([]);
  const [fidoCount, setFidoCount] = useState(0);
  const [credCount, setCredCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [totpView, setTotpView] = useState<'table' | 'grid'>('grid');

  // 统计数据
  const [stats, setStats] = useState({ cards: 0, certs: 0, totp: 0, fido: 0, creds: 0 });

  const loadData = useCallback(async () => {
    if (!connected) return;
    setLoading(true);
    try {
      const cardsRes = await getCards({ page: 1, page_size: 200 });
      const allCards: CardType[] = Array.isArray(cardsRes?.items) ? cardsRes.items : [];
      setCards(allCards);

      const certAcc: typeof certItems = [];
      const totpAcc: TOTPRowData[] = [];
      let fidoTotal = 0;
      let credTotal = 0;

      await Promise.all(allCards.map(async (card) => {
        const owner = accounts.find((a) => a.user_uuid === card.user_uuid);
        const ownerName = owner?.display_name || card.user_uuid.slice(0, 8);
        try {
          const certs = await getCerts(card.uuid);
          (Array.isArray(certs) ? certs : []).forEach((c) => {
            if (c.cert_type === 'fido') fidoTotal++;
            else if (['login', 'note', 'payment', 'text'].includes(c.cert_type)) credTotal++;
            else certAcc.push({ cert: c, cardName: card.card_name, ownerName });
          });
        } catch { /* ignore */ }
        try {
          const totps = await getTOTPList(card.uuid);
          (Array.isArray(totps) ? totps : []).forEach((t) => totpAcc.push({ ...t, ownerName }));
        } catch { /* ignore */ }
      }));

      setCertItems(certAcc);
      setTotpItems(totpAcc);
      setFidoCount(fidoTotal);
      setCredCount(credTotal);
      setStats({
        cards: allCards.length,
        certs: certAcc.length,
        totp: totpAcc.length,
        fido: fidoTotal,
        creds: credTotal,
      });
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [connected, accounts]);

  useEffect(() => { loadData(); }, [loadData]);

  // TOTP 验证码定时刷新
  useEffect(() => {
    if (totpItems.length === 0) return;
    let cancelled = false;
    const refresh = async () => {
      const updated = await Promise.all(
        totpItems.map(async (item) => {
          try {
            const res = await getTOTPCode(item.uuid);
            return { ...item, code: res.code, remaining: res.remaining };
          } catch {
            return { ...item, code: item.code, remaining: Math.max(0, (item.remaining ?? 30) - 1) };
          }
        })
      );
      if (!cancelled) setTotpItems(updated);
    };
    refresh();
    const timer = setInterval(refresh, 1000);
    return () => { cancelled = true; clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totpItems.length]);

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 10,
  };

  // 安全等级配置
  const securityLevelConfig: Record<string, { color: string; label: string }> = {
    high: { color: 'red', label: '高' },
    medium: { color: 'orange', label: '中' },
    low: { color: 'green', label: '低' },
  };

  const slotLabel = (t: string) => {
    switch (t) {
      case 'cloud': return '云端';
      case 'tpm2': return 'TPM2';
      case 'tpmsc': return 'TPM智能卡';
      default: return '本地';
    }
  };

  const certTypeLabels: Record<string, string> = {
    x509: 'X509', ssh: 'SSH', gpg: 'GPG', totp: 'TOTP',
    fido: 'FIDO', login: '登录', text: '文本', note: '笔记', payment: '支付',
  };

  return (
    <div>
      <PageHeader
        icon={<DashboardOutlined />}
        title="系统概览"
        tags={
          <Space size={4}>
            <Badge status={connected ? 'success' : 'error'} />
            <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>
              {connected ? `已连接 · ${accounts.length} 个账号` : '未连接'}
            </Text>
          </Space>
        }
        extra={
          <Button icon={<SyncOutlined />} onClick={loadData} loading={loading} size="small">刷新</Button>
        }
      />

      {!connected && (
        <Alert message="未连接到 client-card 服务" description="请确保 client-card 服务已启动（默认端口 1026）" type="warning" showIcon style={{ marginBottom: 16 }} />
      )}

      <Spin spinning={loading}>
        {/* 统计卡片 - 5列 */}
        <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
          <Col xs={24} sm={12} lg={4} xl={4}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>智能卡</Text>}
                value={stats.cards}
                prefix={<CreditCardOutlined style={{ color: '#1677ff' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined, fontSize: 24 }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={5} xl={5}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>证书</Text>}
                value={stats.certs}
                prefix={<SafetyCertificateOutlined style={{ color: '#722ed1' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined, fontSize: 24 }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={5} xl={5}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>TOTP 条目</Text>}
                value={stats.totp}
                prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined, fontSize: 24 }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={5} xl={5}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>FIDO 凭据</Text>}
                value={stats.fido}
                prefix={<IdcardOutlined style={{ color: '#13c2c2' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined, fontSize: 24 }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={5} xl={5}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>安全凭据</Text>}
                value={stats.creds}
                prefix={<LockOutlined style={{ color: '#52c41a' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined, fontSize: 24 }}
              />
            </Card>
          </Col>
        </Row>

        {/* 最近智能卡 */}
        <Card
          title={<Space size={8}><CreditCardOutlined />最近智能卡</Space>}
          style={{ ...cardStyle, marginBottom: 16 }}
          headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
          size="small"
        >
          {cards.length === 0 ? (
            <Empty description="暂无智能卡" image={Empty.PRESENTED_IMAGE_SIMPLE} />
          ) : (
            <List
              grid={{ gutter: 12, xs: 1, sm: 2, md: 3, lg: 4, xl: 5 }}
              dataSource={cards.slice(0, 10)}
              renderItem={(card) => {
                const cfg = securityLevelConfig[card.security_level] || securityLevelConfig.low;
                const totalCreds = (card.cert_stats?.x509 || 0) + (card.cert_stats?.fido || 0) + (card.cert_stats?.totp || 0) + (card.cert_stats?.creds || 0);
                return (
                  <List.Item>
                    <Card
                      size="small" hoverable
                      style={{
                        background: darkMode ? '#0d1117' : '#fafafa',
                        border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
                        borderRadius: 8,
                      }}
                      bodyStyle={{ padding: '12px 14px' }}
                    >
                      <Space direction="vertical" size={4} style={{ width: '100%' }}>
                        <Space size={4}>
                          <CreditCardOutlined style={{ color: '#1677ff', fontSize: 14 }} />
                          <Text strong style={{ fontSize: 13, color: darkMode ? '#c9d1d9' : '#333' }} ellipsis>
                            {card.card_name}
                          </Text>
                        </Space>
                        <Space size={4} wrap>
                          <Tag color={card.slot_type === 'cloud' ? 'purple' : card.slot_type === 'tpm2' ? 'cyan' : 'green'} style={{ fontSize: 10 }}>
                            {slotLabel(card.slot_type)}
                          </Tag>
                          <Tag color={cfg.color} style={{ fontSize: 10 }}>安全:{cfg.label}</Tag>
                        </Space>
                        <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>
                          凭据: {totalCreds} · {dayjs(card.created_at).format('MM-DD')}
                        </Text>
                      </Space>
                    </Card>
                  </List.Item>
                );
              }}
            />
          )}
        </Card>

        <Row gutter={[12, 12]}>
          {/* TOTP 验证码 */}
          <Col xs={24} lg={12}>
            <Card
              title={<Space size={8}><ClockCircleOutlined />TOTP 实时验证码</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
              size="small"
              extra={
                <Segmented
                  size="small"
                  value={totpView}
                  onChange={(v) => setTotpView(v as any)}
                  options={[
                    { value: 'grid', icon: <AppstoreOutlined /> },
                    { value: 'table', icon: <UnorderedListOutlined /> },
                  ]}
                />
              }
            >
              {totpItems.length === 0 ? (
                <Empty description="暂无 TOTP 条目" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : totpView === 'grid' ? (
                <Row gutter={[8, 8]}>
                  {totpItems.slice(0, 8).map((item) => (
                    <Col key={item.uuid} xs={12} sm={8} md={6}>
                      <TOTPGridCard item={item} darkMode={darkMode} />
                    </Col>
                  ))}
                </Row>
              ) : (
                <Table
                  dataSource={totpItems.slice(0, 8)} rowKey="uuid" pagination={false} size="small"
                  columns={[
                    { title: '服务', dataIndex: 'issuer', width: 100 },
                    { title: '账号', dataIndex: 'account', width: 140 },
                    {
                      title: '验证码', key: 'code', width: 180,
                      render: (_: any, item: TOTPRowData) => {
                        const isExpiring = (item.remaining ?? 30) <= 5;
                        return (
                          <Space>
                            <Text style={{ fontSize: 16, fontWeight: 700, letterSpacing: 2, color: isExpiring ? '#ff4d4f' : (darkMode ? '#c9d1d9' : '#333'), cursor: 'pointer' }}
                              onClick={() => { if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('已复制')); }}
                            >{item.code || '------'}</Text>
                            <Progress type="circle" size={18} percent={((item.remaining ?? 30) / (item.period || 30)) * 100} showInfo={false} strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'} />
                            <Text style={{ fontSize: 10, color: darkMode ? '#8b949e' : '#999' }}>{item.remaining}s</Text>
                            <Tooltip title="复制"><Button type="text" size="small" icon={<CopyOutlined />} onClick={() => { if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('已复制')); }} /></Tooltip>
                          </Space>
                        );
                      },
                    },
                  ]}
                />
              )}
            </Card>
          </Col>

          {/* 最近证书 */}
          <Col xs={24} lg={12}>
            <Card
              title={<Space size={8}><SafetyCertificateOutlined />最近证书</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
              size="small"
            >
              {certItems.length === 0 ? (
                <Empty description="暂无证书" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <Table
                  dataSource={certItems.slice(0, 6)} rowKey={(r) => r.cert.uuid} pagination={false} size="small"
                  columns={[
                    {
                      title: '类型', dataIndex: ['cert', 'cert_type'], width: 70,
                      render: (v: string) => <Tag color="blue">{certTypeLabels[v] || v}</Tag>,
                    },
                    {
                      title: '名称', width: 160,
                      render: (_: any, row: typeof certItems[0]) => (
                        <Text ellipsis style={{ fontSize: 12 }}>{row.cert.common_name || row.cert.key_type || '-'}</Text>
                      ),
                    },
                    { title: '卡片', dataIndex: 'cardName', width: 100, render: (v: string) => <Text style={{ fontSize: 11 }}>{v}</Text> },
                    {
                      title: '创建时间', dataIndex: ['cert', 'created_at'], width: 100,
                      render: (v: string) => <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{dayjs(v).format('MM-DD HH:mm')}</Text>,
                    },
                  ]}
                />
              )}
            </Card>
          </Col>
        </Row>

        {/* FIDO + 安全凭据 概览 */}
        <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
          <Col xs={24} lg={12}>
            <Card
              title={<Space size={8}><IdcardOutlined />FIDO 凭据</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
              size="small"
            >
              {fidoCount === 0 ? (
                <Empty description="暂无 FIDO 凭据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <div style={{ textAlign: 'center', padding: '20px 0' }}>
                  <Statistic value={fidoCount} suffix="个 FIDO 凭据" valueStyle={{ color: '#13c2c2', fontSize: 28 }} />
                  <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>
                    分布在 {cards.filter(c => c.cert_stats && c.cert_stats.fido > 0).length} 张智能卡中
                  </Text>
                </div>
              )}
            </Card>
          </Col>
          <Col xs={24} lg={12}>
            <Card
              title={<Space size={8}><LockOutlined />安全凭据</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
              size="small"
            >
              {credCount === 0 ? (
                <Empty description="暂无安全凭据" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <div style={{ textAlign: 'center', padding: '20px 0' }}>
                  <Statistic value={credCount} suffix="个安全凭据" valueStyle={{ color: '#52c41a', fontSize: 28 }} />
                  <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>
                    包含登录凭据、安全笔记、支付信息等
                  </Text>
                </div>
              )}
            </Card>
          </Col>
        </Row>
      </Spin>
    </div>
  );
};

export default Dashboard;
