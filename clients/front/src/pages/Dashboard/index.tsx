// Dashboard 多账号聚合视图：
//   - 4 个统计卡片：已登录账号数 / Slot 状态 / 证书总数 / TOTP 条目总数
//   - TOTP 实时验证码卡片（汇总所有已登录账号，支持表格/方格视图切换，点击复制）
//   - 证书列表卡片（所有已登录账号的证书，点击查看详情抽屉）
//   - 最近操作日志
import React, { useEffect, useState, useCallback, useMemo, memo } from 'react';
import {
  Row, Col, Card, Statistic, Badge, Table, Tag, Typography, Space, Spin, Alert,
  Button, Tooltip, Progress, Drawer, Descriptions, message, Segmented, Empty,
} from 'antd';
import {
  CreditCardOutlined, UserOutlined, SafetyCertificateOutlined, ApiOutlined,
  CheckCircleOutlined, CloseCircleOutlined, ClockCircleOutlined, CopyOutlined,
  SyncOutlined, AppstoreOutlined, UnorderedListOutlined, KeyOutlined,
} from '@ant-design/icons';
import { useAppStore } from '../../store/appStore';
import { useAuthStore } from '../../store/auth';
import { getCards, getLogs, getCerts, getTOTPList, getTOTPCode } from '../../api';
import type { Log, Card as CardType, Certificate, TOTPEntry } from '../../types';
import dayjs from 'dayjs';

const { Title, Text } = Typography;

// ---- TOTP 行组件（memo 避免全表重渲染）----
interface TOTPRowData extends TOTPEntry {
  code?: string;
  remaining?: number;
  ownerName?: string;
}

const TOTPCodeCell = memo<{ item: TOTPRowData; darkMode: boolean }>(({ item, darkMode }) => {
  const isExpiring = (item.remaining ?? 30) <= 5;
  const pct = ((item.remaining ?? 30) / (item.period || 30)) * 100;

  const handleCopy = () => {
    if (item.code) {
      navigator.clipboard.writeText(item.code).then(() => message.success('验证码已复制'));
    }
  };

  return (
    <Space>
      <Text
        style={{
          fontFamily: 'monospace', fontSize: 18, fontWeight: 700, letterSpacing: 2,
          color: isExpiring ? '#ff4d4f' : (darkMode ? '#c9d1d9' : '#333'),
          cursor: 'pointer',
        }}
        onClick={handleCopy}
      >
        {item.code || '------'}
      </Text>
      <Progress
        type="circle" size={22} percent={pct} showInfo={false}
        strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'}
      />
      <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{item.remaining ?? '-'}s</Text>
      <Tooltip title="复制"><Button type="text" size="small" icon={<CopyOutlined />} onClick={handleCopy} /></Tooltip>
    </Space>
  );
});

// ---- TOTP 方格卡片 ----
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
        borderRadius: 12, textAlign: 'center',
      }}
      bodyStyle={{ padding: '16px 12px' }}
    >
      <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{item.issuer}</Text>
      <div style={{ margin: '6px 0' }}>
        <Text style={{
          fontFamily: 'monospace', fontSize: 22, fontWeight: 700, letterSpacing: 3,
          color: isExpiring ? '#ff4d4f' : (darkMode ? '#c9d1d9' : '#333'),
        }}>
          {item.code || '------'}
        </Text>
      </div>
      <Space size={4}>
        <Text style={{ fontSize: 11, color: darkMode ? '#6e7681' : '#bbb' }}>{item.account}</Text>
        <Progress type="circle" size={16} percent={pct} showInfo={false} strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'} />
      </Space>
    </Card>
  );
});

// ---- 主组件 ----
const Dashboard: React.FC = () => {
  const { connected, slots, slotsLoading, darkMode } = useAppStore();
  const accounts = useAuthStore((s) => s.accounts);

  const [cardCount, setCardCount] = useState(0);
  const [certCount, setCertCount] = useState(0);
  const [totpItems, setTotpItems] = useState<TOTPRowData[]>([]);
  const [certItems, setCertItems] = useState<{ cert: Certificate; cardName: string; ownerName: string }[]>([]);
  const [recentLogs, setRecentLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(true);
  const [totpView, setTotpView] = useState<'table' | 'grid'>('grid');
  const [certDrawer, setCertDrawer] = useState<Certificate | null>(null);

  // 加载聚合数据
  const loadData = useCallback(async () => {
    if (!connected) return;
    setLoading(true);
    try {
      // 卡片 + 日志
      const [cardsRes, logsRes] = await Promise.all([
        getCards({ page: 1, page_size: 200 }),
        getLogs({ page: 1, page_size: 8 }),
      ]);
      const allCards: CardType[] = Array.isArray(cardsRes?.items) ? cardsRes.items : [];
      setCardCount(allCards.length);
      const logItems = Array.isArray(logsRes?.items) ? logsRes.items : [];
      setRecentLogs(logItems);

      // 遍历所有卡片拉取证书 + TOTP
      const certAcc: typeof certItems = [];
      const totpAcc: TOTPRowData[] = [];

      await Promise.all(allCards.map(async (card) => {
        const owner = accounts.find((a) => a.user_uuid === card.user_uuid);
        const ownerName = owner?.display_name || card.user_uuid.slice(0, 8);
        try {
          const certs = await getCerts(card.uuid);
          (Array.isArray(certs) ? certs : []).forEach((c) => certAcc.push({ cert: c, cardName: card.card_name, ownerName }));
        } catch { /* ignore */ }
        try {
          const totps = await getTOTPList(card.uuid);
          (Array.isArray(totps) ? totps : []).forEach((t) => totpAcc.push({ ...t, ownerName }));
        } catch { /* ignore */ }
      }));

      setCertItems(certAcc);
      setCertCount(certAcc.length);
      setTotpItems(totpAcc);
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [connected, accounts]);

  useEffect(() => { loadData(); }, [loadData]);

  // TOTP 验证码定时刷新（单计时器）
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

    refresh(); // 立即刷新一次
    const timer = setInterval(refresh, 1000);
    return () => { cancelled = true; clearInterval(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totpItems.length]);

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const logColumns = [
    {
      title: '时间', dataIndex: 'created_at', width: 140,
      render: (v: string) => <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>{dayjs(v).format('MM-DD HH:mm:ss')}</Text>,
    },
    {
      title: '级别', dataIndex: 'level', width: 70,
      render: (v: string) => <Tag color={v === 'error' ? 'red' : v === 'warn' ? 'orange' : 'blue'} style={{ fontSize: 11 }}>{v?.toUpperCase()}</Tag>,
    },
    { title: '标题', dataIndex: 'title', render: (v: string) => <Text style={{ fontSize: 13 }}>{v}</Text> },
  ];

  const totpColumns = [
    { title: '服务', dataIndex: 'issuer', width: 120 },
    { title: '账号', dataIndex: 'account', width: 160 },
    { title: '所属', dataIndex: 'ownerName', width: 100, render: (v: string) => <Tag>{v}</Tag> },
    {
      title: '验证码', key: 'code', width: 220,
      render: (_: any, item: TOTPRowData) => <TOTPCodeCell item={item} darkMode={darkMode} />,
    },
  ];

  const certColumns = [
    { title: '类型', dataIndex: ['cert', 'cert_type'], width: 70, render: (v: string) => <Tag color="blue">{v}</Tag> },
    { title: '密钥', dataIndex: ['cert', 'key_type'], width: 80 },
    { title: '卡片', dataIndex: 'cardName', width: 120 },
    { title: '所属', dataIndex: 'ownerName', width: 100, render: (v: string) => <Tag>{v}</Tag> },
    {
      title: '操作', key: 'action', width: 70,
      render: (_: any, row: typeof certItems[0]) => (
        <Button type="link" size="small" onClick={() => setCertDrawer(row.cert)}>详情</Button>
      ),
    },
  ];

  return (
    <div>
      <Space style={{ marginBottom: 24, width: '100%', justifyContent: 'space-between' }}>
        <Title level={4} style={{ margin: 0, color: darkMode ? '#c9d1d9' : undefined }}>系统概览</Title>
        <Button icon={<SyncOutlined />} onClick={loadData} loading={loading} size="small">刷新</Button>
      </Space>

      {!connected && (
        <Alert message="未连接到 client-card 服务" description="请确保 client-card 服务已启动（默认端口 1026）" type="warning" showIcon style={{ marginBottom: 24 }} />
      )}

      <Spin spinning={loading}>
        {/* 统计卡片 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} sm={12} lg={6}>
            <Card style={cardStyle} bodyStyle={{ padding: '20px 24px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666' }}>已登录账号</Text>}
                value={accounts.length}
                prefix={<UserOutlined style={{ color: '#1677ff' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Card style={cardStyle} bodyStyle={{ padding: '20px 24px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666' }}>活跃 Slot</Text>}
                value={slots.filter((s) => s.token_present).length}
                suffix={`/ ${slots.length}`}
                prefix={<SafetyCertificateOutlined style={{ color: '#722ed1' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Card style={cardStyle} bodyStyle={{ padding: '20px 24px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666' }}>证书总数</Text>}
                value={certCount}
                prefix={<KeyOutlined style={{ color: '#52c41a' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} lg={6}>
            <Card style={cardStyle} bodyStyle={{ padding: '20px 24px' }}>
              <Statistic
                title={<Text style={{ color: darkMode ? '#8b949e' : '#666' }}>TOTP 条目</Text>}
                value={totpItems.length}
                prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />}
                valueStyle={{ color: darkMode ? '#c9d1d9' : undefined }}
              />
            </Card>
          </Col>
        </Row>

        {/* TOTP 验证码卡片 */}
        <Card
          title={<Space><ClockCircleOutlined />TOTP 实时验证码</Space>}
          style={{ ...cardStyle, marginBottom: 16 }}
          headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
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
            <Row gutter={[12, 12]}>
              {totpItems.map((item) => (
                <Col key={item.uuid} xs={12} sm={8} md={6} lg={4}>
                  <TOTPGridCard item={item} darkMode={darkMode} />
                </Col>
              ))}
            </Row>
          ) : (
            <Table dataSource={totpItems} columns={totpColumns} rowKey="uuid" pagination={{ pageSize: 10, size: 'small' }} size="small" />
          )}
        </Card>

        <Row gutter={[16, 16]}>
          {/* 证书列表卡片 */}
          <Col xs={24} lg={14}>
            <Card
              title={<Space><SafetyCertificateOutlined />证书列表</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
            >
              {certItems.length === 0 ? (
                <Empty description="暂无证书" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <Table dataSource={certItems} columns={certColumns} rowKey={(r) => r.cert.uuid} pagination={{ pageSize: 5, size: 'small' }} size="small" />
              )}
            </Card>
          </Col>

          {/* 最近操作日志 */}
          <Col xs={24} lg={10}>
            <Card
              title={<Space><ApiOutlined />最近操作日志</Space>}
              style={cardStyle}
              headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
            >
              <Table dataSource={recentLogs} columns={logColumns} rowKey="uuid" pagination={false} size="small" />
            </Card>
          </Col>
        </Row>
      </Spin>

      {/* 证书详情抽屉 */}
      <Drawer
        title="证书详情"
        open={!!certDrawer}
        onClose={() => setCertDrawer(null)}
        width={480}
      >
        {certDrawer && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="UUID">{certDrawer.uuid}</Descriptions.Item>
            <Descriptions.Item label="类型">{certDrawer.cert_type}</Descriptions.Item>
            <Descriptions.Item label="密钥类型">{certDrawer.key_type}</Descriptions.Item>
            <Descriptions.Item label="Slot 类型">{certDrawer.slot_type}</Descriptions.Item>
            <Descriptions.Item label="卡片 UUID">{certDrawer.card_uuid}</Descriptions.Item>
            <Descriptions.Item label="备注">{certDrawer.remark || '-'}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{dayjs(certDrawer.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
            {certDrawer.cert_content && (
              <Descriptions.Item label="证书内容（Base64）">
                <Text copyable style={{ fontSize: 11, wordBreak: 'break-all', maxHeight: 200, overflow: 'auto', display: 'block' }}>
                  {certDrawer.cert_content}
                </Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Drawer>
    </div>
  );
};

export default Dashboard;