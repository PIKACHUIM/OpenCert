// Dashboard 多账号聚合视图
import React, { useEffect, useState, useCallback, memo } from 'react';
import {
  Row, Col, Table, Tag, Typography, Space, Spin, Alert,
  Button, Tooltip, Progress, message, Segmented, Empty, Badge, Modal, Input,
} from 'antd';
import {
  CreditCardOutlined, SafetyCertificateOutlined,
  ClockCircleOutlined, CopyOutlined,
  SyncOutlined, AppstoreOutlined, UnorderedListOutlined,
  LockOutlined, IdcardOutlined, DashboardOutlined, UserOutlined,
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

// ---- 统计卡片 ----
const StatCard: React.FC<{
  label: string;
  value: number;
  icon: React.ReactNode;
  color: string;
  bgColor: string;
  darkMode: boolean;
}> = ({ label, value, icon, color, bgColor, darkMode }) => (
  <div style={{
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderLeft: `3px solid ${color}`,
    borderRadius: 10,
    padding: '16px 18px',
    display: 'flex',
    alignItems: 'center',
    gap: 14,
    height: '100%',
  }}>
    <div style={{
      width: 44, height: 44, borderRadius: 10,
      background: bgColor,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontSize: 20, color,
      flexShrink: 0,
    }}>
      {icon}
    </div>
    <div>
      <div style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 700, lineHeight: 1, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>{value}</div>
    </div>
  </div>
);

// ---- 智能卡卡片 ----
const SmartCardItem: React.FC<{ card: CardType; darkMode: boolean }> = ({ card, darkMode }) => {
  const securityConfig: Record<string, { color: string; bg: string; label: string }> = {
    high: { color: '#ff4d4f', bg: 'rgba(255,77,79,0.1)', label: '高' },
    medium: { color: '#fa8c16', bg: 'rgba(250,140,22,0.1)', label: '中' },
    low: { color: '#52c41a', bg: 'rgba(82,196,26,0.1)', label: '低' },
  };
  const cfg = securityConfig[card.security_level] || securityConfig.low;
  const slotColors: Record<string, string> = { cloud: '#722ed1', tpm2: '#13c2c2', tpmsc: '#1677ff', local: '#52c41a' };
  const slotLabels: Record<string, string> = { cloud: '云端', tpm2: 'TPM2', tpmsc: 'TPM卡', local: '本地' };
  const totalCreds = (card.cert_stats?.x509 || 0) + (card.cert_stats?.fido || 0) + (card.cert_stats?.totp || 0) + (card.cert_stats?.creds || 0);
  const slotColor = slotColors[card.slot_type] || slotColors.local;

  return (
    <div style={{
      background: darkMode ? '#0d1117' : '#fafafa',
      border: darkMode ? '1px solid #21262d' : '1px solid #eee',
      borderRadius: 10,
      padding: '14px 16px',
      minWidth: 200,
      maxWidth: 240,
      flexShrink: 0,
      cursor: 'pointer',
      transition: 'all 0.2s',
    }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = slotColor)}
      onMouseLeave={e => (e.currentTarget.style.borderColor = darkMode ? '#21262d' : '#eee')}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: `${slotColor}18`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <CreditCardOutlined style={{ color: slotColor, fontSize: 15 }} />
        </div>
        <Text strong style={{ fontSize: 13, color: darkMode ? '#c9d1d9' : '#333', flex: 1 }} ellipsis>
          {card.card_name}
        </Text>
      </div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <span style={{
          fontSize: 10, padding: '1px 7px', borderRadius: 4,
          background: `${slotColor}18`, color: slotColor, fontWeight: 500,
        }}>
          {slotLabels[card.slot_type] || '本地'}
        </span>
        <span style={{
          fontSize: 10, padding: '1px 7px', borderRadius: 4,
          background: cfg.bg, color: cfg.color, fontWeight: 500,
        }}>
          安全:{cfg.label}
        </span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Text style={{ fontSize: 11, color: darkMode ? '#6e7681' : '#bbb' }}>
          {totalCreds} 个凭据
        </Text>
        <Text style={{ fontSize: 11, color: darkMode ? '#6e7681' : '#bbb' }}>
          {dayjs(card.created_at).format('MM-DD')}
        </Text>
      </div>
    </div>
  );
};

// localStorage PIN 缓存前缀（与 TOTP 页面共用）
const PIN_CACHE_PREFIX = 'totp_pin_';
const getCachedPin = (cardUUID: string) => localStorage.getItem(`${PIN_CACHE_PREFIX}${cardUUID}`) || '';

// ---- TOTP 网格卡片 ----
const TOTPGridCard = memo<{ item: TOTPRowData; darkMode: boolean }>(({ item, darkMode }) => {
  const isExpiring = (item.remaining ?? 30) <= 5;
  const pct = ((item.remaining ?? 30) / (item.period || 30)) * 100;
  const handleCopy = () => {
    if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('验证码已复制'));
  };
  return (
    <div
      onClick={handleCopy}
      style={{
        background: darkMode ? '#161b22' : '#fff',
        border: `1px solid ${isExpiring ? '#ff4d4f40' : (darkMode ? '#21262d' : '#f0f0f0')}`,
        borderRadius: 10,
        padding: '14px 12px',
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'all 0.2s',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* 背景装饰 */}
      <div style={{
        position: 'absolute', top: -10, right: -10,
        width: 50, height: 50, borderRadius: '50%',
        background: isExpiring ? 'rgba(255,77,79,0.06)' : 'rgba(22,119,255,0.06)',
      }} />
      <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999', display: 'block', marginBottom: 4 }}>
        {item.issuer || '-'}
      </Text>
      <div style={{
        fontSize: item.code ? 22 : 13,
        fontWeight: 700,
        letterSpacing: item.code ? 4 : 0,
        color: item.code
          ? (isExpiring ? '#ff4d4f' : (darkMode ? '#e6edf3' : '#1a1a2e'))
          : (darkMode ? '#6e7681' : '#bbb'),
        fontFamily: 'monospace',
        marginBottom: 6,
      }}>
        {item.code || '需要 PIN 解锁'}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
        <Text style={{ fontSize: 10, color: darkMode ? '#6e7681' : '#bbb' }}>{item.account}</Text>
        <Progress
          type="circle" size={16} percent={pct} showInfo={false}
          strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'}
          railColor={darkMode ? '#21262d' : '#f0f0f0'}
        />
        <Text style={{ fontSize: 10, color: isExpiring ? '#ff4d4f' : (darkMode ? '#6e7681' : '#bbb'), fontWeight: isExpiring ? 600 : 400 }}>
          {item.remaining ?? 0}s
        </Text>
      </div>
    </div>
  );
});

// ---- 主组件 ----
const Dashboard: React.FC = () => {
  const { connected, darkMode } = useAppStore();
  const accounts = useAuthStore((s) => s.accounts);

  const [cards, setCards] = useState<CardType[]>([]);
  const [certItems, setCertItems] = useState<{ cert: Certificate; cardName: string; ownerName: string }[]>([]);
  const [totpItems, setTotpItems] = useState<TOTPRowData[]>([]);
  const [fidoCount, setFidoCount] = useState(0);
  const [credCount, setCredCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [totpView, setTotpView] = useState<'table' | 'grid'>('grid');
  const [stats, setStats] = useState({ cards: 0, certs: 0, totp: 0, fido: 0, creds: 0 });
  // PIN 弹窗
  const [pinVisible, setPinVisible] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [pinLoading, setPinLoading] = useState(false);
  // 已解锁的卡片 PIN map: cardUUID -> pin
  const [unlockedPins, setUnlockedPins] = useState<Record<string, string>>(() => {
    // 初始化时从 localStorage 读取所有缓存 PIN
    const result: Record<string, string> = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(PIN_CACHE_PREFIX)) {
        const cardUUID = key.slice(PIN_CACHE_PREFIX.length);
        result[cardUUID] = localStorage.getItem(key) || '';
      }
    }
    return result;
  });

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
      setStats({ cards: allCards.length, certs: certAcc.length, totp: totpAcc.length, fido: fidoTotal, creds: credTotal });
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }, [connected, accounts]);

  useEffect(() => { loadData(); }, [loadData]);

  // 用已知 PIN 获取所有 TOTP 验证码
  const fetchCodesWithPins = useCallback(async (items: TOTPRowData[], pins: Record<string, string>) => {
    for (const item of items) {
      const pin = pins[item.card_uuid];
      if (!pin) continue;
      try {
        const resp = await getTOTPCode(item.uuid, pin);
        setTotpItems(prev => prev.map(t =>
          t.uuid === item.uuid ? { ...t, code: resp.code } : t
        ));
      } catch { /* 静默失败 */ }
    }
  }, []);

  // 确认 PIN 输入，尝试解锁所有属于该卡片的 TOTP
  const handlePinConfirm = useCallback(async () => {
    if (!pinInput) return;
    setPinLoading(true);
    // 找到第一个没有 PIN 的卡片 UUID
    const lockedCardUUIDs = [...new Set(
      totpItems.filter(t => !unlockedPins[t.card_uuid]).map(t => t.card_uuid)
    )];
    if (lockedCardUUIDs.length === 0) { setPinVisible(false); return; }
    // 尝试用该 PIN 解锁第一张卡的第一条 TOTP
    const firstItem = totpItems.find(t => t.card_uuid === lockedCardUUIDs[0]);
    if (!firstItem) { setPinLoading(false); return; }
    try {
      await getTOTPCode(firstItem.uuid, pinInput);
      // PIN 正确，保存并获取所有该卡片的验证码
      const newPins = { ...unlockedPins };
      lockedCardUUIDs.forEach(uuid => {
        newPins[uuid] = pinInput;
        localStorage.setItem(`${PIN_CACHE_PREFIX}${uuid}`, pinInput);
      });
      setUnlockedPins(newPins);
      setPinVisible(false);
      setPinInput('');
      fetchCodesWithPins(totpItems, newPins);
    } catch (err: any) {
      message.error(err.message || 'PIN 错误');
    } finally {
      setPinLoading(false);
    }
  }, [pinInput, totpItems, unlockedPins, fetchCodesWithPins]);

  // 有新 TOTP 条目时，用缓存 PIN 自动获取验证码
  useEffect(() => {
    if (totpItems.length > 0 && Object.keys(unlockedPins).length > 0) {
      fetchCodesWithPins(totpItems, unlockedPins);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totpItems.length]);

  // TOTP 倒计时 + 周期切换时刷新验证码
  useEffect(() => {
    if (totpItems.length === 0) return;
    const prevRemainingMap = new Map<string, number>();
    let cancelled = false;
    const timer = setInterval(() => {
      if (cancelled) return;
      const now = Math.floor(Date.now() / 1000);
      setTotpItems(prev => prev.map(item => {
        const period = item.period || 30;
        const remaining = period - (now % period);
        const prevRemaining = prevRemainingMap.get(item.uuid) ?? remaining;
        // 周期切换时刷新验证码
        if (prevRemaining < remaining && prevRemaining <= 2) {
          const pin = unlockedPins[item.card_uuid];
          if (pin) {
            getTOTPCode(item.uuid, pin).then(resp => {
              setTotpItems(p => p.map(t =>
                t.uuid === item.uuid ? { ...t, code: resp.code } : t
              ));
            }).catch(() => {});
          }
        }
        prevRemainingMap.set(item.uuid, remaining);
        return { ...item, remaining };
      }));
    }, 1000);
    return () => { cancelled = true; clearInterval(timer); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totpItems.length, unlockedPins]);

  const bg = darkMode ? '#0d1117' : '#f5f7fa';
  const cardBg = darkMode ? '#161b22' : '#fff';
  const cardBorder = darkMode ? '1px solid #21262d' : '1px solid #eef0f3';
  const textMuted = darkMode ? '#8b949e' : '#8c8c8c';

  const certTypeLabels: Record<string, string> = {
    x509: 'X509', ssh: 'SSH', gpg: 'GPG', totp: 'TOTP',
    fido: 'FIDO', login: '登录', text: '文本', note: '笔记', payment: '支付',
  };
  const certTypeColors: Record<string, string> = {
    x509: 'blue', ssh: 'green', gpg: 'purple', totp: 'orange',
    fido: 'cyan', login: 'geekblue', text: 'default', note: 'gold', payment: 'red',
  };

  return (
    <div style={{ background: bg, minHeight: '100%' }}>
      <PageHeader
        icon={<DashboardOutlined />}
        title="系统概览"
        tags={
          <Space size={6}>
            <Badge status={connected ? 'success' : 'error'} />
            <Text style={{ fontSize: 12, color: textMuted }}>
              {connected ? `已连接 · ${accounts.length} 个账号` : '未连接'}
            </Text>
          </Space>
        }
        extra={
          <Button icon={<SyncOutlined />} onClick={loadData} loading={loading} size="small">刷新</Button>
        }
      />

      {!connected && (
        <Alert
          title="未连接到 client-card 服务"
          description="请确保 client-card 服务已启动（默认端口 1026）"
          type="warning" showIcon style={{ marginBottom: 16 }}
        />
      )}

      <Spin spinning={loading}>
        {/* ── 统计卡片 ── */}
        <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
          {[
            { label: '用户数', value: accounts.length, icon: <UserOutlined />, color: '#eb2f96', bg: 'rgba(235,47,150,0.1)' },
            { label: '智能卡', value: stats.cards, icon: <CreditCardOutlined />, color: '#1677ff', bg: 'rgba(22,119,255,0.1)' },
            { label: '证书', value: stats.certs, icon: <SafetyCertificateOutlined />, color: '#722ed1', bg: 'rgba(114,46,209,0.1)' },
            { label: 'TOTP 条目', value: stats.totp, icon: <ClockCircleOutlined />, color: '#fa8c16', bg: 'rgba(250,140,22,0.1)' },
            { label: 'FIDO 凭据', value: stats.fido, icon: <IdcardOutlined />, color: '#13c2c2', bg: 'rgba(19,194,194,0.1)' },
            { label: '安全凭据', value: stats.creds, icon: <LockOutlined />, color: '#52c41a', bg: 'rgba(82,196,26,0.1)' },
          ].map((s) => (
            <Col key={s.label} xs={12} sm={8} md={8} lg={4} xl={4}>
              <StatCard {...s} bgColor={s.bg} darkMode={darkMode} />
            </Col>
          ))}
        </Row>

        {/* ── 最近智能卡（横向滚动） ── */}
        <div style={{
          background: cardBg, border: cardBorder, borderRadius: 10,
          padding: '14px 18px', marginBottom: 16,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <Space size={8}>
              <div style={{
                width: 28, height: 28, borderRadius: 7,
                background: 'rgba(22,119,255,0.1)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <CreditCardOutlined style={{ color: '#1677ff', fontSize: 14 }} />
              </div>
              <Text strong style={{ fontSize: 14, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>最近智能卡</Text>
              <Tag color="blue" style={{ fontSize: 10, borderRadius: 4 }}>{cards.length}</Tag>
            </Space>
          </div>
          {cards.length === 0 ? (
            <Empty description="暂无智能卡" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '20px 0' }} />
          ) : (
            <div style={{ display: 'flex', gap: 10, overflowX: 'auto', paddingBottom: 4 }}>
              {cards.slice(0, 10).map((card) => (
                <SmartCardItem key={card.uuid} card={card} darkMode={darkMode} />
              ))}
            </div>
          )}
        </div>

        {/* ── 中间两栏：TOTP + 最近证书 ── */}
        <Row gutter={[12, 12]} style={{ marginBottom: 12 }}>
          {/* TOTP 验证码 */}
          <Col xs={24} lg={12}>
            <div style={{ background: cardBg, border: cardBorder, borderRadius: 10, padding: '14px 18px', height: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <Space size={8}>
                  <div style={{
                    width: 28, height: 28, borderRadius: 7,
                    background: 'rgba(250,140,22,0.1)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <ClockCircleOutlined style={{ color: '#fa8c16', fontSize: 14 }} />
                  </div>
                  <Text strong style={{ fontSize: 14, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>TOTP 实时验证码</Text>
                  {totpItems.length > 0 && (
                    <Tag color="orange" style={{ fontSize: 10, borderRadius: 4 }}>{totpItems.length}</Tag>
                  )}
                  {totpItems.some(t => !unlockedPins[t.card_uuid]) && (
                    <Button
                      size="small" type="primary" ghost
                      icon={<LockOutlined />}
                      onClick={() => { setPinInput(''); setPinVisible(true); }}
                      style={{ fontSize: 11 }}
                    >
                      输入 PIN
                    </Button>
                  )}
                </Space>
                <Segmented
                  size="small"
                  value={totpView}
                  onChange={(v) => setTotpView(v as any)}
                  options={[
                    { value: 'grid', icon: <AppstoreOutlined /> },
                    { value: 'table', icon: <UnorderedListOutlined /> },
                  ]}
                />
              </div>
              {totpItems.length === 0 ? (
                <Empty description="暂无 TOTP 条目" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '20px 0' }} />
              ) : totpView === 'grid' ? (
                <Row gutter={[8, 8]}>
                  {totpItems.slice(0, 8).map((item) => (
                    <Col key={item.uuid} xs={12} sm={8}>
                      <TOTPGridCard item={item} darkMode={darkMode} />
                    </Col>
                  ))}
                </Row>
              ) : (
                <Table
                  dataSource={totpItems.slice(0, 8)} rowKey="uuid" pagination={false} size="small"
                  style={{ fontSize: 12 }}
                  columns={[
                    { title: '服务', dataIndex: 'issuer', width: 90, render: (v: string) => <Text style={{ fontSize: 12 }}>{v || '-'}</Text> },
                    { title: '账号', dataIndex: 'account', ellipsis: true, render: (v: string) => <Text style={{ fontSize: 12 }} ellipsis>{v || '-'}</Text> },
                    {
                      title: '验证码', key: 'code', width: 160,
                      render: (_: any, item: TOTPRowData) => {
                        const isExpiring = (item.remaining ?? 30) <= 5;
                        return (
                          <Space size={4}>
                            <Text
                              style={{ fontSize: 15, fontWeight: 700, letterSpacing: 2, fontFamily: 'monospace', color: isExpiring ? '#ff4d4f' : (darkMode ? '#e6edf3' : '#1a1a2e'), cursor: 'pointer' }}
                              onClick={() => { if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('已复制')); }}
                            >{item.code || '------'}</Text>
                            <Progress type="circle" size={16} percent={((item.remaining ?? 30) / (item.period || 30)) * 100} showInfo={false} strokeColor={isExpiring ? '#ff4d4f' : '#1677ff'} />
                            <Tooltip title="复制">
                              <Button type="text" size="small" icon={<CopyOutlined />} onClick={() => { if (item.code) navigator.clipboard.writeText(item.code).then(() => message.success('已复制')); }} />
                            </Tooltip>
                          </Space>
                        );
                      },
                    },
                  ]}
                />
              )}
            </div>
          </Col>

          {/* 最近证书 */}
          <Col xs={24} lg={12}>
            <div style={{ background: cardBg, border: cardBorder, borderRadius: 10, padding: '14px 18px', height: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                <Space size={8}>
                  <div style={{
                    width: 28, height: 28, borderRadius: 7,
                    background: 'rgba(114,46,209,0.1)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <SafetyCertificateOutlined style={{ color: '#722ed1', fontSize: 14 }} />
                  </div>
                  <Text strong style={{ fontSize: 14, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>最近证书</Text>
                  {certItems.length > 0 && (
                    <Tag color="purple" style={{ fontSize: 10, borderRadius: 4 }}>{certItems.length}</Tag>
                  )}
                </Space>
              </div>
              {certItems.length === 0 ? (
                <Empty description="暂无证书" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '20px 0' }} />
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {certItems.slice(0, 6).map((row) => (
                    <div key={row.cert.uuid} style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 10px', borderRadius: 8,
                      background: darkMode ? '#0d1117' : '#fafafa',
                      border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
                    }}>
                      <Tag
                        color={certTypeColors[row.cert.cert_type] || 'default'}
                        style={{ fontSize: 10, borderRadius: 4, margin: 0, flexShrink: 0 }}
                      >
                        {certTypeLabels[row.cert.cert_type] || row.cert.cert_type}
                      </Tag>
                      <Text ellipsis style={{ flex: 1, fontSize: 12, color: darkMode ? '#c9d1d9' : '#333' }}>
                        {row.cert.common_name || row.cert.key_type || '-'}
                      </Text>
                      <Text style={{ fontSize: 11, color: textMuted, flexShrink: 0, maxWidth: 120 }} ellipsis>
                        {row.cardName}
                      </Text>
                      <Text style={{ fontSize: 11, color: textMuted, flexShrink: 0 }}>
                        {dayjs(row.cert.created_at).format('MM-DD HH:mm')}
                      </Text>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Col>
        </Row>

        {/* ── 底部两栏：FIDO + 安全凭据 ── */}
        <Row gutter={[12, 12]}>
      <Col xs={24} lg={12}>
            <div style={{ background: cardBg, border: cardBorder, borderRadius: 10, padding: '14px 18px', height: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 7,
                  background: 'rgba(19,194,194,0.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <IdcardOutlined style={{ color: '#13c2c2', fontSize: 14 }} />
                </div>
                <Text strong style={{ fontSize: 14, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>FIDO 凭据</Text>
              </div>
              {fidoCount === 0 ? (
                <Empty description="暂无 FIDO 凭据" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '16px 0' }} />
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '8px 0' }}>
                  <div style={{
                    width: 64, height: 64, borderRadius: 16,
                    background: 'rgba(19,194,194,0.1)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 28, fontWeight: 700, color: '#13c2c2',
                  }}>
                    {fidoCount}
                  </div>
                  <div>
                    <Text style={{ fontSize: 15, fontWeight: 600, color: darkMode ? '#e6edf3' : '#1a1a2e', display: 'block' }}>
                      个 FIDO 凭据
                    </Text>
                    <Text style={{ fontSize: 12, color: textMuted }}>
                      分布在 {cards.filter(c => c.cert_stats && c.cert_stats.fido > 0).length} 张智能卡中
                    </Text>
                  </div>
                </div>
              )}
            </div>
          </Col>
      <Col xs={24} lg={12}>
            <div style={{ background: cardBg, border: cardBorder, borderRadius: 10, padding: '14px 18px', height: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                <div style={{
                  width: 28, height: 28, borderRadius: 7,
                  background: 'rgba(82,196,26,0.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <LockOutlined style={{ color: '#52c41a', fontSize: 14 }} />
                </div>
                <Text strong style={{ fontSize: 14, color: darkMode ? '#e6edf3' : '#1a1a2e' }}>安全凭据</Text>
              </div>
              {credCount === 0 ? (
                <Empty description="暂无安全凭据" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: '16px 0' }} />
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '8px 0' }}>
                  <div style={{
                    width: 64, height: 64, borderRadius: 16,
                    background: 'rgba(82,196,26,0.1)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 28, fontWeight: 700, color: '#52c41a',
                  }}>
                    {credCount}
                  </div>
                  <div>
                    <Text style={{ fontSize: 15, fontWeight: 600, color: darkMode ? '#e6edf3' : '#1a1a2e', display: 'block' }}>
                      个安全凭据
                    </Text>
                    <Text style={{ fontSize: 12, color: textMuted }}>
                      包含登录凭据、安全笔记、支付信息等
                    </Text>
                  </div>
                </div>
              )}
            </div>
          </Col>
        </Row>
      </Spin>

      {/* PIN 输入弹窗 */}
      <Modal
        title={<Space><LockOutlined />输入卡片 PIN 查看验证码</Space>}
        open={pinVisible}
        onOk={handlePinConfirm}
        onCancel={() => { setPinVisible(false); setPinInput(''); }}
        confirmLoading={pinLoading}
        okText="解锁"
        width={360}
      >
        <div style={{ marginTop: 16 }}>
          <Input.Password
            placeholder="请输入卡片 PIN"
            autoComplete="current-password"
            value={pinInput}
            onChange={e => setPinInput(e.target.value)}
            onPressEnter={handlePinConfirm}
            autoFocus
          />
          <Text type="secondary" style={{ fontSize: 12, marginTop: 8, display: 'block' }}>
            PIN 将缓存在本地，下次自动解锁
          </Text>
        </div>
      </Modal>
    </div>
  );
};

export default Dashboard;
