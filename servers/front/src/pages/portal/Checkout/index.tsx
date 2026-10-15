import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert, Breadcrumb, Button, Card, Col, Divider, Radio, Result, Row,
  Space, Spin, Tag, Typography, message,
} from 'antd';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  CheckCircleFilled, CopyOutlined, ReloadOutlined, WalletOutlined,
} from '@ant-design/icons';
import {
  getBalance, getMyPortalOrder, getPortalOrderPayment,
  listPortalPaymentChannels, payPortalOrder,
} from '../../../api';
import type { CertOrder, CheckoutResult, PaymentAttempt, PaymentChannel, UserBalance } from '../../../types';

const { Title, Text, Paragraph } = Typography;

/** 支付状态轮询间隔 */
const POLL_INTERVAL_MS = 3000;

/**
 * 收银台。
 *
 * 金额与渠道由服务端校验：余额支付当场结算，第三方渠道返回支付链接/二维码，
 * 之后通过轮询自有订单接口确认结果（不依赖渠道前端回调）。
 */
const PortalCheckout: React.FC = () => {
  const { orderNo = '' } = useParams<{ orderNo: string }>();
  const navigate = useNavigate();

  const [order, setOrder] = useState<CertOrder | null>(null);
  const [channels, setChannels] = useState<PaymentChannel[]>([]);
  const [balance, setBalance] = useState<UserBalance | null>(null);
  const [channel, setChannel] = useState<string>('');
  const [result, setResult] = useState<CheckoutResult | null>(null);
  const [attempt, setAttempt] = useState<PaymentAttempt | null>(null);
  const [loading, setLoading] = useState(true);
  const [paying, setPaying] = useState(false);
  const [error, setError] = useState('');
  const pollTimer = useRef<number | null>(null);

  const amountCents = order?.amount_cents ?? 0;
  const paid = order?.status === 'paid' || order?.status === 'completed';

  const stopPolling = useCallback(() => {
    if (pollTimer.current !== null) {
      window.clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [o, chs, bal] = await Promise.all([
        getMyPortalOrder(orderNo),
        listPortalPaymentChannels().catch(() => [] as PaymentChannel[]),
        getBalance().catch(() => null),
      ]);
      setOrder(o);
      setChannels(chs);
      setBalance(bal);
      // 默认选择余额（若余额充足），否则选择第一个可用渠道
      const affordable = (bal?.available_cents ?? 0) >= (o.amount_cents ?? 0);
      const preferred = affordable ? 'balance' : (chs.find((c) => c.channel !== 'balance')?.channel ?? 'balance');
      setChannel(preferred);
    } catch (e: any) {
      setError(e?.message || '订单不存在或无权访问');
    } finally {
      setLoading(false);
    }
  }, [orderNo]);

  useEffect(() => { load(); }, [load]);

  /** 轮询支付结果 */
  const startPolling = useCallback(() => {
    stopPolling();
    pollTimer.current = window.setInterval(async () => {
      try {
        const a = await getPortalOrderPayment(orderNo);
        setAttempt(a);
        if (a.status === 'paid') {
          stopPolling();
          message.success('支付成功');
          await load();
          setResult(null);
        }
      } catch {
        // 渠道尚未回调时接口可能无记录，继续轮询
      }
    }, POLL_INTERVAL_MS);
  }, [orderNo, load, stopPolling]);

  const handlePay = async () => {
    if (!channel) {
      message.warning('请选择支付渠道');
      return;
    }
    setPaying(true);
    try {
      const res = await payPortalOrder(orderNo, channel);
      setResult(res);
      if (res.settled) {
        message.success('支付完成');
        await load();
      } else {
        message.info('请使用所选渠道完成支付');
        startPolling();
      }
    } catch (e: any) {
      message.error(e?.message || '发起支付失败');
    } finally {
      setPaying(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: '120px 0' }}>
        <Spin size="large" />
      </div>
    );
  }

  if (error || !order) {
    return (
      <div style={{ maxWidth: 640, margin: '0 auto', padding: '80px 32px' }}>
        <Result
          status="404"
          title="订单不存在"
          subTitle={error || '请确认订单号是否正确，或该订单不属于当前账号。'}
          extra={<Button type="primary" onClick={() => navigate('/console/cert-orders')}>返回我的订单</Button>}
        />
      </div>
    );
  }

  // 已支付（含余额/免费当场结算、或轮询确认）
  if (paid) {
    // 订阅套餐支付后自动开通额度，无需提交申请资料
    const isPlan = (order.product_code ?? '').startsWith('plan:');
    const isCard = (() => {
      try { return JSON.parse(order.spec_json || '{}').kind === 'card'; } catch { return false; }
    })();
    return (
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '64px 32px' }}>
        <Result
          status="success"
          title="支付完成"
          subTitle={isPlan
            ? `订单 ${order.order_no} 已支付，订阅额度已自动开通。`
            : `订单 ${order.order_no} 已支付，可立即提交证书申请资料。`}
          extra={[
            <Button key="orders" onClick={() => navigate('/console/cert-orders')}>我的订单</Button>,
            isPlan ? (
              <Button key="subs" type="primary" onClick={() => navigate('/console/profile?tab=finance')}>查看订阅额度</Button>
            ) : isCard ? (
              <Button key="cards" type="primary" onClick={() => navigate('/console/cards')}>去开通智能卡</Button>
            ) : (
              <Button key="apply" type="primary" onClick={() => navigate(`/console/apply?order_no=${order.order_no}`)}>
                去提交申请
              </Button>
            ),
          ]}
        />
      </div>
    );
  }

  const balanceEnough = (balance?.available_cents ?? 0) >= amountCents;

  return (
    <div style={{ maxWidth: 980, margin: '0 auto', padding: '32px 32px 80px' }}>
      <Breadcrumb
        style={{ marginBottom: 20 }}
        items={[
          { title: <Link to="/">首页</Link> },
          { title: <Link to="/console/cert-orders">我的订单</Link> },
          { title: '收银台' },
        ]}
      />

      <Title level={3} style={{ marginBottom: 24 }}>收银台</Title>

      <Row gutter={[24, 24]}>
        <Col xs={24} lg={15}>
          <Card style={{ borderRadius: 14, border: '1px solid #eef0f4' }} styles={{ body: { padding: 28 } }}>
            <Text strong style={{ fontSize: 15 }}>选择支付方式</Text>

            <div style={{ marginTop: 18 }}>
              <Radio.Group
                value={channel}
                onChange={(e) => setChannel(e.target.value)}
                style={{ width: '100%' }}
                disabled={!!result && !result.settled}
              >
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  {channels.map((c) => {
                    const isBalance = c.channel === 'balance';
                    const disabled = isBalance && !balanceEnough;
                    return (
                      <Radio
                        key={c.channel}
                        value={c.channel}
                        disabled={disabled}
                        style={{
                          display: 'flex', alignItems: 'center', padding: '14px 16px',
                          border: '1px solid #e8ecf3', borderRadius: 10, margin: 0, width: '100%',
                        }}
                      >
                        <Space size={10}>
                          <WalletOutlined />
                          <span style={{ fontWeight: 500 }}>{c.name}</span>
                          {isBalance && (
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              可用 ¥{((balance?.available_cents ?? 0) / 100).toFixed(2)}
                            </Text>
                          )}
                          {disabled && <Tag color="orange" style={{ margin: 0 }}>余额不足</Tag>}
                        </Space>
                      </Radio>
                    );
                  })}
                </Space>
              </Radio.Group>
            </div>

            {result && !result.settled && (
              <>
                <Divider style={{ margin: '24px 0' }} />
                <Alert
                  type="info" showIcon
                  message="请完成支付"
                  description="支付完成后本页面会自动更新；如已支付成功但状态未变，可点击下方按钮手动刷新。"
                />
                <div style={{ marginTop: 16, textAlign: 'center' }}>
                  {result.qr_code && (
                    <div style={{
                      padding: 16, background: '#f8fafc', border: '1px solid #e8ecf3',
                      borderRadius: 10, marginBottom: 12, wordBreak: 'break-all', fontSize: 12,
                    }}>
                      <Text type="secondary">二维码内容</Text>
                      <div style={{ marginTop: 6 }}>{result.qr_code}</div>
                    </div>
                  )}
                  {result.pay_url && (
                    <Space direction="vertical" size={10} style={{ width: '100%' }}>
                      <Button type="primary" href={result.pay_url} target="_blank" block size="large">
                        前往支付页面
                      </Button>
                      <Button
                        icon={<CopyOutlined />} block
                        onClick={() => {
                          navigator.clipboard?.writeText(result.pay_url || '');
                          message.success('支付链接已复制');
                        }}
                      >
                        复制支付链接
                      </Button>
                    </Space>
                  )}
                </div>
                <div style={{ marginTop: 16, textAlign: 'center' }}>
                  <Button icon={<ReloadOutlined />} onClick={async () => { await load(); }}>
                    我已完成支付，刷新状态
                  </Button>
                  {attempt?.status === 'pending' && (
                    <Text type="secondary" style={{ display: 'block', marginTop: 8, fontSize: 12 }}>
                      正在等待支付结果…
                    </Text>
                  )}
                </div>
              </>
            )}

            <Divider style={{ margin: '24px 0' }} />

            <Button
              type="primary" size="large" loading={paying}
              disabled={!!result && !result.settled}
              onClick={handlePay}
              style={{ height: 46, padding: '0 32px', borderRadius: 10, fontWeight: 600 }}
            >
              {channel === 'balance' ? '使用余额支付' : '生成支付链接'}
            </Button>
          </Card>
        </Col>

        <Col xs={24} lg={9}>
          <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3' }} styles={{ body: { padding: 24 } }}>
            <Text strong style={{ fontSize: 15 }}>订单信息</Text>
            <Divider style={{ margin: '16px 0' }} />

            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 13 }}>
              <Text type="secondary">订单号</Text>
              <Text copyable style={{ fontSize: 12 }}>{order.order_no}</Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 13 }}>
              <Text type="secondary">商品</Text>
              <Text>{order.spec_json ? (() => {
                try { return JSON.parse(order.spec_json || '{}').sku_name || '-'; } catch { return '-'; }
              })() : '-'}</Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 13 }}>
              <Text type="secondary">状态</Text>
              <Tag color="orange">待支付</Tag>
            </div>

            <Divider style={{ margin: '16px 0' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <Text strong>应付金额</Text>
              <div>
                <span style={{ fontSize: 15, fontWeight: 600, color: '#1d4ed8' }}>¥</span>
                <span style={{ fontSize: 30, fontWeight: 700, color: '#1d4ed8' }}>
                  {(amountCents / 100).toFixed(2)}
                </span>
              </div>
            </div>

            <Paragraph style={{ fontSize: 12, color: '#9ca3af', marginTop: 16, marginBottom: 0 }}>
              <CheckCircleFilled style={{ marginRight: 6, color: '#16a34a' }} />
              支付金额以服务端订单金额为准；换渠道会作废上一次待支付记录。
            </Paragraph>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default PortalCheckout;
