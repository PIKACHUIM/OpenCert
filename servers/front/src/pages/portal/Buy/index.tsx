import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Breadcrumb, Button, Card, Col, Divider, Form, Input, InputNumber,
  Row, Skeleton, Space, Tag, Typography, message,
} from 'antd';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { SafetyOutlined } from '@ant-design/icons';
import { createPortalOrder, quotePortalOrder } from '../../../api';
import { useAuthStore } from '../../../store/auth';
import type { PortalQuote } from '../../../types';

const { Title, Text, Paragraph } = Typography;

/**
 * 门户购买配置页。
 *
 * 价格与可购数量始终由服务端报价接口决定，前端展示仅作参考；
 * 未登录用户先完成登录再下单（业务约定：注册后才能下单）。
 */
const PortalBuy: React.FC = () => {
  const { skuCode = '' } = useParams<{ skuCode: string }>();
  const navigate = useNavigate();
  const { isAuthenticated } = useAuthStore();
  const [form] = Form.useForm();

  const [quote, setQuote] = useState<PortalQuote | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [quantity, setQuantity] = useState(1);

  /** 拉取服务端权威报价 */
  const refreshQuote = useCallback(async (qty: number) => {
    try {
      const q = await quotePortalOrder({ sku_code: skuCode, quantity: qty });
      setQuote(q);
      setError('');
      return q;
    } catch (e: any) {
      setError(e?.message || '获取报价失败');
      return null;
    }
  }, [skuCode]);

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      const q = await refreshQuote(1);
      if (!alive) return;
      if (q) {
        setQuantity(q.quantity);
        form.setFieldsValue({ quantity: q.quantity });
      }
      setLoading(false);
    })();
    return () => { alive = false; };
  }, [refreshQuote, form]);

  const handleQuantityChange = async (value: number | null) => {
    if (!value || value < 1) return;
    setQuantity(value);
    await refreshQuote(value);
  };

  const handleSubmit = async (values: { quantity: number; applicant_email?: string }) => {
    if (!quote) return;

    // 未登录：先登录并回跳，避免丢失当前选择
    if (!isAuthenticated) {
      message.info('下单前请先登录或注册');
      navigate(`/login?redirect=${encodeURIComponent(`/buy/${skuCode}`)}`);
      return;
    }

    setSubmitting(true);
    try {
      const order = await createPortalOrder({
        sku_code: skuCode,
        quantity: values.quantity,
        applicant_email: values.applicant_email,
      });
      message.success('订单已创建，请完成支付');
      if (order.order_no) {
        navigate(`/checkout/${order.order_no}`);
      } else {
        navigate('/console/cert-orders');
      }
    } catch (e: any) {
      message.error(e?.message || '创建订单失败');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '48px 32px' }}>
        <Card style={{ borderRadius: 14 }}><Skeleton active paragraph={{ rows: 6 }} /></Card>
      </div>
    );
  }

  if (!quote) {
    return (
      <div style={{ maxWidth: 640, margin: '0 auto', padding: '80px 32px' }}>
        <Alert
          type="error" showIcon
          message="无法购买该规格"
          description={error || '规格不存在或已下架'}
          action={<Button onClick={() => navigate('/products')}>返回产品中心</Button>}
        />
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto', padding: '32px 32px 80px' }}>
      <Breadcrumb
        style={{ marginBottom: 20 }}
        items={[
          { title: <Link to="/">首页</Link> },
          { title: <Link to="/products">产品中心</Link> },
          { title: <Link to={`/products/${quote.product_code}`}>{quote.product_name}</Link> },
          { title: '购买' },
        ]}
      />

      <Title level={3} style={{ marginBottom: 24 }}>配置并购买</Title>

      <Row gutter={[24, 24]}>
        <Col xs={24} lg={15}>
          <Card style={{ borderRadius: 14, border: '1px solid #eef0f4' }} styles={{ body: { padding: 28 } }}>
            <Form
              form={form}
              layout="vertical"
              onFinish={handleSubmit}
              initialValues={{ quantity: 1 }}
            >
              <div style={{ marginBottom: 28 }}>
                <Text strong style={{ fontSize: 15 }}>套餐</Text>
                <div style={{
                  marginTop: 12, padding: '16px 18px', borderRadius: 12,
                  background: '#f8fafc', border: '1px solid #e8ecf3',
                }}>
                  <Space size={10} wrap>
                    <Text strong style={{ fontSize: 15 }}>{quote.sku_name}</Text>
                    <Tag bordered={false}>{quote.duration_months} 个月</Tag>
                    <Tag bordered={false}>
                      {quote.delivery_mode === 'cloud_card' ? '云端智能卡'
                        : quote.delivery_mode === 'csr' ? '自备 CSR' : '文件下载'}
                    </Tag>
                  </Space>
                  <div style={{ marginTop: 10, fontSize: 13, color: '#6b7280' }}>
                    密钥算法：{quote.key_types.join(' / ') || '-'}
                    {quote.san_included > 0 ? ` · 含 ${quote.san_included} 个域名` : ''}
                  </div>
                </div>
              </div>

              <Form.Item
                name="quantity"
                label={<Text strong style={{ fontSize: 15 }}>购买数量</Text>}
                rules={[{ required: true, message: '请选择购买数量' }]}
              >
                <InputNumber
                  min={1}
                  max={quote.stock < 0 ? 999 : Math.max(quote.stock, 1)}
                  onChange={handleQuantityChange}
                  style={{ width: 180 }}
                  addonAfter="份"
                />
              </Form.Item>

              <Form.Item
                name="applicant_email"
                label={<Text strong style={{ fontSize: 15 }}>联系邮箱</Text>}
                extra="用于接收订单、审核与交付通知；未填写时默认使用账号邮箱"
                rules={[{ type: 'email', message: '请输入有效的邮箱地址' }]}
              >
                <Input placeholder="you@example.com" style={{ maxWidth: 380 }} />
              </Form.Item>

              {!quote.in_stock && (
                <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="库存不足，请调整购买数量" />
              )}

              <Divider style={{ margin: '8px 0 20px' }} />

              <Space size={12}>
                <Button
                  type="primary" size="large" htmlType="submit"
                  loading={submitting} disabled={!quote.in_stock}
                  style={{ height: 46, padding: '0 32px', borderRadius: 10, fontWeight: 600 }}
                >
                  {isAuthenticated ? '提交订单' : '登录后提交订单'}
                </Button>
                <Button size="large" onClick={() => navigate(-1)} style={{ height: 46, borderRadius: 10 }}>
                  返回
                </Button>
              </Space>
            </Form>
          </Card>
        </Col>

        <Col xs={24} lg={9}>
          <Card
            style={{
              borderRadius: 14, border: '1px solid #e8ecf3',
              position: 'sticky', top: 88,
            }}
            styles={{ body: { padding: 24 } }}
          >
            <Text strong style={{ fontSize: 15 }}>费用明细</Text>
            <Divider style={{ margin: '16px 0' }} />

            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 14 }}>
              <Text type="secondary">单价</Text>
              <Text>¥{(quote.unit_price_cents / 100).toFixed(2)}</Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 14 }}>
              <Text type="secondary">数量</Text>
              <Text>{quantity} 份</Text>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10, fontSize: 14 }}>
              <Text type="secondary">服务期</Text>
              <Text>{quote.duration_months} 个月</Text>
            </div>

            <Divider style={{ margin: '16px 0' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <Text strong>应付总额</Text>
              <div>
                <span style={{ fontSize: 15, fontWeight: 600, color: '#1d4ed8' }}>¥</span>
                <span style={{ fontSize: 30, fontWeight: 700, color: '#1d4ed8' }}>
                  {(quote.total_cents / 100).toFixed(2)}
                </span>
              </div>
            </div>

            <Paragraph style={{ fontSize: 12, color: '#9ca3af', marginTop: 16, marginBottom: 0 }}>
              <SafetyOutlined style={{ marginRight: 6 }} />
              金额由服务端根据套餐与数量实时计算，提交订单后以订单金额为准。
            </Paragraph>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default PortalBuy;
