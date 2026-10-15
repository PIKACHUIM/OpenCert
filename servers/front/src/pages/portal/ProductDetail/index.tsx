import React, { useEffect, useState } from 'react';
import {
  Alert, Breadcrumb, Button, Card, Col, Divider, Empty, Row, Skeleton, Space, Tag, Typography,
} from 'antd';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { CheckCircleFilled } from '@ant-design/icons';
import { getPortalProduct } from '../../../api';
import type { PortalProductSKU, ProductView } from '../../../types';

const { Title, Text, Paragraph } = Typography;

const parseList = (raw: string): string[] => {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
};

const deliveryLabel: Record<string, string> = {
  download: '文件下载',
  cloud_card: '云端智能卡',
  csr: '自备 CSR',
};

/**
 * 门户产品详情与规格对比。
 * 规格数据完全来自服务端；不可售（下架/售罄）的规格仍展示但禁用购买。
 */
const PortalProductDetail: React.FC = () => {
  const { category = '', code = '' } = useParams<{ category: string; code: string }>();
  const navigate = useNavigate();
  const [view, setView] = useState<ProductView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const data = await getPortalProduct(code);
        if (alive) setView(data);
      } catch (e: any) {
        if (alive) setError(e?.message || '商品不存在或已下架');
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [code]);

  if (loading) {
    return (
      <div style={{ maxWidth: 1180, margin: '0 auto', padding: '48px 32px' }}>
        <Card style={{ borderRadius: 14 }}><Skeleton active paragraph={{ rows: 6 }} /></Card>
      </div>
    );
  }

  if (error || !view) {
    return (
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '80px 32px' }}>
        <Empty description={error || '商品不存在'}>
          <Button type="primary" onClick={() => navigate('/products')}>返回产品中心</Button>
        </Empty>
      </div>
    );
  }

  const { product, skus } = view;
  const features = parseList(product.features);
  const highlights = parseList(product.highlights);

  /** 规格是否可售 */
  const sellable = (s: PortalProductSKU) => s.enabled && s.stock !== 0;

  return (
    <div style={{ maxWidth: 1180, margin: '0 auto', padding: '32px 32px 80px' }}>
      <Breadcrumb
        style={{ marginBottom: 20 }}
        items={[
          { title: <Link to="/">首页</Link> },
          { title: <Link to="/products">产品中心</Link> },
          { title: <Link to={`/products/${product.category}`}>{(category || product.category).toUpperCase()}</Link> },
          { title: product.name },
        ]}
      />

      <Row gutter={[40, 32]}>
        <Col xs={24} lg={15}>
          <Space size={10} wrap style={{ marginBottom: 10 }}>
            <Tag color="blue" bordered={false}>{product.category.toUpperCase()}</Tag>
            {product.level && <Tag bordered={false}>{product.level.toUpperCase()}</Tag>}
            {product.badge && <Tag color="gold">{product.badge}</Tag>}
          </Space>

          <Title level={2} style={{ margin: '0 0 12px', color: '#0f172a' }}>{product.name}</Title>
          <Paragraph style={{ fontSize: 15, color: '#5b6472', lineHeight: 1.9 }}>
            {product.summary}
          </Paragraph>
          {product.description && (
            <Paragraph style={{ fontSize: 14, color: '#6b7280', lineHeight: 1.9 }}>
              {product.description}
            </Paragraph>
          )}

          {features.length > 0 && (
            <>
              <Divider style={{ margin: '24px 0 20px' }} />
              <Title level={5} style={{ marginBottom: 14 }}>包含权益</Title>
              <Row gutter={[16, 12]}>
                {features.map((f) => (
                  <Col xs={24} sm={12} key={f}>
                    <Space align="start" size={8}>
                      <CheckCircleFilled style={{ color: '#16a34a', marginTop: 3 }} />
                      <Text style={{ fontSize: 14, color: '#4b5563' }}>{f}</Text>
                    </Space>
                  </Col>
                ))}
              </Row>
            </>
          )}
        </Col>

        <Col xs={24} lg={9}>
          {highlights.length > 0 && (
            <Card
              style={{ borderRadius: 14, border: '1px solid #e8ecf3', background: '#f8fafc' }}
              styles={{ body: { padding: 20 } }}
            >
              <Text strong style={{ fontSize: 14 }}>服务说明</Text>
              <ul style={{ paddingLeft: 18, margin: '12px 0 0', color: '#4b5563', fontSize: 13, lineHeight: 2 }}>
                {highlights.map((h) => <li key={h}>{h}</li>)}
              </ul>
            </Card>
          )}
        </Col>
      </Row>

      <Divider style={{ margin: '48px 0 28px' }} />
      <Title level={4} style={{ marginBottom: 6 }}>选择套餐</Title>
      <Text style={{ color: '#6b7280' }}>实际价格、库存与开通参数以服务端为准</Text>

      {skus.length === 0 ? (
        <Alert
          type="info" showIcon style={{ marginTop: 20 }}
          message="该产品暂未配置可购买套餐"
          description="管理员需在控制台为商品配置规格（价格、时长与开通模板）后才能开放购买。"
        />
      ) : (
        <Row gutter={[20, 20]} style={{ marginTop: 20 }}>
          {skus.map((s) => {
            const ok = sellable(s);
            return (
              <Col xs={24} md={12} lg={8} key={s.uuid}>
                <Card
                  style={{
                    borderRadius: 14, height: '100%',
                    border: ok ? '1px solid #e8ecf3' : '1px dashed #e5e7eb',
                    opacity: ok ? 1 : 0.6,
                  }}
                  styles={{ body: { display: 'flex', flexDirection: 'column', height: '100%' } }}
                >
                  <Space size={8} style={{ marginBottom: 10 }} wrap>
                    <Text strong style={{ fontSize: 16, color: '#0f172a' }}>{s.name}</Text>
                    {s.stock === 0 && <Tag color="red" style={{ margin: 0 }}>已售罄</Tag>}
                    {!s.enabled && <Tag style={{ margin: 0 }}>已下架</Tag>}
                  </Space>

                  <div style={{ marginBottom: 14 }}>
                    <span style={{ fontSize: 13, color: '#6b7280' }}>¥</span>
                    <span style={{ fontSize: 28, fontWeight: 700, color: '#1d4ed8' }}>
                      {(s.price_cents / 100).toFixed(2)}
                    </span>
                    <span style={{ fontSize: 13, color: '#6b7280' }}> / {s.duration_months} 个月</span>
                  </div>

                  <div style={{ fontSize: 13, color: '#4b5563', lineHeight: 2 }}>
                    <div>交付方式：{deliveryLabel[s.delivery_mode] ?? s.delivery_mode}</div>
                    <div>密钥算法：{parseList(s.key_types).join(' / ') || '-'}</div>
                    {s.san_included > 0 && <div>含 {s.san_included} 个域名</div>}
                    <div>
                      库存：{s.stock < 0 ? '不限' : s.stock}
                    </div>
                  </div>

                  <div style={{ marginTop: 'auto', paddingTop: 18 }}>
                    <Button
                      type="primary" block size="large" disabled={!ok}
                      onClick={() => navigate(`/buy/${s.code}`)}
                      style={{ borderRadius: 9 }}
                    >
                      {ok ? '立即购买' : '暂不可购买'}
                    </Button>
                  </div>
                </Card>
              </Col>
            );
          })}
        </Row>
      )}
    </div>
  );
};

export default PortalProductDetail;
