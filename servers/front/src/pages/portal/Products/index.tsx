import React, { useEffect, useMemo, useState } from 'react';
import { Button, Card, Col, Empty, Row, Segmented, Space, Tag, Typography, Skeleton, Alert } from 'antd';
import { useNavigate, useParams } from 'react-router-dom';
import { CheckCircleFilled } from '@ant-design/icons';
import { listPortalCategories, listPortalProducts } from '../../../api';
import type { PortalCategory, ProductView } from '../../../types';

const { Title, Text } = Typography;

/** 安全解析 JSON 字符串数组 */
const parseList = (raw: string): string[] => {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch {
    return [];
  }
};

/**
 * 门户产品列表。
 * 支持按分类筛选（路由参数 :category），数据全部来自服务端已发布商品。
 */
const PortalProducts: React.FC = () => {
  const navigate = useNavigate();
  const { category } = useParams<{ category?: string }>();
  const [categories, setCategories] = useState<PortalCategory[]>([]);
  const [views, setViews] = useState<ProductView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const active = category || 'all';

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const params = active === 'all' ? {} : { category: active };
        const [cats, list] = await Promise.all([listPortalCategories(), listPortalProducts(params)]);
        if (!alive) return;
        setCategories(cats);
        setViews(list);
      } catch (e: any) {
        if (alive) setError(e?.message || '加载商品失败');
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [active]);

  const options = useMemo(
    () => [
      { label: '全部产品', value: 'all' },
      ...categories.filter((c) => c.count > 0).map((c) => ({ label: c.name, value: c.code })),
    ],
    [categories],
  );

  const activeCategory = categories.find((c) => c.code === active);

  /** 计算价格区间展示 */
  const priceRange = (v: ProductView) => {
    const prices = v.skus.filter((s) => s.enabled).map((s) => s.price_cents);
    if (prices.length === 0) return null;
    const min = Math.min(...prices) / 100;
    const max = Math.max(...prices) / 100;
    return min === max ? `¥${min}` : `¥${min} - ¥${max}`;
  };

  return (
    <div style={{ maxWidth: 1180, margin: '0 auto', padding: '48px 32px 80px' }}>
      <div style={{ marginBottom: 28 }}>
        <Title level={2} style={{ margin: '0 0 8px', color: '#0f172a' }}>
          {activeCategory ? activeCategory.name : '全部产品'}
        </Title>
        <Text style={{ color: '#6b7280', fontSize: 15 }}>
          {activeCategory ? activeCategory.description : '按用途选择合适的证书或云端智能卡套餐'}
        </Text>
      </div>

      {options.length > 1 && (
        <Segmented
          options={options}
          value={active}
          onChange={(v) => navigate(v === 'all' ? '/products' : `/products/${v}`)}
          style={{ marginBottom: 28 }}
        />
      )}

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 20 }} />}

      {loading ? (
        <Row gutter={[20, 20]}>
          {[0, 1, 2].map((i) => (
            <Col xs={24} md={12} lg={8} key={i}>
              <Card style={{ borderRadius: 14 }}><Skeleton active paragraph={{ rows: 3 }} /></Card>
            </Col>
          ))}
        </Row>
      ) : views.length === 0 ? (
        <Empty
          description="该分类下暂无已发布商品"
          style={{ padding: '60px 0' }}
        >
          <Button type="primary" onClick={() => navigate('/products')}>查看全部产品</Button>
        </Empty>
      ) : (
        <Row gutter={[20, 20]}>
          {views.map((v) => {
            const features = parseList(v.product.features).slice(0, 4);
            return (
              <Col xs={24} md={12} lg={8} key={v.product.uuid}>
                <Card
                  hoverable
                  style={{ borderRadius: 14, border: '1px solid #eef0f4', height: '100%', display: 'flex', flexDirection: 'column' }}
                  styles={{ body: { display: 'flex', flexDirection: 'column', height: '100%' } }}
                  onClick={() => navigate(`/products/${v.product.category}/${v.product.code}`)}
                >
                  <Space size={8} style={{ marginBottom: 8 }} wrap>
                    <Text strong style={{ fontSize: 17, color: '#0f172a' }}>{v.product.name}</Text>
                    {v.product.badge && <Tag color="gold" style={{ margin: 0 }}>{v.product.badge}</Tag>}
                    {v.product.level && <Tag bordered={false} style={{ margin: 0 }}>{v.product.level.toUpperCase()}</Tag>}
                  </Space>

                  <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.7, minHeight: 42 }}>
                    {v.product.summary || v.product.description}
                  </div>

                  {features.length > 0 && (
                    <div style={{ margin: '14px 0' }}>
                      {features.map((f) => (
                        <div key={f} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6 }}>
                          <CheckCircleFilled style={{ color: '#16a34a', fontSize: 13, marginTop: 3 }} />
                          <span style={{ fontSize: 13, color: '#4b5563' }}>{f}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ marginTop: 'auto', paddingTop: 16, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
                    <div>
                      {priceRange(v) ? (
                        <>
                          <div style={{ fontSize: 12, color: '#9ca3af' }}>价格</div>
                          <div style={{ fontSize: 22, fontWeight: 700, color: '#1d4ed8' }}>{priceRange(v)}</div>
                        </>
                      ) : (
                        <Text type="secondary" style={{ fontSize: 13 }}>暂未开放购买</Text>
                      )}
                    </div>
                    <Button type="primary" ghost>查看规格</Button>
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

export default PortalProducts;
