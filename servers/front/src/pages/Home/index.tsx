import React, { useEffect, useState } from 'react';
import { Button, Col, Row, Space, Tag, Typography, Card, Skeleton } from 'antd';
import { useNavigate } from 'react-router-dom';
import {
  SafetyCertificateOutlined, CloudServerOutlined, ArrowRightOutlined,
  CheckCircleFilled, ApiOutlined, IdcardOutlined, FileProtectOutlined,
} from '@ant-design/icons';
import { listPortalCategories, listPortalProducts } from '../../api';
import { useSiteStore } from '../../store/site';
import type { PortalCategory, ProductView } from '../../types';

const { Title, Text, Paragraph } = Typography;

/** 分类图标 */
const categoryIcon: Record<string, React.ReactNode> = {
  ssl: <SafetyCertificateOutlined />,
  codesign: <FileProtectOutlined />,
  email: <IdcardOutlined />,
  docsign: <FileProtectOutlined />,
  cloudcard: <CloudServerOutlined />,
};

/** 使用步骤 */
const steps = [
  { title: '选择产品', desc: '按用途与验证等级挑选合适的证书或云卡套餐' },
  { title: '完成验证', desc: '按指引完成域名、邮箱或组织资料验证' },
  { title: '支付与签发', desc: '在线支付后进入审核与签发流程' },
  { title: '部署使用', desc: '下载证书或绑定客户端，在设备上安全调用' },
];

const Home: React.FC = () => {
  const navigate = useNavigate();
  const { settings } = useSiteStore();
  const [categories, setCategories] = useState<PortalCategory[]>([]);
  const [products, setProducts] = useState<ProductView[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [cats, list] = await Promise.all([listPortalCategories(), listPortalProducts()]);
        if (!alive) return;
        setCategories(cats);
        setProducts(list.slice(0, 3));
      } catch {
        // 未配置商品时首页仍应可用
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  /** 商品最低价，用于卡片展示 */
  const lowestPrice = (view: ProductView) => {
    const prices = view.skus.filter((s) => s.enabled).map((s) => s.price_cents);
    if (prices.length === 0) return null;
    return Math.min(...prices) / 100;
  };

  return (
    <div>
      {/* Hero */}
      <section style={{
        padding: '88px 32px 72px',
        background: 'linear-gradient(180deg, #f7f9fc 0%, #ffffff 100%)',
        borderBottom: '1px solid #eef0f4',
      }}>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          <Row gutter={[48, 40]} align="middle">
            <Col xs={24} lg={13}>
              <Tag color="blue" style={{ borderRadius: 20, padding: '3px 14px', marginBottom: 20, fontSize: 12 }}>
                数字证书 · 云端智能卡
              </Tag>
              <Title style={{ fontSize: 44, lineHeight: 1.2, margin: '0 0 20px', letterSpacing: '-1px', color: '#0f172a' }}>
                统一申请数字证书
                <br />
                <span style={{ color: '#1d4ed8' }}>在设备上安全使用</span>
              </Title>
              <Paragraph style={{ fontSize: 16, color: '#5b6472', maxWidth: 520, lineHeight: 1.8, marginBottom: 32 }}>
                {settings.site_description}
              </Paragraph>
              <Space size={12} wrap>
                <Button
                  type="primary" size="large" icon={<ArrowRightOutlined />}
                  onClick={() => navigate('/products')}
                  style={{ height: 46, padding: '0 28px', borderRadius: 10, fontWeight: 600 }}
                >
                  选购证书
                </Button>
                <Button
                  size="large" icon={<CloudServerOutlined />}
                  onClick={() => navigate('/products/cloudcard')}
                  style={{ height: 46, padding: '0 28px', borderRadius: 10, fontWeight: 600 }}
                >
                  了解云端智能卡
                </Button>
              </Space>
            </Col>

            <Col xs={24} lg={11}>
              <div style={{
                padding: 28, borderRadius: 20, background: '#fff',
                border: '1px solid #e8ecf3', boxShadow: '0 12px 40px rgba(15,23,42,0.06)',
              }}>
                <Text strong style={{ fontSize: 15, color: '#0f172a' }}>从申请到使用，四步完成</Text>
                <div style={{ marginTop: 20 }}>
                  {steps.map((s, i) => (
                    <div key={s.title} style={{ display: 'flex', gap: 14, marginBottom: i === steps.length - 1 ? 0 : 18 }}>
                      <div style={{
                        flex: '0 0 26px', height: 26, borderRadius: '50%',
                        background: '#eff4ff', color: '#1d4ed8',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 12, fontWeight: 700,
                      }}>
                        {i + 1}
                      </div>
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 600, color: '#0f172a' }}>{s.title}</div>
                        <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.7 }}>{s.desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </Col>
          </Row>
        </div>
      </section>

      {/* 产品分类 */}
      <section style={{ padding: '64px 32px', maxWidth: 1180, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <Title level={3} style={{ margin: '0 0 8px', color: '#0f172a' }}>按用途选择产品</Title>
          <Text style={{ color: '#6b7280' }}>覆盖网站、软件发布、邮件与文档签名，以及云端智能卡</Text>
        </div>

        <Row gutter={[20, 20]}>
          {loading
            ? [0, 1, 2, 3, 4].map((i) => (
              <Col xs={24} sm={12} lg={8} key={i}><Card><Skeleton active paragraph={{ rows: 2 }} /></Card></Col>
            ))
            : categories.map((c) => (
              <Col xs={24} sm={12} lg={8} key={c.code}>
                <Card
                  hoverable
                  onClick={() => navigate(`/products/${c.code}`)}
                  style={{ borderRadius: 14, border: '1px solid #eef0f4', height: '100%' }}
                >
                  <div style={{
                    width: 44, height: 44, borderRadius: 12, background: '#eff4ff',
                    color: '#1d4ed8', fontSize: 20,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 14,
                  }}>
                    {categoryIcon[c.code] ?? <SafetyCertificateOutlined />}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Text strong style={{ fontSize: 15, color: '#0f172a' }}>{c.name}</Text>
                    {c.count > 0 && <Tag bordered={false} style={{ margin: 0 }}>{c.count} 款</Tag>}
                  </div>
                  <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.7, marginTop: 6 }}>{c.description}</div>
                </Card>
              </Col>
            ))}
        </Row>
      </section>

      {/* 精选商品 */}
      {products.length > 0 && (
        <section style={{ padding: '8px 32px 72px', maxWidth: 1180, margin: '0 auto' }}>
          <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 24 }}>
            <div>
              <Title level={3} style={{ margin: '0 0 6px', color: '#0f172a' }}>热门产品</Title>
              <Text style={{ color: '#6b7280' }}>价格与库存以页面显示为准</Text>
            </div>
            <Button type="link" onClick={() => navigate('/products')}>查看全部 →</Button>
          </div>

          <Row gutter={[20, 20]}>
            {products.map((v) => (
              <Col xs={24} md={8} key={v.product.uuid}>
                <Card style={{ borderRadius: 14, border: '1px solid #eef0f4', height: '100%' }}>
                  <Space size={8} style={{ marginBottom: 10 }}>
                    <Text strong style={{ fontSize: 16, color: '#0f172a' }}>{v.product.name}</Text>
                    {v.product.badge && <Tag color="gold" style={{ margin: 0 }}>{v.product.badge}</Tag>}
                  </Space>
                  <div style={{ fontSize: 13, color: '#6b7280', minHeight: 40, lineHeight: 1.7 }}>
                    {v.product.summary}
                  </div>
                  <div style={{ margin: '14px 0 18px' }}>
                    {lowestPrice(v) === null ? (
                      <Text type="secondary">暂未开放购买</Text>
                    ) : (
                      <>
                        <span style={{ fontSize: 13, color: '#6b7280' }}>低至 </span>
                        <span style={{ fontSize: 26, fontWeight: 700, color: '#1d4ed8' }}>
                          ¥{lowestPrice(v)}
                        </span>
                        <span style={{ fontSize: 13, color: '#6b7280' }}> 起</span>
                      </>
                    )}
                  </div>
                  <Button
                    type="primary" block
                    onClick={() => navigate(`/products/${v.product.category}/${v.product.code}`)}
                  >
                    查看规格
                  </Button>
                </Card>
              </Col>
            ))}
          </Row>
        </section>
      )}

      {/* 云端智能卡说明 */}
      <section style={{ background: '#0b1220', padding: '64px 32px', color: '#fff' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          <Row gutter={[48, 32]} align="middle">
            <Col xs={24} lg={12}>
              <Tag color="cyan" style={{ borderRadius: 20, padding: '3px 14px', marginBottom: 18 }}>
                云端智能卡
              </Tag>
              <Title level={3} style={{ color: '#fff', margin: '0 0 16px' }}>
                私钥保留在云端，签名在服务端完成
              </Title>
              <Paragraph style={{ color: 'rgba(255,255,255,0.7)', lineHeight: 1.9, fontSize: 15 }}>
                本地客户端只同步公开证书与元数据，签名与解密由云端执行，
                私钥不出服务端。设备端通过标准 PKCS#11 接口调用，无需改造现有业务系统。
              </Paragraph>
              <Button
                type="primary" size="large" icon={<CloudServerOutlined />}
                onClick={() => navigate('/products/cloudcard')}
                style={{ marginTop: 12, height: 44, borderRadius: 10 }}
              >
                查看云卡方案
              </Button>
            </Col>

            <Col xs={24} lg={12}>
              <Space direction="vertical" size={14} style={{ width: '100%' }}>
                {[
                  { icon: <ApiOutlined />, text: '兼容 PKCS#11 / KSP，现有应用无需改造' },
                  { icon: <CloudServerOutlined />, text: '私钥集中托管，支持远程签名与解密' },
                  { icon: <CheckCircleFilled />, text: '卡 PIN 与账号二次验证双重保护' },
                ].map((item) => (
                  <div key={item.text} style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '14px 18px', borderRadius: 12,
                    background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                  }}>
                    <span style={{ color: '#38bdf8', fontSize: 17 }}>{item.icon}</span>
                    <span style={{ color: 'rgba(255,255,255,0.85)', fontSize: 14 }}>{item.text}</span>
                  </div>
                ))}
              </Space>
            </Col>
          </Row>
        </div>
      </section>
    </div>
  );
};

export default Home;
