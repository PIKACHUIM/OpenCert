import React, { useEffect, useState } from 'react';
import {
  Alert, Button, Card, Col, Empty, Row, Space, Skeleton, Tag, Tooltip, Typography, message,
} from 'antd';
import { useNavigate } from 'react-router-dom';
import {
  CopyOutlined, DownloadOutlined, SafetyCertificateOutlined, StopOutlined, ApiOutlined,
} from '@ant-design/icons';
import { listPortalPKIEndpoints, listPortalPolicies } from '../../../api';
import type { PkiEndpoint } from '../../../types';

const { Title, Text, Paragraph } = Typography;

/** 可复制的服务地址行 */
const EndpointRow: React.FC<{ label: string; value: string; hint?: string }> = ({ label, value, hint }) => (
  <div style={{ marginBottom: 10 }}>
    <Text type="secondary" style={{ fontSize: 12 }}>{label}</Text>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
      <Text code style={{ fontSize: 12, wordBreak: 'break-all', flex: 1 }}>{value}</Text>
      <Tooltip title="复制">
        <Button
          size="small" type="text" icon={<CopyOutlined />}
          onClick={() => {
            navigator.clipboard?.writeText(value);
            message.success('已复制');
          }}
        />
      </Tooltip>
    </div>
    {hint && <Text type="secondary" style={{ fontSize: 11 }}>{hint}</Text>}
  </div>
);

/**
 * 公开信任服务中心。
 *
 * 只展示管理员显式标记为公开的 CA；内部 CA 不会出现在此列表中。
 * CRL/OCSP 地址来自服务端实际配置，页面不做任何推测。
 */
const PortalTrust: React.FC = () => {
  const navigate = useNavigate();
  const [items, setItems] = useState<PkiEndpoint[]>([]);
  const [policies, setPolicies] = useState<{ name: string; version: string; url: string }[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    Promise.all([
      listPortalPKIEndpoints().catch(() => [] as PkiEndpoint[]),
      listPortalPolicies().catch(() => []),
    ])
      .then(([list, docs]) => {
        if (!alive) return;
        setItems(list);
        setPolicies(docs);
      })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  return (
    <div style={{ maxWidth: 1180, margin: '0 auto', padding: '48px 32px 80px' }}>
      <div style={{ marginBottom: 32 }}>
        <Title level={2} style={{ margin: '0 0 8px', color: '#0f172a' }}>信任服务中心</Title>
        <Text style={{ color: '#6b7280', fontSize: 15 }}>
          下载根证书与证书链，获取 CRL 分发点与 OCSP 服务地址
        </Text>
      </div>

      {loading ? (
        <Card style={{ borderRadius: 14 }}><Skeleton active paragraph={{ rows: 4 }} /></Card>
      ) : items.length === 0 ? (
        <Empty
          description="暂无对外公开的 CA"
          style={{ padding: '48px 0' }}
        >
          <Button type="primary" onClick={() => navigate('/products')}>了解证书产品</Button>
        </Empty>
      ) : (
        <Row gutter={[20, 20]}>
          {items.map((ca) => (
            <Col xs={24} lg={12} key={ca.ca_uuid}>
              <Card
                style={{ borderRadius: 14, border: '1px solid #e8ecf3', height: '100%' }}
                styles={{ body: { padding: 24 } }}
              >
                <Space size={8} wrap style={{ marginBottom: 10 }}>
                  <SafetyCertificateOutlined style={{ color: '#1d4ed8', fontSize: 18 }} />
                  <Text strong style={{ fontSize: 16 }}>{ca.name}</Text>
                  <Tag color={ca.is_root ? 'geekblue' : 'cyan'} style={{ margin: 0 }}>
                    {ca.is_root ? '根 CA' : '中间 CA'}
                  </Tag>
                  <Tag color={ca.status === 'active' ? 'green' : 'default'} style={{ margin: 0 }}>
                    {ca.status}
                  </Tag>
                  {ca.custom_path && <Tag bordered={false} style={{ margin: 0 }}>自定义路径</Tag>}
                </Space>

                <div style={{ fontSize: 12, color: '#6b7280', lineHeight: 1.9, marginBottom: 14 }}>
                  <div>主体：{ca.subject || '-'}</div>
                  <div>有效期：{ca.not_before?.slice(0, 10)} ~ {ca.not_after?.slice(0, 10)}</div>
                  {ca.fingerprint && (
                    <div style={{ wordBreak: 'break-all' }}>SHA-256：{ca.fingerprint}</div>
                  )}
                </div>

                <Space size={8} style={{ marginBottom: 16 }} wrap>
                  <Button
                    size="small" icon={<DownloadOutlined />}
                    href={ca.ca_url} target="_blank"
                  >
                    下载 CA 证书（DER）
                  </Button>
                  <Button
                    size="small" icon={<DownloadOutlined />}
                    href={ca.chain_url} target="_blank"
                  >
                    下载证书链（PEM）
                  </Button>
                </Space>

                <EndpointRow
                  label="CRL 分发点" value={ca.crl_url}
                  hint="证书吊销列表下载地址，可在应用或设备中直接配置"
                />
                <EndpointRow
                  label="OCSP 服务地址" value={ca.ocsp_url}
                  hint="在线证书状态查询协议地址，不是普通网页，需由客户端以 OCSP 协议访问"
                />
              </Card>
            </Col>
          ))}
        </Row>
      )}

      <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', marginTop: 32 }} styles={{ body: { padding: 28 } }}>
        <Title level={4} style={{ marginTop: 0 }}>证书链与吊销校验</Title>
        <Paragraph style={{ color: '#4b5563', lineHeight: 1.9, marginBottom: 16 }}>
          部署证书时需要一并安装签发该证书的 CA 证书，否则部分客户端会提示"证书链不完整"。
          证书被吊销后，应用可通过 CRL 或 OCSP 校验其状态；两者地址均已在上方列出。
        </Paragraph>

        <Row gutter={[20, 20]}>
          <Col xs={24} md={12}>
            <Space align="start" size={10}>
              <StopOutlined style={{ color: '#1d4ed8', marginTop: 4 }} />
              <div>
                <Text strong>吊销状态如何生效</Text>
                <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>
                  CRL 由服务端定时重新生成，客户端应定期重新拉取；
                  OCSP 为实时查询，需要应用支持该协议。
                </div>
              </div>
            </Space>
          </Col>
          <Col xs={24} md={12}>
            <Space align="start" size={10}>
              <ApiOutlined style={{ color: '#1d4ed8', marginTop: 4 }} />
              <div>
                <Text strong>在设备上使用证书</Text>
                <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>
                  云端智能卡通过 PKCS#11 / KSP 对上层应用提供标准调用，无需改造业务系统。
                  <Button type="link" size="small" style={{ padding: '0 4px' }} onClick={() => navigate('/downloads')}>
                    查看接入与下载
                  </Button>
                </div>
              </div>
            </Space>
          </Col>
        </Row>
      </Card>

      {/* 证书策略与合规文档（由「证书服务 → 证书策略管理」发布） */}
      {policies.length > 0 && (
        <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', marginTop: 32 }} styles={{ body: { padding: 28 } }}>
          <Title level={4} style={{ marginTop: 0 }}>证书策略与合规文档</Title>
          <Paragraph style={{ color: '#4b5563', lineHeight: 1.9, marginBottom: 16 }}>
            以下文档以网页形式发布（Markdown / HTML），可被证书中的 CPS 地址直接引用。
          </Paragraph>
          <Row gutter={[20, 20]}>
            {policies.map((p) => (
              <Col xs={24} md={12} key={p.url}>
                <Space align="start" size={10}>
                  <SafetyCertificateOutlined style={{ color: '#1d4ed8', marginTop: 4 }} />
                  <div>
                    <Text strong>{p.name}</Text>
                    {p.version && <Tag style={{ marginLeft: 8 }}>{p.version}</Tag>}
                    <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>
                      <Text copyable code style={{ fontSize: 12 }}>{p.url}</Text>
                      <div>
                        <Button type="link" size="small" style={{ padding: '0 4px' }}
                          onClick={() => window.open(p.url, '_blank', 'noopener')}>
                          打开文档
                        </Button>
                      </div>
                    </div>
                  </div>
                </Space>
              </Col>
            ))}
          </Row>
        </Card>
      )}

      <Alert
        type="info" showIcon style={{ marginTop: 24 }}
        message="地址由服务端根据实际配置生成"
        description="若此处未列出您需要的 CA，说明该 CA 未对外发布；请联系管理员在控制台中将该 CA 标记为公开。"
      />
    </div>
  );
};

export default PortalTrust;
