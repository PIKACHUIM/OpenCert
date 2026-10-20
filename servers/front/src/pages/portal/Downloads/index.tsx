import React from 'react';
import { Alert, Button, Card, Col, Row, Space, Tag, Typography } from 'antd';
import { useNavigate } from 'react-router-dom';
import {
  CloudDownloadOutlined, ApiOutlined, SafetyCertificateOutlined, WindowsOutlined,
  KeyOutlined, QuestionCircleOutlined,
} from '@ant-design/icons';
import { useSiteStore } from '../../../store/site';

const { Title, Text, Paragraph } = Typography;

/** 三类接入方式的差异说明 */
const integrationOptions = [
  {
    icon: <KeyOutlined />,
    name: 'PKCS#11',
    tag: '跨平台',
    desc: '标准密码设备接口，适用于浏览器以外的多数应用与命令行工具；本项目的驱动通过本地管理端转发密钥操作。',
  },
  {
    icon: <WindowsOutlined />,
    name: 'CSP / KSP',
    tag: 'Windows',
    desc: 'CSP 面向 CryptoAPI（如部分签名工具），KSP 面向 CNG（现代 Windows 应用）。二者都由本地管理端提供密钥与证书容器。',
  },
  {
    icon: <CloudDownloadOutlined />,
    name: '云端智能卡',
    tag: '远程使用',
    desc: '私钥保存在服务端，设备端通过本地管理端调用远程签名与解密，适合无法安全存放私钥的场景。',
  },
];

/**
 * 下载与接入指引。
 *
 * 下载地址来自站点配置；未配置时不展示无效入口，而是给出联系路径。
 */
const PortalDownloads: React.FC = () => {
  const navigate = useNavigate();
  const { settings } = useSiteStore();

  const hasAnyDownload = !!(settings.client_download || settings.driver_download);

  return (
    <div style={{ maxWidth: 1080, margin: '0 auto', padding: '48px 32px 80px' }}>
      <div style={{ marginBottom: 32 }}>
        <Title level={2} style={{ margin: '0 0 8px', color: '#0f172a' }}>下载与接入</Title>
        <Text style={{ color: '#6b7280', fontSize: 15 }}>
          获取本地管理端与 PKCS#11 驱动，让应用通过标准接口使用证书与智能卡
        </Text>
      </div>

      <Row gutter={[20, 20]}>
        <Col xs={24} md={12}>
          <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', height: '100%' }}>
            <Space size={10} style={{ marginBottom: 12 }}>
              <CloudDownloadOutlined style={{ color: '#1d4ed8', fontSize: 20 }} />
              <Text strong style={{ fontSize: 16 }}>本地管理端</Text>
            </Space>
            <Paragraph style={{ color: '#6b7280', fontSize: 13, lineHeight: 1.9 }}>
              管理本地与云端智能卡、签发与导入证书、将证书同步到操作系统证书存储。
              云端卡片需要通过它完成登录与绑定。
            </Paragraph>
            {settings.client_download ? (
              <Button type="primary" href={settings.client_download} target="_blank" icon={<CloudDownloadOutlined />}>
                下载客户端
              </Button>
            ) : (
              <Text type="secondary" style={{ fontSize: 13 }}>下载地址待管理员配置</Text>
            )}
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', height: '100%' }}>
            <Space size={10} style={{ marginBottom: 12 }}>
              <ApiOutlined style={{ color: '#1d4ed8', fontSize: 20 }} />
              <Text strong style={{ fontSize: 16 }}>PKCS#11 驱动</Text>
            </Space>
            <Paragraph style={{ color: '#6b7280', fontSize: 13, lineHeight: 1.9 }}>
              为第三方应用提供标准 PKCS#11 接口。安装后应用即可读取证书、执行签名与解密，
              无需了解云端或本地的密钥存放方式。
            </Paragraph>
            {settings.driver_download ? (
              <Button href={settings.driver_download} target="_blank" icon={<CloudDownloadOutlined />}>
                下载驱动
              </Button>
            ) : (
              <Text type="secondary" style={{ fontSize: 13 }}>下载地址待管理员配置</Text>
            )}
          </Card>
        </Col>
      </Row>

      <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', marginTop: 24 }} styles={{ body: { padding: 28 } }}>
        <Title level={4} style={{ marginTop: 0 }}>接入方式怎么选</Title>
        <Row gutter={[20, 20]}>
          {integrationOptions.map((opt) => (
            <Col xs={24} md={8} key={opt.name}>
              <div style={{
                padding: 20, borderRadius: 12,
                background: '#f8fafc', border: '1px solid #e8ecf3', height: '100%',
              }}>
                <Space size={8} style={{ marginBottom: 10 }}>
                  <span style={{ color: '#1d4ed8', fontSize: 18 }}>{opt.icon}</span>
                  <Text strong>{opt.name}</Text>
                  <Tag bordered={false} style={{ margin: 0 }}>{opt.tag}</Tag>
                </Space>
                <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>{opt.desc}</div>
              </div>
            </Col>
          ))}
        </Row>

      </Card>

      <Card style={{ borderRadius: 14, border: '1px solid #e8ecf3', marginTop: 24 }} styles={{ body: { padding: 28 } }}>
        <Title level={4} style={{ marginTop: 0 }}>还需要什么</Title>
        <Row gutter={[20, 20]}>
          <Col xs={24} md={12}>
            <Space align="start" size={10}>
              <SafetyCertificateOutlined style={{ color: '#1d4ed8', marginTop: 4 }} />
              <div>
                <Text strong>根证书与吊销服务</Text>
                <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>
                  部署证书前先安装对应 CA 证书，并在应用中配置 CRL 或 OCSP 地址。
                  <Button type="link" size="small" style={{ padding: '0 4px' }} onClick={() => navigate('/trust')}>
                    前往信任服务中心
                  </Button>
                </div>
              </div>
            </Space>
          </Col>
          <Col xs={24} md={12}>
            <Space align="start" size={10}>
              <QuestionCircleOutlined style={{ color: '#1d4ed8', marginTop: 4 }} />
              <div>
                <Text strong>遇到问题</Text>
                <div style={{ fontSize: 13, color: '#6b7280', lineHeight: 1.8 }}>
                  {settings.contact_email
                    ? <>可通过 {settings.contact_email} 联系技术支持。</>
                    : '可通过页脚中的联系方式获取技术支持。'}
                  {settings.help_url && (
                    <a href={settings.help_url} target="_blank" rel="noreferrer" style={{ marginLeft: 4 }}>
                      查看帮助中心
                    </a>
                  )}
                </div>
              </div>
            </Space>
          </Col>
        </Row>
      </Card>

      {!hasAnyDownload && (
        <Alert
          type="info" showIcon style={{ marginTop: 24 }}
          message="下载即将开放，敬请期待"
        />
      )}
    </div>
  );
};

export default PortalDownloads;
