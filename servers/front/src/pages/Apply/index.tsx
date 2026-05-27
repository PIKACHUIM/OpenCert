import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card, Form, Input, Select, Button, Space, Typography, Tag, Steps, Result,
  message, Alert, Divider, Row, Col,
} from 'antd';
import {
  SafetyCertificateOutlined, ArrowLeftOutlined, GlobalOutlined,
  MailOutlined, BankOutlined, PlusOutlined, MinusCircleOutlined,
} from '@ant-design/icons';
import http from '../../api/http';

const { Title, Text, Paragraph } = Typography;

const keyTypeOptions = [
  { label: 'ECDSA P-256（推荐）', value: 'ecdsa-p256' },
  { label: 'ECDSA P-384', value: 'ecdsa-p384' },
  { label: 'RSA 2048', value: 'rsa2048' },
  { label: 'RSA 4096', value: 'rsa4096' },
];

/**
 * 公开证书申请页面（无需登录）。
 * 用户填写域名、组织信息后提交，获得申请 UUID 用于查询审核状态。
 */
const ApplyPage: React.FC = () => {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ uuid: string; message: string } | null>(null);

  const handleSubmit = async (values: any) => {
    setLoading(true);
    try {
      const resp = await http.post('/api/public/cert-applications', {
        domains: values.domains.filter((d: string) => d && d.trim()),
        organization: values.organization,
        email: values.email,
        key_type: values.key_type || 'ecdsa-p256',
        country: values.country,
        province: values.province,
        locality: values.locality,
        org_unit: values.org_unit,
        remark: values.remark,
      });
      setResult(resp.data);
    } catch (e: any) {
      message.error(e?.response?.data?.message || e?.message || '提交失败');
    } finally {
      setLoading(false);
    }
  };

  if (result) {
    return (
      <div style={{ minHeight: '100vh', background: '#0d1117', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
        <Card style={{ maxWidth: 600, width: '100%', background: '#161b22', border: '1px solid #30363d', borderRadius: 16 }}>
          <Result
            status="success"
            title={<span style={{ color: '#e6edf3' }}>证书申请已提交</span>}
            subTitle={
              <Space direction="vertical" size={8}>
                <Text style={{ color: '#8b949e' }}>{result.message}</Text>
                <Text copyable style={{ color: '#58a6ff', fontFamily: 'monospace' }}>
                  申请 UUID: {result.uuid}
                </Text>
              </Space>
            }
            extra={[
              <Button key="home" onClick={() => navigate('/')}>返回首页</Button>,
              <Button key="new" type="primary" onClick={() => { setResult(null); form.resetFields(); }}>
                继续申请
              </Button>,
            ]}
          />
          <Alert
            type="info" showIcon style={{ marginTop: 16 }}
            message="请保存申请 UUID，后续可通过此 UUID 查询审核状态。管理员审核通过后，证书将自动签发。"
          />
        </Card>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: '#0d1117', color: '#e6edf3' }}>
      {/* 顶部导航 */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
        padding: '0 48px', height: 64,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'rgba(13,17,23,0.85)', backdropFilter: 'blur(12px)',
        borderBottom: '1px solid rgba(48,54,61,0.6)',
      }}>
        <Space align="center">
          <Button type="text" icon={<ArrowLeftOutlined />} style={{ color: '#8b949e' }}
            onClick={() => navigate('/')}>返回首页</Button>
          <Divider type="vertical" style={{ borderColor: '#30363d' }} />
          <div style={{ width: 28, height: 28, borderRadius: 6, background: 'linear-gradient(135deg, #1677ff, #722ed1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <SafetyCertificateOutlined style={{ color: '#fff', fontSize: 14 }} />
          </div>
          <Text strong style={{ color: '#e6edf3', fontSize: 16 }}>证书申请</Text>
        </Space>
        <Button type="text" style={{ color: '#8b949e' }} onClick={() => navigate('/login')}>管理员登录</Button>
      </div>

      {/* 主体内容 */}
      <div style={{ paddingTop: 100, paddingBottom: 60, maxWidth: 720, margin: '0 auto', padding: '100px 24px 60px' }}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
          <Tag color="blue" style={{ marginBottom: 16, borderRadius: 20, padding: '4px 16px' }}>
            🔐 无需注册，直接申请
          </Tag>
          <Title level={2} style={{ color: '#e6edf3', margin: '0 0 12px' }}>
            申请 SSL/TLS 证书
          </Title>
          <Paragraph style={{ color: '#8b949e', fontSize: 16 }}>
            填写域名与组织信息后提交，管理员审核通过后将自动签发证书。
          </Paragraph>
        </div>

        <Steps
          size="small" style={{ marginBottom: 32 }}
          current={0}
          items={[
            { title: '填写信息' },
            { title: '提交申请' },
            { title: '管理员审核' },
            { title: '证书签发' },
          ]}
        />

        <Card style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 12 }}>
          <Form
            form={form}
            layout="vertical"
            onFinish={handleSubmit}
            initialValues={{ key_type: 'ecdsa-p256', domains: [''] }}
          >
            {/* 域名列表 */}
            <Form.List name="domains" initialValue={['']}>
              {(fields, { add, remove }) => (
                <Form.Item label={<span style={{ color: '#e6edf3' }}><GlobalOutlined /> 域名列表（SAN）</span>}>
                  {fields.map((field, idx) => (
                    <Space key={field.key} style={{ display: 'flex', marginBottom: 8 }} align="baseline">
                      <Form.Item
                        {...field}
                        rules={[{ required: idx === 0, message: '至少填写一个域名' }]}
                        noStyle
                      >
                        <Input placeholder="example.com 或 *.example.com" style={{ width: 400 }} />
                      </Form.Item>
                      {fields.length > 1 && (
                        <MinusCircleOutlined style={{ color: '#f85149' }} onClick={() => remove(field.name)} />
                      )}
                    </Space>
                  ))}
                  <Button type="dashed" onClick={() => add()} icon={<PlusOutlined />} style={{ width: 400 }}>
                    添加域名
                  </Button>
                </Form.Item>
              )}
            </Form.List>

            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="organization" label={<span style={{ color: '#e6edf3' }}><BankOutlined /> 组织名称</span>}
                  rules={[{ required: true, message: '请输入组织名称' }]}>
                  <Input placeholder="如：北京某某科技有限公司" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="email" label={<span style={{ color: '#e6edf3' }}><MailOutlined /> 联系邮箱</span>}
                  rules={[{ required: true, type: 'email', message: '请输入有效邮箱' }]}>
                  <Input placeholder="admin@example.com" />
                </Form.Item>
              </Col>
            </Row>

            <Row gutter={16}>
              <Col span={8}>
                <Form.Item name="country" label={<span style={{ color: '#e6edf3' }}>国家代码</span>}>
                  <Input placeholder="CN" maxLength={2} />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item name="province" label={<span style={{ color: '#e6edf3' }}>省/州</span>}>
                  <Input placeholder="Beijing" />
                </Form.Item>
              </Col>
              <Col span={8}>
                <Form.Item name="locality" label={<span style={{ color: '#e6edf3' }}>城市</span>}>
                  <Input placeholder="Beijing" />
                </Form.Item>
              </Col>
            </Row>

            <Row gutter={16}>
              <Col span={12}>
                <Form.Item name="org_unit" label={<span style={{ color: '#e6edf3' }}>部门（可选）</span>}>
                  <Input placeholder="IT Department" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item name="key_type" label={<span style={{ color: '#e6edf3' }}>密钥算法</span>}>
                  <Select options={keyTypeOptions} />
                </Form.Item>
              </Col>
            </Row>

            <Form.Item name="remark" label={<span style={{ color: '#e6edf3' }}>备注（可选）</span>}>
              <Input.TextArea rows={2} placeholder="如有特殊需求请在此说明" maxLength={500} />
            </Form.Item>

            <Form.Item>
              <Button type="primary" htmlType="submit" loading={loading} size="large" block
                style={{ height: 48, borderRadius: 10, fontWeight: 600, fontSize: 16,
                  background: 'linear-gradient(135deg, #1677ff, #0958d9)', border: 'none' }}>
                提交证书申请
              </Button>
            </Form.Item>
          </Form>
        </Card>

        <Alert
          type="info" showIcon style={{ marginTop: 24, background: '#161b22', border: '1px solid #30363d' }}
          message="申请说明"
          description="提交后管理员将审核您的域名所有权与组织信息。审核通过后证书将自动签发，您可通过申请 UUID 查询进度。如需自动化证书管理，推荐使用 ACME 协议。"
        />
      </div>
    </div>
  );
};

export default ApplyPage;
