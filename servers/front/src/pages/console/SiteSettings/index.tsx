import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Col, Divider, Form, Input, InputNumber, Row, Select, Space, Typography, message } from 'antd';
import { SaveOutlined, ReloadOutlined } from '@ant-design/icons';
import { getSiteSettings, updateSiteSettings } from '../../../api';
import type { SiteSettings } from '../../../types';

const { Title, Text } = Typography;

/**
 * 控制台 - 站点设置。
 *
 * 仅管理门户展示所需信息（品牌、联系方式、下载与条款链接），
 * 不包含任何密钥或账号敏感配置。
 */
const ConsoleSiteSettings: React.FC = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await getSiteSettings();
      form.setFieldsValue(data);
    } catch (e: any) {
      setError(e?.message || '加载站点配置失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, []);

  const submit = async (values: Partial<SiteSettings>) => {
    setSaving(true);
    try {
      // 服务端配置统一为字符串键值，数值项在此转换
      const payload: Record<string, string> = {};
      Object.entries(values).forEach(([k, v]) => {
        if (v !== undefined && v !== null) payload[k] = String(v);
      });
      await updateSiteSettings(payload);
      message.success('站点配置已保存');
    } catch (e: any) {
      message.error(e?.message || '保存失败');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <Title level={4} style={{ margin: 0 }}>站点设置</Title>
          <Text type="secondary" style={{ fontSize: 13 }}>
            门户官网的品牌信息、联系方式与外部链接（保存后前台立即生效）
          </Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={load}>重新加载</Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={() => form.submit()}>
            保存
          </Button>
        </Space>
      </div>

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      <Card loading={loading}>
        <Form form={form} layout="vertical" onFinish={submit}>
          <Divider titlePlacement="start" style={{ marginTop: 0 }}>品牌信息</Divider>
          <Row gutter={16}>
            <Col xs={24} md={12}>
              <Form.Item name="site_name" label="站点名称">
                <Input placeholder="OpenCert" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="site_tagline" label="站点标语">
                <Input placeholder="云端证书与智能卡服务平台" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="site_description" label="站点简介" extra="展示在首页与页脚">
            <Input.TextArea rows={3} maxLength={300} showCount />
          </Form.Item>

          <Divider titlePlacement="start">业务模式与自助限制</Divider>
          <Alert
            type="info" showIcon style={{ marginBottom: 12 }}
            message="决定用户能否自助申请证书/开通智能卡，或必须先购买订单"
            description="销售模式下用户须凭已支付订单操作，不符合条件的入口会自动隐藏。"
          />
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name="cert_apply_mode" label="证书申请模式" extra="sales=必须购买订单；self=允许自助申请">
                <Select options={[
                  { label: '销售模式（需购买）', value: 'sales' },
                  { label: '自助模式（可直接申请）', value: 'self' },
                ]} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="card_apply_mode" label="智能卡开通模式" extra="sales=凭云智能卡订单开卡；self=允许自助开卡">
                <Select options={[
                  { label: '销售模式（需购买）', value: 'sales' },
                  { label: '自助模式（可直接开通）', value: 'self' },
                ]} />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="card_self_limit" label="自助开卡上限" extra="自助模式下每账号可开通数量">
                <InputNumber min={0} max={1000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name="order_expire_hours" label="订单超时时间（小时）" extra="超时未支付的订单自动关闭并归还库存与优惠码">
                <InputNumber min={1} max={720} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col xs={24} md={16}>
              <Form.Item
                name="self_san_policy" label="自助/订阅申请的 SAN 限制（JSON）"
                extra='示例：{"max_dns":5,"max_email":1,"max_ip":0,"allow_wildcard":false,"ip_versions":["v4","v6"],"email_suffixes":["corp.com"]}'
                rules={[{
                  validator: (_, v: string) => {
                    if (!v) return Promise.resolve();
                    try {
                      const parsed = JSON.parse(v);
                      if (typeof parsed !== 'object' || parsed === null) throw new Error('not object');
                      return Promise.resolve();
                    } catch { return Promise.reject(new Error('需为合法 JSON 对象')); }
                  },
                }]}
              >
                <Input.TextArea rows={3} style={{ fontFamily: 'ui-monospace, Menlo, monospace' }} />
              </Form.Item>
            </Col>
          </Row>

          <Divider titlePlacement="start">联系方式与备案</Divider>
          <Row gutter={16}>
            <Col xs={24} md={8}>
              <Form.Item name="contact_email" label="联系邮箱">
                <Input placeholder="support@example.com" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="contact_phone" label="联系电话">
                <Input placeholder="400-000-0000" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="icp_record" label="备案号">
                <Input placeholder="京ICP备00000000号" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="footer_note" label="页脚说明" extra="留空时自动显示版权信息">
            <Input placeholder="© 2026 OpenCert" />
          </Form.Item>

          <Divider titlePlacement="start">外部链接</Divider>
          <Row gutter={16}>
            <Col xs={24} md={12}>
              <Form.Item name="help_url" label="帮助中心地址">
                <Input placeholder="https://docs.example.com" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="client_download" label="客户端下载地址">
                <Input placeholder="https://download.example.com/client" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="driver_download" label="驱动下载地址">
                <Input placeholder="https://download.example.com/driver" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="terms_url" label="服务条款地址">
                <Input placeholder="https://example.com/terms" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="privacy_url" label="隐私政策地址">
                <Input placeholder="https://example.com/privacy" />
              </Form.Item>
            </Col>
          </Row>

          <Alert
            type="info" showIcon
            message="留空的链接不会在门户页脚中显示，避免出现无效入口。"
          />
        </Form>
      </Card>
    </div>
  );
};

export default ConsoleSiteSettings;
