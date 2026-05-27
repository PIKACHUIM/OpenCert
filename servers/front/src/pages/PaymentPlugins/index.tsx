import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm, Alert,
} from 'antd';
import {
  WalletOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { listPaymentPlugins, createPaymentPlugin, deletePaymentPlugin } from '../../api';
import type { PaymentPlugin } from '../../types';

const { Title, Text } = Typography;

/**
 * PaymentPlugins 页面：支付插件管理。
 * - 配置支付渠道（支付宝/微信/Stripe 等）
 * - 管理 API 密钥和回调地址
 */
const PaymentPluginsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<PaymentPlugin[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listPaymentPlugins(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetch(); }, []);

  const handleCreate = async (values: any) => {
    try {
      await createPaymentPlugin({
        name: values.name,
        plugin_type: values.plugin_type,
        api_key: values.api_key,
        api_secret: values.api_secret,
        callback_url: values.callback_url,
        enabled: values.enabled !== false,
      });
      message.success('支付插件已创建');
      setCreateOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deletePaymentPlugin(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const typeColors: Record<string, string> = {
    alipay: 'blue', wechat: 'green', stripe: 'purple',
    paypal: 'orange', manual: 'default',
  };
  const typeTexts: Record<string, string> = {
    alipay: '支付宝', wechat: '微信支付', stripe: 'Stripe',
    paypal: 'PayPal', manual: '手动/线下',
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    {
      title: '类型', dataIndex: 'plugin_type', key: 'plugin_type',
      render: (v: string) => <Tag color={typeColors[v] || 'default'}>{typeTexts[v] || v}</Tag>,
    },
    {
      title: 'API Key', dataIndex: 'api_key', key: 'api_key', ellipsis: true,
      render: (v: string) => v ? <Text code>{v.substring(0, 8)}****</Text> : '-',
    },
    {
      title: '回调地址', dataIndex: 'callback_url', key: 'callback_url', ellipsis: true,
      render: (v: string) => v ? <Text copyable={{ text: v }}>{v}</Text> : '-',
    },
    {
      title: '启用', dataIndex: 'enabled', key: 'enabled',
      render: (v: boolean) => v
        ? <Tag color="success">启用</Tag>
        : <Tag color="default">禁用</Tag>,
    },
    {
      title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN'),
    },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: PaymentPlugin) => (
        <Popconfirm title="确认删除此支付插件？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><WalletOutlined />
          <Title level={4} style={{ margin: 0 }}>支付插件管理</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增插件</Button>
          </Space>
        }
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="支付插件用于对接第三方支付渠道，用户充值和证书订单支付时将通过已启用的插件完成交易。API 密钥将加密存储。"
        />
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新增支付插件"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} width={560} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}
          initialValues={{ plugin_type: 'manual', enabled: true }}>
          <Form.Item name="name" label="插件名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={64} placeholder="例如：支付宝-生产环境" />
          </Form.Item>
          <Form.Item name="plugin_type" label="支付类型" rules={[{ required: true }]}>
            <Select options={Object.entries(typeTexts).map(([v, l]) => ({ label: l, value: v }))} />
          </Form.Item>
          <Form.Item name="api_key" label="API Key"
            extra="支付渠道提供的 API Key / App ID">
            <Input maxLength={256} placeholder="支付渠道 API Key" />
          </Form.Item>
          <Form.Item name="api_secret" label="API Secret"
            extra="支付渠道提供的 API Secret / 私钥">
            <Input.Password maxLength={512} placeholder="支付渠道 API Secret" />
          </Form.Item>
          <Form.Item name="callback_url" label="回调地址"
            extra="支付成功后的回调通知地址">
            <Input maxLength={512} placeholder="https://your-domain.com/api/payment/callback" />
          </Form.Item>
          <Form.Item name="enabled" label="是否启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default PaymentPluginsPage;
