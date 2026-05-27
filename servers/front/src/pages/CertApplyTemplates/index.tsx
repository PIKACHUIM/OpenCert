import React, { useEffect, useState } from 'react';
import {
  Table, Card, Button, Modal, Form, Input, InputNumber, Switch,
  Space, Tag, Typography, Popconfirm, message, Select,
} from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { apiRequest } from '../../api';

const { Title } = Typography;
const { Option } = Select;

interface CertApplyTemplate {
  uuid: string;
  name: string;
  issuance_tmpl_uuid: string;
  valid_days: number;
  ca_uuid: string;
  enabled: boolean;
  require_approval: boolean;
  allow_renewal: boolean;
  allowed_key_types: string;
  price_cents: number;
  description: string;
  created_at: string;
}

const CertApplyTemplates: React.FC = () => {
  const [templates, setTemplates] = useState<CertApplyTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [editItem, setEditItem] = useState<CertApplyTemplate | null>(null);
  const [form] = Form.useForm();

  const fetchTemplates = async () => {
    setLoading(true);
    try {
      const data = await apiRequest('/api/templates/cert-apply');
      setTemplates(Array.isArray(data?.items) ? data.items : []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTemplates(); }, []);

  const handleSubmit = async (values: any) => {
    try {
      const payload = {
        ...values,
        allowed_key_types: JSON.stringify(values.allowed_key_types || ['ec256', 'rsa2048']),
      };
      if (editItem) {
        await apiRequest(`/api/templates/cert-apply/${editItem.uuid}`, { method: 'PUT', body: JSON.stringify(payload) });
        message.success('模板已更新');
      } else {
        await apiRequest('/api/templates/cert-apply', { method: 'POST', body: JSON.stringify(payload) });
        message.success('模板已创建');
      }
      setModalOpen(false);
      form.resetFields();
      setEditItem(null);
      fetchTemplates();
    } catch (e: any) {
      message.error(e.message || '操作失败');
    }
  };

  const handleDelete = async (uuid: string) => {
    try {
      await apiRequest(`/api/templates/cert-apply/${uuid}`, { method: 'DELETE' });
      message.success('模板已删除');
      fetchTemplates();
    } catch (e: any) {
      message.error(e.message || '删除失败');
    }
  };

  const openEdit = (item: CertApplyTemplate) => {
    setEditItem(item);
    form.setFieldsValue({
      ...item,
      allowed_key_types: JSON.parse(item.allowed_key_types || '["ec256","rsa2048"]'),
    });
    setModalOpen(true);
  };

  const columns = [
    { title: '模板名称', dataIndex: 'name', ellipsis: true },
    { title: '有效期(天)', dataIndex: 'valid_days', width: 100 },
    { title: '价格(分)', dataIndex: 'price_cents', width: 100 },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '启用' : '禁用'}</Tag>,
    },
    {
      title: '需要审批',
      dataIndex: 'require_approval',
      width: 90,
      render: (v: boolean) => <Tag color={v ? 'orange' : 'default'}>{v ? '是' : '否'}</Tag>,
    },
    {
      title: '允许续期',
      dataIndex: 'allow_renewal',
      width: 90,
      render: (v: boolean) => <Tag color={v ? 'blue' : 'default'}>{v ? '是' : '否'}</Tag>,
    },
    { title: '描述', dataIndex: 'description', ellipsis: true },
    {
      title: '操作',
      width: 120,
      render: (_: any, r: CertApplyTemplate) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(r)} />
          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(r.uuid)}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>证书申请模板</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditItem(null); form.resetFields(); setModalOpen(true); }}>
          新建模板
        </Button>
      </div>

      <Card>
        <Table columns={columns} dataSource={templates} rowKey="uuid" loading={loading} />
      </Card>

      <Modal
        title={editItem ? '编辑证书申请模板' : '新建证书申请模板'}
        open={modalOpen}
        onCancel={() => { setModalOpen(false); setEditItem(null); form.resetFields(); }}
        onOk={() => form.submit()}
        width={600}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="模板名称" rules={[{ required: true }]}>
            <Input placeholder="如：标准 SSL 证书" />
          </Form.Item>
          <Form.Item name="issuance_tmpl_uuid" label="关联颁发模板 UUID">
            <Input placeholder="颁发模板 UUID（可选）" />
          </Form.Item>
          <Form.Item name="ca_uuid" label="指定签发 CA UUID">
            <Input placeholder="CA UUID（可选）" />
          </Form.Item>
          <Form.Item name="valid_days" label="有效期（天）" initialValue={365}>
            <InputNumber min={1} max={3650} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="price_cents" label="价格（分）" initialValue={0}>
            <InputNumber min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="allowed_key_types" label="允许的密钥类型" initialValue={['ec256', 'rsa2048']}>
            <Select mode="multiple">
              <Option value="ec256">EC P-256</Option>
              <Option value="ec384">EC P-384</Option>
              <Option value="rsa2048">RSA 2048</Option>
              <Option value="rsa4096">RSA 4096</Option>
            </Select>
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} />
          </Form.Item>
          <Space>
            <Form.Item name="enabled" label="启用" valuePropName="checked" initialValue={true}>
              <Switch />
            </Form.Item>
            <Form.Item name="require_approval" label="需要审批" valuePropName="checked" initialValue={false}>
              <Switch />
            </Form.Item>
            <Form.Item name="allow_renewal" label="允许续期" valuePropName="checked" initialValue={true}>
              <Switch />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  );
};

export default CertApplyTemplates;
