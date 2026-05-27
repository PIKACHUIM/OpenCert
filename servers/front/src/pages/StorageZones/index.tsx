import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm,
} from 'antd';
import {
  DatabaseOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined,
} from '@ant-design/icons';
import { listStorageZones, createStorageZone, deleteStorageZone } from '../../api';
import type { StorageZone } from '../../types';

const { Title } = Typography;

/**
 * StorageZones 页面：云端智能卡存储区域管理。
 * - 数据库存储 / HSM（硬件安全模块）
 * - 卡片创建时可选择存储区域
 */
const StorageZonesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<StorageZone[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listStorageZones(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetch(); }, []);

  const handleCreate = async (values: any) => {
    try {
      await createStorageZone({
        name: values.name, storage_type: values.storage_type,
        hsm_driver: values.hsm_driver, status: values.status || 'active',
      });
      message.success('存储区域已创建');
      setCreateOpen(false);
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteStorageZone(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: '存储类型', dataIndex: 'storage_type', key: 'storage_type',
      render: (v: string) => v === 'hsm'
        ? <Tag color="red">HSM</Tag>
        : <Tag color="blue">数据库</Tag> },
    { title: 'HSM 驱动', dataIndex: 'hsm_driver', key: 'hsm_driver',
      render: (v: string) => v || '-' },
    { title: '状态', dataIndex: 'status', key: 'status',
      render: (v: string) => v === 'active'
        ? <Tag color="success">激活</Tag>
        : <Tag color="default">禁用</Tag> },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: StorageZone) => (
        <Popconfirm title="确认删除此存储区域？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><DatabaseOutlined />
          <Title level={4} style={{ margin: 0 }}>云端智能卡存储区域</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新建存储区域</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新建存储区域"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}
          initialValues={{ storage_type: 'database', status: 'active' }}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={64} placeholder="例如：主数据库区、HSM-01" />
          </Form.Item>
          <Form.Item name="storage_type" label="存储类型" rules={[{ required: true }]}>
            <Select options={[
              { label: '数据库（加密存储）', value: 'database' },
              { label: 'HSM（硬件安全模块）', value: 'hsm' },
            ]} />
          </Form.Item>
          <Form.Item name="hsm_driver" label="HSM 驱动"
            tooltip="仅 HSM 类型需要填写，例如 pkcs11、softhsm2">
            <Input placeholder="pkcs11 / softhsm2 / cloudhsm 等" />
          </Form.Item>
          <Form.Item name="status" label="状态">
            <Select options={[
              { label: '激活', value: 'active' },
              { label: '禁用', value: 'disabled' },
            ]} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default StorageZonesPage;
