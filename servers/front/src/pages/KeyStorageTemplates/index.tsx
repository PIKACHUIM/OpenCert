import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, InputNumber,
  Switch, Select, message, Popconfirm,
} from 'antd';
import {
  SafetyOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, EditOutlined,
} from '@ant-design/icons';
import {
  listKeyStorageTemplates, createKeyStorageTemplate,
  updateKeyStorageTemplate, deleteKeyStorageTemplate,
} from '../../api';
import type { KeyStorageTemplate } from '../../types';

const { Title } = Typography;

/**
 * KeyStorageTemplates 页面：密钥存储类型模板。
 * 约束证书申请时允许的存储方式（文件/云端卡/物理卡/虚拟卡/重颁发等）。
 */
const KeyStorageTemplatesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<KeyStorageTemplate[]>([]);
  const [modal, setModal] = useState<{ open: boolean; editing: KeyStorageTemplate | null }>({
    open: false, editing: null,
  });
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { const r = await listKeyStorageTemplates(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetch(); }, []);

  const openCreate = () => {
    form.resetFields();
    form.setFieldsValue({
      allow_file_download: true, allow_cloud_card: true,
      allow_physical_card: false, allow_virtual_card: false,
      virtual_card_security: 'medium', allow_reimport: false,
      cloud_backup: false, allow_reissue: true, max_reissue_count: 3,
    });
    setModal({ open: true, editing: null });
  };

  const openEdit = (r: KeyStorageTemplate) => {
    form.setFieldsValue(r);
    setModal({ open: true, editing: r });
  };

  const handleSubmit = async (values: any) => {
    try {
      if (modal.editing) {
        await updateKeyStorageTemplate(modal.editing.uuid, values);
        message.success('已更新');
      } else {
        await createKeyStorageTemplate(values);
        message.success('已创建');
      }
      setModal({ open: false, editing: null });
      form.resetFields();
      fetch();
    } catch (e: any) { message.error(e.message || '保存失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteKeyStorageTemplate(uuid); message.success('已删除'); fetch(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    {
      title: '允许的存储方式', key: 'flags',
      render: (_: any, r: KeyStorageTemplate) => (
        <Space size={4} wrap>
          {r.allow_file_download && <Tag color="blue">文件下载</Tag>}
          {r.allow_cloud_card && <Tag color="green">云端卡</Tag>}
          {r.allow_physical_card && <Tag color="orange">物理卡</Tag>}
          {r.allow_virtual_card && <Tag color="purple">虚拟卡({r.virtual_card_security})</Tag>}
          {r.cloud_backup && <Tag color="cyan">云备份</Tag>}
          {r.allow_reimport && <Tag color="gold">可重导入</Tag>}
          {r.allow_reissue && <Tag>可重颁发({r.max_reissue_count}次)</Tag>}
        </Space>
      ),
    },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 180,
      render: (_: any, r: KeyStorageTemplate) => (
        <Space>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><SafetyOutlined />
          <Title level={4} style={{ margin: 0 }}>密钥存储类型模板</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建模板</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={modal.open} title={modal.editing ? '编辑模板' : '新建模板'}
        onCancel={() => { setModal({ open: false, editing: null }); form.resetFields(); }}
        onOk={() => form.submit()} width={620} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="模板名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={64} />
          </Form.Item>
          <Space wrap>
            <Form.Item name="allow_file_download" label="允许文件下载" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="allow_cloud_card" label="允许云端卡" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="allow_physical_card" label="允许物理卡" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="allow_virtual_card" label="允许虚拟卡" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="virtual_card_security" label="虚拟卡安全级别">
            <Select options={[
              { label: '高（推荐）', value: 'high' },
              { label: '中', value: 'medium' },
              { label: '低', value: 'low' },
            ]} />
          </Form.Item>
          <Space wrap>
            <Form.Item name="allow_reimport" label="允许重导入" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="cloud_backup" label="云端备份" valuePropName="checked"><Switch /></Form.Item>
            <Form.Item name="allow_reissue" label="允许重颁发" valuePropName="checked"><Switch /></Form.Item>
          </Space>
          <Form.Item name="max_reissue_count" label="最大重颁发次数">
            <InputNumber min={0} max={20} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default KeyStorageTemplatesPage;
