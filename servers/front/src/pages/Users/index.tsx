import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input,
  Select, Switch, Popconfirm, message, Tooltip, Card,
} from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined, UserOutlined, ReloadOutlined } from '@ant-design/icons';
import { listUsers, createUser, updateUser, deleteUser, updateUserRole, toggleUserEnabled } from '../../api';
import type { User } from '../../types';
import { useThemeStore } from '../../store/theme';
import dayjs from 'dayjs';

const { Title, Text } = Typography;
const { Option } = Select;

const Users: React.FC = () => {
  const { darkMode } = useThemeStore();
  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [modalOpen, setModalOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [form] = Form.useForm();

  const load = async (p = page) => {
    setLoading(true);
    try {
      const res = await listUsers({ page: p, page_size: 10 });
      setUsers(res?.items ?? []);
      setTotal(res?.total ?? 0);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      if (editUser) {
        await updateUser(editUser.uuid, values);
        message.success('用户已更新');
      } else {
        await createUser(values);
        message.success('用户已创建');
      }
      setModalOpen(false); form.resetFields(); setEditUser(null); load();
    } catch (e: any) { if (e.message) message.error(e.message); }
  };

  const handleEdit = (user: User) => {
    setEditUser(user);
    form.setFieldsValue({ user_type: user.user_type, display_name: user.display_name, email: user.email, enabled: user.enabled });
    setModalOpen(true);
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const columns = [
    {
      title: '显示名称', dataIndex: 'display_name',
      render: (v: string) => <Space><UserOutlined style={{ color: '#1677ff' }} /><Text strong>{v}</Text></Space>,
    },
    { title: '邮箱', dataIndex: 'email', render: (v: string) => <Text type="secondary">{v || '-'}</Text> },
    {
      title: '角色', dataIndex: 'user_type', width: 160,
      render: (v: string, record: User) => (
        <Select size="small" value={v || 'user'} style={{ width: 140 }}
          onChange={(role) => updateUserRole(record.uuid, role as any).then(() => { message.success('角色已更新'); load(); }).catch((e: any) => message.error(e.message))}
          onClick={(e) => e.stopPropagation()}>
          <Option value="super_admin"><Tag color="red" style={{ margin: 0 }}>超级管理员</Tag></Option>
          <Option value="admin"><Tag color="gold" style={{ margin: 0 }}>管理员</Tag></Option>
          <Option value="operator"><Tag color="blue" style={{ margin: 0 }}>操作员</Tag></Option>
          <Option value="user"><Tag color="green" style={{ margin: 0 }}>普通用户</Tag></Option>
          <Option value="readonly"><Tag color="default" style={{ margin: 0 }}>只读</Tag></Option>
        </Select>
      ),
    },
    {
      title: '启用状态', dataIndex: 'enabled', width: 90,
      render: (v: boolean, record: User) => (
        <Switch size="small" checked={v}
          onChange={(checked) => toggleUserEnabled(record.uuid, checked).then(() => { message.success(checked ? '已启用' : '已禁用'); load(); }).catch((e: any) => message.error(e.message))}
          onClick={(_, e) => e.stopPropagation()} />
      ),
    },
    {
      title: '创建时间', dataIndex: 'created_at', width: 160,
      render: (v: string) => <Text style={{ fontSize: 12, color: '#8b949e' }}>{dayjs(v).format('YYYY-MM-DD HH:mm')}</Text>,
    },
    {
      title: '操作', width: 100,
      render: (_: any, record: User) => (
        <Space>
          <Tooltip title="编辑"><Button type="text" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)} /></Tooltip>
          <Popconfirm title="确认删除此用户？" onConfirm={() => deleteUser(record.uuid).then(() => { message.success('已删除'); load(); }).catch((e: any) => message.error(e.message))} okButtonProps={{ danger: true }}>
            <Tooltip title="删除"><Button type="text" size="small" danger icon={<DeleteOutlined />} /></Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>平台用户管理</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => load()}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditUser(null); form.resetFields(); setModalOpen(true); }}>新建用户</Button>
        </Space>
      </div>
      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table dataSource={users} columns={columns} rowKey="uuid" loading={loading}
          pagination={{ current: page, total, pageSize: 10, onChange: (p) => { setPage(p); load(p); }, showTotal: (t) => `共 ${t} 条` }}
          style={{ background: 'transparent' }} />
      </Card>
      <Modal title={editUser ? '编辑用户' : '新建用户'} open={modalOpen}
        onOk={handleSubmit} onCancel={() => { setModalOpen(false); form.resetFields(); setEditUser(null); }}
        okText={editUser ? '保存' : '创建'} cancelText="取消" width={480}>
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="display_name" label="显示名称" rules={[{ required: true }]}><Input placeholder="例如：张三" /></Form.Item>
          <Form.Item name="email" label="邮箱" rules={[{ type: 'email', message: '请输入有效邮箱' }]}><Input placeholder="user@example.com" /></Form.Item>
          <Form.Item name="user_type" label="用户类型" initialValue="user">
            <Select options={[
              { value: 'super_admin', label: '超级管理员' },
              { value: 'admin', label: '管理员' },
              { value: 'operator', label: '操作员' },
              { value: 'user', label: '普通用户' },
              { value: 'readonly', label: '只读用户' },
            ]} />
          </Form.Item>
          {!editUser && (
            <Form.Item name="password" label="密码" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}>
              <Input.Password placeholder="至少 8 位" />
            </Form.Item>
          )}
          {editUser && (
            <Form.Item name="enabled" label="账号状态" valuePropName="checked">
              <Switch checkedChildren="启用" unCheckedChildren="禁用" />
            </Form.Item>
          )}
        </Form>
      </Modal>
    </div>
  );
};

export default Users;
