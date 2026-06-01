import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input,
  Select, Switch, Popconfirm, message, Tooltip, Card,
} from 'antd';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, UserOutlined, ReloadOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import { getUsers, createUser, updateUser, deleteUser } from '../../api';
import type { User, CreateUserRequest } from '../../types';
import { useAppStore } from '../../store/appStore';
import dayjs from 'dayjs';

const { Text } = Typography;

const Users: React.FC = () => {
  const { darkMode } = useAppStore();
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
      const res = await getUsers({ page: p, page_size: 10 });
      const items = res?.items;
      setUsers(Array.isArray(items) ? items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      if (editUser) {
        await updateUser(editUser.uuid, values);
        message.success('用户已更新');
      } else {
        await createUser(values as CreateUserRequest);
        message.success('用户已创建');
      }
      setModalOpen(false);
      form.resetFields();
      setEditUser(null);
      load();
    } catch (e: any) {
      if (e.message) message.error(e.message);
    }
  };

  const handleEdit = (user: User) => {
    setEditUser(user);
    form.setFieldsValue({
      user_type: user.user_type,
      display_name: user.display_name,
      email: user.email,
      cloud_url: user.cloud_url,
      enabled: user.enabled,
    });
    setModalOpen(true);
  };

  const handleDelete = async (uuid: string) => {
    try {
      await deleteUser(uuid);
      message.success('用户已删除');
      load();
    } catch (e: any) {
      message.error(e.message);
    }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const columns = [
    {
      title: '用户名',
      dataIndex: 'username',
      width: 130,
      render: (v: string) => (
        <Space>
          <UserOutlined style={{ color: '#1677ff' }} />
          <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{v}</Text>
        </Space>
      ),
    },
    {
      title: '显示名称',
      dataIndex: 'display_name',
      render: (v: string) => <Text style={{ color: darkMode ? '#c9d1d9' : undefined }}>{v || '-'}</Text>,
    },
    {
      title: '邮箱',
      dataIndex: 'email',
      render: (v: string) => <Text style={{ color: darkMode ? '#8b949e' : '#666' }}>{v || '-'}</Text>,
    },
    {
      title: '角色',
      dataIndex: 'role',
      width: 100,
      render: (v: string) => {
        const colorMap: Record<string, string> = { admin: 'gold', user: 'blue', readonly: 'default' };
        return <Tag color={colorMap[v] || 'blue'}>{v || 'user'}</Tag>;
      },
    },
    {
      title: '类型',
      dataIndex: 'user_type',
      width: 90,
      render: (v: string) => (
        <Tag color={v === 'cloud' ? 'cyan' : 'purple'}>{v === 'cloud' ? '云端' : '本地'}</Tag>
      ),
    },
    {
      title: '云端地址',
      dataIndex: 'cloud_url',
      ellipsis: true,
      render: (v: string) => (
        <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>{v || '-'}</Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean) => (
        <Tag color={v ? 'success' : 'default'}>{v ? '启用' : '禁用'}</Tag>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 160,
      render: (v: string) => (
        <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>
          {dayjs(v).format('YYYY-MM-DD HH:mm')}
        </Text>
      ),
    },
    {
      title: '操作',
      width: 120,
      render: (_: any, record: User) => (
        <Space>
          <Tooltip title="编辑">
            <Button
              type="text" size="small" icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
            />
          </Tooltip>
          <Popconfirm
            title="确认删除此用户？"
            onConfirm={() => handleDelete(record.uuid)}
            okText="删除" cancelText="取消" okButtonProps={{ danger: true }}
          >
            <Tooltip title="删除">
              <Button type="text" size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  // 展开行渲染详细信息
  const expandedRowRender = (record: User) => (
    <div style={{ padding: '8px 16px', fontSize: 13, color: darkMode ? '#8b949e' : '#666' }}>
<Space orientation="vertical" size={4} style={{ width: '100%' }}>
        <div><Text type="secondary" style={{ width: 80, display: 'inline-block' }}>UUID:</Text> <Text copyable={{ text: record.uuid }} style={{ fontSize: 12, color: darkMode ? '#c9d1d9' : '#333' }}>{record.uuid}</Text></div>
        <div><Text type="secondary" style={{ width: 80, display: 'inline-block' }}>用户名:</Text> <Text style={{ color: darkMode ? '#c9d1d9' : '#333' }}>{record.username}</Text></div>
        {record.email && <div><Text type="secondary" style={{ width: 80, display: 'inline-block' }}>邮箱:</Text> <Text style={{ color: darkMode ? '#c9d1d9' : '#333' }}>{record.email}</Text></div>}
        {record.cloud_url && <div><Text type="secondary" style={{ width: 80, display: 'inline-block' }}>云端地址:</Text> <Text copyable style={{ fontSize: 12, color: darkMode ? '#c9d1d9' : '#333' }}>{record.cloud_url}</Text></div>}
        <div><Text type="secondary" style={{ width: 80, display: 'inline-block' }}>更新时间:</Text> <Text style={{ fontSize: 12, color: darkMode ? '#c9d1d9' : '#333' }}>{dayjs(record.updated_at).format('YYYY-MM-DD HH:mm:ss')}</Text></div>
      </Space>
    </div>
  );

  return (
    <div>
      <PageHeader
        icon={<UserOutlined />}
        title="平台账号管理"
        extra={
          <>
            <Button icon={<ReloadOutlined />} onClick={() => load()} size="small">刷新</Button>
            <Button
              type="primary" icon={<PlusOutlined />} size="small"
              onClick={() => { setEditUser(null); form.resetFields(); setModalOpen(true); }}
            >
              新建用户
            </Button>
          </>
        }
      />

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table
          dataSource={users}
          columns={columns}
          rowKey="uuid"
          loading={loading}
          expandable={{ expandedRowRender, expandRowByClick: true }}
          pagination={{
            current: page,
            total,
            pageSize: 10,
            onChange: (p) => { setPage(p); load(p); },
            showTotal: (t) => `共 ${t} 条`,
          }}
          style={{ background: 'transparent' }}
          scroll={{ x: 900 }}
        />
      </Card>

      {/* 新建/编辑弹窗 */}
      <Modal
        title={editUser ? '编辑用户' : '新建用户'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => { setModalOpen(false); form.resetFields(); setEditUser(null); }}
        okText={editUser ? '保存' : '创建'}
        cancelText="取消"
        width={480}
      >
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="display_name" label="显示名称" rules={[{ required: true, message: '请输入显示名称' }]}>
            <Input placeholder="例如：张三" />
          </Form.Item>
          <Form.Item name="email" label="邮箱">
            <Input placeholder="user@example.com" />
          </Form.Item>
          <Form.Item name="user_type" label="用户类型" initialValue="user">
            <Select options={[{ value: 'user', label: '普通用户' }, { value: 'admin', label: '管理员' }]} />
          </Form.Item>
          {!editUser && (
            <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password placeholder="至少 8 位" />
            </Form.Item>
          )}
          <Form.Item name="cloud_url" label="云端服务地址">
            <Input placeholder="http://server-card:1027" />
          </Form.Item>
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