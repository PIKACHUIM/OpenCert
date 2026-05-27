import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  message, Popconfirm, Tooltip, Alert,
} from 'antd';
import {
  LinkOutlined, PlusOutlined, ReloadOutlined, CheckCircleOutlined, DeleteOutlined,
  MailOutlined, GlobalOutlined, CloudOutlined,
} from '@ant-design/icons';
import {
  listExtensionInfos, createExtensionInfo, deleteExtensionInfo,
  verifyDNS, verifyEmail,
} from '../../api';
import type { ExtensionInfo } from '../../types';

const { Title, Text } = Typography;

/**
 * ExtensionInfos 页面：扩展信息管理。
 * - 域名 / 邮箱 / IP 的新建
 * - DNS TXT 验证、邮件验证码验证
 * - 查看验证 token（用于 DNS 配置或邮件提示）
 */
const ExtensionInfosPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ExtensionInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  const [emailVerifyOpen, setEmailVerifyOpen] = useState<ExtensionInfo | null>(null);
  const [emailForm] = Form.useForm();

  const fetchData = async (p = page, ps = pageSize) => {
    setLoading(true);
    try {
      const res = await listExtensionInfos({ page: p, page_size: ps });
      setData(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally { setLoading(false); }
  };

  useEffect(() => { fetchData(page, pageSize); /* eslint-disable-next-line */ }, [page, pageSize]);

  const handleCreate = async (values: any) => {
    try {
      await createExtensionInfo({ type: values.type, value: values.value });
      message.success('提交成功');
      setCreateOpen(false);
      form.resetFields();
      fetchData();
    } catch (e: any) { message.error(e.message || '提交失败'); }
  };

  const handleVerifyDNS = async (uuid: string) => {
    try { await verifyDNS(uuid); message.success('DNS 验证通过'); fetchData(); }
    catch (e: any) { message.error(e.message || '验证失败，请先配置 DNS TXT 记录'); }
  };

  const handleVerifyEmail = async () => {
    if (!emailVerifyOpen) return;
    try {
      const code = emailForm.getFieldValue('code');
      await verifyEmail(emailVerifyOpen.uuid, code);
      message.success('邮箱验证通过');
      setEmailVerifyOpen(null);
      emailForm.resetFields();
      fetchData();
    } catch (e: any) { message.error(e.message || '邮箱验证失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteExtensionInfo(uuid); message.success('已删除'); fetchData(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const columns = useMemo(() => [
    {
      title: '类型', dataIndex: 'type', key: 'type', width: 100,
      render: (v: string) => {
        const icons: Record<string, React.ReactNode> = {
          domain: <GlobalOutlined />, email: <MailOutlined />, ip: <CloudOutlined />,
        };
        return <Tag icon={icons[v]}>{v}</Tag>;
      },
    },
    {
      title: '值', dataIndex: 'value', key: 'value',
      render: (v: string) => <Text copyable>{v}</Text>,
    },
    { title: '验证方式', dataIndex: 'verify_method', key: 'verify_method',
      render: (v: string) => <Tag>{v}</Tag> },
    {
      title: '验证 Token', dataIndex: 'verify_token', key: 'verify_token', ellipsis: true,
      render: (v: string) => v ? <Tooltip title={v}><Text copyable={{ text: v }}>{v.substring(0, 16)}...</Text></Tooltip> : '-',
    },
    {
      title: '状态', dataIndex: 'status', key: 'status',
      render: (v: string) => {
        const colors: Record<string, string> = { pending: 'processing', verified: 'success', expired: 'error' };
        const texts: Record<string, string> = { pending: '待验证', verified: '已验证', expired: '已过期' };
        return <Tag color={colors[v]}>{texts[v] || v}</Tag>;
      },
    },
    { title: '过期时间', dataIndex: 'expires_at', key: 'expires_at',
      render: (v: string) => v ? new Date(v).toLocaleString('zh-CN') : '-' },
    {
      title: '操作', key: 'actions', width: 260,
      render: (_: any, r: ExtensionInfo) => (
        <Space>
          {r.status !== 'verified' && r.type === 'domain' && (
            <Popconfirm title="确认发起 DNS 验证？请先配置 TXT 记录" onConfirm={() => handleVerifyDNS(r.uuid)}>
              <Button type="link" size="small" icon={<CheckCircleOutlined />}>DNS 验证</Button>
            </Popconfirm>
          )}
          {r.status !== 'verified' && r.type === 'email' && (
            <Button type="link" size="small" icon={<CheckCircleOutlined />}
              onClick={() => setEmailVerifyOpen(r)}>邮箱验证</Button>
          )}
          <Popconfirm title="确认删除？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], []);

  return (
    <div>
      <Card
        title={<Space><LinkOutlined />
          <Title level={4} style={{ margin: 0 }}>扩展信息（SAN）管理</Title></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => fetchData()}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新建扩展信息</Button>
          </Space>
        }
      >
        <Alert
          type="info" showIcon style={{ marginBottom: 16 }}
          message="扩展信息（SAN）在证书签发时用于填充 Subject Alternative Name 字段，申请证书前需通过 DNS TXT 或邮件验证码完成所有权校验。"
        />
        <Table
          rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          pagination={{
            current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <Modal
        open={createOpen} title="新建扩展信息"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate} initialValues={{ type: 'domain' }}>
          <Form.Item name="type" label="类型" rules={[{ required: true }]}>
            <Select options={[
              { label: '域名（domain）', value: 'domain' },
              { label: '邮箱（email）', value: 'email' },
              { label: 'IP 地址（ip）', value: 'ip' },
            ]} />
          </Form.Item>
          <Form.Item
            name="value" label="值" rules={[{ required: true, message: '请输入对应的值' }]}
            extra="域名：example.com；邮箱：admin@example.com；IP：203.0.113.1"
          >
            <Input maxLength={255} placeholder="请根据所选类型填写对应值" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={!!emailVerifyOpen} title="邮箱验证"
        onCancel={() => { setEmailVerifyOpen(null); emailForm.resetFields(); }}
        onOk={handleVerifyEmail} destroyOnClose
      >
        <Alert type="info" showIcon style={{ marginBottom: 12 }}
          message={`系统已向 ${emailVerifyOpen?.value} 发送验证码，请输入 6 位验证码完成验证`} />
        <Form form={emailForm} layout="vertical">
          <Form.Item name="code" label="验证码"
            rules={[{ required: true, message: '请输入验证码' }, { len: 6, message: '验证码为 6 位' }]}>
            <Input maxLength={6} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default ExtensionInfosPage;
