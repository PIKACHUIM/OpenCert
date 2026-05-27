import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, InputNumber,
  Select, message, Popconfirm, Progress, Statistic,
} from 'antd';
import {
  ClockCircleOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, EyeOutlined,
} from '@ant-design/icons';
import {
  listCloudTOTPs, createCloudTOTP, deleteCloudTOTP, getCloudTOTPCode,
} from '../../api';
import type { CloudTOTPEntry } from '../../types';

const { Title, Text } = Typography;

/**
 * CloudTOTP 页面：云端 TOTP 条目管理。
 * - 新建条目（issuer/account/secret/algorithm/digits/period）
 * - 动态获取 TOTP 码并展示倒计时
 * - 删除条目
 */
const CloudTOTPPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<CloudTOTPEntry[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm();

  // 当前展示的 code：uuid -> { code, remaining, period }
  const [codeMap, setCodeMap] = useState<Record<string, { code: string; remaining: number; period: number }>>({});
  const timerRef = useRef<any>(null);

  const fetchData = async () => {
    setLoading(true);
    try { const r = await listCloudTOTPs(); setData(Array.isArray(r) ? r : (r as any)?.items || []); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchData(); }, []);

  // 每秒更新所有条目的倒计时；remaining<=1 时自动重新获取
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setCodeMap((m) => {
        const next = { ...m };
        for (const uuid of Object.keys(next)) {
          const v = next[uuid];
          if (!v) continue;
          const r = v.remaining - 1;
          if (r <= 0) {
            // 过期，移除；下次点击或自动刷新
            delete next[uuid];
          } else {
            next[uuid] = { ...v, remaining: r };
          }
        }
        return next;
      });
    }, 1000);
    return () => clearInterval(timerRef.current);
  }, []);

  const handleCreate = async (values: any) => {
    try {
      await createCloudTOTP({
        issuer: values.issuer, account: values.account,
        secret: values.secret, algorithm: values.algorithm,
        digits: values.digits, period: values.period,
      });
      message.success('TOTP 条目已添加');
      setCreateOpen(false);
      form.resetFields();
      fetchData();
    } catch (e: any) { message.error(e.message || '添加失败'); }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteCloudTOTP(uuid); message.success('已删除'); fetchData(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const handleShowCode = async (entry: CloudTOTPEntry) => {
    try {
      const res: any = await getCloudTOTPCode(entry.uuid);
      setCodeMap((m) => ({
        ...m,
        [entry.uuid]: {
          code: res.code, remaining: res.remaining, period: entry.period,
        },
      }));
    } catch (e: any) { message.error(e.message || '获取验证码失败'); }
  };

  const columns = useMemo(() => [
    { title: '发行方', dataIndex: 'issuer', key: 'issuer' },
    { title: '账户', dataIndex: 'account', key: 'account' },
    { title: '算法', dataIndex: 'algorithm', key: 'algorithm',
      render: (v: string) => <Tag>{v}</Tag> },
    { title: '位数', dataIndex: 'digits', key: 'digits' },
    { title: '周期(s)', dataIndex: 'period', key: 'period' },
    {
      title: '当前验证码', key: 'code',
      render: (_: any, r: CloudTOTPEntry) => {
        const v = codeMap[r.uuid];
        if (!v) return <Button size="small" icon={<EyeOutlined />} onClick={() => handleShowCode(r)}>获取</Button>;
        return (
          <Space>
            <Text strong copyable style={{ fontSize: 18, fontFamily: 'monospace' }}>{v.code}</Text>
            <Progress
              type="circle" size={28} strokeWidth={12}
              percent={Math.round((v.remaining / v.period) * 100)}
              format={() => `${v.remaining}s`}
            />
            <Button size="small" onClick={() => handleShowCode(r)} icon={<ReloadOutlined />} />
          </Space>
        );
      },
    },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 120,
      render: (_: any, r: CloudTOTPEntry) => (
        <Popconfirm title="确认删除此 TOTP 条目？" onConfirm={() => handleDelete(r.uuid)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
        </Popconfirm>
      ),
    },
  ], [codeMap]);

  return (
    <div>
      <Card
        title={<Space><ClockCircleOutlined />
          <Title level={4} style={{ margin: 0 }}>云端 TOTP 管理</Title></Space>}
        extra={
          <Space>
            <Statistic title="条目总数" value={data.length} valueStyle={{ fontSize: 16 }} />
            <Button icon={<ReloadOutlined />} onClick={fetchData}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>新增条目</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal
        open={createOpen} title="新增 TOTP 条目"
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} destroyOnClose
      >
        <Form form={form} layout="vertical" onFinish={handleCreate}
          initialValues={{ algorithm: 'SHA1', digits: 6, period: 30 }}>
          <Form.Item name="issuer" label="发行方" rules={[{ required: true, message: '请输入发行方' }]}>
            <Input maxLength={64} placeholder="例如：Google、GitHub" />
          </Form.Item>
          <Form.Item name="account" label="账户" rules={[{ required: true, message: '请输入账户' }]}>
            <Input maxLength={128} placeholder="例如：user@example.com" />
          </Form.Item>
          <Form.Item name="secret" label="密钥（Base32）"
            rules={[{ required: true, message: '请输入 Base32 密钥' }]}>
            <Input.Password maxLength={128} placeholder="JBSWY3DPEHPK3PXP" />
          </Form.Item>
          <Form.Item name="algorithm" label="哈希算法">
            <Select options={[
              { label: 'SHA1 (默认)', value: 'SHA1' },
              { label: 'SHA256', value: 'SHA256' },
              { label: 'SHA512', value: 'SHA512' },
            ]} />
          </Form.Item>
          <Form.Item name="digits" label="验证码位数">
            <Select options={[{ label: '6', value: 6 }, { label: '8', value: 8 }]} />
          </Form.Item>
          <Form.Item name="period" label="周期（秒）">
            <InputNumber min={15} max={120} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CloudTOTPPage;
