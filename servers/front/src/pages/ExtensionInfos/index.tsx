import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, message,
  Popconfirm, Alert, InputNumber,
} from 'antd';
import {
  LinkOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, CheckCircleOutlined, RedoOutlined,
} from '@ant-design/icons';
import {
  listExtensionInfos, createExtensionInfo, deleteExtensionInfo,
  verifyDNS, verifyHTTP, verifyTLS, verifyEmail, renewExtensionInfo, listExtensionTemplates,
} from '../../api';
import type { ExtensionInfo, ExtensionTemplate } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text, Paragraph } = Typography;

const STATUS: Record<string, { text: string; color: string }> = {
  pending: { text: '待验证', color: 'orange' },
  reviewing: { text: '待人工审核', color: 'purple' },
  verified: { text: '已验证', color: 'green' },
  rejected: { text: '已驳回', color: 'red' },
};

const METHOD_TEXT: Record<string, string> = {
  txt: 'DNS TXT 记录', http: 'HTTP 文件', tls: 'TLS-ALPN', email: '邮箱验证码',
};

/**
 * 证书扩展信息：域名 / 邮箱 / IP 的所有权验证。
 *
 * 验证方式（DNS/HTTP/TLS/邮箱验证码/人工）与验证有效期由扩展信息模板按类型配置；
 * 通过后在有效期内可复用于证书申请，过期可重新验证。
 */
const ExtensionInfosPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ExtensionInfo[]>([]);
  const [templates, setTemplates] = useState<ExtensionTemplate[]>([]);
  const [open, setOpen] = useState(false);
  const [addResult, setAddResult] = useState<{ info: ExtensionInfo; instructions?: string } | null>(null);
  const [codeOpen, setCodeOpen] = useState<ExtensionInfo | null>(null);
  const [code, setCode] = useState('');
  const [form] = Form.useForm();
  const addType = Form.useWatch('type', form);

  const load = async () => {
    setLoading(true);
    try {
      const r = await listExtensionInfos({ page: 1, page_size: 200 });
      setData(r.items ?? []);
      setTemplates(await listExtensionTemplates().catch(() => []));
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const openAdd = () => {
    form.resetFields();
    setAddResult(null);
    form.setFieldsValue({ type: 'domain', verify_method: 'dns', tmpl_uuid: templates[0]?.uuid });
    setOpen(true);
  };

  const submitAdd = async (v: any) => {
    try {
      const info = await createExtensionInfo({
        type: v.type, value: v.value, verify_method: v.verify_method, tmpl_uuid: v.tmpl_uuid,
      });
      setAddResult({ info, instructions: (info as any)?.instructions });
      message.success(info.status === 'verified' ? '已通过验证' : '已创建，请完成验证');
      load();
    } catch (e: any) { message.error(e.message || '创建失败'); }
  };

  const runVerify = async (r: ExtensionInfo) => {
    try {
      if (r.verify_method === 'txt') await verifyDNS(r.uuid);
      else if (r.verify_method === 'http') await verifyHTTP(r.uuid);
      else if (r.verify_method === 'tls') await verifyTLS(r.uuid);
      message.success('验证通过');
      load();
    } catch (e: any) { message.error(e.message || '验证未通过'); }
  };

  const columns = [
    { title: '类型', dataIndex: 'type', key: 'type', width: 90,
      render: (v: string) => ({ domain: '域名', email: '邮箱', ip: 'IP 地址' } as any)[v] ?? v },
    { title: '值', dataIndex: 'value', key: 'value', render: (v: string) => <Text copyable>{v}</Text> },
    { title: '验证方式', dataIndex: 'verify_method', key: 'verify_method', width: 130,
      render: (v: string) => <Tag>{METHOD_TEXT[v] ?? v}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 150,
      render: (v: string, r: ExtensionInfo) => {
        const s = STATUS[v] ?? { text: v, color: 'default' };
        const expired = r.expires_at && new Date(r.expires_at) < new Date();
        return (
          <Space direction="vertical" size={0}>
            <Tag color={expired ? 'red' : s.color}>{expired ? '已过期' : s.text}</Tag>
            {r.reject_reason && <Text type="danger" style={{ fontSize: 12 }}>{r.reject_reason}</Text>}
            {r.expires_at && (
              <Text type="secondary" style={{ fontSize: 12 }}>
                有效期至 {new Date(r.expires_at).toLocaleDateString('zh-CN')}
              </Text>
            )}
          </Space>
        );
      } },
    { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 220,
      render: (_: any, r: ExtensionInfo) => (
        <Space size={4}>
          {r.status === 'pending' && r.verify_method === 'email' && (
            <Button type="link" size="small" icon={<CheckCircleOutlined />}
              onClick={() => { setCodeOpen(r); setCode(''); }}>输入验证码</Button>
          )}
          {r.status === 'pending' && r.verify_method !== 'email' && (
            <Button type="link" size="small" icon={<CheckCircleOutlined />} onClick={() => runVerify(r)}>立即验证</Button>
          )}
          {(r.status === 'rejected' || (r.status === 'verified' && r.expires_at && new Date(r.expires_at) < new Date())) && (
            <Button type="link" size="small" icon={<RedoOutlined />} onClick={async () => {
              try {
                const res: any = await renewExtensionInfo(r.uuid);
                message.success('已重新发起验证');
                if (res?.instructions) Modal.info({ title: '请完成验证', content: res.instructions });
                load();
              } catch (e: any) { message.error(e.message || '操作失败'); }
            }}>重新验证</Button>
          )}
          <Popconfirm title="删除后需重新验证，确认？" onConfirm={async () => {
            try { await deleteExtensionInfo(r.uuid); message.success('已删除'); load(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><LinkOutlined /><Title level={4} style={{ margin: 0 }}>证书扩展信息</Title>
          <HelpLink doc="user-03-apply-certificate" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openAdd}>添加域名 / 邮箱 / IP</Button>
          </Space>
        }
      >
        <Alert type="info" showIcon style={{ marginBottom: 16 }}
          message="域名/邮箱/IP 需通过所有权验证后才能写入证书"
          description="验证方式与有效期由扩展信息模板配置：DNS TXT 记录、HTTP 文件、TLS-ALPN（RFC 8737）、邮箱验证码或人工审核。单张证书允许的数量与格式（通配符、IPv4/IPv6、邮箱后缀）在商品规格中限制。" />
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any} />
      </Card>

      <Modal open={open} title="添加扩展信息" onCancel={() => setOpen(false)}
        onOk={() => (addResult ? setOpen(false) : form.submit())} destroyOnClose width={560}
        footer={addResult ? [<Button key="ok" type="primary" onClick={() => setOpen(false)}>完成</Button>] : undefined}>
        {addResult ? (
          <Alert
            type={addResult.info.status === 'verified' ? 'success' : 'info'} showIcon
            message={addResult.info.status === 'verified' ? '已通过验证' : '请完成验证'}
            description={<Paragraph style={{ marginBottom: 0 }} copyable>{addResult.instructions}</Paragraph>}
          />
        ) : (
          <Form form={form} layout="vertical" onFinish={submitAdd}>
            <Form.Item name="tmpl_uuid" label="扩展信息模板" rules={[{ required: true, message: '请选择模板' }]}
              extra="决定验证方式与验证有效期">
              <Select options={templates.map((t) => ({ label: t.name, value: t.uuid }))} />
            </Form.Item>
            <Form.Item name="type" label="类型" rules={[{ required: true }]}>
              <Select options={[
                { label: '域名', value: 'domain' },
                { label: '邮箱', value: 'email' },
                { label: 'IP 地址', value: 'ip' },
              ]} />
            </Form.Item>
            <Form.Item name="value" label={addType === 'email' ? '邮箱地址' : addType === 'ip' ? 'IP 地址' : '域名'}
              rules={[{ required: true, message: '请输入值' }]}>
              <Input placeholder={addType === 'email' ? 'user@example.com' : addType === 'ip' ? '192.0.2.10' : 'example.com 或 *.example.com'} />
            </Form.Item>
            {addType !== 'email' && (
              <Form.Item name="verify_method" label="验证方式" rules={[{ required: true }]}>
                <Select options={addType === 'ip'
                  ? [{ label: 'HTTP 文件', value: 'http' }]
                  : [
                    { label: 'DNS TXT 记录', value: 'dns' },
                    { label: 'HTTP 文件', value: 'http' },
                    { label: 'TLS-ALPN（RFC 8737）', value: 'tls' },
                  ]} />
              </Form.Item>
            )}
          </Form>
        )}
      </Modal>

      <Modal open={!!codeOpen} title={`输入发送到 ${codeOpen?.value ?? ''} 的验证码`}
        onCancel={() => setCodeOpen(null)} onOk={async () => {
          try {
            await verifyEmail(codeOpen!.uuid, code);
            message.success('邮箱验证通过');
            setCodeOpen(null);
            load();
          } catch (e: any) { message.error(e.message || '验证码错误'); }
        }} destroyOnClose>
        <InputNumber
          style={{ width: '100%' }} value={code ? Number(code) : undefined}
          onChange={(v) => setCode(String(v ?? ''))} maxLength={6}
          placeholder="6 位数字验证码"
        />
        <Text type="secondary" style={{ fontSize: 12 }}>验证码 15 分钟内有效，连续输错 5 次需重新发送</Text>
      </Modal>
    </div>
  );
};

export default ExtensionInfosPage;
