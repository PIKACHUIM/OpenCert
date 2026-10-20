import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm, InputNumber, Tooltip,
} from 'antd';
import {
  SafetyOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, InfoCircleOutlined,
} from '@ant-design/icons';
import {
  listOCSPResponders, saveOCSPResponder, deleteOCSPResponder, listCAs, listAllCerts,
} from '../../api';
import type { CA, Certificate, OcspResponder } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

/**
 * OCSPResponders 页面：独立的 OCSP 响应服务。
 *
 * 与「吊销服务」中的 OCSP 不同：
 * - 吊销服务：每个 CA 使用自身私钥签名，地址 /ocsp/{caUUID}；
 * - 本页面：一个响应服务可用单个签名证书（如 OCSP 委托签名证书，甚至不是 CA）
 *   同时响应多个 CA 签发证书的状态查询，地址 /ocsp/r/{path}。
 */
const OCSPRespondersPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<OcspResponder[]>([]);
  const [cas, setCAs] = useState<CA[]>([]);
  const [certs, setCerts] = useState<Certificate[]>([]);

  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<OcspResponder | null>(null);
  const [form] = Form.useForm();
  const signerType = Form.useWatch('signer_type', form);

  const fetchData = async () => {
    setLoading(true);
    try {
      setData(await listOCSPResponders());
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  const fetchOptions = async () => {
    try {
      const [caRes, certRes] = await Promise.all([
        listCAs({ page: 1, page_size: 200 }),
        listAllCerts({ page: 1, page_size: 200 }),
      ]);
      setCAs(caRes.items ?? []);
      setCerts(certRes.items ?? []);
    } catch { /* 选项加载失败不阻塞列表 */ }
  };

  useEffect(() => { fetchData(); fetchOptions(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      signer_type: 'ca', next_update_minutes: 60, unknown_policy: 'unknown', enabled: true,
    });
    setOpen(true);
  };

  const openEdit = (r: OcspResponder) => {
    setEditing(r);
    form.setFieldsValue({ ...r });
    setOpen(true);
  };

  const handleSubmit = async (values: any) => {
    try {
      await saveOCSPResponder({ ...values, uuid: editing?.uuid });
      message.success(editing ? '已更新' : '已创建');
      setOpen(false);
      fetchData();
    } catch (e: any) {
      message.error(e.message || '保存失败');
    }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteOCSPResponder(uuid); message.success('已删除'); fetchData(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const caName = (uuid: string) => cas.find((c) => c.uuid === uuid)?.name || uuid.slice(0, 8);

  const columns = useMemo(() => [
    { title: '服务名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: OcspResponder) => (
        <Space direction="vertical" size={0}>
          <Text strong>{v}</Text>
          <Text type="secondary" style={{ fontSize: 12 }}>/ocsp/r/{r.path}</Text>
        </Space>
      ) },
    { title: '响应地址', dataIndex: 'url', key: 'url',
      render: (v: string, r: OcspResponder) => (
        <Text copyable code style={{ fontSize: 12 }}>{v || `/ocsp/r/${r.path}`}</Text>
      ) },
    { title: '签名证书', key: 'signer',
      render: (_: any, r: OcspResponder) => (
        <Space direction="vertical" size={0}>
          <Tag color={r.signer_type === 'ca' ? 'blue' : 'purple'}>
            {r.signer_type === 'ca' ? 'CA 自身签名' : '委托证书签名'}
          </Tag>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {r.signer_type === 'ca'
              ? (cas.find((c) => c.uuid === r.signer_ref)?.name || r.signer_ref.slice(0, 8))
              : (certs.find((c) => c.uuid === r.signer_ref)?.subject_dn?.substring(0, 40) || r.signer_ref.slice(0, 8))}
          </Text>
        </Space>
      ) },
    { title: '负责的 CA', dataIndex: 'ca_uuids', key: 'ca_uuids',
      render: (v: string[]) => (
        <Space size={4} wrap>
          {(v || []).map((id) => <Tag key={id}>{caName(id)}</Tag>)}
        </Space>
      ) },
    { title: '未登记序列号', dataIndex: 'unknown_policy', key: 'unknown_policy', width: 130,
      render: (v: string) => v === 'good'
        ? <Tag color="orange">good（宽松）</Tag>
        : <Tag color="green">unknown（推荐）</Tag> },
    { title: '下次更新', dataIndex: 'next_update_minutes', key: 'next_update_minutes', width: 100,
      render: (v: number) => `${v} 分钟` },
    { title: '状态', dataIndex: 'enabled', key: 'enabled', width: 90,
      render: (v: boolean) => v ? <Tag color="success">启用</Tag> : <Tag>停用</Tag> },
    {
      title: '操作', key: 'actions', width: 130,
      render: (_: any, r: OcspResponder) => (
        <Space size={4}>
          <Button type="link" size="small" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="删除后该地址立即失效，确认删除？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], [cas, certs]);

  return (
    <div>
      <Card
        title={<Space><SafetyOutlined /><Title level={4} style={{ margin: 0 }}>OCSP 响应服务</Title>
          <HelpLink doc="admin-11-ocsp-policy" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchData}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增响应服务</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          locale={{ emptyText: '还没有响应服务。一个响应服务可同时服务多个 CA。' }} />
      </Card>

      <Modal
        open={open} title={editing ? '编辑 OCSP 响应服务' : '新增 OCSP 响应服务'}
        onCancel={() => setOpen(false)} onOk={() => form.submit()} destroyOnClose width={640}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="服务名称" rules={[{ required: true, message: '请输入服务名称' }]}>
            <Input placeholder="例如：统一 OCSP 响应服务" />
          </Form.Item>
          <Form.Item
            name="path" label="服务路径" rules={[{ required: true, message: '请输入路径' },
              { pattern: /^[a-z0-9][a-z0-9-]{0,62}$/, message: '仅小写字母、数字与短横线' }]}
            extra="公开地址为 /ocsp/r/{路径}，POST 提交 DER 请求，GET 也可用 /ocsp/r/{路径}/{base64}"
          >
            <Input placeholder="unified" />
          </Form.Item>
          <Form.Item name="signer_type" label="签名证书类型" rules={[{ required: true }]}
            extra="CA 自身签名兼容性最好；委托证书签名适合多 CA 统一响应场景">
            <Select options={[
              { label: '使用 CA 自身私钥签名', value: 'ca' },
              { label: '使用平台内证书（如 OCSP 委托签名证书）', value: 'cert' },
            ]} />
          </Form.Item>
          {signerType === 'cert' ? (
            <Form.Item name="signer_ref" label="签名证书" rules={[{ required: true, message: '请选择签名证书' }]}
              extra="该证书的私钥必须存放在平台内（云端生成的证书），证书建议带 id-kp-OCSPSigning 扩展密钥用法">
              <Select
                showSearch optionFilterProp="label"
                options={certs.map((c) => ({
                  label: `${c.subject_dn || c.uuid}${c.revocation_status === 'revoked' ? '（已吊销）' : ''}`,
                  value: c.uuid,
                  disabled: c.revocation_status === 'revoked',
                }))}
              />
            </Form.Item>
          ) : (
            <Form.Item name="signer_ref" label="签名 CA" rules={[{ required: true, message: '请选择 CA' }]}>
              <Select options={cas.map((c) => ({ label: `${c.name}（${c.common_name}）`, value: c.uuid }))} />
            </Form.Item>
          )}
          <Form.Item name="ca_uuids" label="负责响应的 CA" rules={[{ required: true, message: '至少选择一个 CA' }]}
            extra="只有列表内 CA 签发的证书会被响应，其他 CA 返回 unauthorized">
            <Select mode="multiple" options={cas.map((c) => ({ label: c.name, value: c.uuid }))} />
          </Form.Item>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="next_update_minutes" label="下次更新时间（分钟）" style={{ flex: 1 }}
              extra="在响应中声明状态信息的有效窗口">
              <InputNumber min={5} max={10080} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="unknown_policy" label="未登记序列号" style={{ flex: 1 }}
              extra={<Tooltip title="RFC 6960 建议返回 unknown；若存在平台外签发但仍需响应的证书，可放宽为 good">
                如何选择 <InfoCircleOutlined />
              </Tooltip>}>
              <Select options={[
                { label: 'unknown（推荐）', value: 'unknown' },
                { label: 'good（宽松，兼容外部签发）', value: 'good' },
              ]} />
            </Form.Item>
          </Space>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default OCSPRespondersPage;
