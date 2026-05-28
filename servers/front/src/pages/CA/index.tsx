import React, { useState, useEffect } from 'react';
import {
  Table, Button, Modal, Form, Input, Select, InputNumber, Space,
  Tag, Typography, Drawer, message, Popconfirm,
} from 'antd';
import { PlusOutlined, DownloadOutlined, ImportOutlined, UnorderedListOutlined, SafetyCertificateOutlined, DeleteOutlined } from '@ant-design/icons';
import { listCAs, createCA, deleteCA, importCAChain, listRevokedCerts, revokeCAcert, issueCert, downloadCRL } from '../../api';
import type { CA, RevokedCert } from '../../types';

const { Title, Text } = Typography;
const { Option } = Select;

const reasonOptions = [
  { value: 0, label: '未指定' }, { value: 1, label: '密钥泄露' },
  { value: 2, label: 'CA 泄露' }, { value: 3, label: '关联变更' },
  { value: 4, label: '已取代' }, { value: 5, label: '停止运营' },
];

const CAPage: React.FC = () => {
  const [cas, setCAs] = useState<CA[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [createOpen, setCreateOpen] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);
  const [chainLoading, setChainLoading] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  const [issueLoading, setIssueLoading] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [revokedDrawer, setRevokedDrawer] = useState(false);
  const [revokedList, setRevokedList] = useState<RevokedCert[]>([]);
  const [selectedCA, setSelectedCA] = useState<CA | null>(null);
  const [createForm] = Form.useForm();
  const [chainForm] = Form.useForm();
  const [issueForm] = Form.useForm();
  const [revokeForm] = Form.useForm();

  const loadCAs = async (p = 1) => {
    setLoading(true);
    try {
      const res = await listCAs({ page: p, page_size: 20 });
      setCAs(Array.isArray(res.items) ? res.items : []);
      setTotal(res.total);
    } catch (err: any) { message.error(err.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadCAs(); }, []);

  const handleCreate = async (values: any) => {
    setCreateLoading(true);
    try {
      await createCA(values);
      message.success('CA 创建成功');
      setCreateOpen(false); createForm.resetFields(); loadCAs();
    } catch (err: any) { message.error(err.message); }
    finally { setCreateLoading(false); }
  };

  const handleImportChain = async (values: { chain_pem: string }) => {
    if (!selectedCA) return;
    setChainLoading(true);
    try {
      await importCAChain(selectedCA.uuid, values.chain_pem);
      message.success('证书链导入成功');
      setChainOpen(false); chainForm.resetFields();
    } catch (err: any) { message.error(err.message); }
    finally { setChainLoading(false); }
  };

  const handleIssue = async (values: any) => {
    if (!selectedCA) return;
    setIssueLoading(true);
    try {
      const data = {
        ...values,
        san_dns: values.san_dns ? values.san_dns.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
        san_ip: values.san_ip ? values.san_ip.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
        san_email: values.san_email ? values.san_email.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
      };
      await issueCert(selectedCA.uuid, data);
      message.success('证书签发成功');
      setIssueOpen(false); issueForm.resetFields();
    } catch (err: any) { message.error(err.message); }
    finally { setIssueLoading(false); }
  };

  const handleRevoke = async (values: any) => {
    if (!selectedCA) return;
    setRevokeLoading(true);
    try {
      await revokeCAcert(selectedCA.uuid, values);
      message.success('证书已吊销');
      setRevokeOpen(false); revokeForm.resetFields();
      const list = await listRevokedCerts(selectedCA.uuid);
      setRevokedList(list);
    } catch (err: any) { message.error(err.message); }
    finally { setRevokeLoading(false); }
  };

  const handleShowRevoked = async (ca: CA) => {
    setSelectedCA(ca);
    try {
      const list = await listRevokedCerts(ca.uuid);
      setRevokedList(list); setRevokedDrawer(true);
    } catch (err: any) { message.error(err.message); }
  };

  const handleDownloadCRL = async (ca: CA) => {
    try {
      const blob = await downloadCRL(ca.uuid);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${ca.name}.crl`; a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) { message.error(err.message); }
  };

  const statusColor: Record<string, string> = { active: 'green', revoked: 'red', expired: 'orange' };
  const statusText: Record<string, string> = { active: '有效', revoked: '已吊销', expired: '已过期' };

  const columns = [
    { title: 'CA 名称', dataIndex: 'name', key: 'name', render: (v: string) => <Text strong>{v}</Text> },
    { title: '状态', dataIndex: 'status', key: 'status', render: (v: string) => <Tag color={statusColor[v]}>{statusText[v] || v}</Tag> },
    { title: '密钥类型', dataIndex: 'key_type', key: 'key_type' },
    { title: '有效期', key: 'validity', render: (_: any, r: CA) => <Text style={{ fontSize: 12 }}>{r.not_before?.slice(0, 10)} ~ {r.not_after?.slice(0, 10)}</Text> },
    { title: '已签发', dataIndex: 'issued_count', key: 'issued_count' },
    {
      title: '操作', key: 'action', width: 340,
      render: (_: any, r: CA) => (
        <Space size={4} wrap>
          <Button size="small" icon={<UnorderedListOutlined />} onClick={() => handleShowRevoked(r)}>吊销列表</Button>
          <Button size="small" icon={<ImportOutlined />} onClick={() => { setSelectedCA(r); setChainOpen(true); }}>导入证书链</Button>
          <Button size="small" type="primary" icon={<SafetyCertificateOutlined />} onClick={() => { setSelectedCA(r); setIssueOpen(true); }}>签发证书</Button>
          <Button size="small" icon={<DownloadOutlined />} onClick={() => handleDownloadCRL(r)}>下载 CRL</Button>
          <Popconfirm title="确认删除此 CA？" onConfirm={() => deleteCA(r.uuid).then(() => { message.success('已删除'); loadCAs(); })}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>CA 管理</Title>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建 CA</Button>
      </div>

      <Table rowKey="uuid" columns={columns} dataSource={cas} loading={loading}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); loadCAs(p); } }} />

      {/* 创建 CA */}
      <Modal title="创建 CA" open={createOpen} onCancel={() => setCreateOpen(false)} footer={null} width={520}>
        <Form form={createForm} layout="vertical" onFinish={handleCreate} style={{ marginTop: 16 }}>
          <Form.Item label="CA 名称" name="name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="密钥类型" name="key_type" rules={[{ required: true }]}>
            <Select>{['ec256', 'ec384', 'rsa2048', 'rsa4096'].map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="有效年限" name="validity_years" rules={[{ required: true }]} initialValue={10}>
            <InputNumber min={1} max={30} style={{ width: '100%' }} addonAfter="年" />
          </Form.Item>
          <Form.Item label="CommonName" name="common_name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="组织" name="organization"><Input /></Form.Item>
          <Form.Item label="国家代码" name="country"><Input maxLength={2} placeholder="CN" /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setCreateOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={createLoading}>创建</Button></Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 导入证书链 */}
      <Modal title={`导入证书链 — ${selectedCA?.name}`} open={chainOpen} onCancel={() => setChainOpen(false)} footer={null} width={560}>
        <Form form={chainForm} layout="vertical" onFinish={handleImportChain} style={{ marginTop: 16 }}>
          <Form.Item label="证书链（PEM 格式）" name="chain_pem" rules={[{ required: true }]}>
            <Input.TextArea rows={10} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" style={{ fontSize: 12 }} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setChainOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={chainLoading}>导入</Button></Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 签发证书 */}
      <Modal title={`签发证书 — ${selectedCA?.name}`} open={issueOpen} onCancel={() => setIssueOpen(false)} footer={null} width={560}>
        <Form form={issueForm} layout="vertical" onFinish={handleIssue} style={{ marginTop: 16 }}>
          <Form.Item label="密钥类型" name="key_type" rules={[{ required: true }]}>
            <Select>{['ec256', 'ec384', 'rsa2048', 'rsa4096'].map(k => <Option key={k} value={k}>{k}</Option>)}</Select>
          </Form.Item>
          <Form.Item label="有效天数" name="validity_days" rules={[{ required: true }]} initialValue={365}>
            <InputNumber min={1} max={3650} style={{ width: '100%' }} addonAfter="天" />
          </Form.Item>
          <Form.Item label="CommonName" name="common_name" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item label="组织" name="organization"><Input /></Form.Item>
          <Form.Item label="国家代码" name="country"><Input maxLength={2} placeholder="CN" /></Form.Item>
          <Form.Item label="是否为 CA 证书" name="is_ca" initialValue={false}>
            <Select><Option value={false}>否</Option><Option value={true}>是</Option></Select>
          </Form.Item>
          <Form.Item label="SAN DNS（逗号分隔）" name="san_dns"><Input placeholder="example.com, www.example.com" /></Form.Item>
          <Form.Item label="SAN IP（逗号分隔）" name="san_ip"><Input placeholder="192.168.1.1" /></Form.Item>
          <Form.Item label="SAN 邮箱（逗号分隔）" name="san_email"><Input placeholder="admin@example.com" /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setIssueOpen(false)}>取消</Button><Button type="primary" htmlType="submit" loading={issueLoading}>签发</Button></Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 吊销列表 Drawer */}
      <Drawer title={`吊销列表 — ${selectedCA?.name}`} open={revokedDrawer} onClose={() => setRevokedDrawer(false)} width={600}
        extra={<Button type="primary" danger onClick={() => setRevokeOpen(true)}>吊销证书</Button>}>
        <Table rowKey="serial" size="small" dataSource={revokedList}
          columns={[
            { title: '序列号', dataIndex: 'serial', key: 'serial', render: (v: string) => <Text code style={{ fontSize: 11 }}>{v}</Text> },
            { title: '吊销时间', dataIndex: 'revoked_at', key: 'revoked_at', render: (v: string) => v?.slice(0, 19) },
            { title: '原因', dataIndex: 'reason_text', key: 'reason_text', render: (v: string, r: RevokedCert) => v || String(r.reason) },
          ]} />
      </Drawer>

      {/* 吊销证书 */}
      <Modal title="吊销证书" open={revokeOpen} onCancel={() => setRevokeOpen(false)} footer={null}>
        <Form form={revokeForm} layout="vertical" onFinish={handleRevoke} style={{ marginTop: 16 }}>
          <Form.Item label="证书序列号（十六进制）" name="serial" rules={[{ required: true }]}>
            <Input placeholder="e.g. 0a1b2c3d"  />
          </Form.Item>
          <Form.Item label="吊销原因" name="reason" rules={[{ required: true }]} initialValue={0}>
            <Select>{reasonOptions.map(o => <Option key={o.value} value={o.value}>{o.label}</Option>)}</Select>
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space><Button onClick={() => setRevokeOpen(false)}>取消</Button><Button type="primary" danger htmlType="submit" loading={revokeLoading}>确认吊销</Button></Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CAPage;
