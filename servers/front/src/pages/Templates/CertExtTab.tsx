import React, { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Space, Typography, message, Popconfirm } from 'antd';
import { PlusOutlined, DeleteOutlined } from '@ant-design/icons';
import { listCertExtTemplates, createCertExtTemplate, updateCertExtTemplate, deleteCertExtTemplate } from '../../api';
import type { CertExtTemplate } from '../../types';
const { Text } = Typography;
// ---- 证书拓展模板 ----
const CertExtTab: React.FC = () => {
  const [data, setData] = useState<CertExtTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<CertExtTemplate | null>(null);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try { setData(await listCertExtTemplates()); }
    catch { /* 忽略 */ } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    setOpen(true);
  };

  const openEdit = (r: CertExtTemplate) => {
    setEditing(r);
    form.setFieldsValue({
      name: r.name,
      crl_distribution_points: (r.crl_distribution_points ?? []).join('\n'),
      ocsp_servers: (r.ocsp_servers ?? []).join('\n'),
      aia_issuers: (r.aia_issuers ?? []).join('\n'),
      ct_servers: (r.ct_servers ?? []).join('\n'),
      ev_policy_oid: r.ev_policy_oid,
    });
    setOpen(true);
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name' },
    { title: 'CRL 分发点', dataIndex: 'crl_distribution_points', key: 'crl', render: (v: string[]) => v?.length || 0 },
    { title: 'OCSP 服务器', dataIndex: 'ocsp_servers', key: 'ocsp', render: (v: string[]) => v?.length || 0 },
    { title: 'AIA 颁发者', dataIndex: 'aia_issuers', key: 'aia', render: (v: string[]) => v?.length || 0 },
    { title: 'CT 服务器', dataIndex: 'ct_servers', key: 'ct', render: (v: string[]) => v?.length || 0 },
    {
      title: 'EV 策略 OID', dataIndex: 'ev_policy_oid', key: 'ev',
      render: (v: string) => (v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : '-'),
    },
    {
      title: '操作', key: 'action', width: 150, fixed: 'right' as const,
      render: (_: any, r: CertExtTemplate) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button type="link" size="small" onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="被颁发模板引用时无法删除" onConfirm={async () => {
            try { await deleteCertExtTemplate(r.uuid); message.success('已删除'); load(); }
            catch (e: any) { message.error(e.message || '删除失败'); }
          }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
        <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建证书拓展模板</Button>
      </div>
      <Table rowKey="uuid" columns={columns as any} dataSource={data} loading={loading} size="small" scroll={{ x: 900 }} />
      <Modal title={editing ? '编辑证书拓展模板' : '新建证书拓展模板'} open={open}
        onCancel={() => setOpen(false)} footer={null} width={600}>
        <Form form={form} layout="vertical" onFinish={async (v) => {
          setSaving(true);
          try {
            const split = (s?: string) => (s ? s.split('\n').map((x: string) => x.trim()).filter(Boolean) : []);
            const payload = {
              name: v.name,
              crl_distribution_points: split(v.crl_distribution_points),
              ocsp_servers: split(v.ocsp_servers),
              aia_issuers: split(v.aia_issuers),
              ct_servers: split(v.ct_servers),
              ev_policy_oid: v.ev_policy_oid || undefined,
            };
            if (editing) await updateCertExtTemplate(editing.uuid, payload);
            else await createCertExtTemplate(payload);
            message.success('已保存'); setOpen(false); form.resetFields(); load();
          } catch (e: any) { message.error(e.message); } finally { setSaving(false); }
        }} style={{ marginTop: 16 }}>
          <Form.Item label="名称" name="name" rules={[{ required: true, message: '请填写名称' }]}><Input /></Form.Item>
          <Form.Item label="CRL 分发点（每行一个 URL）" name="crl_distribution_points" extra="签发时写入证书，客户端据此下载吊销列表">
            <Input.TextArea rows={2} placeholder="http://crl.example.com/ca.crl" />
          </Form.Item>
          <Form.Item label="OCSP 服务器（每行一个 URL）" name="ocsp_servers">
            <Input.TextArea rows={2} placeholder="http://ocsp.example.com" />
          </Form.Item>
          <Form.Item label="AIA 颁发者（每行一个 URL）" name="aia_issuers" extra="指向 CA 证书，便于客户端补链">
            <Input.TextArea rows={2} placeholder="http://ca.example.com/ca.crt" />
          </Form.Item>
          <Form.Item label="CT 服务器（每行一个 URL）" name="ct_servers">
            <Input.TextArea rows={2} placeholder="https://ct.example.com/logs/1" />
          </Form.Item>
          <Form.Item label="EV 策略 OID（可选）" name="ev_policy_oid">
            <Input placeholder="2.23.140.1.1" />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={saving}>保存</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};
export default CertExtTab;