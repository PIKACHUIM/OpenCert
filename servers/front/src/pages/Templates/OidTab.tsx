import React, { useEffect, useMemo, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Switch, Space, Tag, Typography, message, Popconfirm } from 'antd';
import { PlusOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons';
import { listOIDs, createOID, updateOID, deleteOID } from '../../api';
const { Text } = Typography;
// ---- 自定义 OID（由原「证书 OIDS 管理」并入） ----
const OidTab: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any[]>([]);
  const [filter, setFilter] = useState<string | undefined>();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<any | null>(null);
  const [form] = Form.useForm();

  const fetch = async () => {
    setLoading(true);
    try { setData(await listOIDs() as any); }
    catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };
  useEffect(() => { fetch(); }, []);

  const usageTexts: Record<string, string> = {
    ext_key_usage: '扩展密钥用途', subject_field: '主体字段', ev_policy: 'EV 策略', asn1_extension: 'ASN.1 扩展',
  };
  const filtered = useMemo(
    () => (filter ? data.filter((d) => d.usage_type === filter) : data),
    [data, filter],
  );

  return (
    <>
      <Space style={{ marginBottom: 12 }}>
        <Select allowClear placeholder="按用途筛选" style={{ width: 200 }} value={filter} onChange={setFilter}
          options={Object.entries(usageTexts).map(([v, l]) => ({ label: l, value: v }))} />
        <Button icon={<ReloadOutlined />} onClick={fetch}>刷新</Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditing(null); form.resetFields(); setOpen(true); }}>
          新增 OID
        </Button>
      </Space>
      <Table rowKey="uuid" loading={loading} dataSource={filtered} size="small"
        columns={[
          { title: 'OID', dataIndex: 'oid_value', key: 'oid_value',
            render: (v: string, r: any) => <Text copyable code>{v || r.oid}</Text> },
          { title: '名称', dataIndex: 'name', key: 'name' },
          { title: '用途类型', dataIndex: 'usage_type', key: 'usage_type',
            render: (v: string) => <Tag>{usageTexts[v] || v}</Tag> },
          { title: 'ASN.1 类型', dataIndex: 'asn1_type', key: 'asn1_type',
            render: (v: string) => v || '—' },
          {
            title: '关键扩展', dataIndex: 'is_critical', key: 'is_critical', width: 100,
            render: (v: boolean) => (v ? <Tag color="orange">是</Tag> : <Tag>否</Tag>),
          },
          { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true },
          {
            title: '操作', key: 'actions', width: 150, fixed: 'right' as const,
            render: (_: any, r: any) => (
              <Space size={4} style={{ whiteSpace: 'nowrap' }}>
                <Button type="link" size="small" onClick={() => {
                  setEditing(r);
                  form.setFieldsValue({
                    oid: r.oid_value || r.oid, name: r.name, usage_type: r.usage_type,
                    asn1_type: r.asn1_type || 'UTF8String', is_critical: !!r.is_critical,
                    description: r.description,
                  });
                  setOpen(true);
                }}>编辑</Button>
                <Popconfirm title="被模板引用时无法删除" onConfirm={async () => {
                  try { await deleteOID(r.uuid); fetch(); }
                  catch (e: any) { message.error(e.message); }
                }}>
                  <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
                </Popconfirm>
              </Space>
            ),
          },
        ] as any} />

      <Modal open={open} title={editing ? '编辑 OID' : '新增 OID'}
        onCancel={() => { setOpen(false); form.resetFields(); }}
        onOk={() => form.submit()} width={560}>
        <Form form={form} layout="vertical" initialValues={{ usage_type: 'ext_key_usage', asn1_type: 'UTF8String' }}
          onFinish={async (v) => {
            try {
              const payload = {
                oid: v.oid, name: v.name, description: v.description,
                usage_type: v.usage_type, asn1_type: v.asn1_type, is_critical: !!v.is_critical,
              } as any;
              if (editing) await updateOID(editing.uuid, payload);
              else await createOID(payload);
              message.success('已保存');
              setOpen(false); form.resetFields(); fetch();
            } catch (e: any) { message.error(e.message || '保存失败'); }
          }}>
          <Form.Item name="oid" label="OID" rules={[{ required: true, message: '请输入 OID' },
            { pattern: /^(\d+\.)+\d+$/, message: 'OID 格式错误，如：1.3.6.1.4.1.311' }]}>
            <Input placeholder="1.3.6.1.4.1.311" />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={128} placeholder="例如：msSmartcardLogon" />
          </Form.Item>
          <Form.Item name="usage_type" label="用途类型" rules={[{ required: true }]}>
            <Select options={Object.entries(usageTexts).map(([v, l]) => ({ label: l, value: v }))} />
          </Form.Item>
          <Space size={16} style={{ display: 'flex' }}>
            <Form.Item name="asn1_type" label="ASN.1 类型" style={{ flex: 1 }}
              extra="仅在证书拓展模板中作为自定义扩展使用时生效">
              <Select options={['UTF8String', 'PrintableString', 'IA5String', 'OCTET STRING', 'INTEGER', 'BOOLEAN', 'NULL']
                .map((v) => ({ label: v, value: v }))} />
            </Form.Item>
            <Form.Item name="is_critical" label="标记为关键扩展" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3} maxLength={500} /></Form.Item>
        </Form>
      </Modal>
    </>
  );
};
export default OidTab;