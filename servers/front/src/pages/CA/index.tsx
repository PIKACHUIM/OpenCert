import React, { useEffect, useMemo, useState } from 'react';
import {
  Table, Button, Modal, Form, Input, InputNumber, Space, Tag, Typography,
  Drawer, message, Switch, Tooltip, Select, Radio, DatePicker, Descriptions, Upload, Divider, Dropdown,
} from 'antd';
import {
  PlusOutlined, ImportOutlined, SafetyCertificateOutlined,
  MoreOutlined, DownloadOutlined, ReloadOutlined, UploadOutlined, EyeOutlined,
} from '@ant-design/icons';
import {
  listCAs, createCA, deleteCA, issueCert, updateCA, downloadCA, downloadCRL,
  importCA, importCAChain, listRevokedCerts, revokeCAcert, listIssuanceTemplates, listStorageZones,
} from '../../api';
import type { CA, IssuanceTemplate, StorageZone, RevokedCert } from '../../types';
import AlgorithmSelect from '../../components/AlgorithmSelect';
import StorageZoneSelect, { isHardwareZone } from '../../components/StorageZoneSelect';

const { Title, Text } = Typography;
const { RangePicker } = DatePicker;

const reasonOptions = [
  { value: 0, label: '未指定' }, { value: 1, label: '密钥泄露' },
  { value: 2, label: 'CA 泄露' }, { value: 3, label: '关联变更' },
  { value: 4, label: '已取代' }, { value: 5, label: '停止运营' },
];

const statusColor: Record<string, string> = { active: 'green', disabled: 'default', revoked: 'red', expired: 'orange' };
const statusText: Record<string, string> = { active: '有效', disabled: '已停用', revoked: '已吊销', expired: '已过期' };

/** 读取上传文件为文本或 base64 */
const readFile = (file: File, as: 'text' | 'base64'): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error('读取文件失败'));
    reader.onload = () => {
      const result = reader.result as string;
      resolve(as === 'base64' ? String(result).split(',')[1] ?? '' : String(result));
    };
    if (as === 'base64') reader.readAsDataURL(file);
    else reader.readAsText(file);
  });

const CAPage: React.FC = () => {
  const [cas, setCAs] = useState<CA[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [templates, setTemplates] = useState<IssuanceTemplate[]>([]);
  const [zones, setZones] = useState<StorageZone[]>([]);

  const [createOpen, setCreateOpen] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importLoading, setImportLoading] = useState(false);
  const [issueOpen, setIssueOpen] = useState(false);
  const [issueLoading, setIssueLoading] = useState(false);
  const [chainOpen, setChainOpen] = useState(false);
  const [chainLoading, setChainLoading] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [revokedDrawer, setRevokedDrawer] = useState(false);
  const [revokedList, setRevokedList] = useState<RevokedCert[]>([]);
  const [selectedCA, setSelectedCA] = useState<CA | null>(null);

  const [createForm] = Form.useForm();
  const [importForm] = Form.useForm();
  const [issueForm] = Form.useForm();
  const [chainForm] = Form.useForm();
  const [revokeForm] = Form.useForm();

  const loadCAs = async (p = 1) => {
    setLoading(true);
    try {
      const res = await listCAs({ page: p, page_size: 20 });
      setCAs(res.items);
      setTotal(res.total);
    } catch (err: any) { message.error(err.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    loadCAs();
    // 只取 CA 类颁发模板（创建 CA 时用来约束算法、有效期与路径长度）
    listIssuanceTemplates({ page: 1, page_size: 100 })
      .then((r) => setTemplates(r.items.filter((t) => t.is_ca)))
      .catch(() => setTemplates([]));
    listStorageZones().then(setZones).catch(() => setZones([]));
  }, []);

  const zoneLabel = (uuid?: string) => zones.find((z) => z.uuid === uuid)?.name || (uuid ? '未知区域' : '本地加密');

  // 创建 CA：模板变化时联动算法范围
  const createTmplUUID = Form.useWatch('issuance_tmpl_uuid', createForm);
  const createTmpl = useMemo(() => templates.find((t) => t.uuid === createTmplUUID), [templates, createTmplUUID]);
  const importZoneUUID = Form.useWatch('storage_zone_uuid', importForm);
  const importCertOnly = Form.useWatch('cert_only', importForm);
  const importMode = Form.useWatch('mode', importForm);

  const handleCreate = async (values: any) => {
    setCreateLoading(true);
    try {
      const [notBefore, notAfter] = values.validity || [];
      const payload = {
        name: values.name,
        issuance_tmpl_uuid: values.issuance_tmpl_uuid,
        parent_uuid: values.parent_uuid || '',
        key_type: values.key_type,
        sig_alg: values.sig_alg || '',
        common_name: values.common_name,
        organization: values.organization,
        country: values.country,
        not_before: notBefore ? notBefore.toISOString() : undefined,
        not_after: notAfter ? notAfter.toISOString() : undefined,
        path_len: values.path_len ?? 0,
        path_len_zero: (values.path_len ?? 0) === 0,
        storage_zone_uuid: values.storage_zone_uuid || '',
      };
      await createCA(payload as any);
      message.success('CA 创建成功');
      setCreateOpen(false); createForm.resetFields(); loadCAs();
    } catch (err: any) { message.error(err.message); }
    finally { setCreateLoading(false); }
  };

  const handleImport = async (values: any) => {
    setImportLoading(true);
    try {
      const payload: Record<string, any> = {
        name: values.name,
        parent_uuid: values.parent_uuid || '',
        cert_only: !!values.cert_only,
        storage_zone_uuid: values.cert_only ? '' : (values.storage_zone_uuid || ''),
      };
      if (values.mode === 'pkcs12') {
        if (!values.pkcs12_base64) { message.error('请选择 PKCS#12 文件'); return; }
        payload.pkcs12_base64 = values.pkcs12_base64;
        payload.pkcs12_password = values.pkcs12_password || '';
      } else {
        if (!values.cert_text) { message.error('请粘贴或上传证书'); return; }
        payload.cert_pem = values.cert_text;
        payload.private_key_pem = values.key_text || '';
      }
      await importCA(payload as any);
      message.success('CA 导入成功');
      setImportOpen(false); importForm.resetFields(); loadCAs();
    } catch (err: any) { message.error(err.message); }
    finally { setImportLoading(false); }
  };

  const handleIssue = async (values: any) => {
    if (!selectedCA) return;
    setIssueLoading(true);
    try {
      const [notBefore, notAfter] = values.validity || [];
      const days = notAfter && notBefore ? Math.max(1, notAfter.diff(notBefore, 'day')) : 365;
      await issueCert(selectedCA.uuid, {
        key_type: values.key_type,
        validity_days: days,
        not_before: notBefore ? notBefore.toISOString() : undefined,
        not_after: notAfter ? notAfter.toISOString() : undefined,
        common_name: values.common_name,
        organization: values.organization,
        country: values.country,
        is_ca: !!values.is_ca,
        path_len: values.path_len,
        san_dns: values.san_dns ? values.san_dns.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
        san_ip: values.san_ip ? values.san_ip.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
        san_email: values.san_email ? values.san_email.split(',').map((s: string) => s.trim()).filter(Boolean) : [],
      });
      message.success('证书签发成功');
      setIssueOpen(false); issueForm.resetFields();
    } catch (err: any) { message.error(err.message); }
    finally { setIssueLoading(false); }
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

  const handleRevoke = async (values: any) => {
    if (!selectedCA) return;
    setRevokeLoading(true);
    try {
      await revokeCAcert(selectedCA.uuid, values);
      message.success('证书已吊销');
      setRevokeOpen(false); revokeForm.resetFields();
      setRevokedList(await listRevokedCerts(selectedCA.uuid));
    } catch (err: any) { message.error(err.message); }
    finally { setRevokeLoading(false); }
  };

  const handleShowRevoked = async (ca: CA) => {
    setSelectedCA(ca);
    try {
      setRevokedList(await listRevokedCerts(ca.uuid));
      setRevokedDrawer(true);
    } catch (err: any) { message.error(err.message); }
  };

  const handleDownload = async (ca: CA, format: 'pem' | 'der' | 'chain') => {
    try {
      const blob = await downloadCA(ca.uuid, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ext = format === 'der' ? 'cer' : 'pem';
      a.href = url; a.download = `${ca.name}.${ext}`; a.click();
      URL.revokeObjectURL(url);
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

  const handleTogglePublish = async (ca: CA, next: boolean) => {
    try {
      await updateCA(ca.uuid, { name: ca.name, status: ca.status, is_public: next });
      message.success(next ? '已在门户公开' : '已从门户撤下');
      loadCAs(page);
    } catch (err: any) { message.error(err.message); }
  };

  const handleToggleStatus = async (ca: CA) => {
    const next = ca.status === 'active' ? 'disabled' : 'active';
    try {
      await updateCA(ca.uuid, { name: ca.name, status: next });
      message.success(next === 'active' ? 'CA 已启用' : 'CA 已停用');
      loadCAs(page);
    } catch (err: any) { message.error(err.message); }
  };

  const columns = [
    {
      title: 'CA 名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: CA) => (
        <div>
          <Text strong>{v}</Text>
          {r.subject_dn && <div><Text type="secondary" style={{ fontSize: 12 }}>{r.subject_dn}</Text></div>}
        </div>
      ),
    },
    { title: '状态', dataIndex: 'status', key: 'status', width: 90, render: (v: string) => <Tag color={statusColor[v]}>{statusText[v] || v}</Tag> },
    { title: '算法', key: 'algo', width: 140, render: (_: any, r: CA) => <Text>{r.key_type || '-'}</Text> },
    { title: '存储区域', key: 'zone', width: 130, render: (_: any, r: CA) => <Text>{r.storage_zone_name || zoneLabel(r.storage_zone_uuid)}</Text> },
    {
      title: '有效期', key: 'validity', width: 200,
      render: (_: any, r: CA) => (
        <Text style={{ fontSize: 12 }}>{r.not_before?.slice(0, 10)} ~ {r.not_after?.slice(0, 10)}</Text>
      ),
    },
    { title: '已签发', dataIndex: 'issued_count', key: 'issued_count', width: 80 },
    {
      title: '门户公开', dataIndex: 'is_public', key: 'is_public', width: 90,
      render: (v: boolean, r: CA) => (
        <Tooltip title={r.status === 'active' ? '在门户「信任服务」中展示该 CA 及其 CRL/OCSP 地址' : '仅有效状态的 CA 可公开'}>
          <Switch size="small" checked={!!v} disabled={r.status !== 'active'} onChange={(c) => handleTogglePublish(r, c)} />
        </Tooltip>
      ),
    },
    {
      title: '操作', key: 'action', width: 260, fixed: 'right' as const,
      render: (_: any, r: CA) => (
        <Space size={4} style={{ whiteSpace: 'nowrap' }}>
          <Button size="small" type="primary" icon={<SafetyCertificateOutlined />}
            onClick={() => { setSelectedCA(r); setIssueOpen(true); }}>签发证书</Button>
          <Button size="small" icon={<EyeOutlined />}
            onClick={() => { setSelectedCA(r); setDetailOpen(true); }}>详情</Button>
          <Dropdown
            menu={{
              items: [
                { key: 'chain', label: '导入证书链' },
                { key: 'revoked', label: '吊销列表' },
                { key: 'crl', label: '下载 CRL' },
                { key: 'pem', label: '下载证书（PEM）' },
                { key: 'der', label: '下载证书（DER）' },
                { key: 'toggle', label: r.status === 'active' ? '停用 CA' : '启用 CA' },
                { key: 'del', label: <Text type="danger">删除 CA</Text> },
              ],
              onClick: ({ key }) => {
                if (key === 'chain') { setSelectedCA(r); setChainOpen(true); }
                if (key === 'revoked') handleShowRevoked(r);
                if (key === 'crl') handleDownloadCRL(r);
                if (key === 'pem') handleDownload(r, 'pem');
                if (key === 'der') handleDownload(r, 'der');
                if (key === 'toggle') handleToggleStatus(r);
                if (key === 'del') {
                  Modal.confirm({
                    title: '确认删除此 CA？', content: '已签发过证书的 CA 不能删除。',
                    onOk: () => deleteCA(r.uuid).then(() => { message.success('已删除'); loadCAs(); }),
                  });
                }
              },
            }}
          >
            <Button size="small" icon={<MoreOutlined />} />
          </Dropdown>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>CA 管理</Title>
        <Space>
          <Button icon={<ImportOutlined />} onClick={() => { importForm.setFieldsValue({ mode: 'pem', cert_only: false }); setImportOpen(true); }}>
            导入 CA
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>创建 CA</Button>
        </Space>
      </div>

      <Table rowKey="uuid" columns={columns} dataSource={cas} loading={loading} scroll={{ x: 1080 }}
        pagination={{ current: page, total, pageSize: 20, onChange: (p) => { setPage(p); loadCAs(p); } }} />

      {/* 创建 CA：与签发证书共用同一套字段 */}
      <Modal title="创建 CA" open={createOpen} onCancel={() => setCreateOpen(false)} footer={null} width={640}>
        <Form form={createForm} layout="vertical" onFinish={handleCreate} style={{ marginTop: 16 }}>
          <Form.Item label="CA 名称" name="name" rules={[{ required: true, message: '请填写 CA 名称' }]}>
            <Input placeholder="例如：示例根 CA" />
          </Form.Item>
          <Form.Item label="颁发模板" name="issuance_tmpl_uuid"
            extra="决定可选算法、有效期范围与路径长度；没有 CA 类模板时可先在「模板管理」中创建">
            <Select allowClear placeholder="不指定（手工配置）"
              options={templates.map((t) => ({ value: t.uuid, label: t.name }))} />
          </Form.Item>
          <Form.Item label="上级 CA" name="parent_uuid" extra="留空表示自签根 CA">
            <Select allowClear placeholder="自签根 CA"
              options={cas.filter((c) => c.status === 'active').map((c) => ({ value: c.uuid, label: c.name }))} />
          </Form.Item>
          <Form.Item label="密钥算法" name="key_type" rules={[{ required: true, message: '请选择密钥算法' }]}>
            <AlgorithmSelect allowed={createTmpl?.allowed_key_types} family={undefined} />
          </Form.Item>
          {createTmpl && (createTmpl.allowed_sig_algs?.length ?? 0) > 0 && (
            <Form.Item label="签名算法" name="sig_alg" extra="留空按 CA 密钥类型自动选择">
              <Select allowClear placeholder="自动选择"
                options={(createTmpl.allowed_sig_algs ?? []).map((s) => ({ value: s, label: s }))} />
            </Form.Item>
          )}
          <Form.Item label="CommonName" name="common_name" rules={[{ required: true, message: '请填写 CommonName' }]}>
            <Input placeholder="例如：Example Root CA" />
          </Form.Item>
          <Space style={{ width: '100%' }} size={12}>
            <Form.Item label="组织" name="organization" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item label="国家代码" name="country" style={{ width: 140 }}><Input maxLength={2} placeholder="CN" /></Form.Item>
          </Space>
          <Form.Item label="生效 / 失效时间" name="validity" extra="不填则按模板默认有效期计算">
            <RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Space style={{ width: '100%' }} size={12}>
            <Form.Item label="路径长度" name="path_len" initialValue={0} style={{ flex: 1 }}
              extra="0 表示只能签发终端证书（不能再签下级 CA）">
              <InputNumber min={0} max={10} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item label="存储区域" name="storage_zone_uuid" style={{ flex: 1 }} extra="私钥保存位置">
              <StorageZoneSelect />
            </Form.Item>
          </Space>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setCreateOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={createLoading}>创建</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 导入 CA */}
      <Modal title="导入 CA" open={importOpen} onCancel={() => setImportOpen(false)} footer={null} width={640}>
        <Form form={importForm} layout="vertical" onFinish={handleImport} style={{ marginTop: 16 }} initialValues={{ mode: 'pem' }}>
          <Form.Item label="CA 名称" name="name" rules={[{ required: true, message: '请填写 CA 名称' }]}><Input /></Form.Item>
          <Form.Item label="导入内容" name="mode">
            <Radio.Group>
              <Radio.Button value="pem">证书 + 私钥（PEM）</Radio.Button>
              <Radio.Button value="pkcs12">PKCS#12 文件</Radio.Button>
            </Radio.Group>
          </Form.Item>

          {importMode !== 'pkcs12' && (
            <>
              <Form.Item label="CA 证书（PEM，可含证书链）" name="cert_text" rules={[{ required: true, message: '请粘贴或上传证书' }]}>
                <Input.TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----" style={{ fontSize: 12 }} />
              </Form.Item>
              <Form.Item label="上传证书文件">
                <Upload accept=".pem,.crt,.cer" showUploadList={false} beforeUpload={async (file) => {
                  importForm.setFieldValue('cert_text', await readFile(file, 'text'));
                  return false;
                }}>
                  <Button icon={<UploadOutlined />}>选择证书文件</Button>
                </Upload>
              </Form.Item>
              <Form.Item label="CA 私钥（PEM，留空表示仅导入证书）" name="key_text">
                <Input.TextArea rows={4} placeholder="-----BEGIN PRIVATE KEY-----" style={{ fontSize: 12 }} />
              </Form.Item>
            </>
          )}

          {importMode === 'pkcs12' && (
            <>
              <Form.Item label="PKCS#12 文件" name="pkcs12_base64" rules={[{ required: true, message: '请选择 PKCS#12 文件' }]}>
                <Upload accept=".p12,.pfx" showUploadList={false} maxCount={1} beforeUpload={async (file) => {
                  importForm.setFieldValue('pkcs12_base64', await readFile(file, 'base64'));
                  importForm.setFieldValue('pkcs12_name', file.name);
                  return false;
                }}>
                  <Button icon={<UploadOutlined />}>选择 .p12 / .pfx 文件</Button>
                </Upload>
              </Form.Item>
              <Form.Item label="文件密码" name="pkcs12_password">
                <Input.Password placeholder="PKCS#12 密码" autoComplete="new-password" />
              </Form.Item>
            </>
          )}

          <Form.Item label="仅导入证书（作为外部 CA，仅用于证书链）" name="cert_only" valuePropName="checked"
            extra="仅证书导入的 CA 不能用于签发">
            <Switch />
          </Form.Item>
          <Form.Item label="上级 CA" name="parent_uuid">
            <Select allowClear placeholder="无"
              options={cas.filter((c) => c.status === 'active').map((c) => ({ value: c.uuid, label: c.name }))} />
          </Form.Item>
          {!importCertOnly && importMode !== 'pkcs12' && (
            <Form.Item label="私钥存储区域" name="storage_zone_uuid"
              extra={isHardwareZone(zones.find((z) => z.uuid === importZoneUUID))
                ? '所选为硬件区域：私钥将导入设备，之后无法导出'
                : '私钥将用平台主密钥加密保存'}>
              <StorageZoneSelect />
            </Form.Item>
          )}
          {!importCertOnly && importMode === 'pkcs12' && (
            <Form.Item label="私钥存储区域" name="storage_zone_uuid">
              <StorageZoneSelect />
            </Form.Item>
          )}
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setImportOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={importLoading}>导入</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 签发证书 */}
      <Modal title={`签发证书 — ${selectedCA?.name || ''}`} open={issueOpen} onCancel={() => setIssueOpen(false)} footer={null} width={640}>
        <Form form={issueForm} layout="vertical" onFinish={handleIssue} style={{ marginTop: 16 }}>
          <Form.Item label="密钥算法" name="key_type" rules={[{ required: true, message: '请选择密钥算法' }]}>
            <AlgorithmSelect allowed={selectedCA?.key_type?.startsWith('sm2') ? ['sm2'] : undefined} />
          </Form.Item>
          <Form.Item label="CommonName" name="common_name" rules={[{ required: true, message: '请填写 CommonName' }]}>
            <Input placeholder="example.com" />
          </Form.Item>
          <Space style={{ width: '100%' }} size={12}>
            <Form.Item label="组织" name="organization" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item label="国家代码" name="country" style={{ width: 140 }}><Input maxLength={2} placeholder="CN" /></Form.Item>
          </Space>
          <Form.Item label="生效 / 失效时间" name="validity" extra="不填按 365 天签发，且不超过 CA 有效期">
            <RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Space style={{ width: '100%' }} size={12}>
            <Form.Item label="是否为 CA 证书" name="is_ca" initialValue={false} style={{ flex: 1 }}>
              <Select options={[{ value: false, label: '否' }, { value: true, label: '是' }]} />
            </Form.Item>
            <Form.Item label="路径长度" name="path_len" style={{ flex: 1 }}><InputNumber min={0} max={10} style={{ width: '100%' }} /></Form.Item>
          </Space>
          <Form.Item label="SAN DNS（逗号分隔）" name="san_dns"><Input placeholder="example.com, www.example.com" /></Form.Item>
          <Form.Item label="SAN IP（逗号分隔）" name="san_ip"><Input placeholder="192.168.1.1" /></Form.Item>
          <Form.Item label="SAN 邮箱（逗号分隔）" name="san_email"><Input placeholder="admin@example.com" /></Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setIssueOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={issueLoading}>签发</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 详情 */}
      <Drawer title={`CA 详情 — ${selectedCA?.name || ''}`} open={detailOpen} onClose={() => setDetailOpen(false)} width={640}>
        {selectedCA && (
          <>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="主体">{selectedCA.subject_dn || selectedCA.common_name || '-'}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={statusColor[selectedCA.status]}>{statusText[selectedCA.status] || selectedCA.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="密钥算法">{selectedCA.key_type || '-'}</Descriptions.Item>
              <Descriptions.Item label="签名算法">{selectedCA.sig_alg || '-'}</Descriptions.Item>
              <Descriptions.Item label="私钥位置">
                {selectedCA.key_source === 'external'
                  ? '仅证书（无私钥）'
                  : `${selectedCA.storage_zone_name || zoneLabel(selectedCA.storage_zone_uuid)} / ${selectedCA.key_backend || 'database'}`}
              </Descriptions.Item>
              <Descriptions.Item label="有效期">
                {selectedCA.not_before?.slice(0, 19)} ~ {selectedCA.not_after?.slice(0, 19)}
              </Descriptions.Item>
              <Descriptions.Item label="已签发">{selectedCA.issued_count}</Descriptions.Item>
            </Descriptions>
            <Divider titlePlacement="start" plain>证书内容</Divider>
            <Input.TextArea rows={12} readOnly value={selectedCA.cert_pem || ''} style={{ fontSize: 11, fontFamily: 'monospace' }} />
            <Space style={{ marginTop: 12 }}>
              <Button icon={<DownloadOutlined />} onClick={() => handleDownload(selectedCA, 'pem')}>下载 PEM</Button>
              <Button icon={<DownloadOutlined />} onClick={() => handleDownload(selectedCA, 'chain')}>下载证书链</Button>
              <Button icon={<ReloadOutlined />} onClick={() => { setDetailOpen(false); handleShowRevoked(selectedCA); }}>查看吊销列表</Button>
            </Space>
          </>
        )}
      </Drawer>

      {/* 导入证书链 */}
      <Modal title={`导入证书链 — ${selectedCA?.name || ''}`} open={chainOpen} onCancel={() => setChainOpen(false)} footer={null} width={560}>
        <Form form={chainForm} layout="vertical" onFinish={handleImportChain} style={{ marginTop: 16 }}>
          <Form.Item label="证书链（PEM 格式）" name="chain_pem" rules={[{ required: true, message: '请粘贴证书链' }]}>
            <Input.TextArea rows={10} placeholder="-----BEGIN CERTIFICATE-----" style={{ fontSize: 12 }} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setChainOpen(false)}>取消</Button>
              <Button type="primary" htmlType="submit" loading={chainLoading}>导入</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* 吊销列表 */}
      <Drawer title={`吊销列表 — ${selectedCA?.name || ''}`} open={revokedDrawer} onClose={() => setRevokedDrawer(false)} width={600}
        extra={<Button danger onClick={() => setRevokeOpen(true)}>吊销证书</Button>}>
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
          <Form.Item label="证书序列号（十六进制）" name="serial" rules={[{ required: true, message: '请填写序列号' }]}>
            <Input placeholder="例如 0a1b2c3d" />
          </Form.Item>
          <Form.Item label="吊销原因" name="reason" rules={[{ required: true }]} initialValue={0}>
            <Select options={reasonOptions} />
          </Form.Item>
          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setRevokeOpen(false)}>取消</Button>
              <Button type="primary" danger htmlType="submit" loading={revokeLoading}>确认吊销</Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CAPage;
