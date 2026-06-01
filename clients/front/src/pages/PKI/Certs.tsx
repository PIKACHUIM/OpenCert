import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  Popconfirm, message, Tooltip, Card, Drawer, Descriptions, Divider,
  Row, Col, Alert, DatePicker, Checkbox, Collapse, InputNumber, Switch,
} from 'antd';
import dayjs from 'dayjs';
import {
  PlusOutlined, DeleteOutlined, ReloadOutlined, SafetyCertificateOutlined,
  ImportOutlined, DownloadOutlined, StopOutlined, EyeOutlined,
  KeyOutlined, ExportOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import {
  getPKICerts, issuePKICert, selfSignFromCSR, importPKICert, deletePKICert, deletePKICertKey,
  exportPKICert, importPKICertToCard, revokePKICert,
  getLocalCAs, getCSRList, getCards,
} from '../../api';
import type {
  PKICert, IssueCertRequest, ImportCertRequest, ImportCertMode,
  LocalCA, CSRRecord, Card as CardType, ExportCertFormat, CertExtensions,
} from '../../types';
import { useAppStore } from '../../store/appStore';

const { Text } = Typography;
const { TextArea } = Input;

const IMPORT_MODE_OPTIONS = [
  { label: '仅证书（自动匹配已有私钥）', value: 'cert_only' },
  { label: '证书 + 私钥', value: 'cert_key' },
  { label: 'PKCS#12 文件（Base64）', value: 'pkcs12' },
  { label: '仅私钥（等待未来关联证书）', value: 'key_only' },
];

const KEY_USAGE_OPTIONS = [
  { label: '数字签名', value: 'digitalSignature' },
  { label: '内容加密', value: 'keyEncipherment' },
  { label: '数据加密', value: 'dataEncipherment' },
  { label: '密钥协商', value: 'keyAgreement' },
  { label: '证书签名', value: 'certSign' },
  { label: 'CRL 签名', value: 'crlSign' },
];

const EXT_KEY_USAGE_OPTIONS = [
  { label: 'TLS 服务器认证', value: 'serverAuth' },
  { label: 'TLS 客户端认证', value: 'clientAuth' },
  { label: '代码签名', value: 'codeSigning' },
  { label: '邮件保护', value: 'emailProtection' },
  { label: '时间戳', value: 'timeStamping' },
  { label: 'OCSP 签名', value: 'ocspSigning' },
];

// 自签名标识（CA 选择器中的特殊值）
const SELF_SIGN_KEY = '__selfsign__';

const CertsPage: React.FC = () => {
  const { darkMode } = useAppStore();
  const [list, setList] = useState<PKICert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);

  const [cas, setCAs] = useState<LocalCA[]>([]);
  const [csrList, setCSRList] = useState<CSRRecord[]>([]);
  const [cards, setCards] = useState<CardType[]>([]);

  // 签发弹窗
  const [issueOpen, setIssueOpen] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [issueForm] = Form.useForm();

  // 导入弹窗
  const [importOpen, setImportOpen] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importForm] = Form.useForm();
  const [importMode, setImportMode] = useState<ImportCertMode>('cert_only');

  // 导出弹窗
  const [exportOpen, setExportOpen] = useState(false);
  const [exportRecord, setExportRecord] = useState<PKICert | null>(null);
  const [exportForm] = Form.useForm();
  const [exporting, setExporting] = useState(false);

  // 导入到智能卡弹窗
  const [toCardOpen, setToCardOpen] = useState(false);
  const [toCardRecord, setToCardRecord] = useState<PKICert | null>(null);
  const [toCardForm] = Form.useForm();
  const [toCardLoading, setToCardLoading] = useState(false);

  // 查看详情抽屉
  const [viewOpen, setViewOpen] = useState(false);
  const [viewRecord, setViewRecord] = useState<PKICert | null>(null);

  const load = async (p = page) => {
    setLoading(true);
    try {
      const res = await getPKICerts({ page: p, page_size: 10 });
      setList(res.items);
      setTotal(res.total);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    Promise.all([
      getLocalCAs({ page: 1, page_size: 100 }),
      getCSRList({ page: 1, page_size: 100 }),
      getCards({ page: 1, page_size: 100 }),
    ]).then(([caRes, csrRes, cardRes]) => {
      setCAs(caRes.items);
      setCSRList(csrRes.items);
      setCards(cardRes.items);
    }).catch(() => {});
  }, []);

  const handleIssue = async () => {
    try {
      const values = await issueForm.validateFields();
      setIssuing(true);

      const [notBefore, notAfter] = values.date_range;
      const validityDays = notAfter.diff(notBefore, 'day');

      // 构建证书扩展选项
      const extensions: CertExtensions = {};
      if (values.key_usage?.length) extensions.key_usage = values.key_usage;
      if (values.ext_key_usage?.length) extensions.ext_key_usage = values.ext_key_usage;
      if (values.is_ca !== undefined) extensions.is_ca = values.is_ca;
      if (values.is_ca && values.path_len_constraint !== undefined && values.path_len_constraint !== null) {
        extensions.path_len_constraint = values.path_len_constraint;
      }
      if (values.crl_urls?.trim()) extensions.crl_urls = values.crl_urls.split(',').map((s: string) => s.trim()).filter(Boolean);
      if (values.ocsp_urls?.trim()) extensions.ocsp_urls = values.ocsp_urls.split(',').map((s: string) => s.trim()).filter(Boolean);
      if (values.aia_urls?.trim()) extensions.aia_urls = values.aia_urls.split(',').map((s: string) => s.trim()).filter(Boolean);
      if (values.csp_name?.trim()) extensions.csp_name = values.csp_name.trim();
      const hasExtensions = Object.keys(extensions).length > 0;

      if (values.ca_uuid === SELF_SIGN_KEY) {
        // 自签名：用 CSR 的私钥对自身签名
        await selfSignFromCSR(
          values.csr_uuid,
          validityDays,
          values.remark,
          notBefore.toISOString(),
          notAfter.toISOString(),
          values.card_password,
          hasExtensions ? extensions : undefined,
        );
        message.success('自签名证书已生成');
      } else {
        // CA 签发
        await issuePKICert({
          csr_uuid: values.csr_uuid,
          ca_uuid: values.ca_uuid,
          not_before: notBefore.toISOString(),
          not_after: notAfter.toISOString(),
          validity_days: validityDays,
          remark: values.remark,
          extensions: hasExtensions ? extensions : undefined,
        } as IssueCertRequest);
        message.success('证书已签发');
      }

      setIssueOpen(false);
      issueForm.resetFields();
      load();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setIssuing(false); }
  };

  const handleImport = async () => {
    try {
      const values = await importForm.validateFields();
      setImporting(true);
      const result = await importPKICert(values as ImportCertRequest);
      if (result.key_matched) {
        message.success('证书已导入，并自动匹配到已有私钥');
      } else {
        message.success('证书已导入');
      }
      setImportOpen(false);
      importForm.resetFields();
      setImportMode('cert_only');
      load();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setImporting(false); }
  };

  const handleExport = async () => {
    if (!exportRecord) return;
    try {
      const values = await exportForm.validateFields();
      setExporting(true);
      const extMap: Record<string, string> = { pem: '.pem', der: '.der', pkcs12: '.p12', key_pem: '.key.pem' };
      const filename = `${exportRecord.common_name}${extMap[values.format] || '.pem'}`;
      await exportPKICert(exportRecord.uuid, values.format as ExportCertFormat, values.password, filename);
      setExportOpen(false);
      exportForm.resetFields();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setExporting(false); }
  };

  const handleToCard = async () => {
    if (!toCardRecord) return;
    try {
      const values = await toCardForm.validateFields();
      setToCardLoading(true);
      await importPKICertToCard(toCardRecord.uuid, values.card_uuid);
      message.success('证书已导入到智能卡');
      setToCardOpen(false);
      toCardForm.resetFields();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setToCardLoading(false); }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  // 格式化密钥用途显示
  const formatKeyUsage = (raw?: string): string => {
    if (!raw) return '-';
    const map: Record<string, string> = {
      digitalSignature: '数字签名', keyEncipherment: '密钥加密',
      dataEncipherment: '数据加密', keyAgreement: '密钥协商',
      certSign: '证书签名', crlSign: 'CRL签名',
      contentCommitment: '内容承诺', encipherOnly: '仅加密', decipherOnly: '仅解密',
    };
    try {
      const arr: string[] = JSON.parse(raw);
      return arr.map((k) => map[k] || k).join(', ');
    } catch { return raw; }
  };

  const formatExtKeyUsage = (raw?: string): string => {
    if (!raw) return '-';
    const map: Record<string, string> = {
      serverAuth: '服务器认证', clientAuth: '客户端认证',
      codeSigning: '代码签名', emailProtection: '邮件保护',
      timeStamping: '时间戳', ocspSigning: 'OCSP签名',
    };
    try {
      const arr: string[] = JSON.parse(raw);
      return arr.map((k) => map[k] || k).join(', ');
    } catch { return raw; }
  };

  const columns = [
    {
      title: '通用名称 (CN)',
      dataIndex: 'common_name',
      ellipsis: true,
      render: (v: string, r: PKICert) => (
        <Space>
          <SafetyCertificateOutlined style={{ color: r.revoked ? '#ff4d4f' : '#52c41a' }} />
          <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{v}</Text>
        </Space>
      ),
    },
    {
      title: '颁发 CA',
      dataIndex: 'ca_name',
      width: 120,
      ellipsis: true,
      render: (v: string) => <Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>{v || '自签名'}</Text>,
    },
    {
      title: '密钥',
      width: 110,
      render: (_: any, r: PKICert) => (
<Space orientation="vertical" size={0}>
          <Tag color="blue" style={{ margin: 0 }}>{r.key_type?.toUpperCase()}</Tag>
          <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>
            {r.key_storage === 'smartcard' ? '智能卡' : '数据库'} | {r.has_private_key ? '有私钥' : '无私钥'}
          </Text>
        </Space>
      ),
    },
    {
      title: '有效期',
      width: 190,
      render: (_: any, r: PKICert) => {
        const expired = dayjs(r.not_after).isBefore(dayjs());
        return (
          <Text style={{ fontSize: 12, color: expired ? '#ff4d4f' : darkMode ? '#8b949e' : '#666' }}>
            {dayjs(r.not_before).format('YYYY-MM-DD')} ~ {dayjs(r.not_after).format('YYYY-MM-DD')}
          </Text>
        );
      },
    },
    {
      title: '密钥用途',
      width: 150,
      ellipsis: true,
      render: (_: any, r: PKICert) => {
        const usage = formatKeyUsage(r.key_usage);
        return (
          <Tooltip title={usage}>
            <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>{usage}</Text>
          </Tooltip>
        );
      },
    },
    {
      title: '扩展用途',
      width: 140,
      ellipsis: true,
      render: (_: any, r: PKICert) => {
        const usage = formatExtKeyUsage(r.ext_key_usage);
        return (
          <Tooltip title={usage}>
            <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>{usage}</Text>
          </Tooltip>
        );
      },
    },
    {
      title: 'SAN',
      width: 140,
      ellipsis: true,
      render: (_: any, r: PKICert) => {
        const parts: string[] = [];
        if (r.san_dns) parts.push(r.san_dns);
        if (r.san_ip) parts.push(r.san_ip);
        if (r.san_email) parts.push(r.san_email);
        const san = parts.join(', ') || '-';
        return (
          <Tooltip title={san}>
            <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>{san}</Text>
          </Tooltip>
        );
      },
    },
    {
      title: '状态',
      width: 70,
      render: (_: any, r: PKICert) => {
        if (r.revoked) return <Tag color="red">已吊销</Tag>;
        if (dayjs(r.not_after).isBefore(dayjs())) return <Tag color="orange">已过期</Tag>;
        return <Tag color="green">有效</Tag>;
      },
    },
    {
      title: '操作',
      width: 200,
      fixed: 'right' as const,
      render: (_: any, record: PKICert) => (
        <Space size={2} wrap>
          <Tooltip title="查看详情">
            <Button type="text" size="small" icon={<EyeOutlined />}
              onClick={() => { setViewRecord(record); setViewOpen(true); }} />
          </Tooltip>
          <Tooltip title="导出">
            <Button type="text" size="small" icon={<DownloadOutlined />}
              onClick={() => { setExportRecord(record); setExportOpen(true); }} />
          </Tooltip>
          <Tooltip title="导入到智能卡">
            <Button type="text" size="small" icon={<ExportOutlined />}
              onClick={() => { setToCardRecord(record); setToCardOpen(true); }} />
          </Tooltip>
          {record.has_private_key && (
            <Popconfirm title="确认删除私钥？此操作不可恢复，证书仍保留。"
              onConfirm={() => deletePKICertKey(record.uuid).then(() => { message.success('私钥已删除'); load(); }).catch((e) => message.error(e.message))}
              okText="删除私钥" cancelText="取消" okButtonProps={{ danger: true }}>
              <Tooltip title="删除私钥">
                <Button type="text" size="small" danger icon={<KeyOutlined />} />
              </Tooltip>
            </Popconfirm>
          )}
          {!record.revoked && (
            <Popconfirm title="确认吊销此证书？"
              onConfirm={() => revokePKICert(record.uuid).then(() => { message.success('已吊销'); load(); }).catch((e) => message.error(e.message))}
              okText="吊销" cancelText="取消" okButtonProps={{ danger: true }}>
              <Tooltip title="吊销">
                <Button type="text" size="small" danger icon={<StopOutlined />} />
              </Tooltip>
            </Popconfirm>
          )}
          <Popconfirm title="确认删除此证书？"
            onConfirm={() => deletePKICert(record.uuid).then(() => { message.success('已删除'); load(); }).catch((e) => message.error(e.message))}
            okText="删除" cancelText="取消" okButtonProps={{ danger: true }}>
            <Tooltip title="删除">
              <Button type="text" size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        icon={<SafetyCertificateOutlined />}
        title="证书签发管理"
        extra={
          <>
            <Button icon={<ReloadOutlined />} onClick={() => load()} size="small">刷新</Button>
            <Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)} size="small">导入证书</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setIssueOpen(true)} size="small">签发证书</Button>
          </>
        }
      />

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table dataSource={list} columns={columns} rowKey="uuid" loading={loading}
          scroll={{ x: 1200 }}
          pagination={{ current: page, total, pageSize: 10, onChange: (p) => { setPage(p); load(p); }, showTotal: (t) => `共 ${t} 条` }} />
      </Card>

      {/* 签发证书弹窗 */}
      <Modal title={<Space><PlusOutlined />签发证书</Space>} open={issueOpen}
        onOk={handleIssue} onCancel={() => { setIssueOpen(false); issueForm.resetFields(); }}
        okText="签发" cancelText="取消" confirmLoading={issuing} width={700}>
        <Form form={issueForm} layout="vertical" style={{ marginTop: 16 }}
          initialValues={{
            date_range: [dayjs(), dayjs().add(1, 'year')],
          }}>
          <Form.Item name="csr_uuid" label="选择 CSR" rules={[{ required: true, message: '请选择 CSR' }]}>
            <Select placeholder="选择要签发的 CSR"
              options={csrList.map((c) => ({ value: c.uuid, label: `${c.common_name} (${c.key_type})` }))} />
          </Form.Item>
          <Form.Item name="ca_uuid" label="签发 CA" rules={[{ required: true, message: '请选择 CA' }]}>
            <Select placeholder="选择签发此证书的 CA，或选择自签名">
              <Select.Option value={SELF_SIGN_KEY}>
                <Space>
                  <Tag color="orange" style={{ margin: 0 }}>自签名</Tag>
                  使用 CSR 私钥自签（无需 CA）
                </Space>
              </Select.Option>
              {cas.filter((c) => !c.revoked && c.has_priv_key).map((c) => (
                <Select.Option key={c.uuid} value={c.uuid}>
                  {c.name} ({c.key_type})
                </Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item
            noStyle
            shouldUpdate={(prev, cur) => prev.ca_uuid !== cur.ca_uuid || prev.csr_uuid !== cur.csr_uuid}
          >
            {({ getFieldValue }) => {
              if (getFieldValue('ca_uuid') !== SELF_SIGN_KEY) return null;
              const selectedCSR = csrList.find((c) => c.uuid === getFieldValue('csr_uuid'));
              const isSmartcard = selectedCSR?.key_storage === 'smartcard';
              return (
                <>
                  <Alert
                    type="warning" showIcon
                    title={isSmartcard
                      ? '自签名模式：私钥存储在智能卡上，需要输入卡片密码解密私钥'
                      : '自签名模式：使用 CSR 中存储的私钥进行自签名'
                    }
                    style={{ marginBottom: 12 }}
                  />
                  {isSmartcard && (
                    <Form.Item
                      name="card_password"
                      label="卡片密码"
                      rules={[{ required: true, message: '智能卡模式需要输入卡片密码' }]}
                    >
                      <Input.Password placeholder="请输入智能卡密码以解密私钥" />
                    </Form.Item>
                  )}
                </>
              );
            }}
          </Form.Item>
          <Form.Item
            name="date_range"
            label="有效期（起止日期）"
            rules={[{ required: true, message: '请选择有效期' }]}
          >
            <DatePicker.RangePicker
              style={{ width: '100%' }}
              format="YYYY-MM-DD"
              disabledDate={(d) => d && d.isBefore(dayjs().subtract(1, 'day'))}
              presets={[
                { label: '30 天', value: [dayjs(), dayjs().add(30, 'day')] },
                { label: '90 天', value: [dayjs(), dayjs().add(90, 'day')] },
                { label: '1 年', value: [dayjs(), dayjs().add(1, 'year')] },
                { label: '2 年', value: [dayjs(), dayjs().add(2, 'year')] },
                { label: '3 年', value: [dayjs(), dayjs().add(3, 'year')] },
                { label: '5 年', value: [dayjs(), dayjs().add(5, 'year')] },
              ]}
            />
          </Form.Item>

          {/* 证书扩展选项（折叠面板） */}
          <Collapse ghost size="small" style={{ marginBottom: 8 }}
            items={[{
              key: 'extensions',
              label: <Text type="secondary" style={{ fontSize: 13 }}>高级扩展选项（密钥用途、基本约束、CRL/OCSP/AIA、CSP）</Text>,
              children: (
                <>
                  <Divider plain style={{ fontSize: 12, margin: '4px 0 12px' }}>密钥用途</Divider>
                  <Form.Item name="key_usage" label="密钥用途 (Key Usage)">
                    <Checkbox.Group options={KEY_USAGE_OPTIONS} />
                  </Form.Item>
                  <Form.Item name="ext_key_usage" label="扩展密钥用途 (Extended Key Usage)">
                    <Checkbox.Group options={EXT_KEY_USAGE_OPTIONS} />
                  </Form.Item>

                  <Divider plain style={{ fontSize: 12, margin: '4px 0 12px' }}>基本约束</Divider>
                  <Row gutter={16}>
                    <Col span={8}>
                      <Form.Item name="is_ca" label="是否 CA" valuePropName="checked">
                        <Switch checkedChildren="是" unCheckedChildren="否" />
                      </Form.Item>
                    </Col>
                    <Col span={16}>
                      <Form.Item noStyle shouldUpdate={(prev, cur) => prev.is_ca !== cur.is_ca}>
                        {({ getFieldValue }) => getFieldValue('is_ca') && (
                          <Form.Item name="path_len_constraint" label="路径长度约束" tooltip="CA 链最大深度，-1 表示不限制">
                            <InputNumber min={-1} max={10} placeholder="-1 不限制" style={{ width: '100%' }} />
                          </Form.Item>
                        )}
                      </Form.Item>
                    </Col>
                  </Row>

                  <Divider plain style={{ fontSize: 12, margin: '4px 0 12px' }}>CRL / OCSP / AIA</Divider>
                  <Form.Item name="crl_urls" label="CRL 分发点 URL" tooltip="多个地址用逗号分隔">
                    <Input placeholder="http://crl.example.com/ca.crl" />
                  </Form.Item>
                  <Form.Item name="ocsp_urls" label="OCSP 响应者 URL" tooltip="多个地址用逗号分隔">
                    <Input placeholder="http://ocsp.example.com" />
                  </Form.Item>
                  <Form.Item name="aia_urls" label="AIA 颁发者信息访问 URL" tooltip="多个地址用逗号分隔">
                    <Input placeholder="http://ca.example.com/ca.crt" />
                  </Form.Item>

                  <Divider plain style={{ fontSize: 12, margin: '4px 0 12px' }}>CSP 信息</Divider>
                  <Form.Item name="csp_name" label="CSP 名称" tooltip="Microsoft Cryptographic Service Provider 名称">
                    <Input placeholder="Microsoft Enhanced RSA and AES Cryptographic Provider" />
                  </Form.Item>
                </>
              ),
            }]}
          />

          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 导入证书弹窗 */}
      <Modal title={<Space><ImportOutlined />导入证书</Space>} open={importOpen}
        onOk={handleImport} onCancel={() => { setImportOpen(false); importForm.resetFields(); setImportMode('cert_only'); }}
        okText="导入" cancelText="取消" confirmLoading={importing} width={620}>
        <Form form={importForm} layout="vertical" style={{ marginTop: 16 }} initialValues={{ mode: 'cert_only' }}>
          <Form.Item name="mode" label="导入模式" rules={[{ required: true }]}>
            <Select options={IMPORT_MODE_OPTIONS} onChange={(v) => setImportMode(v as ImportCertMode)} />
          </Form.Item>

          {importMode === 'cert_only' && (
            <>
<Alert type="info" showIcon title="系统将自动匹配数据库或智能卡中已有的私钥并关联到此证书" style={{ marginBottom: 12 }} />
              <Form.Item name="cert_pem" label="证书（PEM 格式）" rules={[{ required: true }]}>
                <TextArea rows={8} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  style={{ fontFamily: 'monospace', fontSize: 12 }} />
              </Form.Item>
            </>
          )}

          {importMode === 'cert_key' && (
            <>
              <Form.Item name="cert_pem" label="证书（PEM 格式）" rules={[{ required: true }]}>
                <TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  style={{ fontFamily: 'monospace', fontSize: 12 }} />
              </Form.Item>
              <Form.Item name="key_pem" label="私钥（PEM 格式）" rules={[{ required: true }]}>
                <TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  style={{ fontFamily: 'monospace', fontSize: 12 }} />
              </Form.Item>
            </>
          )}

          {importMode === 'pkcs12' && (
            <>
              <Form.Item name="pkcs12_b64" label="PKCS#12 文件（Base64 编码）" rules={[{ required: true }]}>
                <TextArea rows={6} placeholder="将 .p12/.pfx 文件内容 Base64 编码后粘贴到此处"
                  style={{ fontFamily: 'monospace', fontSize: 12 }} />
              </Form.Item>
              <Form.Item name="pkcs12_password" label="PKCS#12 密码">
                <Input.Password placeholder="PKCS#12 文件密码（如有）" />
              </Form.Item>
            </>
          )}

          {importMode === 'key_only' && (
            <>
<Alert type="warning" showIcon title="仅导入私钥，证书可在未来导入时自动关联" style={{ marginBottom: 12 }} />
              <Form.Item name="key_pem" label="私钥（PEM 格式）" rules={[{ required: true }]}>
                <TextArea rows={8} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  style={{ fontFamily: 'monospace', fontSize: 12 }} />
              </Form.Item>
            </>
          )}

          <Form.Item name="card_uuid" label="导入到智能卡（可选）">
            <Select allowClear placeholder="若需存储到智能卡，请选择（留空则存数据库）"
              options={cards.map((c) => ({ value: c.uuid, label: `${c.card_name} (${c.slot_type})` }))} />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 导出弹窗 */}
      <Modal title={<Space><DownloadOutlined />导出证书 — {exportRecord?.common_name}</Space>}
        open={exportOpen} onOk={handleExport}
        onCancel={() => { setExportOpen(false); exportForm.resetFields(); }}
        okText="导出" cancelText="取消" confirmLoading={exporting} width={400}>
        <Form form={exportForm} layout="vertical" style={{ marginTop: 16 }} initialValues={{ format: 'pem' }}>
          <Form.Item name="format" label="导出格式" rules={[{ required: true }]}>
            <Select options={[
              { label: 'PEM 证书', value: 'pem' },
              { label: 'DER 证书', value: 'der' },
              { label: 'PKCS#12（含私钥）', value: 'pkcs12', disabled: !exportRecord?.has_private_key },
              { label: '私钥 PEM', value: 'key_pem', disabled: !exportRecord?.has_private_key },
            ]} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(p, c) => p.format !== c.format}>
            {({ getFieldValue }) => getFieldValue('format') === 'pkcs12' && (
              <Form.Item name="password" label="PKCS#12 密码">
                <Input.Password placeholder="设置导出文件密码（可选）" />
              </Form.Item>
            )}
          </Form.Item>
        </Form>
      </Modal>

      {/* 导入到智能卡弹窗 */}
      <Modal title={<Space><ExportOutlined />导入到智能卡 — {toCardRecord?.common_name}</Space>}
        open={toCardOpen} onOk={handleToCard}
        onCancel={() => { setToCardOpen(false); toCardForm.resetFields(); }}
        okText="导入" cancelText="取消" confirmLoading={toCardLoading} width={400}>
        <Form form={toCardForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="card_uuid" label="目标智能卡" rules={[{ required: true, message: '请选择智能卡' }]}>
            <Select placeholder="选择目标智能卡"
              options={cards.map((c) => ({ value: c.uuid, label: `${c.card_name} (${c.slot_type})` }))} />
          </Form.Item>
        </Form>
      </Modal>

      {/* 查看详情抽屉 */}
      <Drawer title={<Space><EyeOutlined />证书详情 — {viewRecord?.common_name}</Space>}
        open={viewOpen} onClose={() => setViewOpen(false)} width={640}>
        {viewRecord && (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="通用名称">{viewRecord.common_name}</Descriptions.Item>
              <Descriptions.Item label="序列号">
                <Text copyable style={{ fontSize: 12 }}>{viewRecord.serial_number || '-'}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="颁发 CA">{viewRecord.ca_name || '-'}</Descriptions.Item>
              <Descriptions.Item label="密钥类型"><Tag color="blue">{viewRecord.key_type}</Tag></Descriptions.Item>
              <Descriptions.Item label="含私钥">
                <Tag color={viewRecord.has_private_key ? 'green' : 'default'}>{viewRecord.has_private_key ? '是' : '否'}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={viewRecord.revoked ? 'red' : 'green'}>{viewRecord.revoked ? '已吊销' : '有效'}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="生效时间">{dayjs(viewRecord.not_before).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
              <Descriptions.Item label="过期时间">{dayjs(viewRecord.not_after).format('YYYY-MM-DD HH:mm')}</Descriptions.Item>
              {viewRecord.san_dns && <Descriptions.Item label="DNS SAN" span={2}>{viewRecord.san_dns}</Descriptions.Item>}
              {viewRecord.san_ip && <Descriptions.Item label="IP SAN" span={2}>{viewRecord.san_ip}</Descriptions.Item>}
              {viewRecord.san_email && <Descriptions.Item label="邮箱 SAN" span={2}>{viewRecord.san_email}</Descriptions.Item>}
              {viewRecord.key_usage && <Descriptions.Item label="密钥用途" span={2}>{viewRecord.key_usage}</Descriptions.Item>}
              {viewRecord.ext_key_usage && <Descriptions.Item label="扩展密钥用途" span={2}>{viewRecord.ext_key_usage}</Descriptions.Item>}
            </Descriptions>
            <Divider style={{ margin: '8px 0' }} />
            <Text type="secondary" style={{ fontSize: 12 }}>证书内容（PEM）</Text>
            <TextArea value={viewRecord.cert_pem} rows={12} readOnly
              style={{ fontSize: 11, marginTop: 8 }} />
          </>
        )}
      </Drawer>
    </div>
  );
};

export default CertsPage;
