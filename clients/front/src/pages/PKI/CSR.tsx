import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, Form, Input, Select,
  Popconfirm, message, Tooltip, Card, Drawer, Divider, Row, Col, Checkbox, Collapse,
} from 'antd';
import {
  PlusOutlined, DeleteOutlined, ReloadOutlined, DownloadOutlined,
  CopyOutlined, EyeOutlined, KeyOutlined,
} from '@ant-design/icons';
import { getCSRList, createCSR, deleteCSR, downloadCSRFile, getCards } from '../../api';
import type { CSRRecord, CreateCSRRequest, Card as CardType } from '../../types';
import { useAppStore } from '../../store/appStore';
import dayjs from 'dayjs';

const { Text } = Typography;
const { TextArea } = Input;

// 额外 DN 字段定义（对齐 dn.txt 25 个标准字段，排除已有的 C/ST/L/O/OU/CN/E 共 7 个）
const EXTRA_DN_FIELDS = [
  { name: 'serialNumber', label: '序列号 (serialNumber)', placeholder: '设备或实体序列号', oid: '2.5.4.5' },
  { name: 'givenName', label: '名 (givenName)', placeholder: '个人名字', oid: '2.5.4.42' },
  { name: 'surname', label: '姓 (surname)', placeholder: '个人姓氏', oid: '2.5.4.4' },
  { name: 'title', label: '职位 (title)', placeholder: '职位头衔', oid: '2.5.4.12' },
  { name: 'initials', label: '缩写 (initials)', placeholder: '姓名缩写', oid: '2.5.4.43' },
  { name: 'description', label: '描述 (description)', placeholder: '描述信息', oid: '2.5.4.13' },
  { name: 'role', label: '角色 (role)', placeholder: '组织角色', oid: '2.5.4.72' },
  { name: 'pseudonym', label: '笔名 (pseudonym)', placeholder: '笔名/别名', oid: '2.5.4.65' },
  { name: 'name', label: '全名 (name)', placeholder: '完整名称', oid: '2.5.4.41' },
  { name: 'dnQualifier', label: 'DN 限定符 (dnQualifier)', placeholder: 'DN 限定符', oid: '2.5.4.46' },
  { name: 'generationQualifier', label: '世代限定符 (generationQualifier)', placeholder: '如 Jr./Sr./III', oid: '2.5.4.44' },
  { name: 'x500UniqueIdentifier', label: 'X.500 唯一标识 (x500UniqueIdentifier)', placeholder: 'X.500 唯一标识', oid: '2.5.4.45' },
  { name: 'businessCategory', label: '业务类别 (businessCategory)', placeholder: '业务类别', oid: '2.5.4.15' },
  { name: 'streetAddress', label: '街道地址 (streetAddress)', placeholder: '街道地址', oid: '2.5.4.9' },
  { name: 'postalCode', label: '邮政编码 (postalCode)', placeholder: '邮政编码', oid: '2.5.4.17' },
  { name: 'IncLocalityName', label: 'Inc 注册城市', placeholder: '公司注册城市', oid: '1.3.6.1.4.1.311.60.2.1.1' },
  { name: 'IncStateOrProvinceName', label: 'Inc 注册省份', placeholder: '公司注册省份', oid: '1.3.6.1.4.1.311.60.2.1.2' },
  { name: 'IncCountryName', label: 'Inc 注册国家', placeholder: '公司注册国家（2 字母）', oid: '1.3.6.1.4.1.311.60.2.1.3' },
];

const KEY_TYPE_OPTIONS = [
  { label: 'RSA 2048', value: 'rsa2048' },
  { label: 'RSA 4096', value: 'rsa4096' },
  { label: 'RSA 8192', value: 'rsa8192' },
  { label: 'EC P-256（推荐）', value: 'ec256' },
  { label: 'EC P-384', value: 'ec384' },
  { label: 'EC P-521', value: 'ec521' },
  { label: 'Ed25519', value: 'ed25519' },
  { label: 'SM2', value: 'sm2' },
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

const CSRPage: React.FC = () => {
  const { darkMode } = useAppStore();
  const [list, setList] = useState<CSRRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [cards, setCards] = useState<CardType[]>([]);

  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form] = Form.useForm();
  const [keyStorage, setKeyStorage] = useState<'database' | 'smartcard'>('database');

  const [viewOpen, setViewOpen] = useState(false);
  const [viewRecord, setViewRecord] = useState<CSRRecord | null>(null);

  const load = async (p = page) => {
    setLoading(true);
    try {
      const res = await getCSRList({ page: p, page_size: 10 });
      setList(res.items);
      setTotal(res.total);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    getCards({ page: 1, page_size: 100 }).then((r) => setCards(r.items)).catch(() => {});
  }, []);

  const handleCreate = async () => {
    try {
      const values = await form.validateFields();
      setCreating(true);
      // 将 extra_subject 下的嵌套字段提取为 flat map
      const extraSubject: Record<string, string> = {};
      if (values.extra_subject) {
        for (const [k, v] of Object.entries(values.extra_subject)) {
          if (typeof v === 'string' && v.trim()) extraSubject[k] = v.trim();
        }
      }
      const payload = { ...values, extra_subject: Object.keys(extraSubject).length > 0 ? extraSubject : undefined };
      await createCSR(payload as CreateCSRRequest);
      message.success('CSR 已生成');
      setCreateOpen(false);
      form.resetFields();
      setKeyStorage('database');
      load();
    } catch (e: any) { if (e.message) message.error(e.message); }
    finally { setCreating(false); }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  // 格式化密钥用途显示
  const formatKeyUsage = (raw?: string) => {
    if (!raw) return null;
    try {
      const arr: string[] = JSON.parse(raw);
      const map: Record<string, string> = {
        digitalSignature: '数字签名', keyEncipherment: '内容加密', dataEncipherment: '数据加密',
        keyAgreement: '密钥协商', certSign: '证书签名', crlSign: 'CRL签名',
      };
      return arr.map((k) => map[k] || k);
    } catch { return [raw]; }
  };

  const formatExtKeyUsage = (raw?: string) => {
    if (!raw) return null;
    try {
      const arr: string[] = JSON.parse(raw);
      const map: Record<string, string> = {
        serverAuth: '服务器认证', clientAuth: '客户端认证', codeSigning: '代码签名',
        emailProtection: '邮件保护', timeStamping: '时间戳', ocspSigning: 'OCSP签名',
      };
      return arr.map((k) => map[k] || k);
    } catch { return [raw]; }
  };

  const columns = [
    {
      title: '证书信息',
      dataIndex: 'common_name',
      ellipsis: true,
      render: (v: string, r: CSRRecord) => (
        <div>
          <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{v}</Text>
          {r.organization && (
            <div><Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>{r.organization}{r.org_unit ? ` / ${r.org_unit}` : ''}</Text></div>
          )}
        </div>
      ),
    },
    {
      title: '密钥',
      width: 140,
      render: (_: any, r: CSRRecord) => (
        <Space direction="vertical" size={0}>
          <Tag color="blue">{r.key_type?.toUpperCase()}</Tag>
          <Space size={4} style={{ marginTop: 2 }}>
            <Tag color={r.key_storage === 'smartcard' ? 'purple' : 'green'} style={{ fontSize: 11 }}>
              {r.key_storage === 'smartcard' ? '智能卡' : '数据库'}
            </Tag>
            <Tag color={r.has_private_key ? 'green' : 'default'} style={{ fontSize: 11 }}>
              {r.has_private_key ? '有私钥' : '无私钥'}
            </Tag>
          </Space>
        </Space>
      ),
    },
    {
      title: 'SAN',
      width: 180,
      ellipsis: true,
      render: (_: any, r: CSRRecord) => {
        const items: string[] = [];
        if (r.san_dns) items.push(...r.san_dns.split(',').map((s) => s.trim()));
        if (r.san_ip) items.push(...r.san_ip.split(',').map((s) => s.trim()));
        if (r.san_email) items.push(...r.san_email.split(',').map((s) => s.trim()));
        if (r.san_uri) items.push(...r.san_uri.split(',').map((s) => s.trim()));
        if (items.length === 0) return <Text type="secondary" style={{ fontSize: 12 }}>-</Text>;
        return (
          <Tooltip title={items.join(', ')}>
            <div style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#666' }}>
              {items.slice(0, 2).map((s, i) => <div key={i}>{s}</div>)}
              {items.length > 2 && <Text type="secondary" style={{ fontSize: 11 }}>+{items.length - 2} 更多</Text>}
            </div>
          </Tooltip>
        );
      },
    },
    {
      title: '密钥用途',
      width: 160,
      ellipsis: true,
      render: (_: any, r: CSRRecord) => {
        const ku = formatKeyUsage(r.key_usage);
        const eku = formatExtKeyUsage(r.ext_key_usage);
        if (!ku && !eku) return <Text type="secondary" style={{ fontSize: 12 }}>-</Text>;
        return (
          <Tooltip title={<>{ku && <div>密钥用途: {ku.join(', ')}</div>}{eku && <div>扩展用途: {eku.join(', ')}</div>}</>}>
            <div style={{ fontSize: 12 }}>
              {ku && <div style={{ color: darkMode ? '#8b949e' : '#666' }}>{ku.slice(0, 2).join(', ')}{ku.length > 2 ? '...' : ''}</div>}
              {eku && <div style={{ color: darkMode ? '#7ee787' : '#389e0d' }}>{eku.slice(0, 2).join(', ')}{eku.length > 2 ? '...' : ''}</div>}
            </div>
          </Tooltip>
        );
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 130,
      render: (v: string) => (
        <Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>
          {dayjs(v).format('YYYY-MM-DD HH:mm')}
        </Text>
      ),
    },
    {
      title: '操作',
      width: 150,
      render: (_: any, record: CSRRecord) => (
        <Space>
          <Tooltip title="查看 CSR">
            <Button type="text" size="small" icon={<EyeOutlined />}
              onClick={() => { setViewRecord(record); setViewOpen(true); }} />
          </Tooltip>
          <Tooltip title="复制 PEM">
            <Button type="text" size="small" icon={<CopyOutlined />}
              onClick={() => { navigator.clipboard.writeText(record.csr_pem); message.success('已复制'); }} />
          </Tooltip>
          <Tooltip title="下载 CSR">
            <Button type="text" size="small" icon={<DownloadOutlined />}
              onClick={() => downloadCSRFile(record.uuid, `${record.common_name}.csr`).catch((e) => message.error(e.message))} />
          </Tooltip>
          <Popconfirm title="确认删除此 CSR？若有私钥将一并删除。"
            onConfirm={() => deleteCSR(record.uuid).then(() => { message.success('已删除'); load(); }).catch((e) => message.error(e.message))}
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
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Text strong style={{ fontSize: 16, color: darkMode ? '#c9d1d9' : undefined }}>
          <KeyOutlined style={{ marginRight: 8 }} />本地证书申请
        </Text>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={() => load()}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>生成 CSR</Button>
        </Space>
      </div>

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table dataSource={list} columns={columns} rowKey="uuid" loading={loading}
          pagination={{ current: page, total, pageSize: 10, onChange: (p) => { setPage(p); load(p); }, showTotal: (t) => `共 ${t} 条` }} />
      </Card>

      {/* 生成 CSR 弹窗 */}
      <Modal title={<Space><KeyOutlined />生成 CSR</Space>} open={createOpen}
        onOk={handleCreate} onCancel={() => { setCreateOpen(false); form.resetFields(); setKeyStorage('database'); }}
        okText="生成" cancelText="取消" confirmLoading={creating} width={700}>
        <Form form={form} layout="vertical" style={{ marginTop: 16 }}
          initialValues={{ key_type: 'ec256', key_storage: 'database' }}>
          <Divider plain style={{ fontSize: 13 }}>主体信息</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="common_name" label="通用名称 (CN)" rules={[{ required: true }]}>
                <Input placeholder="example.com" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="organization" label="组织 (O)">
                <Input placeholder="My Organization" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="org_unit" label="部门 (OU)">
                <Input placeholder="IT Department" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="country" label="国家 (C)">
                <Input placeholder="CN" maxLength={2} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="state" label="省份 (ST)">
                <Input placeholder="Beijing" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="locality" label="城市 (L)">
                <Input placeholder="Beijing" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="email" label="邮箱 (E)">
                <Input placeholder="admin@example.com" />
              </Form.Item>
            </Col>
          </Row>

          <Collapse ghost size="small" style={{ marginBottom: 8 }}
            items={[{
              key: 'extra',
              label: <Text type="secondary" style={{ fontSize: 13 }}>高级主体字段（共 {EXTRA_DN_FIELDS.length} 个标准 DN 字段，按需填写）</Text>,
              children: (
                <Row gutter={16}>
                  {EXTRA_DN_FIELDS.map((f) => (
                    <Col span={12} key={f.name}>
                      <Form.Item name={['extra_subject', f.name]} label={<Tooltip title={`OID: ${f.oid}`}>{f.label}</Tooltip>}>
                        <Input placeholder={f.placeholder} />
                      </Form.Item>
                    </Col>
                  ))}
                </Row>
              ),
            }]}
          />

          <Divider plain style={{ fontSize: 13 }}>密钥参数</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="key_type" label="密钥类型" rules={[{ required: true }]}>
                <Select options={KEY_TYPE_OPTIONS} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="key_storage" label="密钥存储位置" rules={[{ required: true }]}>
                <Select onChange={(v) => setKeyStorage(v)} options={[
                  { label: '存储到数据库（可导出私钥）', value: 'database' },
                  { label: '片上生成（智能卡，不可导出）', value: 'smartcard' },
                ]} />
              </Form.Item>
            </Col>
          </Row>
          {keyStorage === 'smartcard' && (
            <>
              <Form.Item name="card_uuid" label="目标智能卡" rules={[{ required: true, message: '请选择智能卡' }]}>
                <Select placeholder="选择智能卡（密钥将在卡上生成）"
                  options={cards.map((c) => ({ value: c.uuid, label: `${c.card_name} (${c.slot_type})` }))} />
              </Form.Item>
              <Form.Item name="card_password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码以解锁主密钥' }]}>
                <Input.Password placeholder="输入卡片密码（用于加密存储密钥）" />
              </Form.Item>
            </>
          )}

          <Divider plain style={{ fontSize: 13 }}>SAN 扩展</Divider>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="san_dns" label="DNS 名称（逗号分隔）">
                <Input placeholder="example.com, *.example.com" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="san_ip" label="IP 地址（逗号分隔）">
                <Input placeholder="192.168.1.1, 10.0.0.1" />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="san_email" label="邮箱 SAN">
                <Input placeholder="user@example.com" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="san_uri" label="URI SAN">
                <Input placeholder="https://example.com" />
              </Form.Item>
            </Col>
          </Row>

          <Divider plain style={{ fontSize: 13 }}>密钥用途</Divider>
          <Form.Item name="key_usage" label="密钥用途 (Key Usage)">
            <Checkbox.Group options={KEY_USAGE_OPTIONS} />
          </Form.Item>
          <Form.Item name="ext_key_usage" label="扩展密钥用途 (Extended Key Usage)">
            <Checkbox.Group options={EXT_KEY_USAGE_OPTIONS} />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 查看 CSR 抽屉 */}
      <Drawer title={<Space><EyeOutlined />查看 CSR — {viewRecord?.common_name}</Space>}
        open={viewOpen} onClose={() => setViewOpen(false)} width={600}
        extra={
          <Space>
            <Button size="small" icon={<CopyOutlined />} onClick={() => {
              if (viewRecord?.csr_pem) { navigator.clipboard.writeText(viewRecord.csr_pem); message.success('已复制'); }
            }}>复制</Button>
            <Button size="small" icon={<DownloadOutlined />}
              onClick={() => viewRecord && downloadCSRFile(viewRecord.uuid, `${viewRecord.common_name}.csr`).catch((e) => message.error(e.message))}>
              下载
            </Button>
          </Space>
        }>
        {viewRecord && (
          <>
            <Divider plain style={{ fontSize: 13, margin: '8px 0 12px' }}>主体信息</Divider>
            <Row gutter={[16, 8]} style={{ marginBottom: 16 }}>
              <Col span={12}><Text type="secondary">通用名称 (CN)：</Text><Text strong>{viewRecord.common_name}</Text></Col>
              <Col span={12}><Text type="secondary">组织 (O)：</Text><Text>{viewRecord.organization || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">部门 (OU)：</Text><Text>{viewRecord.org_unit || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">国家 (C)：</Text><Text>{viewRecord.country || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">省份 (ST)：</Text><Text>{viewRecord.state || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">城市 (L)：</Text><Text>{viewRecord.locality || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">邮箱 (E)：</Text><Text>{viewRecord.email || '-'}</Text></Col>
              <Col span={12}><Text type="secondary">备注：</Text><Text>{viewRecord.remark || '-'}</Text></Col>
            </Row>

            {(viewRecord.san_dns || viewRecord.san_ip || viewRecord.san_email || viewRecord.san_uri) && (
              <>
                <Divider plain style={{ fontSize: 13, margin: '8px 0 12px' }}>SAN 扩展</Divider>
                <Row gutter={[16, 8]} style={{ marginBottom: 16 }}>
                  {viewRecord.san_dns && <Col span={24}><Text type="secondary">DNS：</Text><Text>{viewRecord.san_dns}</Text></Col>}
                  {viewRecord.san_ip && <Col span={24}><Text type="secondary">IP：</Text><Text>{viewRecord.san_ip}</Text></Col>}
                  {viewRecord.san_email && <Col span={24}><Text type="secondary">邮箱：</Text><Text>{viewRecord.san_email}</Text></Col>}
                  {viewRecord.san_uri && <Col span={24}><Text type="secondary">URI：</Text><Text>{viewRecord.san_uri}</Text></Col>}
                </Row>
              </>
            )}

            <Divider plain style={{ fontSize: 13, margin: '8px 0 12px' }}>密钥信息</Divider>
            <Row gutter={[16, 8]} style={{ marginBottom: 16 }}>
              <Col span={12}><Text type="secondary">密钥类型：</Text><Tag color="blue">{viewRecord.key_type}</Tag></Col>
              <Col span={12}><Text type="secondary">存储位置：</Text>
                <Tag color={viewRecord.key_storage === 'smartcard' ? 'purple' : 'green'}>
                  {viewRecord.key_storage === 'smartcard' ? '智能卡' : '数据库'}
                </Tag>
              </Col>
              <Col span={12}><Text type="secondary">含私钥：</Text><Tag color={viewRecord.has_private_key ? 'green' : 'default'}>{viewRecord.has_private_key ? '是' : '否'}</Tag></Col>
              <Col span={12}><Text type="secondary">创建时间：</Text><Text>{dayjs(viewRecord.created_at).format('YYYY-MM-DD HH:mm')}</Text></Col>
              {formatKeyUsage(viewRecord.key_usage) && (
                <Col span={24}><Text type="secondary">密钥用途：</Text><Text>{formatKeyUsage(viewRecord.key_usage)!.join('、')}</Text></Col>
              )}
              {formatExtKeyUsage(viewRecord.ext_key_usage) && (
                <Col span={24}><Text type="secondary">扩展用途：</Text><Text>{formatExtKeyUsage(viewRecord.ext_key_usage)!.join('、')}</Text></Col>
              )}
            </Row>

            <Divider plain style={{ fontSize: 13, margin: '8px 0 12px' }}>CSR 内容（PEM）</Divider>
            <TextArea value={viewRecord.csr_pem} rows={14} readOnly
              style={{ fontSize: 11, marginTop: 8 }} />
          </>
        )}
      </Drawer>
    </div>
  );
};

export default CSRPage;
