import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, message,
  Descriptions, Drawer, Select, InputNumber, Row, Col, Card,
} from 'antd';
import {
  EyeOutlined, DeleteOutlined, StopOutlined, SwapOutlined,
  ReloadOutlined, SafetyCertificateOutlined, CopyOutlined, ExportOutlined,
} from '@ant-design/icons';
import { listAllCerts, revokeCert, assignCert, renewCert, exportCert, listCAs } from '../../api';
import type { Certificate, CA } from '../../types';
import { useThemeStore } from '../../store/theme';
import dayjs from 'dayjs';

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

const certTypeLabels: Record<string, string> = {
  x509: 'X.509 证书', ssh: 'SSH 密钥', gpg: 'GPG 证书', totp: 'TOTP 认证',
};
const certTypeColors: Record<string, string> = {
  x509: 'blue', ssh: 'green', gpg: 'purple', totp: 'orange',
};
const statusColor: Record<string, string> = { valid: 'green', revoked: 'red', expired: 'orange' };
const statusText: Record<string, string> = { valid: '有效', revoked: '已吊销', expired: '已过期' };

const Certs: React.FC = () => {
  const { darkMode } = useThemeStore();
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filterCertType, setFilterCertType] = useState<string | undefined>();
  const [filterCAUUID, setFilterCAUUID] = useState<string | undefined>();
  const [cas, setCAs] = useState<CA[]>([]);
  const [detailVisible, setDetailVisible] = useState(false);
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignTarget, setAssignTarget] = useState('');
  const [assignCard, setAssignCard] = useState('');
  const [renewOpen, setRenewOpen] = useState(false);
  const [renewTarget, setRenewTarget] = useState('');
  const [renewDays, setRenewDays] = useState(365);

  const load = async (p = 1) => {
    setLoading(true);
    try {
      const res = await listAllCerts({ ca_uuid: filterCAUUID, cert_type: filterCertType, page: p, page_size: 20 });
      setCerts(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    listCAs({ page: 1, page_size: 100 }).then(r => setCAs(Array.isArray(r?.items) ? r.items : [])).catch(() => {});
  }, [filterCertType, filterCAUUID]);

  const handleRevoke = (cert: Certificate) => {
    Modal.confirm({
      title: '确认吊销证书',
      content: `确定要吊销证书 ${cert.uuid.slice(0, 8)}... 吗？吊销后无法恢复。`,
      okType: 'danger', okText: '确认吊销',
      onOk: async () => {
        try { await revokeCert(cert.uuid); message.success('证书已吊销'); load(); }
        catch (e: any) { message.error(e.message); }
      },
    });
  };

  const handleAssign = async () => {
    if (!assignTarget || !assignCard) return;
    try { await assignCert(assignTarget, assignCard); message.success('证书已分配'); setAssignOpen(false); load(); }
    catch (e: any) { message.error(e.message); }
  };

  const handleRenew = async () => {
    if (!renewTarget) return;
    try { await renewCert(renewTarget, renewDays); message.success('证书续期成功'); setRenewOpen(false); load(); }
    catch (e: any) { message.error(e.message); }
  };

  const handleExport = async (cert: Certificate, format: string) => {
    try {
      const blob = await exportCert(cert.uuid, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${cert.uuid.slice(0, 8)}.${format}`; a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) { message.error(e.message); }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  const columns = [
    {
      title: '类型', dataIndex: 'cert_type', width: 120,
      render: (v: string) => <Tag color={certTypeColors[v] || 'default'}>{certTypeLabels[v] || v}</Tag>,
    },
    {
      title: '密钥类型', dataIndex: 'key_type', width: 110,
      render: (v: string) => <Tag>{v?.toUpperCase() || '-'}</Tag>,
    },
    {
      title: '状态', dataIndex: 'status', width: 90,
      render: (v: string) => <Tag color={statusColor[v] || 'green'}>{statusText[v] || '有效'}</Tag>,
    },
    {
      title: '有效期', key: 'validity', width: 200,
      render: (_: any, r: Certificate) => r.not_before ? (
        <Text style={{ fontSize: 12 }}>{r.not_before?.slice(0, 10)} ~ {r.not_after?.slice(0, 10)}</Text>
      ) : '-',
    },
    { title: '备注', dataIndex: 'remark', ellipsis: true, render: (v: string) => v || '-' },
    {
      title: '创建时间', dataIndex: 'created_at', width: 160,
      render: (v: string) => dayjs(v).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: '操作', width: 200,
      render: (_: any, record: Certificate) => (
        <Space size={4} wrap>
          <Button type="text" size="small" icon={<EyeOutlined />} onClick={() => { setSelectedCert(record); setDetailVisible(true); }} />
          <Button type="text" size="small" danger icon={<StopOutlined />} onClick={() => handleRevoke(record)} />
          <Button type="text" size="small" icon={<SwapOutlined />} onClick={() => { setAssignTarget(record.uuid); setAssignOpen(true); }} />
          <Button type="text" size="small" icon={<ReloadOutlined />} onClick={() => { setRenewTarget(record.uuid); setRenewOpen(true); }} />
          <Button type="text" size="small" danger icon={<DeleteOutlined />} onClick={() => Modal.confirm({
            title: '确认删除', okType: 'danger',
            onOk: async () => { /* 调用删除接口 */ message.info('暂不支持直接删除，请先吊销'); },
          })} />
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 16px' }}>
        <Space><SafetyCertificateOutlined />证书管理</Space>
      </Title>

      {/* 筛选栏 */}
      <Row gutter={12} style={{ marginBottom: 16 }}>
        <Col xs={24} sm={8} md={6}>
          <Select allowClear placeholder="证书类型" style={{ width: '100%' }} value={filterCertType} onChange={setFilterCertType}>
            {Object.entries(certTypeLabels).map(([k, v]) => <Option key={k} value={k}>{v}</Option>)}
          </Select>
        </Col>
        <Col xs={24} sm={8} md={6}>
          <Select allowClear placeholder="所属 CA" style={{ width: '100%' }} value={filterCAUUID} onChange={setFilterCAUUID}>
            {cas.map(c => <Option key={c.uuid} value={c.uuid}>{c.name}</Option>)}
          </Select>
        </Col>
      </Row>

      <Card style={cardStyle} bodyStyle={{ padding: 0 }}>
        <Table rowKey="uuid" columns={columns} dataSource={certs} loading={loading}
          pagination={{ current: page, total, pageSize: 20, showTotal: (t) => `共 ${t} 条`, onChange: (p) => { setPage(p); load(p); } }} />
      </Card>

      {/* 证书详情 */}
      <Drawer title="证书详情" width={560} open={detailVisible} onClose={() => setDetailVisible(false)}
        extra={
          <Space>
            <Button icon={<ExportOutlined />} onClick={() => selectedCert && handleExport(selectedCert, 'pem')}>导出 PEM</Button>
            <Button icon={<CopyOutlined />} onClick={() => {
              if (selectedCert?.cert_content) {
                navigator.clipboard.writeText(atob(selectedCert.cert_content));
                message.success('已复制到剪贴板');
              }
            }}>复制</Button>
          </Space>
        }>
        {selectedCert && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="UUID">{selectedCert.uuid}</Descriptions.Item>
            <Descriptions.Item label="证书类型"><Tag color={certTypeColors[selectedCert.cert_type]}>{certTypeLabels[selectedCert.cert_type] || selectedCert.cert_type}</Tag></Descriptions.Item>
            <Descriptions.Item label="密钥类型">{selectedCert.key_type}</Descriptions.Item>
            <Descriptions.Item label="状态"><Tag color={statusColor[selectedCert.status || 'valid']}>{statusText[selectedCert.status || 'valid']}</Tag></Descriptions.Item>
            <Descriptions.Item label="有效期">{selectedCert.not_before?.slice(0, 10)} ~ {selectedCert.not_after?.slice(0, 10)}</Descriptions.Item>
            <Descriptions.Item label="备注">{selectedCert.remark || '-'}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{dayjs(selectedCert.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
            {selectedCert.cert_content && (
              <Descriptions.Item label="证书内容">
                <Paragraph copyable ellipsis={{ rows: 4, expandable: true }}
                  style={{ fontFamily: 'monospace', fontSize: 12, marginBottom: 0 }}>
                  {atob(selectedCert.cert_content)}
                </Paragraph>
              </Descriptions.Item>
            )}
          </Descriptions>
        )}
      </Drawer>

      {/* 分配到智能卡 */}
      <Modal title="分配证书到智能卡" open={assignOpen} onCancel={() => setAssignOpen(false)} onOk={handleAssign} okText="确认分配">
        <div style={{ marginTop: 16 }}>
          <Text>目标智能卡 UUID：</Text>
          <input style={{ width: '100%', marginTop: 8, padding: '4px 8px', border: '1px solid #d9d9d9', borderRadius: 6 }}
            placeholder="请输入智能卡 UUID" value={assignCard} onChange={e => setAssignCard(e.target.value)} />
        </div>
      </Modal>

      {/* 续期 */}
      <Modal title="证书续期" open={renewOpen} onCancel={() => setRenewOpen(false)} onOk={handleRenew} okText="确认续期">
        <div style={{ marginTop: 16 }}>
          <Text>新增有效天数：</Text>
          <InputNumber min={1} max={3650} value={renewDays} onChange={v => setRenewDays(v || 365)}
            style={{ width: '100%', marginTop: 8 }} addonAfter="天" />
        </div>
      </Modal>
    </div>
  );
};

export default Certs;
