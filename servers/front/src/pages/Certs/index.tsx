import React, { useEffect, useState } from 'react';
import {
  Table, Button, Space, Tag, Typography, Modal, message, Alert, Form,
  Descriptions, Drawer, Select, Row, Col, Card, Input,
} from 'antd';
import {
  EyeOutlined, DeleteOutlined, StopOutlined, SwapOutlined,
  ReloadOutlined, SafetyCertificateOutlined, CopyOutlined, ExportOutlined,
} from '@ant-design/icons';
import { listAllCerts, revokeCert, assignCert, renewCert, getCertificateRenewalContext, exportCert, listCAs } from '../../api';
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
const isCSRDeliveryMode = (mode?: string) => mode === 'csr' || mode === 'physical_card' || mode === 'virtual_card';

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
  const [renewOrders, setRenewOrders] = useState<Array<{ order_no: string; sku_name: string; delivery_mode: string; remaining: number }>>([]);
  const [renewCards, setRenewCards] = useState<Array<{ uuid: string; card_name: string }>>([]);
  const [renewOrderNo, setRenewOrderNo] = useState<string>();
  const [renewCardUUID, setRenewCardUUID] = useState<string>();
  const [renewCSR, setRenewCSR] = useState('');
  const [renewLoading, setRenewLoading] = useState(false);

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

  const openRenew = async (certUUID: string) => {
    setRenewTarget(certUUID);
    setRenewOrderNo(undefined);
    setRenewCardUUID(undefined);
    setRenewCSR('');
    setRenewOrders([]);
    setRenewCards([]);
    setRenewOpen(true);
    setRenewLoading(true);
    try {
      const context = await getCertificateRenewalContext(certUUID);
      setRenewOrders(context.orders);
      setRenewCards(context.cards);
      setRenewOrderNo(context.orders[0]?.order_no);
      setRenewCardUUID(context.original_card_uuid && context.cards.some((card) => card.uuid === context.original_card_uuid)
        ? context.original_card_uuid : context.cards[0]?.uuid);
    } catch (e: any) {
      message.error(e?.message || '加载续期资料失败');
    } finally {
      setRenewLoading(false);
    }
  };

  const selectedRenewOrder = renewOrders.find((order) => order.order_no === renewOrderNo);
  const handleRenew = async () => {
    if (!renewTarget || !renewOrderNo) return;
    if (selectedRenewOrder?.delivery_mode === 'cloud_card' && !renewCardUUID) {
      message.warning('请先开通并选择一张可用云端智能卡');
      return;
    }
    if (isCSRDeliveryMode(selectedRenewOrder?.delivery_mode) && !renewCSR.trim()) {
      message.warning('该续期订单需要提交由新密钥生成的 CSR');
      return;
    }
    try {
      const result = await renewCert(renewTarget, {
        order_no: renewOrderNo,
        card_uuid: selectedRenewOrder?.delivery_mode === 'cloud_card' ? renewCardUUID : undefined,
        csr_pem: isCSRDeliveryMode(selectedRenewOrder?.delivery_mode) ? renewCSR : undefined,
      }) as { auto_issued?: boolean };
      message.success(result.auto_issued ? '已按新订单重新签发证书，原证书保持不变' : '续期申请已提交，等待审批');
      setRenewOpen(false);
      load();
    } catch (e: any) { message.error(e.message || '续期申请失败'); }
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
          <Button type="text" size="small" icon={<ReloadOutlined />} onClick={() => openRenew(record.uuid)} />
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
                  style={{ fontSize: 12, marginBottom: 0 }}>
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

      {/* 续期：必须使用新购买的证书订单，并重新验证当前资料 */}
      <Modal
        title="证书续期"
        open={renewOpen}
        onCancel={() => setRenewOpen(false)}
        onOk={handleRenew}
        okText="提交续期申请"
        confirmLoading={renewLoading}
        okButtonProps={{ disabled: renewLoading || !renewOrderNo }}
        destroyOnClose
      >
        <Alert
          type="info" showIcon style={{ marginTop: 16, marginBottom: 16 }}
          message="续期将使用一笔新的已支付证书订单，按当前模板与仍有效的身份/域名验证重新签发；原证书不会被覆盖。"
        />
        {!renewLoading && renewOrders.length === 0 ? (
          <Alert type="warning" showIcon message="没有可用于续期的已支付订单，请先购买相同证书类型的套餐。" />
        ) : (
          <>
            <Form.Item label="续期订单" required>
              <Select
                value={renewOrderNo}
                onChange={setRenewOrderNo}
                loading={renewLoading}
                placeholder="选择相同证书类型的已支付订单"
                options={renewOrders.map((order) => ({
                  value: order.order_no,
                  label: `${order.sku_name || '证书套餐'} · 剩余 ${order.remaining} 份`,
                }))}
              />
            </Form.Item>
            {selectedRenewOrder?.delivery_mode === 'cloud_card' && (
              <Form.Item label="签发到云端智能卡" required>
                <Select
                  value={renewCardUUID}
                  onChange={setRenewCardUUID}
                  placeholder="选择服务有效的云端智能卡"
                  options={renewCards.map((card) => ({ value: card.uuid, label: card.card_name }))}
                />
              </Form.Item>
            )}
            {isCSRDeliveryMode(selectedRenewOrder?.delivery_mode) && (
              <Form.Item label="新密钥的 CSR" required extra="请使用客户端的目标实体卡/TPM 生成新的 CSR；私钥不会上传。">
                <Input.TextArea rows={5} value={renewCSR} onChange={(event) => setRenewCSR(event.target.value)}
                  placeholder="-----BEGIN CERTIFICATE REQUEST-----" />
              </Form.Item>
            )}
          </>
        )}
      </Modal>
    </div>
  );
};

export default Certs;
