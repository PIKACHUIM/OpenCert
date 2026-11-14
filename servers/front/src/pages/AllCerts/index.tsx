import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Input, Select, Tooltip,
  message, Popconfirm, Drawer, Descriptions, Alert, Form, Modal,
} from 'antd';
import {
  SafetyCertificateOutlined, ReloadOutlined, SearchOutlined,
  StopOutlined, ReconciliationOutlined, DownloadOutlined,
} from '@ant-design/icons';
import {
  listAllCerts, revokeCert, renewCert, getCertificateRenewalContext, exportCert, listCAs, listIssuanceTemplates,
} from '../../api';
import type { CertificateRenewalContext } from '../../api';
import type { Certificate, CA, IssuanceTemplate } from '../../types';

const { Title, Text } = Typography;
const isCSRDeliveryMode = (mode?: string) => mode === 'csr' || mode === 'physical_card' || mode === 'virtual_card';

/**
 * AllCerts 页面：全局证书管理（管理员）。
 * - 按 CA/模板/用户/类型过滤
 * - 分页
 * - 吊销、续期、导出
 */
const AllCertsPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<Certificate[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // 筛选条件
  const [caUUID, setCAUUID] = useState<string | undefined>();
  const [tmplUUID, setTmplUUID] = useState<string | undefined>();
  const [certType, setCertType] = useState<string | undefined>();
  const [userUUID, setUserUUID] = useState<string>('');

  // 下拉数据
  const [cas, setCAs] = useState<CA[]>([]);
  const [tmpls, setTmpls] = useState<IssuanceTemplate[]>([]);

  // 详情抽屉
  const [detail, setDetail] = useState<Certificate | null>(null);
  const [renewOpen, setRenewOpen] = useState(false);
  const [renewLoading, setRenewLoading] = useState(false);
  const [renewTarget, setRenewTarget] = useState('');
  const [renewContext, setRenewContext] = useState<CertificateRenewalContext | null>(null);
  const [renewOrderNo, setRenewOrderNo] = useState<string>();
  const [renewCardUUID, setRenewCardUUID] = useState<string>();
  const [renewCSR, setRenewCSR] = useState('');

  const fetchData = async (p = page, ps = pageSize) => {
    setLoading(true);
    try {
      const res = await listAllCerts({
        ca_uuid: caUUID, template_uuid: tmplUUID, cert_type: certType,
        user_uuid: userUUID || undefined, page: p, page_size: ps,
      });
      setData(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  const fetchOptions = async () => {
    try {
      const [caRes, tmplRes] = await Promise.all([
        listCAs({ page: 1, page_size: 100 }),
        listIssuanceTemplates({ page: 1, page_size: 100 }),
      ]);
      setCAs(Array.isArray(caRes?.items) ? caRes.items : []);
      setTmpls(Array.isArray(tmplRes?.items) ? tmplRes.items : []);
    } catch { /* ignore */ }
  };

  useEffect(() => { fetchOptions(); }, []);
  useEffect(() => { fetchData(page, pageSize); /* eslint-disable-next-line */ }, [page, pageSize]);

  const handleSearch = () => { setPage(1); fetchData(1, pageSize); };

  const handleRevoke = async (uuid: string) => {
    try {
      await revokeCert(uuid);
      message.success('证书已吊销');
      fetchData();
    } catch (e: any) { message.error(e.message || '吊销失败'); }
  };

  const openRenew = async (uuid: string) => {
    setRenewTarget(uuid);
    setRenewContext(null);
    setRenewOrderNo(undefined);
    setRenewCardUUID(undefined);
    setRenewCSR('');
    setRenewOpen(true);
    setRenewLoading(true);
    try {
      const context = await getCertificateRenewalContext(uuid);
      setRenewContext(context);
      setRenewOrderNo(context.orders[0]?.order_no);
      setRenewCardUUID(context.cards.some((card) => card.uuid === context.original_card_uuid)
        ? context.original_card_uuid : context.cards[0]?.uuid);
    } catch (e: any) {
      message.error(e.message || '加载续期信息失败');
    } finally {
      setRenewLoading(false);
    }
  };

  const selectedRenewOrder = renewContext?.orders.find((order) => order.order_no === renewOrderNo);
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
      fetchData();
    } catch (e: any) { message.error(e.message || '续期申请失败'); }
  };

  const handleExport = async (uuid: string, format: 'pem' | 'der' | 'chain' | 'p7b') => {
    try {
      const blob = await exportCert(uuid, format);
      const url = URL.createObjectURL(blob as Blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cert-${uuid.substring(0, 8)}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) { message.error(e.message || '导出失败'); }
  };

  const columns = useMemo(() => [
    {
      title: 'UUID', dataIndex: 'uuid', key: 'uuid', width: 140, ellipsis: true,
      render: (v: string) => <Text copyable={{ text: v }}>{v.substring(0, 8)}...</Text>,
    },
    { title: '类型', dataIndex: 'cert_type', key: 'cert_type',
      render: (v: string) => <Tag color="blue">{v || '-'}</Tag> },
    { title: '密钥类型', dataIndex: 'key_type', key: 'key_type' },
    {
      title: '状态', dataIndex: 'status', key: 'status',
      render: (v: string) => {
        const colors: Record<string, string> = { valid: 'success', revoked: 'error', expired: 'warning' };
        return <Tag color={colors[v] || 'default'}>{v || '-'}</Tag>;
      },
    },
    {
      title: '有效期', key: 'validity',
      render: (_: any, r: Certificate) =>
        r.not_before && r.not_after
          ? <Tooltip title={`${r.not_before} ~ ${r.not_after}`}>
              <Text type="secondary">
                {new Date(r.not_before).toLocaleDateString()} ~ {new Date(r.not_after).toLocaleDateString()}
              </Text>
            </Tooltip>
          : '-',
    },
    { title: '备注', dataIndex: 'remark', key: 'remark', ellipsis: true },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 280, fixed: 'right' as const,
      render: (_: any, r: Certificate) => (
        <Space wrap>
          <Button type="link" size="small" onClick={() => setDetail(r)}>详情</Button>
          <Button type="link" size="small" icon={<DownloadOutlined />}
            onClick={() => handleExport(r.uuid, 'pem')}>PEM</Button>
          <Button type="link" size="small" onClick={() => handleExport(r.uuid, 'chain')}>证书链</Button>
          <Button type="link" size="small" icon={<ReconciliationOutlined />}
            onClick={() => openRenew(r.uuid)}>续期</Button>
          <Popconfirm title="确认吊销此证书？（不可恢复）" onConfirm={() => handleRevoke(r.uuid)}>
            <Button type="link" size="small" danger icon={<StopOutlined />}>吊销</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ], []);

  return (
    <div>
      <Card
        title={<Space><SafetyCertificateOutlined />
          <Title level={4} style={{ margin: 0 }}>全局证书管理</Title></Space>}
        extra={<Button icon={<ReloadOutlined />} onClick={() => fetchData()}>刷新</Button>}
      >
        <Space wrap style={{ marginBottom: 16 }}>
          <Select style={{ width: 220 }} allowClear placeholder="按 CA 过滤"
            value={caUUID} onChange={setCAUUID}
            options={cas.map((c) => ({ label: c.name, value: c.uuid }))} />
          <Select style={{ width: 220 }} allowClear placeholder="按颁发模板过滤"
            value={tmplUUID} onChange={setTmplUUID}
            options={tmpls.map((t) => ({ label: t.name, value: t.uuid }))} />
          <Select style={{ width: 160 }} allowClear placeholder="按证书类型"
            value={certType} onChange={setCertType}
            options={[
              { label: 'ssl', value: 'ssl' },
              { label: 'code_sign', value: 'code_sign' },
              { label: 'email', value: 'email' },
              { label: 'ca', value: 'ca' },
            ]} />
          <Input placeholder="按用户 UUID" style={{ width: 260 }} allowClear
            value={userUUID} onChange={(e) => setUserUUID(e.target.value)} />
          <Button type="primary" icon={<SearchOutlined />} onClick={handleSearch}>查询</Button>
        </Space>

        <Table
          rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          scroll={{ x: 1200 }}
          pagination={{
            current: page, pageSize, total, showSizeChanger: true,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <Drawer width={640} open={!!detail} onClose={() => setDetail(null)} title="证书详情">
        {detail && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="UUID">{detail.uuid}</Descriptions.Item>
            <Descriptions.Item label="证书类型">{detail.cert_type}</Descriptions.Item>
            <Descriptions.Item label="密钥类型">{detail.key_type}</Descriptions.Item>
            <Descriptions.Item label="状态"><Tag>{detail.status}</Tag></Descriptions.Item>
            <Descriptions.Item label="CA UUID">{detail.ca_uuid || '-'}</Descriptions.Item>
            <Descriptions.Item label="模板 UUID">{detail.template_uuid || '-'}</Descriptions.Item>
            <Descriptions.Item label="用户 UUID">{detail.user_uuid || '-'}</Descriptions.Item>
            <Descriptions.Item label="卡片 UUID">{detail.card_uuid || '-'}</Descriptions.Item>
            <Descriptions.Item label="生效时间">{detail.not_before || '-'}</Descriptions.Item>
            <Descriptions.Item label="到期时间">{detail.not_after || '-'}</Descriptions.Item>
            <Descriptions.Item label="备注">{detail.remark || '-'}</Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {new Date(detail.created_at).toLocaleString('zh-CN')}
            </Descriptions.Item>
            <Descriptions.Item label="PEM">
              <Input.TextArea rows={10} value={detail.cert_content || ''} readOnly />
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>

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
          message="续期将使用证书所有者的新已支付订单，按当前模板及有效验证资料重新签发；原证书保持不变。"
        />
        {!renewLoading && renewContext?.orders.length === 0 && (
          <Alert type="warning" showIcon message="没有可用于续期的已支付订单。" />
        )}
        {renewContext && renewContext.orders.length > 0 && (
          <>
            <Form.Item label="续期订单" required>
              <Select
                value={renewOrderNo}
                onChange={setRenewOrderNo}
                placeholder="选择已支付的同类型证书订单"
                options={renewContext.orders.map((order) => ({
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
                  options={renewContext.cards.map((card) => ({ value: card.uuid, label: card.card_name }))}
                />
              </Form.Item>
            )}
            {isCSRDeliveryMode(selectedRenewOrder?.delivery_mode) && (
              <Form.Item label="新密钥的 CSR" required extra="请使用目标设备生成新的 CSR；私钥不会上传。">
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

export default AllCertsPage;
