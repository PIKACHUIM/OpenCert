import React, { useEffect, useState } from 'react';
import { Table, Card, Tag, Space, Typography, Alert, Select, Button, Tabs, Input, message, Popconfirm } from 'antd';
import { ReloadOutlined, WarningOutlined, SearchOutlined, DeleteOutlined } from '@ant-design/icons';
import { useSearchParams } from 'react-router-dom';
import { apiRequest, listCTEntries, deleteCTEntry } from '../../api';
import type { CTEntry } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;
const { Option } = Select;

interface AuditLog {
  id: number;
  user_uuid: string;
  action: string;
  resource_type: string;
  resource_uuid: string;
  detail: string;
  ip_address: string;
  prev_hash: string;
  created_at: string;
  integrity_broken?: boolean;
}

/**
 * 证书审计日志（含证书透明度 CT）。
 *
 * 审计日志记录平台内的管理/业务操作并做链式哈希防篡改；
 * CT 记录是证书提交到证书透明度日志后返回的 SCT 存证，两者都属于「可审计证据」，
 * 因此合并在同一页面用选项卡区分。
 */
const AuditLogs: React.FC = () => {
  const [params, setParams] = useSearchParams();
  const activeTab = params.get('tab') === 'ct' ? 'ct' : 'audit';

  // ---- 审计日志 ----
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [integrityBroken, setIntegrityBroken] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({ action: '', resource_type: '' });

  // ---- CT 记录 ----
  const [ctData, setCTData] = useState<CTEntry[]>([]);
  const [ctLoading, setCTLoading] = useState(false);
  const [ctTotal, setCTTotal] = useState(0);
  const [ctPage, setCTPage] = useState(1);
  const [certHash, setCertHash] = useState('');
  const [certUUID, setCertUUID] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const query = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
        ...(filters.action && { action: filters.action }),
        ...(filters.resource_type && { resource_type: filters.resource_type }),
      });
      const data = await apiRequest(`/api/audit-logs?${query}`);
      setLogs(Array.isArray(data?.items) ? data.items : []);
      setTotal(data?.total ?? 0);
      setIntegrityBroken(data.integrity_broken || false);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const loadCT = async (p = 1) => {
    setCTLoading(true);
    try {
      const res = await listCTEntries({ cert_hash: certHash || undefined, cert_uuid: certUUID || undefined, page: p, page_size: 20 });
      setCTData(Array.isArray(res?.items) ? res.items : []);
      setCTTotal(res?.total ?? 0);
    } catch (e: any) { message.error(e.message || '加载 CT 记录失败'); }
    finally { setCTLoading(false); }
  };

  useEffect(() => { fetchLogs(); }, [page, filters]);
  useEffect(() => { if (activeTab === 'ct') loadCT(ctPage); }, [activeTab, ctPage]);

  const logColumns = [
    { title: 'ID', dataIndex: 'id', width: 70 },
    { title: '操作', dataIndex: 'action', render: (v: string) => <Tag color="blue">{v}</Tag> },
    { title: '资源类型', dataIndex: 'resource_type', render: (v: string) => v ? <Tag>{v}</Tag> : '-' },
    { title: '资源 UUID', dataIndex: 'resource_uuid', ellipsis: true, width: 200 },
    { title: 'IP 地址', dataIndex: 'ip_address', width: 140 },
    {
      title: '完整性', dataIndex: 'integrity_broken', width: 90,
      render: (v: boolean) => v ? <Tag color="red" icon={<WarningOutlined />}>断裂</Tag> : <Tag color="green">正常</Tag>,
    },
    { title: '时间', dataIndex: 'created_at', width: 180, render: (v: string) => new Date(v).toLocaleString('zh-CN') },
  ];

  const ctColumns = [
    { title: '证书哈希', dataIndex: 'cert_hash', key: 'cert_hash',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 16)}...${v.slice(-8)}` : '-'}</Text> },
    { title: '证书 UUID', dataIndex: 'cert_uuid', key: 'cert_uuid',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 16)}...` : '-'}</Text> },
    { title: 'CT 服务器', dataIndex: 'ct_server', key: 'ct_server',
      render: (v: string) => <Tag color="blue" style={{ fontSize: 11 }}>{v || '-'}</Tag> },
    { title: 'SCT 数据', dataIndex: 'sct_data', key: 'sct_data',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 20)}...` : '-'}</Text> },
    { title: '提交时间', dataIndex: 'submitted_at', key: 'submitted_at', render: (v: string) => v?.slice(0, 19) || '-' },
    {
      title: '操作', key: 'action', width: 80,
      render: (_: any, r: CTEntry) => (
        <Popconfirm title="确认删除此 CT 记录？" onConfirm={() => deleteCTEntry(r.uuid)
          .then(() => { message.success('已删除'); loadCT(ctPage); })
          .catch((e: any) => message.error(e.message))} okButtonProps={{ danger: true }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <Title level={4} style={{ marginBottom: 16 }}>
        证书审计日志 <HelpLink doc="admin-09-users-audit" />
      </Title>

      {integrityBroken && (
        <Alert
          type="error" icon={<WarningOutlined />} showIcon style={{ marginBottom: 16 }}
          message="链式哈希完整性校验失败！部分日志可能已被篡改，请立即检查。"
        />
      )}

      <Card>
        <Tabs
          activeKey={activeTab}
          onChange={(k) => setParams(k === 'ct' ? { tab: 'ct' } : {})}
          items={[
            {
              key: 'audit', label: '操作审计日志',
              children: (
                <>
                  <Space style={{ marginBottom: 16 }} wrap>
                    <Select placeholder="操作类型" allowClear style={{ width: 180 }}
                      onChange={(v) => setFilters(f => ({ ...f, action: v || '' }))}>
                      <Option value="issue_cert">签发证书</Option>
                      <Option value="revoke_cert">吊销证书</Option>
                      <Option value="user_revoke_cert">用户自助吊销</Option>
                      <Option value="create_ca">创建 CA</Option>
                      <Option value="login">登录</Option>
                      <Option value="create_cert_apply_template">创建开通模板</Option>
                      <Option value="approve_subject_info">审核主体信息</Option>
                      <Option value="reject_extension_info">驳回扩展信息</Option>
                      <Option value="confirm_offline_payment">确认线下到账</Option>
                      <Option value="grant_subscription">发放订阅</Option>
                    </Select>
                    <Select placeholder="资源类型" allowClear style={{ width: 160 }}
                      onChange={(v) => setFilters(f => ({ ...f, resource_type: v || '' }))}>
                      <Option value="certificate">证书</Option>
                      <Option value="ca">CA</Option>
                      <Option value="user">用户</Option>
                      <Option value="cert_apply_template">开通模板</Option>
                      <Option value="identity">身份认证</Option>
                      <Option value="cert_order">订单</Option>
                      <Option value="subscription">订阅</Option>
                      <Option value="ocsp_responder">OCSP 服务</Option>
                      <Option value="cert_policy">证书策略</Option>
                    </Select>
                    <Button icon={<ReloadOutlined />} onClick={fetchLogs}>刷新</Button>
                  </Space>
                  <Table
                    columns={logColumns} dataSource={logs} rowKey="id" loading={loading}
                    pagination={{ current: page, pageSize, total, onChange: setPage, showTotal: (t) => `共 ${t} 条` }}
                    rowClassName={(r) => r.integrity_broken ? 'ant-table-row-danger' : ''}
                    expandable={{
                      expandedRowRender: (r) => (
                        <div>
                          <Text type="secondary">详情：</Text>
                          <pre style={{ fontSize: 12, margin: 0 }}>{r.detail}</pre>
                          <Text type="secondary">Prev Hash：</Text>
                          <Text code style={{ fontSize: 11 }}>{r.prev_hash || '(首条)'}</Text>
                        </div>
                      ),
                    }}
                  />
                </>
              ),
            },
            {
              key: 'ct', label: '证书透明度（CT）',
              children: (
                <>
                  <Alert type="info" showIcon style={{ marginBottom: 12 }}
                    message="CT 记录是证书提交到证书透明度日志后返回的 SCT 存证"
                    description="在证书拓展模板中配置 CT 服务器后，签发证书会自动提交并记录 SCT；此处可查询与清理记录。" />
                  <Space style={{ marginBottom: 16 }} wrap>
                    <Input placeholder="按证书哈希筛选" value={certHash} onChange={e => setCertHash(e.target.value)} style={{ width: 240 }} allowClear />
                    <Input placeholder="按证书 UUID 筛选" value={certUUID} onChange={e => setCertUUID(e.target.value)} style={{ width: 280 }} allowClear />
                    <Button type="primary" icon={<SearchOutlined />} onClick={() => { setCTPage(1); loadCT(1); }}>搜索</Button>
                    <Button onClick={() => { setCertHash(''); setCertUUID(''); setCTPage(1); setTimeout(() => loadCT(1), 0); }}>重置</Button>
                  </Space>
                  <Table rowKey="uuid" columns={ctColumns} dataSource={ctData} loading={ctLoading}
                    pagination={{ current: ctPage, total: ctTotal, pageSize: 20, showTotal: (t) => `共 ${t} 条`, onChange: setCTPage }} />
                </>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
};

export default AuditLogs;
