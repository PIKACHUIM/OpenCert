import React, { useEffect, useState } from 'react';
import { Table, Card, Tag, Space, Typography, Alert, Input, Select, Button } from 'antd';
import { SearchOutlined, ReloadOutlined, WarningOutlined } from '@ant-design/icons';
import { apiRequest } from '../../api';

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

const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [integrityBroken, setIntegrityBroken] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [filters, setFilters] = useState({ action: '', resource_type: '' });

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: String(page),
        page_size: String(pageSize),
        ...(filters.action && { action: filters.action }),
        ...(filters.resource_type && { resource_type: filters.resource_type }),
      });
      const data = await apiRequest(`/api/audit-logs?${params}`);
      setLogs(Array.isArray(data?.items) ? data.items : []);
      setTotal(data?.total ?? 0);
      setIntegrityBroken(data.integrity_broken || false);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, [page, filters]);

  const columns = [
    { title: 'ID', dataIndex: 'id', width: 70 },
    {
      title: '操作',
      dataIndex: 'action',
      render: (v: string) => <Tag color="blue">{v}</Tag>,
    },
    {
      title: '资源类型',
      dataIndex: 'resource_type',
      render: (v: string) => v ? <Tag>{v}</Tag> : '-',
    },
    { title: '资源 UUID', dataIndex: 'resource_uuid', ellipsis: true, width: 200 },
    { title: 'IP 地址', dataIndex: 'ip_address', width: 140 },
    {
      title: '完整性',
      dataIndex: 'integrity_broken',
      width: 90,
      render: (v: boolean) => v
        ? <Tag color="red" icon={<WarningOutlined />}>断裂</Tag>
        : <Tag color="green">正常</Tag>,
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      width: 180,
      render: (v: string) => new Date(v).toLocaleString('zh-CN'),
    },
  ];

  return (
    <div>
      <Title level={4} style={{ marginBottom: 16 }}>审计日志</Title>

      {integrityBroken && (
        <Alert
          type="error"
          icon={<WarningOutlined />}
          message="链式哈希完整性校验失败！部分日志可能已被篡改，请立即检查。"
          style={{ marginBottom: 16 }}
          showIcon
        />
      )}

      <Card>
        <Space style={{ marginBottom: 16 }}>
          <Select
            placeholder="操作类型"
            allowClear
            style={{ width: 160 }}
            onChange={(v) => setFilters(f => ({ ...f, action: v || '' }))}
          >
            <Option value="issue_cert">签发证书</Option>
            <Option value="revoke_cert">吊销证书</Option>
            <Option value="create_ca">创建 CA</Option>
            <Option value="login">登录</Option>
            <Option value="create_cert_apply_template">创建申请模板</Option>
          </Select>
          <Select
            placeholder="资源类型"
            allowClear
            style={{ width: 140 }}
            onChange={(v) => setFilters(f => ({ ...f, resource_type: v || '' }))}
          >
            <Option value="certificate">证书</Option>
            <Option value="ca">CA</Option>
            <Option value="user">用户</Option>
            <Option value="cert_apply_template">申请模板</Option>
          </Select>
          <Button icon={<ReloadOutlined />} onClick={fetchLogs}>刷新</Button>
        </Space>

        <Table
          columns={columns}
          dataSource={logs}
          rowKey="id"
          loading={loading}
          pagination={{
            current: page,
            pageSize,
            total,
            onChange: setPage,
            showTotal: (t) => `共 ${t} 条`,
          }}
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
      </Card>
    </div>
  );
};

export default AuditLogs;
