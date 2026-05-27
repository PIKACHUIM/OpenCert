import React, { useState, useEffect } from 'react';
import { Table, Button, Input, Space, Tag, Typography, message, Popconfirm } from 'antd';
import { SearchOutlined, DeleteOutlined, AuditOutlined } from '@ant-design/icons';
import { listCTEntries, deleteCTEntry } from '../../api';
import type { CTEntry } from '../../types';

const { Title, Text } = Typography;

const CTRecords: React.FC = () => {
  const [data, setData] = useState<CTEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [certHash, setCertHash] = useState('');
  const [certUUID, setCertUUID] = useState('');

  const load = async (p = 1) => {
    setLoading(true);
    try {
      const res = await listCTEntries({ cert_hash: certHash || undefined, cert_uuid: certUUID || undefined, page: p, page_size: 20 });
      setData(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const columns = [
    {
      title: '证书哈希', dataIndex: 'cert_hash', key: 'cert_hash',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 16)}...${v.slice(-8)}` : '-'}</Text>,
    },
    {
      title: '证书 UUID', dataIndex: 'cert_uuid', key: 'cert_uuid',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 16)}...` : '-'}</Text>,
    },
    {
      title: 'CT 服务器', dataIndex: 'ct_server', key: 'ct_server',
      render: (v: string) => <Tag color="blue" style={{ fontSize: 11 }}>{v || '-'}</Tag>,
    },
    {
      title: 'SCT 数据', dataIndex: 'sct_data', key: 'sct_data',
      render: (v: string) => <Text code style={{ fontSize: 11 }}>{v ? `${v.slice(0, 20)}...` : '-'}</Text>,
    },
    { title: '提交时间', dataIndex: 'submitted_at', key: 'submitted_at', render: (v: string) => v?.slice(0, 19) || '-' },
    {
      title: '操作', key: 'action', width: 80,
      render: (_: any, r: CTEntry) => (
        <Popconfirm title="确认删除此 CT 记录？" onConfirm={() => deleteCTEntry(r.uuid).then(() => { message.success('已删除'); load(page); }).catch((e: any) => message.error(e.message))} okButtonProps={{ danger: true }}>
          <Button size="small" danger icon={<DeleteOutlined />} />
        </Popconfirm>
      ),
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Space>
          <AuditOutlined style={{ fontSize: 18, color: '#1677ff' }} />
          <Title level={4} style={{ margin: 0 }}>CT 记录管理</Title>
        </Space>
      </div>
      <Space style={{ marginBottom: 16 }} wrap>
        <Input placeholder="按证书哈希筛选" value={certHash} onChange={e => setCertHash(e.target.value)} style={{ width: 240 }} allowClear />
        <Input placeholder="按证书 UUID 筛选" value={certUUID} onChange={e => setCertUUID(e.target.value)} style={{ width: 280 }} allowClear />
        <Button type="primary" icon={<SearchOutlined />} onClick={() => { setPage(1); load(1); }}>搜索</Button>
        <Button onClick={() => { setCertHash(''); setCertUUID(''); setTimeout(() => load(1), 0); }}>重置</Button>
      </Space>
      <Table rowKey="uuid" columns={columns} dataSource={data} loading={loading}
        pagination={{ current: page, total, pageSize: 20, showTotal: (t) => `共 ${t} 条`, onChange: (p) => { setPage(p); load(p); } }} />
    </div>
  );
};

export default CTRecords;
