import React, { useState, useEffect } from 'react';
import { Table, Select, Space, Tag, Typography, message } from 'antd';
import { getLogs } from '../../api';
import type { Log } from '../../types';
import dayjs from 'dayjs';

const { Title, Text } = Typography;
const { Option } = Select;

const Logs: React.FC = () => {
  const [logs, setLogs] = useState<Log[]>([]);
  const [loading, setLoading] = useState(false);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [filterLevel, setFilterLevel] = useState<string | undefined>();

  const load = async (p = 1) => {
    setLoading(true);
    try {
      const res = await getLogs({ level: filterLevel, page: p, page_size: 20 });
      setLogs(Array.isArray(res?.items) ? res.items : []);
      setTotal(res?.total ?? 0);
    } catch (e: any) { message.error(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [filterLevel]);

  const columns = [
    {
      title: '时间', dataIndex: 'created_at', width: 160,
      render: (v: string) => <Text style={{ fontSize: 12, color: '#8b949e' }}>{dayjs(v).format('MM-DD HH:mm:ss')}</Text>,
    },
    {
      title: '级别', dataIndex: 'level', width: 80,
      render: (v: string) => <Tag color={v === 'error' ? 'red' : v === 'warn' ? 'orange' : 'blue'} style={{ fontSize: 11 }}>{v?.toUpperCase()}</Tag>,
    },
    { title: '标题', dataIndex: 'title', render: (v: string) => <Text>{v}</Text> },
    { title: '内容', dataIndex: 'content', ellipsis: true, render: (v: string) => <Text type="secondary" style={{ fontSize: 12 }}>{v || '-'}</Text> },
    {
      title: '用户', dataIndex: 'user_uuid', width: 140,
      render: (v: string) => v ? <Text code style={{ fontSize: 11 }}>{v.slice(0, 12)}...</Text> : '-',
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>操作日志</Title>
        <Space>
          <Select allowClear placeholder="日志级别" style={{ width: 120 }} value={filterLevel} onChange={setFilterLevel}>
            <Option value="info">INFO</Option>
            <Option value="warn">WARN</Option>
            <Option value="error">ERROR</Option>
          </Select>
        </Space>
      </div>
      <Table
        rowKey="uuid"
        columns={columns}
        dataSource={logs}
        loading={loading}
        pagination={{
          current: page, total, pageSize: 20,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p) => { setPage(p); load(p); },
        }}
      />
    </div>
  );
};

export default Logs;
