import React, { useEffect, useState } from 'react';
import {
  Card, Table, Space, Tag, Typography, Button, message, Descriptions, Drawer, Alert, Popconfirm,
} from 'antd';
import { AuditOutlined, ReloadOutlined, FileDoneOutlined, StopOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { listCertApplications, revokeMyCert, listMySubscriptions } from '../../api';
import type { CertApplication, Subscription } from '../../types';
import HelpLink from '../../components/HelpLink';

const { Title, Text } = Typography;

const STATUS: Record<string, { text: string; color: string }> = {
  pending: { text: '审核中', color: 'orange' },
  approved: { text: '已签发', color: 'green' },
  rejected: { text: '已驳回', color: 'red' },
};

/** 我的证书申请：跟踪申请进度、查看驳回原因、撤销/查看已签发证书 */
const MyApplicationsPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [apps, setApps] = useState<CertApplication[]>([]);
  const [subs, setSubs] = useState<Subscription[]>([]);
  const [detail, setDetail] = useState<CertApplication | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const r = await listCertApplications({ page: 1, page_size: 50 });
      setApps(r.items ?? []);
      setSubs(await listMySubscriptions().catch(() => []));
    } catch (e: any) { message.error(e.message || '加载失败'); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  /** 订阅是否允许自行吊销（存在生效中的订阅且套餐禁止吊销时隐藏入口；服务端也会再校验） */
  const revokeAllowed = () => {
    const sub = subs.find((s) => s.status === 'active' && new Date(s.ends_at) > new Date());
    if (!sub) return true;
    return sub.plan?.allow_revoke !== false;
  };

  const parse = (s?: string) => { try { return s ? JSON.parse(s) : {}; } catch { return {}; } };

  const columns = [
    { title: '申请编号', dataIndex: 'uuid', key: 'uuid',
      render: (v: string) => <Text copyable code style={{ fontSize: 12 }}>{v.slice(0, 8)}</Text> },
    { title: '证书主体', dataIndex: 'subject_json', key: 'subject_json',
      render: (v: string) => {
        const o = parse(v);
        return <Text>{o.CN || o.commonName || '—'}</Text>;
      } },
    { title: 'SAN', dataIndex: 'san_json', key: 'san_json',
      render: (v: string) => {
        const o = parse(v);
        const all = [...(o.dns ?? []), ...(o.email ?? []), ...(o.ip ?? [])];
        return all.length ? <Text style={{ fontSize: 12 }}>{all.join('，')}</Text> : '—';
      } },
    { title: '算法', dataIndex: 'key_type', key: 'key_type', width: 90 },
    { title: '状态', dataIndex: 'status', key: 'status', width: 110,
      render: (v: string) => {
        const s = STATUS[v] ?? { text: v, color: 'default' };
        return <Tag color={s.color}>{s.text}</Tag>;
      } },
    { title: '提交时间', dataIndex: 'created_at', key: 'created_at', width: 165,
      render: (v: string) => (v ? new Date(v).toLocaleString('zh-CN') : '—') },
    {
      title: '操作', key: 'actions', width: 200,
      render: (_: any, r: CertApplication) => (
        <Space size={4}>
          <Button type="link" size="small" onClick={() => setDetail(r)}>详情</Button>
          {r.status === 'approved' && r.cert_uuid && (
            <>
              <Button type="link" size="small" icon={<FileDoneOutlined />}
                onClick={() => navigate('/console/certs')}>查看证书</Button>
              {revokeAllowed() && (
                <Popconfirm title="吊销后证书立即失效且不可恢复，确认吊销？"
                  onConfirm={async () => {
                    try {
                      await revokeMyCert(r.cert_uuid!, 4);
                      message.success('证书已吊销');
                      load();
                    } catch (e: any) { message.error(e.message || '吊销失败'); }
                  }}>
                  <Button type="link" size="small" danger icon={<StopOutlined />}>吊销</Button>
                </Popconfirm>
              )}
            </>
          )}
        </Space>
      ),
    },
  ];

  const subject = detail ? parse(detail.subject_json) : {};
  const san = detail ? parse(detail.san_json) : {};

  return (
    <div>
      <Card
        title={<Space><AuditOutlined /><Title level={4} style={{ margin: 0 }}>我的证书申请</Title>
          <HelpLink doc="user-03-apply-certificate" /></Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
            <Button type="primary" onClick={() => navigate('/console/apply')}>申请证书</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={apps} columns={columns as any}
          locale={{ emptyText: '暂无申请。提交后进入审核，审核通过会自动签发。' }} />
      </Card>

      <Drawer open={!!detail} onClose={() => setDetail(null)} title="申请详情" width={560}>
        {detail && (
          <>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="申请编号">{detail.uuid}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={(STATUS[detail.status] ?? {}).color}>{(STATUS[detail.status] ?? {}).text ?? detail.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="主体">
                {Object.entries(subject).map(([k, v]) => <div key={k}>{k} = {String(v)}</div>)}
              </Descriptions.Item>
              <Descriptions.Item label="SAN">
                {(san.dns ?? []).map((d: string) => <div key={d}>DNS: {d}</div>)}
                {(san.email ?? []).map((d: string) => <div key={d}>Email: {d}</div>)}
                {(san.ip ?? []).map((d: string) => <div key={d}>IP: {d}</div>)}
              </Descriptions.Item>
              <Descriptions.Item label="密钥算法">{detail.key_type}</Descriptions.Item>
              <Descriptions.Item label="申请人邮箱">{detail.applicant_email || '—'}</Descriptions.Item>
              <Descriptions.Item label="提交时间">
                {detail.created_at ? new Date(detail.created_at).toLocaleString('zh-CN') : '—'}
              </Descriptions.Item>
              <Descriptions.Item label="审批时间">
                {detail.updated_at ? new Date(detail.updated_at).toLocaleString('zh-CN') : '—'}
              </Descriptions.Item>
            </Descriptions>
            {detail.reject_reason && (
              <Alert type="error" showIcon style={{ marginTop: 16 }}
                message="驳回原因" description={detail.reject_reason} />
            )}
            {detail.cert_uuid && (
              <Alert type="success" showIcon style={{ marginTop: 16 }}
                message="证书已签发" description={`证书编号 ${detail.cert_uuid}`} />
            )}
          </>
        )}
      </Drawer>
    </div>
  );
};

export default MyApplicationsPage;
