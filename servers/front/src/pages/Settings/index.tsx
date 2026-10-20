import React, { useEffect, useState } from 'react';
import {
  Tabs, Card, Typography, Table, Tag, Button, Space, Select, Input, message,
  Form, Descriptions, Alert, Empty,
} from 'antd';
import { MailOutlined, InfoCircleOutlined, SendOutlined, SaveOutlined } from '@ant-design/icons';
import { getSystemInfo, getSystemMail, updateSystemMail } from '../../api';
import { useAuthStore } from '../../store/auth';
import type { SystemInfo, SystemMailView } from '../../types';

const { Title, Text, Paragraph } = Typography;

/** 系统邮件：选择默认发信接口、发送测试邮件 */
const MailTab: React.FC = () => {
  const [view, setView] = useState<SystemMailView | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [defaultUUID, setDefaultUUID] = useState<string>('');
  const [testTo, setTestTo] = useState('');
  const [testing, setTesting] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const data = await getSystemMail();
      setView(data);
      setDefaultUUID(data.default_provider_uuid || '');
    } catch (err: any) { message.error(err.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSystemMail({ default_provider_uuid: defaultUUID });
      message.success('已保存');
      load();
    } catch (err: any) { message.error(err.message); }
    finally { setSaving(false); }
  };

  const handleTest = async () => {
    if (!testTo.includes('@')) { message.warning('请填写接收测试邮件的邮箱'); return; }
    setTesting(true);
    try {
      await updateSystemMail({ default_provider_uuid: defaultUUID, test_to: testTo });
      message.success('测试邮件已发送，请查收');
    } catch (err: any) { message.error(err.message); }
    finally { setTesting(false); }
  };

  const providers = view?.providers ?? [];

  return (
    <Card loading={loading}>
      <Paragraph type="secondary">
        系统邮件用于发送邮箱验证码与业务通知。选择一个邮件接口作为默认发信通道；
        也可以在「身份认证审核」中添加更多接口。
      </Paragraph>

      {providers.length === 0 ? (
        <Empty description="还没有邮件发送通道，请先添加一个。" />
      ) : (
        <>
          <Form layout="vertical" style={{ maxWidth: 520 }}>
            <Form.Item label="默认邮件接口" extra="未选择时使用平台默认发信配置">
              <Select
                allowClear
                placeholder="使用平台默认配置"
                value={defaultUUID || undefined}
                onChange={(v) => setDefaultUUID(v ?? '')}
                options={providers.map((p) => ({
                  value: p.uuid,
                  label: `${p.name}${p.enabled ? '' : '（已停用）'}`,
                  disabled: !p.enabled,
                }))}
              />
            </Form.Item>
            <Form.Item label="发送测试邮件">
              <Space.Compact style={{ width: '100%' }}>
                <Input placeholder="接收测试邮件的邮箱" value={testTo} onChange={(e) => setTestTo(e.target.value)} />
                <Button icon={<SendOutlined />} loading={testing} onClick={handleTest}>发送测试</Button>
              </Space.Compact>
            </Form.Item>
            <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave}>保存</Button>
          </Form>

          <Table
            style={{ marginTop: 24 }}
            rowKey="uuid"
            size="small"
            pagination={false}
            dataSource={providers}
            columns={[
              { title: '名称', dataIndex: 'name', key: 'name' },
              { title: '驱动', dataIndex: 'driver', key: 'driver' },
              {
                title: '状态', dataIndex: 'enabled', key: 'enabled', width: 100,
                render: (v: boolean) => <Tag color={v ? 'green' : 'default'}>{v ? '启用' : '停用'}</Tag>,
              },
              {
                title: '默认', dataIndex: 'is_default', key: 'is_default', width: 90,
                render: (v: boolean) => (v ? <Tag color="blue">默认</Tag> : '-'),
              },
            ]}
          />
        </>
      )}
    </Card>
  );
};

/** 系统信息：版本、数据库、密钥驱动、国密支持 */
const InfoTab: React.FC = () => {
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    getSystemInfo().then(setInfo).catch((err) => message.error(err.message)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Card loading />;
  if (!info) return <Empty description="无法获取系统信息" />;

  const smText = [info.sm.sm2 && 'SM2', info.sm.sm3 && 'SM3', info.sm.sm4 && 'SM4'].filter(Boolean).join(' / ');

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="运行环境">
        <Descriptions column={2} size="small">
          <Descriptions.Item label="平台版本">{info.version}</Descriptions.Item>
          <Descriptions.Item label="数据库">{info.database.driver}</Descriptions.Item>
          <Descriptions.Item label="国密算法">
            {smText ? <Tag color="green">可用：{smText}</Tag> : <Tag>未启用</Tag>}
          </Descriptions.Item>
          <Descriptions.Item label="存储区域">{info.storage_zones.length} 个</Descriptions.Item>
        </Descriptions>
        {info.storage_zones.length > 0 && (
          <Space size={8} wrap style={{ marginTop: 8 }}>
            {info.storage_zones.map((z) => (
              <Tag key={z.name} color={z.storage_type === 'database' ? 'blue' : 'orange'}>
                {z.name}（{z.storage_type === 'database' ? '本地加密' : z.storage_type.toUpperCase()}）
              </Tag>
            ))}
          </Space>
        )}
      </Card>

      <Card title="密钥驱动">
        <Table
          rowKey="driver"
          size="small"
          pagination={false}
          dataSource={info.key_drivers}
          columns={[
            { title: '驱动', dataIndex: 'name', key: 'name' },
            { title: '类型', dataIndex: 'kind', key: 'kind', width: 110 },
            {
              title: '状态', dataIndex: 'available', key: 'available', width: 110,
              render: (v: boolean, r) => (
                <Tag color={v ? 'green' : 'red'}>{v ? '可用' : (r.detail || '不可用')}</Tag>
              ),
            },
            {
              title: '私钥可导出', dataIndex: 'exportable', key: 'exportable', width: 110,
              render: (v: boolean) => (v ? '可以' : '不可导出'),
            },
            {
              title: '支持算法', key: 'key_types',
              render: (_: any, r) => (r.key_types?.length ? r.key_types.join(', ') : '-'),
            },
          ]}
        />
        <Text type="secondary" style={{ fontSize: 12 }}>
          Windows 系统证书存储需安装驱动后才能使用国密证书。
        </Text>
      </Card>
    </Space>
  );
};

const SettingsPage: React.FC = () => {
  const role = useAuthStore((s) => s.role);
  const isAdmin = role === 'admin' || role === 'super_admin';

  if (!isAdmin) {
    return (
      <Alert type="info" showIcon message="无访问权限" />
    );
  }

  return (
    <div>
      <Title level={4} style={{ marginTop: 0 }}>系统设置</Title>
      <Tabs
        defaultActiveKey="mail"
        items={[
          {
            key: 'mail',
            label: <span><MailOutlined /> 系统邮件</span>,
            children: <MailTab />,
          },
          {
            key: 'info',
            label: <span><InfoCircleOutlined /> 系统信息</span>,
            children: <InfoTab />,
          },
        ]}
      />
    </div>
  );
};

export default SettingsPage;
