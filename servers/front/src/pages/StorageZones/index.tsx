import React, { useEffect, useMemo, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Typography, Modal, Form, Input, Select, Switch,
  message, Popconfirm, Alert, Drawer, Tooltip, Divider, Empty, Spin,
} from 'antd';
import {
  DatabaseOutlined, PlusOutlined, ReloadOutlined, DeleteOutlined, SafetyCertificateOutlined,
  ThunderboltOutlined, ApiOutlined, CheckCircleOutlined, CloseCircleOutlined, ScanOutlined,
  EditOutlined, HddOutlined,
} from '@ant-design/icons';
import {
  listStorageZones, createStorageZone, updateStorageZone, deleteStorageZone,
  listKeyBackendDrivers, scanKeyModules, probeKeyBackend, checkStorageZone,
} from '../../api';
import type {
  StorageZone, KeyBackendDriver, DiscoveredKeyModule, KeyBackendProbeResult, KeyBackendPreset,
} from '../../types';

const { Title, Text, Paragraph } = Typography;

/**
 * StorageZones 页面：私钥存储区域管理。
 *
 * 支持三类私钥存放位置：
 *  - 本地加密存储（服务端数据库 + 主密钥加密）
 *  - TPM（本机可信平台模块，私钥不可导出）
 *  - HSM / USB 令牌（PKCS#11 通用接口，如 SafeNet eToken 5110）
 *
 * 驱动与配置项由后端下发（插件化），前端按字段定义动态渲染表单。
 */
const StorageZonesPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<StorageZone[]>([]);
  const [drivers, setDrivers] = useState<KeyBackendDriver[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<StorageZone | null>(null);
  const [form] = Form.useForm();

  // 选定驱动的配置表单
  const [driverId, setDriverId] = useState<string>('database');
  const [testing, setTesting] = useState(false);
  const [probe, setProbe] = useState<KeyBackendProbeResult | null>(null);

  // 本机 PKCS#11 模块扫描
  const [scanOpen, setScanOpen] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [modules, setModules] = useState<DiscoveredKeyModule[]>([]);

  const driver = useMemo(
    () => drivers.find((d) => d.driver === driverId),
    [drivers, driverId],
  );

  const load = async () => {
    setLoading(true);
    try {
      const r = await listStorageZones();
      setData(Array.isArray(r) ? r : (r as any)?.items || []);
    } catch (e: any) {
      message.error(e.message || '加载失败');
    } finally {
      setLoading(false);
    }
  };

  const loadDrivers = async () => {
    try {
      const list = await listKeyBackendDrivers();
      setDrivers(Array.isArray(list) ? list : []);
    } catch { /* 驱动清单失败不阻塞页面 */ }
  };

  useEffect(() => { load(); loadDrivers(); }, []);

  const openCreate = () => {
    setEditing(null);
    setProbe(null);
    setDriverId('database');
    form.resetFields();
    form.setFieldsValue({ storage_type: 'database', status: 'active', params: {} });
    setCreateOpen(true);
  };

  const openEdit = (z: StorageZone) => {
    setEditing(z);
    setProbe(null);
    const id = z.hsm_driver || z.storage_type || 'database';
    setDriverId(id);
    form.resetFields();
    form.setFieldsValue({
      name: z.name,
      storage_type: z.storage_type,
      hsm_driver: id,
      status: z.status || 'active',
      params: z.params || {},
    });
    setCreateOpen(true);
  };

  /** 切换驱动时同步 storage_type 并清空参数。 */
  const handleDriverChange = (id: string) => {
    setDriverId(id);
    const d = drivers.find((x) => x.driver === id);
    setProbe(null);
    form.setFieldsValue({ hsm_driver: id, storage_type: d?.kind || 'database', params: {} });
  };

  /** 套用厂商预设（例如 eToken 5110 的库路径）。 */
  const applyPreset = (preset: KeyBackendPreset) => {
    if (preset.driver && preset.driver !== driverId) {
      handleDriverChange(preset.driver);
    }
    form.setFieldsValue({ params: { ...(form.getFieldValue('params') || {}), ...preset.params } });
    message.success(`已套用预设：${preset.name}`);
  };

  const buildPayload = (values: any) => {
    const d = drivers.find((x) => x.driver === driverId);
    const params: Record<string, string> = {};
    (d?.fields || []).forEach((f) => {
      const v = values?.[`param_${f.key}`];
      if (v === undefined || v === null) return;
      if (typeof v === 'boolean') params[f.key] = v ? 'true' : 'false';
      else if (String(v) !== '') params[f.key] = String(v);
    });
    return {
      name: values.name,
      storage_type: d?.kind || values.storage_type || 'database',
      hsm_driver: driverId,
      status: values.status || 'active',
      params,
    };
  };

  const handleSubmit = async (values: any) => {
    try {
      const payload = buildPayload(values);
      if (editing) {
        await updateStorageZone(editing.uuid, payload as any);
        message.success('存储区域已更新');
      } else {
        await createStorageZone(payload as any);
        message.success('存储区域已创建');
      }
      setCreateOpen(false);
      form.resetFields();
      load();
    } catch (e: any) {
      message.error(e.message || '保存失败');
    }
  };

  const handleDelete = async (uuid: string) => {
    try { await deleteStorageZone(uuid); message.success('已删除'); load(); }
    catch (e: any) { message.error(e.message || '删除失败'); }
  };

  const handleCheck = async (uuid: string) => {
    try {
      const r = await checkStorageZone(uuid);
      if (r.ok) message.success(r.detail || '连接正常');
      else message.error(r.error || '连接失败');
      load();
    } catch (e: any) { message.error(e.message || '检测失败'); }
  };

  /** 用当前表单里的配置直接测试连通性（不保存）。 */
  const handleProbe = async () => {
    try {
      await form.validateFields(['param_library', 'param_pin']);
    } catch { /* 允许不完整时也尝试 */ }
    setTesting(true);
    setProbe(null);
    try {
      const values = form.getFieldsValue(true);
      const payload = buildPayload(values);
      const r = await probeKeyBackend({
        storage_type: payload.storage_type,
        hsm_driver: payload.hsm_driver,
        params: payload.params,
      });
      setProbe(r);
      if (r.ok) message.success('连接成功');
      else message.warning(r.error || '连接失败');
    } catch (e: any) {
      message.error(e.message || '测试失败');
    } finally {
      setTesting(false);
    }
  };

  const handleScan = async () => {
    setScanOpen(true);
    setScanning(true);
    try {
      const list = await scanKeyModules();
      setModules(Array.isArray(list) ? list : []);
    } catch (e: any) {
      message.error(e.message || '扫描失败');
      setModules([]);
    } finally {
      setScanning(false);
    }
  };

  /** 用扫描结果直接填入表单。 */
  const useScanned = (m: DiscoveredKeyModule) => {
    handleDriverChange(m.driver || 'pkcs11');
    setTimeout(() => {
      form.setFieldsValue({
        params: { ...(form.getFieldValue('params') || {}), ...m.params, library: m.path },
      });
    }, 0);
    setScanOpen(false);
    setCreateOpen(true);
    message.success('已填入模块路径，请补全 PIN 后保存');
  };

  const kindTag = (z: StorageZone) => {
    const kind = z.kind || z.storage_type;
    if (kind === 'hsm') return <Tag color="red" icon={<SafetyCertificateOutlined />}>HSM 硬件</Tag>;
    if (kind === 'tpm') return <Tag color="purple" icon={<ThunderboltOutlined />}>TPM</Tag>;
    return <Tag color="blue" icon={<DatabaseOutlined />}>本地加密</Tag>;
  };

  const columns = [
    { title: '名称', dataIndex: 'name', key: 'name',
      render: (v: string, r: StorageZone) => (
        <Space>
          {v}
          {r.card_count ? <Tooltip title={`${r.card_count} 张卡片正在使用`}><Tag>{r.card_count} 卡</Tag></Tooltip> : null}
        </Space>
      ) },
    { title: '私钥位置', key: 'kind', render: (_: any, r: StorageZone) => kindTag(r) },
    { title: '驱动', dataIndex: 'driver_name', key: 'driver_name',
      render: (v: string, r: StorageZone) => (
        <Tooltip title={r.hsm_driver}>
          <Text type="secondary">{v || r.hsm_driver || '-'}</Text>
        </Tooltip>
      ) },
    { title: '能力', key: 'cap', render: (_: any, r: StorageZone) => {
      const c = r.capabilities || {};
      return (
        <Space size={4} wrap>
          {c.generate ? <Tag color="green">可生成</Tag> : null}
          {c.import ? <Tag color="cyan">可导入</Tag> : null}
          {c.sign ? <Tag>可签名</Tag> : null}
          {c.decrypt ? <Tag>可解密</Tag> : null}
          {c.exportable ? <Tag color="orange">可导出私钥</Tag> : <Tag color="green">私钥不可导出</Tag>}
        </Space>
      );
    } },
    { title: '状态', key: 'status', render: (_: any, r: StorageZone) => (
      <Space direction="vertical" size={0}>
        {r.status === 'active' ? <Tag color="success">激活</Tag> : <Tag>禁用</Tag>}
        {r.last_check_error
          ? <Tooltip title={r.last_check_error}><Text type="danger" style={{ fontSize: 12 }}>
              <CloseCircleOutlined /> 检测异常
            </Text></Tooltip>
          : r.last_check_at
            ? <Tooltip title={r.last_check_detail}><Text type="success" style={{ fontSize: 12 }}>
                <CheckCircleOutlined /> {new Date(r.last_check_at).toLocaleString('zh-CN')}
              </Text></Tooltip>
            : null}
      </Space>
    ) },
    { title: '创建时间', dataIndex: 'created_at', key: 'created_at',
      render: (v: string) => new Date(v).toLocaleString('zh-CN') },
    {
      title: '操作', key: 'actions', width: 210,
      render: (_: any, r: StorageZone) => (
        <Space size={0}>
          <Button type="link" size="small" icon={<ApiOutlined />} onClick={() => handleCheck(r.uuid)}>检测</Button>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => openEdit(r)}>编辑</Button>
          <Popconfirm title="确认删除此存储区域？" onConfirm={() => handleDelete(r.uuid)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card
        title={<Space><HddOutlined />
          <Title level={4} style={{ margin: 0 }}>私钥存储区域</Title></Space>}
        extra={
          <Space>
            <Button icon={<ScanOutlined />} onClick={handleScan}>扫描本机 HSM</Button>
            <Button icon={<ReloadOutlined />} onClick={load}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建存储区域</Button>
          </Space>
        }
      >
        <Table rowKey="uuid" loading={loading} dataSource={data} columns={columns as any}
          locale={{ emptyText: '还没有存储区域。新建后开卡时即可选择私钥保存在哪里。' }} />
      </Card>

      {/* 新建 / 编辑 */}
      <Modal
        open={createOpen}
        title={editing ? `编辑存储区域：${editing.name}` : '新建存储区域'}
        width={720}
        onCancel={() => { setCreateOpen(false); form.resetFields(); }}
        onOk={() => form.submit()}
        confirmLoading={testing}
        destroyOnClose
        footer={[
          <Button key="probe" icon={<ApiOutlined />} loading={testing} onClick={handleProbe}>测试连接</Button>,
          <Button key="cancel" onClick={() => { setCreateOpen(false); form.resetFields(); }}>取消</Button>,
          <Button key="ok" type="primary" onClick={() => form.submit()}>{editing ? '保存' : '创建'}</Button>,
        ]}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}
          initialValues={{ storage_type: 'database', status: 'active' }}>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input maxLength={64} placeholder="例如：主库加密存储、eToken 5110 一号机" />
          </Form.Item>

          <Form.Item label="私钥存储驱动" required>
            <Select
              value={driverId}
              onChange={handleDriverChange}
              options={drivers.map((d) => ({
                value: d.driver,
                label: (
                  <Space>
                    {d.kind === 'hsm' ? <SafetyCertificateOutlined /> : d.kind === 'tpm' ? <ThunderboltOutlined /> : <DatabaseOutlined />}
                    {d.name}
                    {!d.available ? <Tag color="warning">当前主机不可用</Tag> : null}
                  </Space>
                ),
              }))}
            />
            {driver ? (
              <Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
                {driver.description}
                {driver.available_detail ? <>（{driver.available_detail}）</> : null}
              </Paragraph>
            ) : null}
          </Form.Item>

          <Form.Item name="hsm_driver" hidden><Input /></Form.Item>
          <Form.Item name="storage_type" hidden><Input /></Form.Item>

          {/* 厂商预设 */}
          {driver?.presets?.length ? (
            <Form.Item label="厂商预设" tooltip="一键填入该厂商模块的推荐参数">
              <Space wrap>
                {driver.presets.map((p) => (
                  <Button key={p.id} size="small" onClick={() => applyPreset(p)}>{p.name}</Button>
                ))}
              </Space>
            </Form.Item>
          ) : null}

          {/* 动态配置项 */}
          {(driver?.fields || []).length > 0 && <Divider plain>驱动配置</Divider>}
          {(driver?.fields || []).map((f) => {
            const name = `param_${f.key}`;
            const rules = f.required ? [{ required: true, message: `请填写${f.label}` }] : undefined;
            if (f.type === 'bool') {
              return (
                <Form.Item key={f.key} name={name} label={f.label}
                  valuePropName="checked" tooltip={f.hint}
                  getValueFromEvent={(v: boolean) => (v ? 'true' : 'false')}
                  getValueProps={(v: any) => ({ checked: v === true || v === 'true' })}>
                  <Switch />
                </Form.Item>
              );
            }
            if (f.type === 'select') {
              return (
                <Form.Item key={f.key} name={name} label={f.label} rules={rules} tooltip={f.hint}>
                  <Select allowClear options={(f.options || []).map((o) => ({ label: o, value: o }))}
                    placeholder={f.default} />
                </Form.Item>
              );
            }
            return (
              <Form.Item key={f.key} name={name} label={f.label} rules={rules} tooltip={f.hint}
                extra={f.hint && !f.secret ? undefined : (f.secret ? '敏感信息将加密保存，不会回显' : undefined)}>
                {f.type === 'password'
                  ? <Input.Password placeholder={f.secret ? '请输入（不回显）' : f.default} autoComplete="new-password" />
                  : f.type === 'number'
                    ? <Input placeholder={f.default} />
                    : <Input placeholder={f.type === 'file' ? '例如 C:\\Windows\\System32\\eTPKCS11.dll' : f.default} />}
              </Form.Item>
            );
          })}

          <Form.Item name="status" label="状态">
            <Select options={[{ label: '激活', value: 'active' }, { label: '禁用', value: 'disabled' }]} />
          </Form.Item>

          {probe ? (
            <Alert
              type={probe.ok ? 'success' : 'error'}
              showIcon
              message={probe.ok ? `连接成功：${probe.detail || ''}` : `连接失败：${probe.error || '未知错误'}`}
              description={probe.devices?.length ? (
                <Space direction="vertical" size={0}>
                  {probe.devices.map((d, i) => (
                    <Text key={i} type="secondary">
                      设备：{d.name || '-'} 型号 {d.model || '-'} 序列号 {d.serial || '-'} 槽位 {d.slot_index ?? '-'}
                    </Text>
                  ))}
                </Space>
              ) : undefined}
            />
          ) : null}
        </Form>
      </Modal>

      {/* 本机模块扫描 */}
      <Drawer
        open={scanOpen}
        title="扫描本机 PKCS#11 模块"
        width={640}
        onClose={() => setScanOpen(false)}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Alert
            type="info" showIcon
            message="扫描本机已安装的加密设备"
            description="未发现设备时可手动填写模块路径；如需支持特定型号，请联系技术支持。"
          />
          {scanning ? <Spin /> : modules.length === 0
            ? <Empty description="未发现可用的 PKCS#11 模块" />
            : modules.map((m, i) => (
              <Card key={i} size="small"
                title={<Space>{m.exists && m.verified ? <CheckCircleOutlined style={{ color: '#52c41a' }} /> : <CloseCircleOutlined style={{ color: '#ff4d4f' }} />}
                  {m.preset_name}</Space>}
                extra={m.exists
                  ? <Button size="small" type="primary" onClick={() => useScanned(m)}>使用</Button>
                  : <Tag>未安装</Tag>}
              >
                <Space direction="vertical" size={2} style={{ width: '100%' }}>
                  <Text code style={{ fontSize: 12 }}>{m.path}</Text>
                  {m.library_name ? <Text type="success">{m.library_name}</Text> : null}
                  {m.error ? <Text type="danger" style={{ fontSize: 12 }}>{m.error}</Text> : null}
                </Space>
              </Card>
            ))}
        </Space>
      </Drawer>

    </div>
  );
};

export default StorageZonesPage;
