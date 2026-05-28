// Settings 页面：4 个分组（通用 / 云端 / 集成 / 安全）+ 服务连接 + 关于
// 对接后端 GET/PUT /api/settings，保存后热更新
import React, { useState, useEffect } from 'react';
import {
  Card, Form, Input, Button, Typography, Space, Divider, message, Tag, Alert, Segmented,
  Switch, InputNumber, Spin,
} from 'antd';
import {
  SaveOutlined, ApiOutlined, BulbOutlined, DesktopOutlined, MoonOutlined, SunOutlined,
  CloudOutlined, SettingOutlined, LockOutlined, SyncOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import i18n from '../../i18n';
import { useAppStore } from '../../store/appStore';
import type { ThemeMode } from '../../store/appStore';
import { getSettings, putSettings } from '../../api';
import type { ClientSettings } from '../../types';

const { Title, Text } = Typography;

const Settings: React.FC = () => {
  const { t } = useTranslation();
  const { darkMode, themeMode, setThemeMode, connected, serverVersion, checkConnection } = useAppStore();
  const [apiBase, setApiBase] = useState(localStorage.getItem('apiBase') || 'http://localhost:1026');
  const [testing, setTesting] = useState(false);

  // 后端 ClientSettings
  const [settings, setSettings] = useState<ClientSettings | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm();

  // 主题选项与 t() 关联，确保切换语言后实时刷新
  const THEME_OPTIONS: { label: React.ReactNode; value: ThemeMode }[] = [
    { label: <Space><SunOutlined />{t('settings.lightMode')}</Space>, value: 'light' },
    { label: <Space><MoonOutlined />{t('settings.darkMode')}</Space>, value: 'dark' },
    { label: <Space><DesktopOutlined />{t('settings.followSystem')}</Space>, value: 'system' },
  ];

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
    marginBottom: 16,
  };

  // 加载后端配置
  const loadSettings = async () => {
    setSettingsLoading(true);
    try {
      const data = await getSettings();
      setSettings(data);
      form.setFieldsValue(data);
    } catch { /* ignore - 可能后端未绑定 */ }
    finally { setSettingsLoading(false); }
  };

  useEffect(() => { if (connected) loadSettings(); }, [connected]);

  // 保存后端配置
  const handleSaveSettings = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      const updated = await putSettings(values);
      setSettings(updated);
      // 语言变更后立即应用到 i18n 并持久化（i18n.ts 已监听 languageChanged 写入 localStorage）
      if (values.language && values.language !== i18n.language) {
        i18n.changeLanguage(values.language);
      }
      message.success(t('settings.saved'));
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveApiBase = () => {
    localStorage.setItem('apiBase', apiBase);
    message.success(t('settings.apiBaseSaved'));
  };

  const handleTestConnection = async () => {
    setTesting(true);
    try {
      await checkConnection();
      if (connected) {
        message.success(t('settings.connectOk', { version: serverVersion }));
      } else {
        message.error(t('settings.connectFail'));
      }
    } finally { setTesting(false); }
  };

  return (
    <div style={{ padding: 24, maxWidth: 720 }}>
      <Space style={{ marginBottom: 24, width: '100%', justifyContent: 'space-between' }}>
        <Title level={4} style={{ margin: 0, color: darkMode ? '#c9d1d9' : undefined }}>{t('settings.title')}</Title>
        <Button type="primary" icon={<SaveOutlined />} onClick={handleSaveSettings} loading={saving}>
          {t('settings.saveAll')}
        </Button>
      </Space>

      <Spin spinning={settingsLoading}>
        <Form form={form} layout="vertical">

          {/* 通用 */}
          <Card
            title={<Space><BulbOutlined />{t('settings.general')}</Space>}
            style={cardStyle}
            headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <Text strong style={{ color: darkMode ? '#c9d1d9' : undefined }}>{t('settings.theme')}</Text>
                <br /><Text style={{ fontSize: 12, color: darkMode ? '#8b949e' : '#999' }}>{t('settings.themeHint')}</Text>
              </div>
              <Segmented<ThemeMode> value={themeMode} onChange={setThemeMode} options={THEME_OPTIONS} size="middle" />
            </div>
            <Form.Item name="language" label={t('settings.language')} initialValue={i18n.language || 'zh-CN'}>
              <Segmented
                options={[
                  { label: '中文', value: 'zh-CN' },
                  { label: 'English', value: 'en-US' },
                ]}
                onChange={(val) => i18n.changeLanguage(val as string)}
              />
            </Form.Item>
            <Form.Item name="close_to_tray" label={t('settings.closeWindow')} valuePropName="checked">
              <Switch checkedChildren={t('settings.closeToTray')} unCheckedChildren={t('settings.closeExit')} />
            </Form.Item>
          </Card>

          {/* 云端 */}
          <Card
            title={<Space><CloudOutlined />{t('settings.cloud')}</Space>}
            style={cardStyle}
            headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
          >
            <Form.Item name="default_cloud_url" label={t('settings.defaultCloudUrl')} extra={t('settings.defaultCloudUrlHint')}>
              <Input placeholder="https://server.example.com" />
            </Form.Item>
            <Form.Item name="allow_insecure_cloud" label={t('settings.allowInsecure')} valuePropName="checked">
              <Switch checkedChildren={t('settings.allow')} unCheckedChildren={t('settings.httpsOnly')} />
            </Form.Item>
            <Divider style={{ margin: '12px 0', borderColor: darkMode ? '#21262d' : undefined }} />
            <Form.Item name="auto_sync" label={t('settings.autoSync')} valuePropName="checked" extra={t('settings.autoSyncHint')}>
              <Switch checkedChildren={t('settings.enabled')} unCheckedChildren={t('settings.disabled')} />
            </Form.Item>
            <Form.Item name="sync_interval_minutes" label={t('settings.syncInterval')}>
              <InputNumber min={1} max={1440} style={{ width: 120 }} />
            </Form.Item>
          </Card>

          {/* 集成 */}
          <Card
            title={<Space><SettingOutlined />{t('settings.integration')}</Space>}
            style={cardStyle}
            headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
          >
            <Form.Item name="register_pkcs11_mock" label={t('settings.registerPkcs11')} valuePropName="checked"
              extra={t('settings.registerPkcs11Hint')}>
              <Switch checkedChildren={t('settings.enabled')} unCheckedChildren={t('settings.disabled')} />
            </Form.Item>
            <Form.Item label={t('settings.ipcPath')}>
              <Input disabled value={`\\\\.\\pipe\\clients`} style={{ fontSize: 12 }} />
            </Form.Item>
          </Card>

          {/* 安全 */}
          <Card
            title={<Space><LockOutlined />{t('settings.security')}</Space>}
            style={cardStyle}
            headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
          >
            <Form.Item name="session_expires_minutes" label={t('settings.sessionExpires')} extra={t('settings.sessionExpiresHint')}>
              <InputNumber min={5} max={43200} style={{ width: 160 }} />
            </Form.Item>
            <Form.Item name="detailed_request_log" label={t('settings.detailedLog')} valuePropName="checked"
              extra={t('settings.detailedLogHint')}>
              <Switch checkedChildren={t('settings.enabled')} unCheckedChildren={t('settings.disabled')} />
            </Form.Item>
          </Card>

        </Form>
      </Spin>

      {/* 服务连接 */}
      <Card
        title={<Space><ApiOutlined />{t('settings.serviceConn')}</Space>}
        style={cardStyle}
        headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}
      >
        <Alert
          message={connected ? t('layout.connected', { version: serverVersion }) : t('settings.notConnected')}
          type={connected ? 'success' : 'warning'} showIcon style={{ marginBottom: 16 }}
        />
        <Form layout="vertical">
          <Form.Item label={t('settings.clientCardAddr')} extra={t('settings.refreshHint')}>
            <Space.Compact style={{ width: '100%' }}>
              <Input value={apiBase} onChange={(e) => setApiBase(e.target.value)} placeholder="http://localhost:1026" style={{ flex: 1 }} />
              <Button onClick={handleSaveApiBase} icon={<SaveOutlined />}>{t('common.save')}</Button>
            </Space.Compact>
          </Form.Item>
          <Button onClick={handleTestConnection} loading={testing} icon={<ApiOutlined />}>{t('settings.testConn')}</Button>
        </Form>
      </Card>

      {/* 关于 */}
      <Card title={t('settings.about')} style={cardStyle} headStyle={{ borderBottom: darkMode ? '1px solid #21262d' : undefined }}>
        <Space direction="vertical" style={{ width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <Text style={{ color: darkMode ? '#8b949e' : '#666' }}>{t('settings.frontVersion')}</Text>
            <Tag color="blue">v1.0.0</Tag>
          </div>
          <Divider style={{ margin: '8px 0', borderColor: darkMode ? '#21262d' : undefined }} />
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <Text style={{ color: darkMode ? '#8b949e' : '#666' }}>{t('settings.clientCardVersion')}</Text>
            <Tag color={connected ? 'success' : 'default'}>{connected ? `v${serverVersion}` : t('layout.notLogin')}</Tag>
          </div>
          <Divider style={{ margin: '8px 0', borderColor: darkMode ? '#21262d' : undefined }} />
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <Text style={{ color: darkMode ? '#8b949e' : '#666' }}>{t('settings.techStack')}</Text>
            <Space><Tag>React 19</Tag><Tag>Ant Design 6</Tag><Tag>Vite</Tag><Tag>Electron</Tag></Space>
          </div>
          <Divider style={{ margin: '8px 0', borderColor: darkMode ? '#21262d' : undefined }} />
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <Text style={{ color: darkMode ? '#8b949e' : '#666' }}>{t('settings.project')}</Text>
            <Text style={{ color: darkMode ? '#8b949e' : '#666', fontSize: 12 }}>OpenCert Manager — GlobalTrusts</Text>
          </div>
        </Space>
      </Card>
    </div>
  );
};

export default Settings;
