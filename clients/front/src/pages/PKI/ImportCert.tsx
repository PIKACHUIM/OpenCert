// 多模式证书导入页：
//   Radio 4 模式：cert_only / cert_key / pkcs12 / key_only
//   每种模式展示不同字段；提交后根据返回的 matched_source 显示匹配结果提示
import React, { useState } from 'react';
import {
  Card, Space, Form, Input, Radio, Button, message, Alert, Typography, Tag, Upload,
} from 'antd';
import {
  ImportOutlined, SafetyCertificateOutlined, KeyOutlined, LockOutlined, FileProtectOutlined,
} from '@ant-design/icons';
import { importPKICert } from '../../api';
import type { ImportCertMode } from '../../types';
import { useAppStore } from '../../store/appStore';

const { Text, Paragraph } = Typography;
const { TextArea } = Input;

const modeLabels: Record<ImportCertMode, { label: string; icon: React.ReactNode; desc: string }> = {
  cert_only: { label: '仅证书', icon: <SafetyCertificateOutlined />, desc: '导入证书 PEM，自动匹配已有私钥' },
  cert_key: { label: '证书+私钥', icon: <KeyOutlined />, desc: '同时导入证书和私钥 PEM' },
  pkcs12: { label: 'PKCS#12', icon: <LockOutlined />, desc: '导入 .p12/.pfx 文件（需要密码）' },
  key_only: { label: '仅私钥', icon: <FileProtectOutlined />, desc: '仅存储私钥，未来导入证书时自动关联' },
};

const ImportCertPage: React.FC = () => {
  const { darkMode } = useAppStore();
  const [form] = Form.useForm();
  const [mode, setMode] = useState<ImportCertMode>('cert_only');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{ key_matched: boolean; matched_source?: string; cert?: any } | null>(null);

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields();
      setLoading(true);
      setResult(null);
      const res = await importPKICert({ mode, ...values });
      setResult(res as any);
      message.success('导入成功');
      form.resetFields();
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  // 读取文件为 base64
  const readFileAsBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = (reader.result as string).split(',')[1] || '';
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  return (
    <div style={{ padding: 24 }}>
      <Card
        style={cardStyle}
        title={<Space><ImportOutlined />导入证书</Space>}
      >
        {/* 模式选择 */}
        <Radio.Group
          value={mode}
          onChange={(e) => { setMode(e.target.value); setResult(null); form.resetFields(); }}
          style={{ marginBottom: 24, display: 'flex', gap: 12 }}
          optionType="button"
          buttonStyle="solid"
        >
          {(Object.keys(modeLabels) as ImportCertMode[]).map((k) => (
            <Radio.Button key={k} value={k} style={{ height: 'auto', padding: '8px 16px', lineHeight: 1.4 }}>
              <Space direction="vertical" size={2} align="center">
                <Space size={4}>{modeLabels[k].icon}<span>{modeLabels[k].label}</span></Space>
                <Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{modeLabels[k].desc}</Text>
              </Space>
            </Radio.Button>
          ))}
        </Radio.Group>

        <Form form={form} layout="vertical" style={{ maxWidth: 640 }}>
          {/* cert_only / cert_key 共用证书 PEM */}
          {(mode === 'cert_only' || mode === 'cert_key') && (
            <Form.Item name="cert_pem" label="证书 PEM" rules={[{ required: true, message: '请粘贴证书 PEM 内容' }]}>
              <TextArea rows={6} placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </Form.Item>
          )}

          {/* cert_key / key_only 共用私钥 PEM */}
          {(mode === 'cert_key' || mode === 'key_only') && (
            <Form.Item name="key_pem" label="私钥 PEM" rules={[{ required: true, message: '请粘贴私钥 PEM 内容' }]}>
              <TextArea rows={6} placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </Form.Item>
          )}

          {/* pkcs12 */}
          {mode === 'pkcs12' && (
            <>
              <Form.Item name="pkcs12_b64" label="PKCS#12 文件" rules={[{ required: true, message: '请上传 .p12/.pfx 文件' }]}>
                <Upload.Dragger
                  accept=".p12,.pfx"
                  multiple={false}
                  showUploadList={false}
                  beforeUpload={async (file) => {
                    try {
                      const b64 = await readFileAsBase64(file);
                      form.setFieldsValue({ pkcs12_b64: b64 });
                      message.success(`已选择: ${file.name}`);
                    } catch {
                      message.error('读取文件失败');
                    }
                    return false;
                  }}
                >
                  <p className="ant-upload-drag-icon"><LockOutlined style={{ fontSize: 36, color: '#1677ff' }} /></p>
                  <p className="ant-upload-text">拖拽 .p12/.pfx 文件到此处</p>
                </Upload.Dragger>
              </Form.Item>
              <Form.Item name="pkcs12_password" label="PKCS#12 密码" rules={[{ required: true, message: '请输入密码' }]}>
                <Input.Password placeholder="PKCS#12 文件密码" />
              </Form.Item>
            </>
          )}

          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" onClick={handleSubmit} loading={loading} icon={<ImportOutlined />}>
              导入
            </Button>
          </Form.Item>
        </Form>

        {/* 匹配结果提示 */}
        {result && (
          <Alert
            type={result.key_matched ? 'success' : 'info'}
            showIcon
            style={{ marginTop: 16 }}
            message={result.key_matched ? '已自动匹配到私钥' : '导入成功（未匹配到私钥）'}
            description={
              <Space direction="vertical" size={4}>
                {result.matched_source && <Text>匹配来源：<Tag color="blue">{result.matched_source}</Tag></Text>}
                {result.cert?.common_name && <Text>CN：{result.cert.common_name}</Text>}
                {result.cert?.uuid && <Text>UUID：<Text copyable style={{ fontSize: 12 }}>{result.cert.uuid}</Text></Text>}
              </Space>
            }
          />
        )}
      </Card>
    </div>
  );
};

export default ImportCertPage;
