import React, { useState, useEffect } from 'react';
import {
  Tabs, Form, Input, Button, message, Typography, Space,
  Upload, Card, Descriptions, Divider,
} from 'antd';
import {
  UserOutlined, LockOutlined, KeyOutlined, LogoutOutlined, UploadOutlined,
} from '@ant-design/icons';
import { getMe, updateMe, changePassword, updatePubkey, logout } from '../../api';
import { useAuthStore } from '../../store/auth';
import { useNavigate } from 'react-router-dom';
import type { User } from '../../types';

const { Title, Text } = Typography;

const Profile: React.FC = () => {
  const navigate = useNavigate();
  const { clearAuth, username } = useAuthStore();
  const [user, setUser] = useState<User | null>(null);
  const [infoLoading, setInfoLoading] = useState(false);
  const [pwdLoading, setPwdLoading] = useState(false);
  const [pubkeyLoading, setPubkeyLoading] = useState(false);
  const [infoForm] = Form.useForm();
  const [pwdForm] = Form.useForm();
  const [pubkeyForm] = Form.useForm();

  useEffect(() => {
    getMe().then((u) => {
      setUser(u);
      infoForm.setFieldsValue({ display_name: u.display_name, email: u.email });
    }).catch(() => {});
  }, []);

  const handleUpdateInfo = async (values: { display_name: string; email: string }) => {
    setInfoLoading(true);
    try {
      const updated = await updateMe(values);
      setUser(updated);
      message.success('个人信息已更新');
    } catch (err: any) { message.error(err.message || '更新失败'); }
    finally { setInfoLoading(false); }
  };

  const handleChangePassword = async (values: { old_password: string; new_password: string; confirm: string }) => {
    if (values.new_password !== values.confirm) { message.error('两次密码不一致'); return; }
    setPwdLoading(true);
    try {
      await changePassword({ old_password: values.old_password, new_password: values.new_password });
      message.success('密码已修改，请重新登录');
      pwdForm.resetFields();
    } catch (err: any) { message.error(err.message || '修改失败'); }
    finally { setPwdLoading(false); }
  };

  const handleUpdatePubkey = async (values: { pubkey_pem: string }) => {
    setPubkeyLoading(true);
    try {
      await updatePubkey(values.pubkey_pem);
      message.success('云端公钥已更新');
      pubkeyForm.resetFields();
    } catch (err: any) { message.error(err.message || '更新失败'); }
    finally { setPubkeyLoading(false); }
  };

  const handleLogout = async () => {
    try { await logout(); } catch {}
    clearAuth();
    navigate('/login', { replace: true });
  };

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 24px' }}>个人中心</Title>
      <Tabs items={[
        {
          key: 'info',
          label: <Space><UserOutlined />基本信息</Space>,
          children: (
            <div style={{ maxWidth: 480 }}>
              {user && (
                <Descriptions column={1} style={{ marginBottom: 24 }} bordered size="small">
                  <Descriptions.Item label="用户名">{user.display_name || username}</Descriptions.Item>
                  <Descriptions.Item label="邮箱">{user.email}</Descriptions.Item>
                  <Descriptions.Item label="注册时间">{new Date(user.created_at).toLocaleString()}</Descriptions.Item>
                </Descriptions>
              )}
              <Form form={infoForm} layout="vertical" onFinish={handleUpdateInfo}>
                <Form.Item label="显示名称" name="display_name" rules={[{ required: true }]}><Input /></Form.Item>
                <Form.Item label="邮箱" name="email" rules={[{ required: true, type: 'email' }]}><Input /></Form.Item>
                <Form.Item><Button type="primary" htmlType="submit" loading={infoLoading}>保存修改</Button></Form.Item>
              </Form>
            </div>
          ),
        },
        {
          key: 'password',
          label: <Space><LockOutlined />安全设置</Space>,
          children: (
            <div style={{ maxWidth: 480 }}>
              <Form form={pwdForm} layout="vertical" onFinish={handleChangePassword}>
                <Form.Item label="当前密码" name="old_password" rules={[{ required: true }]}><Input.Password /></Form.Item>
                <Form.Item label="新密码" name="new_password" rules={[{ required: true }, { min: 8, message: '密码至少8位' }]}><Input.Password placeholder="至少8位" /></Form.Item>
                <Form.Item label="确认新密码" name="confirm" rules={[{ required: true }]}><Input.Password /></Form.Item>
                <Form.Item><Button type="primary" htmlType="submit" loading={pwdLoading}>修改密码</Button></Form.Item>
              </Form>
              <Divider />
              <Card size="small" style={{ borderColor: '#ff4d4f' }}>
                <Title level={5} style={{ color: '#ff4d4f', margin: '0 0 8px' }}>退出登录</Title>
                <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>退出后需要重新登录才能访问平台。</Text>
                <Button danger icon={<LogoutOutlined />} onClick={handleLogout}>退出登录</Button>
              </Card>
            </div>
          ),
        },
        {
          key: 'pubkey',
          label: <Space><KeyOutlined />云端公钥</Space>,
          children: (
            <div style={{ maxWidth: 560 }}>
              <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
                云端公钥用于加密传输到云端的私钥数据。请上传 PEM 格式的 RSA/EC 公钥。
              </Text>
              <Form form={pubkeyForm} layout="vertical" onFinish={handleUpdatePubkey}>
                <Form.Item label="公钥（PEM 格式）" name="pubkey_pem" rules={[{ required: true }]}>
                  <Input.TextArea rows={8}
                    placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                    style={{ fontSize: 12 }} />
                </Form.Item>
                <Form.Item>
                  <Space>
                    <Button type="primary" htmlType="submit" loading={pubkeyLoading} icon={<UploadOutlined />}>上传公钥</Button>
                    <Upload accept=".pem,.crt,.cer" showUploadList={false}
                      beforeUpload={(file) => {
                        const reader = new FileReader();
                        reader.onload = (e) => { pubkeyForm.setFieldValue('pubkey_pem', e.target?.result as string); };
                        reader.readAsText(file);
                        return false;
                      }}>
                      <Button icon={<UploadOutlined />}>从文件导入</Button>
                    </Upload>
                  </Space>
                </Form.Item>
              </Form>
            </div>
          ),
        },
      ]} />
    </div>
  );
};

export default Profile;
