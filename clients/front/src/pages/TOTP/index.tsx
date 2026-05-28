import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Card, Table, Button, Space, Tag, Modal, Form, Input, Select,
  message, Progress, Typography, Tooltip, InputNumber, Row, Col,
} from 'antd';
import {
  PlusOutlined, DeleteOutlined, CopyOutlined, ClockCircleOutlined,
  ReloadOutlined, QrcodeOutlined, KeyOutlined,
} from '@ant-design/icons';
import { getTOTPList, getTOTPCode, createTOTP, deleteTOTP, getCards } from '../../api';
import type { TOTPEntry, Card as CardType } from '../../types';

const { Text } = Typography;

interface TOTPWithCode extends TOTPEntry {
  code?: string;
  remaining?: number;
}

const TOTPPage: React.FC = () => {
  const [entries, setEntries] = useState<TOTPWithCode[]>([]);
  const [loading, setLoading] = useState(false);
  const [addVisible, setAddVisible] = useState(false);
  const [form] = Form.useForm();
  const timerRef = useRef<ReturnType<typeof setInterval>>();
  const [cards, setCards] = useState<CardType[]>([]);
  const [selectedCardUUID, setSelectedCardUUID] = useState<string>('');

  useEffect(() => {
    getCards({ page: 1, page_size: 100 }).then(r => {
      const list = Array.isArray(r?.items) ? r.items : [];
      setCards(list);
      if (list.length > 0 && !selectedCardUUID) {
        setSelectedCardUUID(list[0].uuid);
      }
    }).catch(() => {});
  }, []);

  const loadEntries = async () => {
    if (!selectedCardUUID) return;
    setLoading(true);
    try {
      const data = await getTOTPList(selectedCardUUID);
      const items = Array.isArray(data) ? data : [];
      setEntries(items.map((e: TOTPEntry) => ({ ...e })));
    } catch (err: any) {
      message.error(err.message || '加载 TOTP 列表失败');
    } finally {
      setLoading(false);
    }
  };

  const refreshCodes = useCallback(async () => {
    setEntries(prev => prev.map(e => {
      const period = e.period || 30;
      const now = Math.floor(Date.now() / 1000);
      const remaining = period - (now % period);
      return { ...e, remaining };
    }));
    for (const entry of entries) {
      try {
        const resp = await getTOTPCode(entry.uuid);
        setEntries(prev => prev.map(e =>
          e.uuid === entry.uuid ? { ...e, code: resp.code } : e
        ));
      } catch {
        // 静默失败，保留旧验证码
      }
    }
  }, [entries]);

  useEffect(() => { loadEntries(); }, [selectedCardUUID]);

  // 每秒更新倒计时，每个周期刷新验证码
  useEffect(() => {
    timerRef.current = setInterval(() => {
      const now = Math.floor(Date.now() / 1000);
      setEntries(prev => prev.map(e => {
        const period = e.period || 30;
        const remaining = period - (now % period);
        if (remaining === period) {
          getTOTPCode(e.uuid).then(resp => {
            setEntries(p => p.map(x =>
              x.uuid === e.uuid ? { ...x, code: resp.code, remaining } : x
            ));
          }).catch(() => {});
        }
        return { ...e, remaining };
      }));
    }, 1000);
    return () => clearInterval(timerRef.current);
  }, []);

  useEffect(() => {
    if (entries.length > 0 && !entries[0].code) {
      refreshCodes();
    }
  }, [entries.length]);

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    message.success('验证码已复制');
  };

  const handleAdd = async () => {
    try {
      const values = await form.validateFields();
      await createTOTP({ ...values, card_uuid: selectedCardUUID });
      message.success('TOTP 条目已添加');
      setAddVisible(false);
      form.resetFields();
      loadEntries();
    } catch (err: any) {
      if (err.message) message.error(err.message);
    }
  };

  const handleDelete = (entry: TOTPWithCode) => {
    Modal.confirm({
      title: '确认删除',
      content: `确定要删除 ${entry.issuer}:${entry.account} 的 TOTP 条目吗？此操作不可恢复！`,
      okType: 'danger',
      okText: '确认删除',
      onOk: async () => {
        try {
          await deleteTOTP(entry.uuid);
          message.success('已删除');
          loadEntries();
        } catch (err: any) {
          message.error(err.message || '删除失败');
        }
      },
    });
  };

  const columns = [
    {
      title: '发行者',
      dataIndex: 'issuer',
      width: 160,
      render: (v: string) => <Text strong>{v || '-'}</Text>,
    },
    {
      title: '账户',
      dataIndex: 'account',
      width: 200,
      ellipsis: true,
    },
    {
      title: '验证码',
      width: 200,
      render: (_: unknown, record: TOTPWithCode) => {
        const code = record.code || '------';
        const period = record.period || 30;
        const remaining = record.remaining || 0;
        const percent = (remaining / period) * 100;
        const isUrgent = remaining <= 5;

        return (
          <Space>
            <Tooltip title="点击复制">
              <Button
                type="text"
                size="large"
                style={{
                  fontSize: 22,
                  fontWeight: 700,
                  letterSpacing: 4,
                  color: isUrgent ? '#ff4d4f' : '#1677ff',
                }}
                icon={<CopyOutlined style={{ fontSize: 14 }} />}
                onClick={() => record.code && handleCopy(record.code)}
              >
                {code}
              </Button>
            </Tooltip>
            <Progress
              type="circle"
              percent={percent}
              size={28}
              format={() => `${remaining}`}
              strokeColor={isUrgent ? '#ff4d4f' : '#1677ff'}
            />
          </Space>
        );
      },
    },
    {
      title: '算法',
      dataIndex: 'algorithm',
      width: 80,
      render: (v: string) => <Tag>{v || 'SHA1'}</Tag>,
    },
    {
      title: '位数',
      dataIndex: 'digits',
      width: 60,
      render: (v: number) => v || 6,
    },
    {
      title: '操作',
      width: 80,
      render: (_: unknown, record: TOTPWithCode) => (
        <Tooltip title="删除">
          <Button type="text" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record)} />
        </Tooltip>
      ),
    },
  ];

  return (
    <div style={{ padding: 24 }}>
      <Card
        title={
          <Space>
            <ClockCircleOutlined />
            <span>TOTP 验证器</span>
            <Tag color="blue">{entries.length} 个条目</Tag>
            {cards.length > 0 && (
              <Select
                size="small"
                value={selectedCardUUID}
                onChange={setSelectedCardUUID}
                style={{ minWidth: 160 }}
                options={cards.map(c => ({ value: c.uuid, label: c.card_name }))}
                placeholder="选择卡片"
              />
            )}
          </Space>
        }
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={refreshCodes}>刷新</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddVisible(true)}>
              添加 TOTP
            </Button>
          </Space>
        }
      >
        <Table
          rowKey="uuid"
          columns={columns}
          dataSource={entries}
          loading={loading}
          pagination={false}
        />
      </Card>

      {/* 添加 TOTP 对话框 */}
      <Modal
        title="添加 TOTP 条目"
        open={addVisible}
        onOk={handleAdd}
        onCancel={() => { setAddVisible(false); form.resetFields(); }}
        width={520}
      >
        <Form form={form} layout="vertical" initialValues={{ algorithm: 'SHA1', digits: 6, period: 30 }}>
          <Form.Item name="issuer" label="发行者" rules={[{ required: true, message: '请输入发行者名称' }]}>
            <Input placeholder="例如：GitHub、Google" prefix={<KeyOutlined />} />
          </Form.Item>
          <Form.Item name="account" label="账户名" rules={[{ required: true, message: '请输入账户名' }]}>
            <Input placeholder="例如：user@example.com" />
          </Form.Item>
          <Form.Item name="secret" label="密钥 (Base32)" rules={[{ required: true, message: '请输入 Base32 编码的密钥' }]}>
            <Input.TextArea placeholder="JBSWY3DPEHPK3PXP..." rows={2}  />
          </Form.Item>
          <Form.Item name="uri" label="或粘贴 otpauth:// URI（可选）">
            <Input placeholder="otpauth://totp/..." prefix={<QrcodeOutlined />} />
          </Form.Item>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item name="algorithm" label="算法">
                <Select options={[
                  { value: 'SHA1', label: 'SHA1' },
                  { value: 'SHA256', label: 'SHA256' },
                  { value: 'SHA512', label: 'SHA512' },
                ]} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="digits" label="位数">
                <Select options={[
                  { value: 6, label: '6 位' },
                  { value: 8, label: '8 位' },
                ]} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="period" label="周期（秒）">
                <InputNumber min={15} max={120} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    </div>
  );
};

export default TOTPPage;