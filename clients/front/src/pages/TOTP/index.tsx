import React, { useEffect, useState, useRef, useCallback } from 'react';
import {
  Card, Table, Button, Space, Tag, Modal, Form, Input, Select,
  message, Progress, Typography, Tooltip, InputNumber, Row, Col, Upload,
} from 'antd';
import {
  PlusOutlined, DeleteOutlined, CopyOutlined, ClockCircleOutlined,
  ReloadOutlined, QrcodeOutlined, KeyOutlined, UploadOutlined,
  EyeOutlined, LockOutlined,
} from '@ant-design/icons';
import jsQR from 'jsqr';
import PageHeader from '../../components/PageHeader';
import { getTOTPList, getTOTPCode, createTOTP, deleteTOTP, getCards } from '../../api';
import type { TOTPEntry, Card as CardType } from '../../types';

const { Text } = Typography;

// localStorage key 前缀，按卡片 UUID 缓存 PIN
const PIN_CACHE_PREFIX = 'totp_pin_';

interface TOTPWithCode extends TOTPEntry {
  code?: string;
  remaining?: number;
  revealed?: boolean; // 是否已解锁显示验证码
}

/** 生成随机 Base32 密钥（n 字节，默认 20 字节 = 160 bit） */
const randomBase32 = (n = 20): string => {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < arr.length; i++) {
    value = (value << 8) | arr[i];
    bits += 8;
    while (bits >= 5) {
      output += CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += CHARS[(value << (5 - bits)) & 31];
  return output;
};

/** 解析 otpauth:// URI，返回表单字段 */
const parseOtpauthURI = (uri: string) => {
  try {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:') return null;
    const label = decodeURIComponent(url.pathname.replace(/^\/\/totp\//, ''));
    const [issuerFromLabel, accountFromLabel] = label.includes(':')
      ? label.split(':', 2)
      : ['', label];
    const params = url.searchParams;
    return {
      issuer: params.get('issuer') || issuerFromLabel || '',
      account: accountFromLabel || '',
      secret: params.get('secret') || '',
      algorithm: (params.get('algorithm') || 'SHA1').toUpperCase(),
      digits: parseInt(params.get('digits') || '6', 10),
      period: parseInt(params.get('period') || '30', 10),
    };
  } catch {
    return null;
  }
};

/** 从图片文件中解析 QR 码，返回文本内容 */
const decodeQRFromFile = (file: File): Promise<string> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d')!;
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const result = jsQR(imageData.data, imageData.width, imageData.height);
        if (result) resolve(result.data);
        else reject(new Error('未能识别二维码，请确保图片清晰'));
      };
      img.onerror = () => reject(new Error('图片加载失败'));
      img.src = e.target!.result as string;
    };
    reader.onerror = () => reject(new Error('文件读取失败'));
    reader.readAsDataURL(file);
  });
};

const TOTPPage: React.FC = () => {
  const [entries, setEntries] = useState<TOTPWithCode[]>([]);
  const [loading, setLoading] = useState(false);
  const [addVisible, setAddVisible] = useState(false);
  const [form] = Form.useForm();
  const [pinForm] = Form.useForm();
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [cards, setCards] = useState<CardType[]>([]);
  const [selectedCardUUID, setSelectedCardUUID] = useState<string>('');
  const [qrScanning, setQrScanning] = useState(false);
  // 当前已解锁的 PIN（内存中），空字符串表示未解锁
  const [cardPassword, setCardPassword] = useState<string>('');
  // PIN 输入弹窗
  const [pinVisible, setPinVisible] = useState(false);
  const [pinLoading, setPinLoading] = useState(false);
  // 用 ref 存最新 entries 和 PIN，避免 timer 闭包拿到旧值
  const entriesRef = useRef<TOTPWithCode[]>([]);
  const cardPasswordRef = useRef<string>('');

  // 读取缓存的 PIN
  const getCachedPin = (cardUUID: string) =>
    localStorage.getItem(`${PIN_CACHE_PREFIX}${cardUUID}`) || '';

  // 缓存 PIN
  const setCachedPin = (cardUUID: string, pin: string) => {
    if (pin) localStorage.setItem(`${PIN_CACHE_PREFIX}${cardUUID}`, pin);
    else localStorage.removeItem(`${PIN_CACHE_PREFIX}${cardUUID}`);
  };

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
      const newEntries = items.map((e: TOTPEntry) => ({ ...e }));
      setEntries(newEntries);
      entriesRef.current = newEntries;
    } catch (err: any) {
      message.error(err.message || '加载 TOTP 列表失败');
    } finally {
      setLoading(false);
    }
  };

  // 用 PIN 获取所有条目的验证码
  const fetchAllCodes = useCallback(async (pin: string) => {
    if (!pin) return;
    const current = entriesRef.current;
    if (current.length === 0) return;
    let hasError = false;
    for (const entry of current) {
      try {
        const resp = await getTOTPCode(entry.uuid, pin);
        setEntries(prev => {
          const next = prev.map(e =>
            e.uuid === entry.uuid ? { ...e, code: resp.code, revealed: true } : e
          );
          entriesRef.current = next;
          return next;
        });
      } catch (err: any) {
        if (!hasError) {
          hasError = true;
          message.error(err.message || '卡片 PIN 错误，请重新输入');
        }
      }
    }
    return !hasError;
  }, []);

  useEffect(() => {
    loadEntries();
    // 切换卡片时清空验证码和 PIN
    setCardPassword('');
    cardPasswordRef.current = '';
  }, [selectedCardUUID]);

  // 切换卡片后，尝试用缓存 PIN 自动解锁
  useEffect(() => {
    if (!selectedCardUUID) return;
    const cached = getCachedPin(selectedCardUUID);
    if (cached) {
      setCardPassword(cached);
      cardPasswordRef.current = cached;
    }
  }, [selectedCardUUID]);

  // 有 PIN 且有条目时自动获取验证码
  useEffect(() => {
    if (cardPassword && entriesRef.current.length > 0) {
      fetchAllCodes(cardPassword);
    }
  }, [cardPassword, fetchAllCodes]);

  // 每秒更新倒计时，周期切换时自动刷新验证码
  useEffect(() => {
    const prevRemainingMap = new Map<string, number>();

    timerRef.current = setInterval(() => {
      const pin = cardPasswordRef.current;
      const now = Math.floor(Date.now() / 1000);

      setEntries(prev => {
        const next = prev.map(e => {
          const period = e.period || 30;
          const remaining = period - (now % period);
          const prevRemaining = prevRemainingMap.get(e.uuid) ?? remaining;

          // 周期切换时（且有 PIN）刷新验证码
          if (pin && prevRemaining < remaining && prevRemaining <= 2) {
            getTOTPCode(e.uuid, pin).then(resp => {
              setEntries(p => {
                const updated = p.map(x =>
                  x.uuid === e.uuid ? { ...x, code: resp.code, remaining } : x
                );
                entriesRef.current = updated;
                return updated;
              });
            }).catch(() => {});
          }

          prevRemainingMap.set(e.uuid, remaining);
          return { ...e, remaining };
        });
        entriesRef.current = next;
        return next;
      });
    }, 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []); // 只挂载一次，通过 ref 访问最新 PIN

  const handleCopy = (code: string) => {
    navigator.clipboard.writeText(code);
    message.success('验证码已复制');
  };

  // 点击"查看验证码"按钮
  const handleReveal = () => {
    const cached = getCachedPin(selectedCardUUID);
    if (cached) {
      // 有缓存直接用
      setCardPassword(cached);
      cardPasswordRef.current = cached;
    } else {
      // 弹出 PIN 输入框
      pinForm.resetFields();
      setPinVisible(true);
    }
  };

  // 确认 PIN 输入
  const handlePinConfirm = async () => {
    const values = await pinForm.validateFields().catch(() => null);
    if (!values) return;
    const pin: string = values.pin;
    setPinLoading(true);
    try {
      // 先尝试获取第一条验证码验证 PIN 是否正确
      const first = entriesRef.current[0];
      if (first) {
        await getTOTPCode(first.uuid, pin);
      }
      // PIN 正确，保存并获取所有验证码
      setCardPassword(pin);
      cardPasswordRef.current = pin;
      setCachedPin(selectedCardUUID, pin);
      setPinVisible(false);
      fetchAllCodes(pin);
    } catch (err: any) {
      message.error(err.message || '卡片 PIN 错误');
    } finally {
      setPinLoading(false);
    }
  };

  // 锁定（清除 PIN 和验证码）
  const handleLock = () => {
    setCardPassword('');
    cardPasswordRef.current = '';
    setCachedPin(selectedCardUUID, '');
    setEntries(prev => {
      const next = prev.map(e => ({ ...e, code: undefined, revealed: false }));
      entriesRef.current = next;
      return next;
    });
    message.success('已锁定');
  };

  const handleAdd = async () => {
    try {
      const values = await form.validateFields();
      await createTOTP({ ...values, card_uuid: selectedCardUUID });
      message.success('TOTP 条目已添加');
      // 添加成功后缓存 PIN
      const pin = values.card_password || '';
      setCardPassword(pin);
      cardPasswordRef.current = pin;
      setCachedPin(selectedCardUUID, pin);
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

  const isUnlocked = !!cardPassword;

  const columns = [
    {
      title: 'UUID',
      dataIndex: 'uuid',
      width: 400,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Text copyable={{ text: v }}>
            {v}
          </Text>
        </Tooltip>
      ),
    },
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
      width: 240,
      render: (_: unknown, record: TOTPWithCode) => {
        const period = record.period || 30;
        const remaining = record.remaining || 0;
        const percent = (remaining / period) * 100;
        const isUrgent = remaining <= 5;

        if (!isUnlocked || !record.revealed) {
          // 未解锁：显示遮罩
          return (
            <Space>
              <span style={{
                fontSize: 22, fontWeight: 700, letterSpacing: 4,
                color: '#ccc', fontFamily: 'monospace', userSelect: 'none',
              }}>
                ••••••
              </span>
              <Button
                type="text" size="small" icon={<EyeOutlined />}
                onClick={handleReveal}
                style={{ color: '#1677ff' }}
              >
                查看
              </Button>
            </Space>
          );
        }

        return (
          <Space>
            <Tooltip title="点击复制">
              <Button
                type="text"
                size="large"
                style={{
                  fontSize: 22, fontWeight: 700, letterSpacing: 4,
                  color: isUrgent ? '#ff4d4f' : '#1677ff',
                }}
                icon={<CopyOutlined style={{ fontSize: 14 }} />}
                onClick={() => record.code && handleCopy(record.code)}
              >
                {record.code || '------'}
              </Button>
            </Tooltip>
            <Progress
              type="circle"
              percent={percent}
              size={28}
              format={() => `${remaining}`}
              strokeColor={isUrgent ? '#ff4d4f' : '#1677ff'}
              railColor="#f0f0f0"
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
    <div>
      <PageHeader
        icon={<ClockCircleOutlined />}
        title="TOTP 验证器"
        tags={
          <Space size={8}>
            <Tag color="blue">{entries.length} 个条目</Tag>
            <Select
              size="small"
              style={{ width: 260 }}
              placeholder="选择卡片"
              value={selectedCardUUID || undefined}
              onChange={(v) => { setSelectedCardUUID(v); }}
              options={cards.map(c => ({ value: c.uuid, label: c.card_name }))}
            />
          </Space>
        }
        extra={
          <Space size={8}>
            {isUnlocked && (
              <Tag color="green" icon={<LockOutlined />} style={{ cursor: 'pointer' }} onClick={handleLock}>
                已解锁 · 点击锁定
              </Tag>
            )}
            {!isUnlocked ? (
              <Button icon={<EyeOutlined />} onClick={handleReveal} size="small" type="primary" ghost>
                输入 PIN 查看验证码
              </Button>
            ) : (
              <Button icon={<ReloadOutlined />} onClick={() => fetchAllCodes(cardPassword)} size="small">
                刷新
              </Button>
            )}
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setAddVisible(true)} size="small">
              添加 TOTP
            </Button>
          </Space>
        }
      />
      <Card>
        <Table
          rowKey="uuid"
          columns={columns}
          dataSource={entries}
          loading={loading}
          pagination={false}
        />
      </Card>

      {/* PIN 输入弹窗 */}
      <Modal
        title={<Space><LockOutlined />输入卡片 PIN</Space>}
        open={pinVisible}
        onOk={handlePinConfirm}
        onCancel={() => setPinVisible(false)}
        confirmLoading={pinLoading}
        okText="解锁"
        width={360}
      >
        <Form form={pinForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item
            name="pin"
            label="卡片 PIN"
            rules={[{ required: true, message: '请输入卡片 PIN' }]}
            extra="PIN 将缓存在本地浏览器，下次自动解锁"
          >
            <Input.Password
              placeholder="请输入卡片 PIN"
              autoComplete="current-password"
              autoFocus
              onPressEnter={handlePinConfirm}
            />
          </Form.Item>
        </Form>
      </Modal>

      {/* 添加 TOTP 对话框 */}
      <Modal
        title="添加 TOTP 条目"
        open={addVisible}
        onOk={handleAdd}
        onCancel={() => { setAddVisible(false); form.resetFields(); }}
        width={520}
      >
        <Form form={form} layout="vertical" initialValues={{ algorithm: 'SHA1', digits: 6, period: 30 }}>
          <Form.Item label="扫描二维码（可选）">
            <Upload
              accept="image/*"
              showUploadList={false}
              beforeUpload={(file) => {
                setQrScanning(true);
                decodeQRFromFile(file)
                  .then((text) => {
                    const parsed = parseOtpauthURI(text);
                    if (parsed) {
                      form.setFieldsValue(parsed);
                      message.success('二维码解析成功，已自动填充');
                    } else {
                      form.setFieldValue('secret', text.trim());
                      message.info('已将二维码内容填入密钥字段');
                    }
                  })
                  .catch((err) => message.error(err.message))
                  .finally(() => setQrScanning(false));
                return false;
              }}
            >
              <Button icon={<QrcodeOutlined />} loading={qrScanning}>
                {qrScanning ? '识别中...' : '上传二维码图片'}
              </Button>
            </Upload>
            <Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
              支持 PNG/JPG，自动解析 otpauth:// 链接并填充表单
            </Text>
          </Form.Item>

          <Form.Item name="issuer" label="发行者" rules={[{ required: true, message: '请输入发行者名称' }]}>
            <Input placeholder="例如：GitHub、Google" prefix={<KeyOutlined />} />
          </Form.Item>
          <Form.Item name="account" label="账户名（可选）">
            <Input placeholder="例如：user@example.com" />
          </Form.Item>
          <Form.Item name="secret" label="密钥 (Base32)" rules={[{ required: true, message: '请输入 Base32 编码的密钥' }]}>
            <Space.Compact style={{ width: '100%' }}>
              <Form.Item name="secret" noStyle>
                <Input placeholder="JBSWY3DPEHPK3PXP..." />
              </Form.Item>
              <Tooltip title="随机生成 Base32 密钥（160 bit）">
                <Button icon={<ReloadOutlined />} onClick={() => form.setFieldValue('secret', randomBase32())} />
              </Tooltip>
            </Space.Compact>
          </Form.Item>
          <Form.Item name="uri" label="或粘贴 otpauth:// URI（可选）">
            <Space.Compact style={{ width: '100%' }}>
              <Form.Item name="uri" noStyle>
                <Input placeholder="otpauth://totp/..." prefix={<QrcodeOutlined />} />
              </Form.Item>
              <Tooltip title="解析 URI 并填充表单">
                <Button
                  icon={<UploadOutlined />}
                  onClick={() => {
                    const uri = form.getFieldValue('uri');
                    if (!uri) { message.warning('请先粘贴 otpauth:// URI'); return; }
                    const parsed = parseOtpauthURI(uri);
                    if (parsed) { form.setFieldsValue(parsed); message.success('URI 解析成功'); }
                    else message.error('URI 格式不正确，请检查');
                  }}
                >解析</Button>
              </Tooltip>
            </Space.Compact>
          </Form.Item>
          <Form.Item name="card_password" label="卡片 PIN" rules={[{ required: true, message: '请输入卡片 PIN 以加密存储' }]}>
            <Input.Password placeholder="卡片登录 PIN" autoComplete="new-password" />
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
                <Select options={[{ value: 6, label: '6 位' }, { value: 8, label: '8 位' }]} />
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