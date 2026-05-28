// 证书管理页：
//   - 顶部账号过滤 Radio（当前账号 / 全部已登录）
//   - 卡片选择器（从过滤后的卡片中选择）
//   - 云端证书行尾"下发"按钮 → 下发向导 Modal
import React, { useEffect, useState } from 'react';
import {
  Card, Table, Button, Space, Tag, Modal, message, Radio,
  Descriptions, Typography, Tooltip, Drawer, Select, Form, Input, Empty, Upload, Alert,
} from 'antd';
import {
  DeleteOutlined, EyeOutlined, ImportOutlined,
  ExportOutlined, SafetyCertificateOutlined, CopyOutlined,
  KeyOutlined, CloudDownloadOutlined, ReloadOutlined, InboxOutlined,
  LinkOutlined, GlobalOutlined, LockOutlined,
} from '@ant-design/icons';
import PageHeader from '../../components/PageHeader';
import type { Certificate, Card as CardType, CertDetail } from '../../types';
import { getCerts, deleteCert, getCards, deliverCert, getCertDetail, exportCertKey, importCertWithKey } from '../../api';
import { useAppStore } from '../../store/appStore';
import { useAuthStore } from '../../store/auth';
import dayjs from 'dayjs';

const { Text } = Typography;

const certTypeColors: Record<string, string> = {
  x509: 'blue', ssh: 'green', gpg: 'purple', totp: 'orange',
  fido: 'cyan', login: 'gold', text: 'default', note: 'lime', payment: 'red',
};
const certTypeLabels: Record<string, string> = {
  x509: 'X509', ssh: 'SSH 密钥', gpg: 'GPG 证书', totp: 'TOTP 认证',
  fido: 'FIDO', login: '登录信息', text: '密钥文本', note: '安全笔记', payment: '支付信息',
};

// Slot 类型中文标签
const slotLabel = (t: string) => {
  switch (t) {
    case 'cloud': return '云端智能卡';
    case 'tpm2': return 'TPM2 硬件卡';
    case 'tpmsc': return 'TPM 智能卡';
    default: return '本地智能卡';
  }
};

const CertsPage: React.FC = () => {
  const { darkMode } = useAppStore();
  const activeUUID = useAuthStore((s) => s.activeUUID);

  const [filterMode, setFilterMode] = useState<'active' | 'all'>('active');
  const [allCards, setAllCards] = useState<CardType[]>([]);
  const [selectedCardUUID, setSelectedCardUUID] = useState<string>('');
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState(false);
  const [cardsLoading, setCardsLoading] = useState(false);
  const [detailVisible, setDetailVisible] = useState(false);
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);

  // 下发向导
  const [deliverOpen, setDeliverOpen] = useState(false);
  const [deliverCertItem, setDeliverCertItem] = useState<Certificate | null>(null);
  const [deliverForm] = Form.useForm();
  const [delivering, setDelivering] = useState(false);

  // 证书详情解析
  const [certDetail, setCertDetail] = useState<CertDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // 表格内联详情缓存：certUUID -> CertDetail
  const [certDetailsMap, setCertDetailsMap] = useState<Record<string, CertDetail | null>>({});

  // 密钥导出弹窗
  const [keyExportOpen, setKeyExportOpen] = useState(false);
  const [keyExportCert, setKeyExportCert] = useState<Certificate | null>(null);
  const [keyExportForm] = Form.useForm();
  const [keyExporting, setKeyExporting] = useState(false);

  // 证书+密钥导入弹窗
  const [importOpen, setImportOpen] = useState(false);
  const [importForm] = Form.useForm();
  const [importing, setImporting] = useState(false);

  // 加载卡片列表（按过滤模式）
  const loadCards = async () => {
    setCardsLoading(true);
    try {
      const params: any = { page: 1, page_size: 200 };
      if (filterMode === 'active' && activeUUID) {
        params.user_uuid = activeUUID;
      }
      const res = await getCards(params);
      const items = res?.items;
      const allItems = Array.isArray(items) ? items : [];
      // 过滤掉已禁用或已过期的卡片（其证书不显示在证书管理中）
      const now = new Date();
      const cards = allItems.filter((c) => {
        if (c.enabled === false) return false;
        if (c.expires_at && new Date(c.expires_at) < now) return false;
        return true;
      });
      setAllCards(cards);
      // 自动选中第一张卡片
      if (cards.length > 0 && !cards.find((c) => c.uuid === selectedCardUUID)) {
        setSelectedCardUUID(cards[0].uuid);
      }
      if (cards.length === 0) {
        setSelectedCardUUID('');
        setCerts([]);
      }
    } catch { /* ignore */ } finally {
      setCardsLoading(false);
    }
  };

  // 加载证书列表
  const loadCerts = async () => {
    if (!selectedCardUUID) { setCerts([]); return; }
    setLoading(true);
    try {
      const data = await getCerts(selectedCardUUID);
      setCerts(Array.isArray(data) ? data : []);
    } catch (err: any) {
      message.error(err.message || '加载证书列表失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadCards(); }, [filterMode]);
  useEffect(() => { loadCerts(); }, [selectedCardUUID]);

  // 证书列表加载后，批量解析 x509 证书详情用于表格展示
  useEffect(() => {
    if (certs.length === 0 || !selectedCardUUID) {
      setCertDetailsMap({});
      return;
    }
    const x509Certs = certs.filter((c) => c.cert_type === 'x509' && c.cert_content);
    if (x509Certs.length === 0) return;
    const loadDetails = async () => {
      const map: Record<string, CertDetail | null> = {};
      await Promise.allSettled(
        x509Certs.map(async (cert) => {
          try {
            const detail = await getCertDetail(selectedCardUUID, cert.uuid);
            map[cert.uuid] = detail;
          } catch {
            map[cert.uuid] = null;
          }
        })
      );
      setCertDetailsMap(map);
    };
    loadDetails();
  }, [certs, selectedCardUUID]);

  const handleDelete = (cert: Certificate) => {
    let confirmUUID = '';
    let confirmPassword = '';
    Modal.confirm({
      title: '确认删除证书',
      icon: null,
      width: 440,
      okType: 'danger',
      okText: '删除',
      cancelText: '取消',
      content: (
        <div style={{ marginTop: 12 }}>
          <Alert message={`确定要删除证书 ${cert.uuid.slice(0, 8)}... 吗？此操作不可恢复。`} type="error" showIcon style={{ marginBottom: 12 }} />
          <div style={{ marginBottom: 8 }}>
            <Text style={{ fontSize: 12 }}>请输入证书 UUID 以确认：</Text>
            <Input
              placeholder={cert.uuid}
              style={{ marginTop: 4, fontFamily: 'monospace', fontSize: 12 }}
              onChange={(e) => { confirmUUID = e.target.value; }}
            />
          </div>
          <div>
            <Text style={{ fontSize: 12 }}>当前用户密码：</Text>
            <Input.Password
              placeholder="验证当前用户身份"
              style={{ marginTop: 4 }}
              onChange={(e) => { confirmPassword = e.target.value; }}
            />
          </div>
        </div>
      ),
      onOk: async () => {
        if (confirmUUID !== cert.uuid) {
          message.error('UUID 不匹配，删除已取消');
          return Promise.reject();
        }
        if (!confirmPassword) {
          message.error('请输入用户密码');
          return Promise.reject();
        }
        try {
          await deleteCert(selectedCardUUID, cert.uuid);
          message.success('证书已删除');
          loadCerts();
        } catch (err: any) {
          message.error(err.message || '删除失败');
          return Promise.reject();
        }
      },
    });
  };

  const handleExportCrt = (cert: Certificate) => {
    if (!cert.cert_content) {
      message.error('该证书没有证书内容，无法导出');
      return;
    }
    try {
      // cert_content 是 base64 编码的证书数据（可能是 PEM 格式或 DER 格式）
      const decoded = atob(cert.cert_content);
      let pemContent: string;
      if (decoded.startsWith('-----BEGIN')) {
        // 已经是 PEM 格式，直接使用
        pemContent = decoded;
      } else {
        // 原始 DER 数据，需要包装为 PEM 格式
        // cert_content 本身就是 DER 的 base64 编码，直接用作 PEM body
        const lines = cert.cert_content.match(/.{1,64}/g) || [];
        pemContent = `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
      }
      const blob = new Blob([pemContent], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${cert.uuid.slice(0, 8)}.crt`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      message.error(err.message || '导出失败');
    }
  };

  const showDetail = (cert: Certificate) => {
    loadCertDetail(cert);
  };

  // 打开下发向导
  const openDeliver = (cert: Certificate) => {
    setDeliverCertItem(cert);
    deliverForm.resetFields();
    deliverForm.setFieldsValue({ target: 'database' });
    setDeliverOpen(true);
  };

  // 执行下发
  const handleDeliver = async () => {
    if (!deliverCertItem) return;
    try {
      const values = await deliverForm.validateFields();
      setDelivering(true);
      // 找到当前卡片以获取 cloud_url
      const srcCard = allCards.find((c) => c.uuid === selectedCardUUID);
      await deliverCert({
        cert_uuid: deliverCertItem.uuid,
        source_card_uuid: selectedCardUUID,
        source_cloud_url: srcCard?.cloud_url,
        target: values.target,
        target_card_uuid: values.target === 'card' ? values.target_card_uuid : undefined,
        card_password: values.target === 'card' ? values.card_password : undefined,
        remark: values.remark,
      });
      message.success('证书下发成功');
      setDeliverOpen(false);
    } catch (e: any) {
      if (e.message) message.error(e.message);
    } finally {
      setDelivering(false);
    }
  };

  const selectedCard = allCards.find((c) => c.uuid === selectedCardUUID);
  const isCloudCard = selectedCard?.slot_type === 'cloud';
  // 本地/TPM2 卡片（用于下发目标选择）
  const localCards = allCards.filter((c) => c.slot_type === 'local' || c.slot_type === 'tpm2');

  const columns = [
    {
      title: '类型', width: 100,
      render: (_: unknown, record: Certificate) => (
        <div>
          <Tag color={certTypeColors[record.cert_type] || 'default'}>{certTypeLabels[record.cert_type] || record.cert_type}</Tag>
          <Tag color={record.slot_type === 'cloud' ? 'purple' : record.slot_type === 'tpm2' ? 'cyan' : 'green'} style={{ fontSize: 10 }}>{record.slot_type}</Tag>
        </div>
      ),
    },
    {
      title: '证书信息', width: 360, ellipsis: true,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
        if (!detail) return <Text type="secondary">未知</Text>;
        const subjectParts = [detail.organization, detail.org_unit, detail.country].filter(Boolean);
        return (
          <div>
            <Text strong style={{ fontSize: 12 }}>{detail.common_name || '未知'}</Text>
            {detail.is_ca && <Tag color="red" style={{ marginLeft: 4, fontSize: 10 }}>CA</Tag>}
            {subjectParts.length > 0 && (
              <div><Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{subjectParts.join(' / ')}</Text></div>
            )}
          </div>
        );
      },
    },
    // {
    //   title: '颁发者', width: 240, ellipsis: true,
    //   render: (_: unknown, record: Certificate) => {
    //     const detail = certDetailsMap[record.uuid];
    //     if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
    //     if (!detail) return <Text type="secondary">未知</Text>;
    //     return (
    //       <Tooltip title={
    //         <div>
    //           <div>CN: {detail.issuer_cn || '-'}</div>
    //           {detail.issuer_org && <div>O: {detail.issuer_org}</div>}
    //           {detail.issuer_ou && <div>OU: {detail.issuer_ou}</div>}
    //           {detail.issuer_country && <div>C: {detail.issuer_country}</div>}
    //         </div>
    //       }>
    //         <div>
    //           <span style={{ fontSize: 12 }}>{detail.issuer_cn}{detail.is_self_signed && <Tag color="orange" style={{ marginLeft: 4, fontSize: 10 }}>自签名</Tag>}</span>
    //           {detail.issuer_org && <div><Text style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#999' }}>{detail.issuer_org}</Text></div>}
    //         </div>
    //       </Tooltip>
    //     );
    //   },
    // },
    {
      title: '拓展信息', width: 200, ellipsis: true,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
        if (!detail) return <Text type="secondary">-</Text>;
        const items: { type: string; value: string }[] = [
          ...(detail.san_dns || []).map(v => ({ type: 'DNS', value: v })),
          ...(detail.san_ip || []).map(v => ({ type: 'IP', value: v })),
          ...(detail.san_email || []).map(v => ({ type: 'Email', value: v })),
          ...(detail.san_uri || []).map(v => ({ type: 'URI', value: v })),
        ];
        if (items.length === 0) return <Text type="secondary">-</Text>;
        return (
          <Tooltip title={
            <div>
              {items.map((s, i) => <div key={i}><Tag color="blue" style={{ fontSize: 10 }}>{s.type}</Tag> {s.value}</div>)}
            </div>
          }>
            <div style={{ fontSize: 11, color: darkMode ? '#8b949e' : '#666' }}>
              {items.slice(0, 2).map((s, i) => <div key={i}><Tag style={{ fontSize: 9, padding: '0 4px' }}>{s.type}</Tag>{s.value}</div>)}
              {items.length > 2 && <Text type="secondary" style={{ fontSize: 10 }}>+{items.length - 2} 更多</Text>}
            </div>
          </Tooltip>
        );
      },
    },
    {
      title: '有效期', width: 130,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
        if (!detail) return <Text type="secondary">-</Text>;
        const now = dayjs();
        const notAfter = dayjs(detail.not_after);
        const expired = notAfter.isBefore(now);
        return (
          <div style={{ fontSize: 11 }}>
            <div style={{ color: darkMode ? '#8b949e' : '#999' }}>生效日期：{dayjs(detail.not_before).format('YYYY-MM-DD')}
              <br></br> 失效日期：{notAfter.format('YYYY-MM-DD')} {expired && <Tag color="red" style={{ marginLeft: 4, fontSize: 10 }}>已过期</Tag>}
            </div>
          </div>
        );
      },
    },
    {
      title: '证书算法', width: 120, ellipsis: true,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
        if (!detail) return <Text type="secondary">-</Text>;
        return (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Space size={4}>
              <Tag color="geekblue" style={{ fontSize: 10, margin: 0 }}>签名</Tag>
              <Text style={{ fontSize: 11 }}>{detail.signature_algo}</Text>
            </Space>
            <Space size={4}>
              <Tag color="volcano" style={{ fontSize: 10, margin: 0 }}>公钥</Tag>
              <Text style={{ fontSize: 11 }}>{detail.public_key_algo}{detail.key_bits ? ` (${detail.key_bits}bit)` : ''}</Text>
            </Space>
          </div>
        );
      },
    },
    {
      title: '密钥用途', width: 120, ellipsis: true,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509') return <Text type="secondary">-</Text>;
        if (!detail) return <Text type="secondary">-</Text>;
        const ku = detail.key_usage || [];
        const eku = detail.ext_key_usage || [];
        if (ku.length === 0 && eku.length === 0) return <Text type="secondary">-</Text>;
        return (
          <Tooltip title={<>{ku.length > 0 && <div>密钥用途: {ku.join(', ')}</div>}{eku.length > 0 && <div>扩展用途: {eku.join(', ')}</div>}</>}>
            <div style={{ fontSize: 11 }}>
              {ku.length > 0 && <div>{ku.slice(0, 2).join(', ')}{ku.length > 2 ? '...' : ''}</div>}
              {eku.length > 0 && <div style={{ color: darkMode ? '#7ee787' : '#389e0d' }}>{eku.slice(0, 2).join(', ')}{eku.length > 2 ? '...' : ''}</div>}
            </div>
          </Tooltip>
        );
      },
    },
    // {
    //   title: '链接', width: 80,
    //   render: (_: unknown, record: Certificate) => {
    //     const detail = certDetailsMap[record.uuid];
    //     if (record.cert_type !== 'x509' || !detail) return <Text type="secondary">-</Text>;
    //     const hasOCSP = detail.ocsp_servers && detail.ocsp_servers.length > 0;
    //     const hasCRL = detail.crl_dist_points && detail.crl_dist_points.length > 0;
    //     const hasAIA = detail.issuing_cert_url && detail.issuing_cert_url.length > 0;
    //     const hasCPS = detail.cps_urls && detail.cps_urls.length > 0;
    //     if (!hasOCSP && !hasCRL && !hasAIA && !hasCPS) return <Text type="secondary">-</Text>;
    //     return (
    //       <Space size={2}>
    //         {hasOCSP && <Tooltip title={`OCSP: ${detail.ocsp_servers!.join(', ')}`}><GlobalOutlined style={{ color: '#1677ff', fontSize: 13 }} /></Tooltip>}
    //         {hasCRL && <Tooltip title={`CRL: ${detail.crl_dist_points!.join(', ')}`}><LinkOutlined style={{ color: '#fa8c16', fontSize: 13 }} /></Tooltip>}
    //         {hasAIA && <Tooltip title={`AIA: ${detail.issuing_cert_url!.join(', ')}`}><SafetyCertificateOutlined style={{ color: '#52c41a', fontSize: 13 }} /></Tooltip>}
    //         {hasCPS && <Tooltip title={`CPS: ${detail.cps_urls!.join(', ')}`}><LockOutlined style={{ color: '#722ed1', fontSize: 13 }} /></Tooltip>}
    //       </Space>
    //     );
    //   },
    // },
    {
      title: '序列号/哈希', width: 200, ellipsis: true,
      render: (_: unknown, record: Certificate) => {
        const detail = certDetailsMap[record.uuid];
        if (record.cert_type !== 'x509' || !detail) return <Text type="secondary">-</Text>;
        const sn = detail.serial_number?.toUpperCase() || '';
        const sha1 = (detail.sha1_fingerprint || '').replace(/:/g, '').toUpperCase();
        const sha256 = (detail.sha256_fingerprint || '').replace(/:/g, '').toUpperCase();
        return (
          <Tooltip title={
            <div>
              <div>序列号: {sn}</div>
              <div>SHA-1: {sha1}</div>
              {sha256 && <div>SHA-256: {sha256}</div>}
            </div>
          }>
            <div style={{ fontSize: 11 }}>
              <div><Tag style={{ fontSize: 9, padding: '0 3px', margin: 0 }}>SN</Tag> <Text copyable={{ text: sn }} style={{ fontSize: 10, fontFamily: 'monospace' }}>{sn}</Text></div>
              <div><Tag style={{ fontSize: 9, padding: '0 3px', margin: 0 }}>SHA1</Tag> <Text copyable={{ text: sha1 }} style={{ fontSize: 10, fontFamily: 'monospace', color: darkMode ? '#8b949e' : '#999' }}>{sha1}</Text></div>
            </div>
          </Tooltip>
        );
      },
    },
    { title: '备注', dataIndex: 'remark', width: 100, ellipsis: true, render: (v: string) => v || <Text type="secondary">-</Text> },
    {
      title: '操作', width: 150, fixed: 'right' as const,
      render: (_: unknown, record: Certificate) => (
        <Space size={4} wrap>
          <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => showDetail(record)}>
            详情
          </Button>
          {isCloudCard && (
            <Button type="link" size="small" icon={<CloudDownloadOutlined />} onClick={() => openDeliver(record)}>
              下发
            </Button>
          )}
          <Button type="link" size="small" icon={<ExportOutlined />} onClick={() => handleExportCrt(record)}>
            导出
          </Button>
          <Button type="link" size="small" icon={<KeyOutlined />} onClick={() => { setKeyExportCert(record); setKeyExportOpen(true); }}>
            密钥
          </Button>
          <Button type="link" size="small" danger icon={<DeleteOutlined />} onClick={() => handleDelete(record)}>
            删除
          </Button>
        </Space>
      ),
    },
  ];

  // 查看证书详情时加载解析信息
  const loadCertDetail = async (cert: Certificate) => {
    setSelectedCert(cert);
    setDetailVisible(true);
    setCertDetail(null);
    if (cert.cert_type === 'x509' && cert.cert_content && selectedCardUUID) {
      setDetailLoading(true);
      try {
        const detail = await getCertDetail(selectedCardUUID, cert.uuid);
        setCertDetail(detail);
      } catch { /* 解析失败不影响显示 */ } finally {
        setDetailLoading(false);
      }
    }
  };

  // 导出证书密钥
  const handleKeyExport = async () => {
    if (!keyExportCert || !selectedCardUUID) return;
    try {
      const values = await keyExportForm.validateFields();
      setKeyExporting(true);
      const result = await exportCertKey(selectedCardUUID, keyExportCert.uuid, {
        password: values.password,
        admin_key: values.admin_key,
        format: values.format || 'pem',
        pfx_password: values.pfx_password,
      });

      if (values.format === 'pfx' && result.pfx_data) {
        // PFX 格式：直接下载 pfx 文件
        const binary = atob(result.pfx_data);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        const blob = new Blob([bytes], { type: 'application/x-pkcs12' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${keyExportCert.uuid.slice(0, 8)}.pfx`;
        a.click();
        URL.revokeObjectURL(url);
        message.success('PFX 文件已下载');
      } else {
        // PEM 格式：下载 .key 和 .crt 文件
        if (result.private_key) {
          const keyPem = atob(result.private_key);
          const keyBlob = new Blob([keyPem], { type: 'application/x-pem-file' });
          const keyUrl = URL.createObjectURL(keyBlob);
          const a = document.createElement('a');
          a.href = keyUrl;
          a.download = `${keyExportCert.uuid.slice(0, 8)}.key`;
          a.click();
          URL.revokeObjectURL(keyUrl);
        }
        if (result.certificate) {
          const certPem = atob(result.certificate);
          const certBlob = new Blob([certPem], { type: 'application/x-pem-file' });
          const certUrl = URL.createObjectURL(certBlob);
          const a = document.createElement('a');
          a.href = certUrl;
          a.download = `${keyExportCert.uuid.slice(0, 8)}.crt`;
          a.click();
          URL.revokeObjectURL(certUrl);
        }
        message.success('密钥和证书文件已下载');
      }
      setKeyExportOpen(false);
      keyExportForm.resetFields();
    } catch (e: any) {
      message.error(e.message || '导出失败');
    } finally {
      setKeyExporting(false);
    }
  };

  // 导入证书+密钥
  const handleImport = async () => {
    if (!selectedCardUUID) return;
    try {
      const values = await importForm.validateFields();
      setImporting(true);
      await importCertWithKey(selectedCardUUID, {
        mode: values.mode || 'pem',
        cert_pem: values.cert_pem,
        key_pem: values.key_pem,
        pfx_b64: values.pfx_b64,
        pfx_password: values.pfx_password,
        card_password: values.card_password,
        remark: values.remark,
      });
      message.success('证书导入成功');
      setImportOpen(false);
      importForm.resetFields();
      loadCerts();
    } catch (e: any) {
      message.error(e.message || '导入失败');
    } finally {
      setImporting(false);
    }
  };

  const cardStyle = {
    background: darkMode ? '#161b22' : '#fff',
    border: darkMode ? '1px solid #21262d' : '1px solid #f0f0f0',
    borderRadius: 12,
  };

  return (
    <div>
      <PageHeader
        icon={<SafetyCertificateOutlined />}
        title="用户证书管理"
        tags={
          <Radio.Group value={filterMode} onChange={(e) => { setFilterMode(e.target.value); }} size="small" buttonStyle="solid">
            <Radio.Button value="active">当前账号</Radio.Button>
            <Radio.Button value="all">全部已登录</Radio.Button>
          </Radio.Group>
        }
        extra={
          <>
            <Select
              style={{ width: 240 }}
              placeholder="选择卡片"
              value={selectedCardUUID || undefined}
              onChange={(v) => setSelectedCardUUID(v)}
              loading={cardsLoading}
              size="small"
              options={allCards.map((c) => ({
                value: c.uuid,
                label: (
                  <Space size={4}>
                    <Tag color={c.slot_type === 'cloud' ? 'purple' : c.slot_type === 'tpm2' ? 'cyan' : 'green'} style={{ fontSize: 11 }}>
                      {slotLabel(c.slot_type)}
                    </Tag>
                    {c.card_name}
                  </Space>
                ),
              }))}
            />
            <Button icon={<ReloadOutlined />} onClick={loadCerts} size="small">刷新</Button>
            <Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)} disabled={!selectedCardUUID} size="small">
              导入证书
            </Button>
          </>
        }
      />
      <Card style={cardStyle} styles={{ body: { padding: 0 } }}>
        {!selectedCardUUID ? (
          <Empty description="请选择一张卡片查看证书" image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ padding: 40 }} />
        ) : (
          <Table
            rowKey="uuid" columns={columns} dataSource={certs} loading={loading}
            pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
            scroll={{ x: 1200 }}
            size="small"
            className="nowrap-table"
            expandable={{
              expandedRowRender: (record: Certificate) => {
                const detail = certDetailsMap[record.uuid];
                if (record.cert_type !== 'x509' || !detail) {
                  return <Text type="secondary">非 X.509 证书或详情加载中...</Text>;
                }
                return (
                  <div style={{ padding: '8px 16px' }}>
                    <Descriptions column={10} size="small" bordered labelStyle={{ width: 110 }}>
                      {/* 行1: 使用者 CN / 国家 / 省份 / 城市 */}
                      <Descriptions.Item label="使用者" span={5}>{detail.common_name || '-'}</Descriptions.Item>
                      <Descriptions.Item label="国家CC" span={1}>{detail.country || '-'}</Descriptions.Item>
                      <Descriptions.Item label="所在省" span={2}>{detail.state || '-'}</Descriptions.Item>
                      <Descriptions.Item label="所在市" span={2}>{detail.locality || '-'}</Descriptions.Item>

                      {/* 行2: 组织 / 部门 / 管辖地 / 公司序列号 / 描述 */}
                      <Descriptions.Item label="组织" span={5}>{detail.organization || '-'}</Descriptions.Item>
                      <Descriptions.Item label="部门" span={3}>{detail.org_unit || '-'}</Descriptions.Item>
                      <Descriptions.Item label="管辖地" span={2}>{detail.street || '-'}</Descriptions.Item>
                      <Descriptions.Item label="描述" span={5}>{detail.description || '-'}</Descriptions.Item>
                      <Descriptions.Item label="序列号" span={5}>{detail.subject_serial || '-'}</Descriptions.Item>


                      {/* 行3: 颁发者 CN / 国家 / 省份 / 城市 */}
                      <Descriptions.Item label="颁发者" span={5}>{detail.issuer_cn || '-'}</Descriptions.Item>
                      <Descriptions.Item label="国家CC" span={1}>{detail.issuer_country || '-'}</Descriptions.Item>
                      <Descriptions.Item label="所在省" span={2}>{detail.issuer_state || '-'}</Descriptions.Item>
                      <Descriptions.Item label="所在市" span={2}>{detail.issuer_locality || '-'}</Descriptions.Item>

                      {/* 行4: 颁发者组织 / 部门 / 管辖地 / 序列号 / 描述 */}
                      <Descriptions.Item label="组织" span={5}>{detail.issuer_org || '-'}</Descriptions.Item>
                      <Descriptions.Item label="部门" span={3}>{detail.issuer_ou || '-'}</Descriptions.Item>
                      <Descriptions.Item label="管辖地" span={2}>{detail.issuer_street || '-'}</Descriptions.Item>
                      <Descriptions.Item label="描述" span={5}>{detail.issuer_description || '-'}</Descriptions.Item>
                      <Descriptions.Item label="序列号" span={5}>{detail.issuer_serial || '-'}</Descriptions.Item>


                      {/* 行5: 基本约束 / 公钥算法 / 签名算法 */}
                      <Descriptions.Item label="基本约束" span={5}>
                        {detail.is_ca
                          ? <Tag color="red">CA 证书{detail.max_path_len_zero ? '（路径: 0）' : detail.max_path_len > 0 ? `（路径: ${detail.max_path_len}）` : ''}</Tag>
                          : <Tag>终端证书 - {detail.is_self_signed ? '自签名' : '三方'}</Tag>}
                      </Descriptions.Item>
                      <Descriptions.Item label="公钥算法" span={3}>{detail.public_key_algo}{detail.key_bits ? ` (${detail.key_bits} bits)` : ''}</Descriptions.Item>
                      <Descriptions.Item label="签名算法" span={2}>{detail.signature_algo}</Descriptions.Item>


                      {/* 行6: 颁发日期 / 有效期至 / 序列号 */}
                      <Descriptions.Item label="颁发日期" span={5}>{dayjs(detail.not_before).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                      <Descriptions.Item label="有效期至" span={3}>{dayjs(detail.not_after).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                      <Descriptions.Item label="序列号" span={2}><Text copyable>{detail.serial_number}</Text></Descriptions.Item>

                      {/* 行7: SHA-1 / SHA-256 */}
                      <Descriptions.Item label="SHA1-160" span={5}>
                        <Text copyable>{(detail.sha1_fingerprint || '').replace(/:/g, '').toUpperCase()}</Text>
                      </Descriptions.Item>
                      <Descriptions.Item label="SHA2-256" span={5}>
                        <Text copyable style={{ wordBreak: 'break-all' }}>{(detail.sha256_fingerprint || '').replace(/:/g, '').toUpperCase() || '-'}</Text>
                      </Descriptions.Item>

                      {/* 行8: 密钥用途 / 扩展用途 */}
                      <Descriptions.Item label="密钥用途" span={5}>{detail.key_usage?.join(', ') || '-'}</Descriptions.Item>
                      <Descriptions.Item label="扩展用途" span={5}>{detail.ext_key_usage?.join(', ') || '-'}</Descriptions.Item>

                      {/* 行9: OCSP / AIA */}
                      <Descriptions.Item label="OCSP地址" span={8}>
                        {detail.ocsp_servers && detail.ocsp_servers.length > 0
                          ? detail.ocsp_servers.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ wordBreak: 'break-all' }}>{u}</a></div>)
                          : '-'}
                      </Descriptions.Item>
                      <Descriptions.Item label="AIA 地址" span={5}>
                        {detail.issuing_cert_url && detail.issuing_cert_url.length > 0
                          ? detail.issuing_cert_url.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ wordBreak: 'break-all' }}>{u}</a></div>)
                          : '-'}
                      </Descriptions.Item>

                      {/* 行10: CRL / SAN */}
                      <Descriptions.Item label="CRL 地址" span={8}>
                        {detail.crl_dist_points && detail.crl_dist_points.length > 0
                          ? detail.crl_dist_points.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ wordBreak: 'break-all' }}>{u}</a></div>)
                          : '-'}
                      </Descriptions.Item>
                      <Descriptions.Item label="SAN 信息" span={5}>
                        {(() => {
                          const items = [
                            ...(detail.san_dns || []).map(v => `DNS: ${v}`),
                            ...(detail.san_ip || []).map(v => `IP: ${v}`),
                            ...(detail.san_email || []).map(v => `Email: ${v}`),
                            ...(detail.san_uri || []).map(v => `URI: ${v}`),
                          ];
                          return items.length > 0
                            ? <div style={{ whiteSpace: 'normal' }}>{items.map((s, i) => <div key={i}>{s}</div>)}</div>
                            : '-';
                        })()}
                      </Descriptions.Item>

                      {/* 行11: 证书策略 */}
                      <Descriptions.Item label="证书策略" span={10}>
                        {detail.cert_policies && detail.cert_policies.length > 0
                          ? detail.cert_policies.map((p, i) => (
                            <span key={i} style={{ marginRight: 12 }}>
                              <Text code>{p.oid}</Text>
                              {p.description && <Tag color={p.description.startsWith('EV') ? 'green' : p.description.startsWith('OV') ? 'blue' : 'purple'} style={{ marginLeft: 4 }}>{p.description}</Tag>}
                            </span>
                          ))
                          : '-'}
                      </Descriptions.Item>
                    </Descriptions>
                  </div>
                );
              },
              rowExpandable: (record: Certificate) => record.cert_type === 'x509' && !!certDetailsMap[record.uuid],
            }}
          />
        )}
      </Card>
      <Drawer
        title="证书详情" open={detailVisible} onClose={() => setDetailVisible(false)} styles={{ wrapper: { width: 560 } }}
        extra={
          <Space>
            <Button icon={<ExportOutlined />} onClick={() => selectedCert && handleExportCrt(selectedCert)}>导出证书</Button>
            <Button icon={<KeyOutlined />} onClick={() => {
              if (selectedCert) { setKeyExportCert(selectedCert); setKeyExportOpen(true); }
            }}>导出密钥</Button>
            <Button icon={<CopyOutlined />} onClick={() => {
              if (selectedCert?.cert_content) {
                navigator.clipboard.writeText(atob(selectedCert.cert_content));
                message.success('已复制到剪贴板');
              }
            }}>复制</Button>
          </Space>
        }
      >
        {selectedCert && (
          <Descriptions column={1} bordered size="small">
            <Descriptions.Item label="UUID">{selectedCert.uuid}</Descriptions.Item>
            <Descriptions.Item label="证书类型">
              <Tag color={certTypeColors[selectedCert.cert_type]}>{certTypeLabels[selectedCert.cert_type] || selectedCert.cert_type}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="密钥类型">{selectedCert.key_type}</Descriptions.Item>
<Descriptions.Item label="Slot">{slotLabel(selectedCert.slot_type)}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{dayjs(selectedCert.created_at).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
            {certDetail && (
              <>
                {/* ===== 主体信息（多行展示） ===== */}
                <Descriptions.Item label="主体信息 (Subject)">
                  <div style={{ lineHeight: '1.8' }}>
                    <div><Text strong>CN:</Text> {certDetail.common_name || '-'}</div>
                    {certDetail.organization && <div><Text strong>O:</Text> {certDetail.organization}</div>}
                    {certDetail.org_unit && <div><Text strong>OU:</Text> {certDetail.org_unit}</div>}
                    {certDetail.locality && <div><Text strong>L:</Text> {certDetail.locality}</div>}
                    {certDetail.state && <div><Text strong>ST:</Text> {certDetail.state}</div>}
                    {certDetail.country && <div><Text strong>C:</Text> {certDetail.country}</div>}
                  </div>
                </Descriptions.Item>

                {/* ===== 颁发者信息（多行展示） ===== */}
                <Descriptions.Item label="颁发者 (Issuer)">
                  <div style={{ lineHeight: '1.8' }}>
                    <div><Text strong>CN:</Text> {certDetail.issuer_cn || '-'}</div>
                    {certDetail.issuer_org && <div><Text strong>O:</Text> {certDetail.issuer_org}</div>}
                    {certDetail.issuer_ou && <div><Text strong>OU:</Text> {certDetail.issuer_ou}</div>}
                    {certDetail.issuer_locality && <div><Text strong>L:</Text> {certDetail.issuer_locality}</div>}
                    {certDetail.issuer_state && <div><Text strong>ST:</Text> {certDetail.issuer_state}</div>}
                    {certDetail.issuer_country && <div><Text strong>C:</Text> {certDetail.issuer_country}</div>}
                    {certDetail.is_self_signed && <Tag color="orange" style={{ marginTop: 4 }}>自签名证书</Tag>}
                  </div>
                </Descriptions.Item>

                {/* ===== 有效期 ===== */}
                <Descriptions.Item label="颁发日期">{dayjs(certDetail.not_before).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>
                <Descriptions.Item label="有效期至">{dayjs(certDetail.not_after).format('YYYY-MM-DD HH:mm:ss')}</Descriptions.Item>

                {/* ===== 算法信息 ===== */}
                <Descriptions.Item label="签名算法">{certDetail.signature_algo}</Descriptions.Item>
                <Descriptions.Item label="公钥算法">
                  {certDetail.public_key_algo}
                  {certDetail.key_bits ? ` (${certDetail.key_bits} bits)` : ''}
                </Descriptions.Item>

                {/* ===== 序列号和指纹 ===== */}
                <Descriptions.Item label="序列号"><Text copyable>{certDetail.serial_number}</Text></Descriptions.Item>
                <Descriptions.Item label="SHA-1 指纹"><Text copyable>{certDetail.sha1_fingerprint}</Text></Descriptions.Item>
                {certDetail.sha256_fingerprint && (
                  <Descriptions.Item label="SHA-256 指纹"><Text copyable style={{wordBreak: 'break-all' }}>{certDetail.sha256_fingerprint}</Text></Descriptions.Item>
                )}

                {/* ===== 基本约束 ===== */}
                <Descriptions.Item label="基本约束">
                  {certDetail.is_ca
                    ? <Tag color="red">CA 证书{certDetail.max_path_len_zero ? '（路径长度: 0）' : certDetail.max_path_len > 0 ? `（路径长度: ${certDetail.max_path_len}）` : ''}</Tag>
                    : <Tag>终端实体证书</Tag>
                  }
                </Descriptions.Item>

                {/* ===== 密钥用途 ===== */}
                <Descriptions.Item label="密钥用途">{certDetail.key_usage?.join(', ') || '-'}</Descriptions.Item>
                <Descriptions.Item label="扩展密钥用途">{certDetail.ext_key_usage?.join(', ') || '-'}</Descriptions.Item>

                {/* ===== SAN ===== */}
                {certDetail.san_dns && certDetail.san_dns.length > 0 && (
                  <Descriptions.Item label="SAN DNS">
                    <div style={{ lineHeight: '1.8' }}>{certDetail.san_dns.map((s, i) => <div key={i}>{s}</div>)}</div>
                  </Descriptions.Item>
                )}
                {certDetail.san_ip && certDetail.san_ip.length > 0 && (
                  <Descriptions.Item label="SAN IP">
                    <div style={{ lineHeight: '1.8' }}>{certDetail.san_ip.map((s, i) => <div key={i}>{s}</div>)}</div>
                  </Descriptions.Item>
                )}
                {certDetail.san_email && certDetail.san_email.length > 0 && (
                  <Descriptions.Item label="SAN 邮箱">
                    <div style={{ lineHeight: '1.8' }}>{certDetail.san_email.map((s, i) => <div key={i}>{s}</div>)}</div>
                  </Descriptions.Item>
                )}
                {certDetail.san_uri && certDetail.san_uri.length > 0 && (
                  <Descriptions.Item label="SAN URI">
                    <div style={{ lineHeight: '1.8' }}>{certDetail.san_uri.map((s, i) => <div key={i} style={{ wordBreak: 'break-all' }}>{s}</div>)}</div>
                  </Descriptions.Item>
                )}

                {/* ===== 证书策略 OID ===== */}
                {certDetail.cert_policies && certDetail.cert_policies.length > 0 && (
                  <Descriptions.Item label="证书策略 (OID)">
                    <div style={{ lineHeight: '1.8' }}>
                      {certDetail.cert_policies.map((p, i) => (
                        <div key={i}>
                          <Text code style={{ fontSize: 11 }}>{p.oid}</Text>
                          {p.description && <Tag color={p.description.startsWith('EV') ? 'green' : p.description.startsWith('OV') ? 'blue' : p.description.startsWith('DV') ? 'default' : 'purple'} style={{ marginLeft: 6, fontSize: 10 }}>{p.description}</Tag>}
                        </div>
                      ))}
                    </div>
                  </Descriptions.Item>
                )}

                {/* ===== CRL 分发点 ===== */}
                {certDetail.crl_dist_points && certDetail.crl_dist_points.length > 0 && (
                  <Descriptions.Item label="CRL 分发点">
                    <div style={{ lineHeight: '1.8' }}>
                      {certDetail.crl_dist_points.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ fontSize: 12, wordBreak: 'break-all' }}>{u}</a></div>)}
                    </div>
                  </Descriptions.Item>
                )}

                {/* ===== OCSP 服务器 ===== */}
                {certDetail.ocsp_servers && certDetail.ocsp_servers.length > 0 && (
                  <Descriptions.Item label="OCSP 服务器">
                    <div style={{ lineHeight: '1.8' }}>
                      {certDetail.ocsp_servers.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ fontSize: 12, wordBreak: 'break-all' }}>{u}</a></div>)}
                    </div>
                  </Descriptions.Item>
                )}

                {/* ===== AIA 颁发者证书 ===== */}
                {certDetail.issuing_cert_url && certDetail.issuing_cert_url.length > 0 && (
                  <Descriptions.Item label="AIA 颁发者证书">
                    <div style={{ lineHeight: '1.8' }}>
                      {certDetail.issuing_cert_url.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ fontSize: 12, wordBreak: 'break-all' }}>{u}</a></div>)}
                    </div>
                  </Descriptions.Item>
                )}

                {/* ===== CPS 策略 URL ===== */}
                {certDetail.cps_urls && certDetail.cps_urls.length > 0 && (
                  <Descriptions.Item label="CPS 策略 URL">
                    <div style={{ lineHeight: '1.8' }}>
                      {certDetail.cps_urls.map((u, i) => <div key={i}><a href={u} target="_blank" rel="noreferrer" style={{ fontSize: 12, wordBreak: 'break-all' }}>{u}</a></div>)}
                    </div>
                  </Descriptions.Item>
                )}
              </>
            )}
            {/*{selectedCert.cert_content && (*/}
            {/*  <Descriptions.Item label="证书内容 (PEM)">*/}
            {/*    <Paragraph copyable ellipsis={{ rows: 4, expandable: true }} style={{ fontFamily: 'monospace', fontSize: 11, marginBottom: 0, wordBreak: 'break-all' }}>*/}
            {/*      {atob(selectedCert.cert_content)}*/}
            {/*    </Paragraph>*/}
            {/*  </Descriptions.Item>*/}
            {/*)}*/}
          </Descriptions>
        )}
      </Drawer>

      {/* 云端证书下发向导 */}
      <Modal
        title={<Space><CloudDownloadOutlined />云端证书下发</Space>}
        open={deliverOpen}
        onOk={handleDeliver}
        onCancel={() => setDeliverOpen(false)}
        okText="下发" cancelText="取消"
        confirmLoading={delivering}
        width={480}
      >
        <Form form={deliverForm} layout="vertical" style={{ marginTop: 16 }}>
          <Form.Item name="target" label="下发目标" rules={[{ required: true }]}>
            <Select options={[
              { value: 'database', label: '下发到本地数据库' },
              { value: 'card', label: '下发到本地智能卡' },
            ]} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.target !== cur.target}>
            {({ getFieldValue }) => getFieldValue('target') === 'card' && (
              <>
                <Form.Item name="target_card_uuid" label="目标卡片" rules={[{ required: true, message: '请选择目标卡片' }]}>
                  <Select
                    placeholder="选择本地/TPM2 卡片"
                    options={localCards.map((c) => ({
                      value: c.uuid,
label: `${c.card_name} (${slotLabel(c.slot_type)})`,
                    }))}
                  />
                </Form.Item>
                <Form.Item name="card_password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码' }]}>
                  <Input.Password placeholder="目标卡片的密码" />
                </Form.Item>
              </>
            )}
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 密钥导出弹窗 */}
      <Modal
        title="导出证书密钥"
        open={keyExportOpen}
        onOk={handleKeyExport}
        onCancel={() => { setKeyExportOpen(false); keyExportForm.resetFields(); }}
        okText="导出" cancelText="取消"
        confirmLoading={keyExporting}
        width={420}
      >
        <Form form={keyExportForm} layout="vertical">
          <Form.Item name="format" label="导出格式" initialValue="pem" rules={[{ required: true }]}>
            <Select options={[
              { value: 'pem', label: 'PEM 密钥 + CRT 证书' },
              { value: 'pfx', label: 'PFX/PKCS12（证书+密钥合并，密码保护）' },
            ]} />
          </Form.Item>
          <Form.Item name="password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码' }]}>
            <Input.Password placeholder="输入卡片密码以解密私钥" />
          </Form.Item>
          <Form.Item name="admin_key" label="Admin Key（中安全性需要）">
            <Input.Password placeholder="中安全性卡片需要 Admin Key" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.format !== cur.format}>
            {({ getFieldValue }) => getFieldValue('format') === 'pfx' && (
              <Form.Item name="pfx_password" label="PFX 保护密码" rules={[{ required: true, message: '请输入 PFX 文件保护密码' }]}>
                <Input.Password placeholder="设置 PFX 文件的保护密码" />
              </Form.Item>
            )}
          </Form.Item>
        </Form>
      </Modal>

      {/* 证书+密钥导入弹窗 */}
      <Modal
        title="导入证书+密钥"
        open={importOpen}
        onOk={handleImport}
        onCancel={() => { setImportOpen(false); importForm.resetFields(); }}
        okText="导入" cancelText="取消"
        confirmLoading={importing}
        width={560}
      >
        <Form form={importForm} layout="vertical">
          <Form.Item name="mode" label="导入格式" initialValue="pem" rules={[{ required: true }]}>
            <Select options={[
              { value: 'pem', label: 'PEM 格式（证书 + 私钥分开）' },
              { value: 'pfx', label: 'PFX/PKCS12 格式（证书+密钥合并）' },
            ]} />
          </Form.Item>

          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.mode !== cur.mode}>
            {({ getFieldValue }) => getFieldValue('mode') === 'pem' ? (
              <>
                <Form.Item label="证书 PEM" required>
                  <Upload.Dragger
                    accept=".pem,.crt,.cer"
                    maxCount={1}
                    beforeUpload={(file) => {
                      const reader = new FileReader();
                      reader.onload = (e) => {
                        const content = e.target?.result as string;
                        importForm.setFieldsValue({ cert_pem: content });
                      };
                      reader.readAsText(file);
                      return false;
                    }}
                    onRemove={() => { importForm.setFieldsValue({ cert_pem: undefined }); }}
                  >
                    <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                    <p className="ant-upload-text">点击或拖拽上传证书文件</p>
                    <p className="ant-upload-hint">支持 .pem / .crt / .cer 格式</p>
                  </Upload.Dragger>
                  <Input.TextArea
                    rows={3}
                    placeholder="或直接粘贴证书 PEM 内容"
                    style={{ marginTop: 8 }}
                    onChange={(e) => importForm.setFieldsValue({ cert_pem: e.target.value })}
                    value={importForm.getFieldValue('cert_pem')}
                  />
                </Form.Item>
                <Form.Item name="cert_pem" hidden><Input /></Form.Item>

                <Form.Item label="私钥 PEM（可选，不填则仅导入证书）">
                  <Upload.Dragger
                    accept=".pem,.key"
                    maxCount={1}
                    beforeUpload={(file) => {
                      const reader = new FileReader();
                      reader.onload = (e) => {
                        const content = e.target?.result as string;
                        importForm.setFieldsValue({ key_pem: content });
                      };
                      reader.readAsText(file);
                      return false;
                    }}
                    onRemove={() => { importForm.setFieldsValue({ key_pem: undefined }); }}
                  >
                    <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                    <p className="ant-upload-text">点击或拖拽上传私钥文件</p>
                    <p className="ant-upload-hint">支持 .pem / .key 格式</p>
                  </Upload.Dragger>
                  <Input.TextArea
                    rows={3}
                    placeholder="或直接粘贴私钥 PEM 内容"
                    style={{ marginTop: 8 }}
                    onChange={(e) => importForm.setFieldsValue({ key_pem: e.target.value })}
                    value={importForm.getFieldValue('key_pem')}
                  />
                </Form.Item>
                <Form.Item name="key_pem" hidden><Input /></Form.Item>
              </>
            ) : (
              <>
                <Form.Item label="PFX 文件" required>
                  <Upload.Dragger
                    accept=".pfx,.p12"
                    maxCount={1}
                    beforeUpload={(file) => {
                      const reader = new FileReader();
                      reader.onload = (e) => {
                        const arrayBuffer = e.target?.result as ArrayBuffer;
                        const bytes = new Uint8Array(arrayBuffer);
                        let binary = '';
                        bytes.forEach((b) => { binary += String.fromCharCode(b); });
                        const b64 = btoa(binary);
                        importForm.setFieldsValue({ pfx_b64: b64 });
                      };
                      reader.readAsArrayBuffer(file);
                      return false;
                    }}
                    onRemove={() => { importForm.setFieldsValue({ pfx_b64: undefined }); }}
                  >
                    <p className="ant-upload-drag-icon"><InboxOutlined /></p>
                    <p className="ant-upload-text">点击或拖拽上传 PFX/P12 文件</p>
                    <p className="ant-upload-hint">支持 .pfx / .p12 格式</p>
                  </Upload.Dragger>
                  <Input.TextArea
                    rows={3}
                    placeholder="或直接粘贴 PFX Base64 内容"
                    style={{ marginTop: 8 }}
                    onChange={(e) => importForm.setFieldsValue({ pfx_b64: e.target.value })}
                    value={importForm.getFieldValue('pfx_b64')}
                  />
                </Form.Item>
                <Form.Item name="pfx_b64" hidden><Input /></Form.Item>
                <Form.Item name="pfx_password" label="PFX 密码">
                  <Input.Password placeholder="PFX 文件的保护密码" />
                </Form.Item>
              </>
            )}
          </Form.Item>

          <Form.Item name="card_password" label="卡片密码" rules={[{ required: true, message: '请输入卡片密码' }]}>
            <Input.Password placeholder="用于加密导入的私钥" />
          </Form.Item>
          <Form.Item name="remark" label="备注">
            <Input placeholder="可选备注" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default CertsPage;
