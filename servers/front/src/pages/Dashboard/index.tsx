import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Tooltip } from 'antd';
import {
  ApartmentOutlined, SafetyCertificateOutlined, WalletOutlined, AuditOutlined,
  UserOutlined, FileTextOutlined, AppstoreOutlined, CloudServerOutlined,
  ReloadOutlined, ArrowRightOutlined, SafetyOutlined, CreditCardOutlined,
  ShoppingOutlined, IdcardOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import { useAuthStore } from '../../store/auth';
import { useThemeStore } from '../../store/theme';
import { listUsers, listCAs, listAllCerts, listCertApplications, getBalance, getLogs } from '../../api';
import type { Log } from '../../types';

/** 指标卡定义 */
interface Metric {
  key: string;
  label: string;
  value: string;
  suffix?: string;
  hint: string;
  icon: React.ReactNode;
  color: string;
  soft: string;
}

/** 快捷入口定义 */
interface QuickLink {
  key: string;
  label: string;
  desc: string;
  path: string;
  icon: React.ReactNode;
  adminOnly?: boolean;
}

const QUICK_LINKS: QuickLink[] = [
  { key: 'certs', label: '个人证书管理', desc: '查看、下载与吊销本人证书', path: '/console/certs', icon: <SafetyCertificateOutlined /> },
  { key: 'cards', label: '智能卡片管理', desc: '管理云端卡片与 PIN 口令', path: '/console/cards', icon: <CreditCardOutlined /> },
  { key: 'orders', label: '个人订单管理', desc: '跟踪证书申请与支付进度', path: '/console/cert-orders', icon: <ShoppingOutlined /> },
  { key: 'applications', label: '证书申请审核', desc: '处理待审批的证书申请', path: '/console/cert-applications', icon: <AuditOutlined />, adminOnly: true },
  { key: 'users', label: '用户管理', desc: '账号、角色与二次验证设置', path: '/console/users', icon: <UserOutlined />, adminOnly: true },
];

const ROLE_LABEL: Record<string, string> = {
  super_admin: '超级管理员',
  admin: '管理员',
  operator: '操作员',
  readonly: '只读成员',
  user: '普通用户',
};

/** 日志级别 → 展示信息 */
const levelMeta = (level?: string): { cls: string; text: string } => {
  const lv = (level || '').toLowerCase();
  if (lv === 'error' || lv === 'fatal') return { cls: 'error', text: 'ERROR' };
  if (lv === 'warn' || lv === 'warning') return { cls: 'warn', text: 'WARN' };
  if (lv === 'success') return { cls: 'success', text: 'DONE' };
  return { cls: 'info', text: 'INFO' };
};

const fmt = (n: number) => n.toLocaleString('zh-CN');

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { role, username } = useAuthStore();
  const { darkMode } = useThemeStore();
  const [loading, setLoading] = useState(true);
  const [userCount, setUserCount] = useState(0);
  const [caCount, setCACount] = useState(0);
  const [certCount, setCertCount] = useState(0);
  const [pendingApps, setPendingApps] = useState(0);
  const [balance, setBalance] = useState<number | null>(null);
  const [recentLogs, setRecentLogs] = useState<Log[]>([]);

  const isAdmin = role === 'admin' || role === 'super_admin';

  const load = useCallback(() => {
    setLoading(true);
    const tasks: Promise<any>[] = [
      listCAs({ page: 1, page_size: 1 }).catch(() => null),
      listAllCerts({ page: 1, page_size: 1 }).catch(() => null),
      getLogs({ page: 1, page_size: 8 }).catch(() => null),
      getBalance().catch(() => null),
    ];
    if (isAdmin) {
      tasks.push(listUsers({ page: 1, page_size: 1 }).catch(() => null));
      tasks.push(listCertApplications({ page: 1, page_size: 1, status: 'pending' }).catch(() => null));
    }
    Promise.all(tasks)
      .then(([cas, certs, logs, bal, users, apps]) => {
        setCACount(cas?.total ?? 0);
        setCertCount(certs?.total ?? 0);
        setRecentLogs(logs?.items ?? []);
        if (bal) setBalance(bal.available ?? null);
        if (users) setUserCount(users.total ?? 0);
        if (apps) setPendingApps(apps.total ?? 0);
      })
      .finally(() => setLoading(false));
  }, [isAdmin]);

  useEffect(() => { load(); }, [load]);

  /** 最近 8 条日志中的告警量（真实统计，非占位值） */
  const alertCount = useMemo(
    () => recentLogs.filter((l) => ['error', 'fatal', 'warn', 'warning'].includes((l.level || '').toLowerCase())).length,
    [recentLogs],
  );

  /** 日志级别分布，用于面板头部的真实比例条 */
  const levelDist = useMemo(() => {
    const counts = { info: 0, warn: 0, error: 0, success: 0 };
    recentLogs.forEach((l) => {
      const cls = levelMeta(l.level).cls as keyof typeof counts;
      counts[cls] = (counts[cls] ?? 0) + 1;
    });
    return counts;
  }, [recentLogs]);

  const metrics: Metric[] = useMemo(() => {
    const list: Metric[] = [
      {
        key: 'ca', label: 'CA 数量', value: fmt(caCount), hint: '已登记的颁发机构',
        icon: <ApartmentOutlined />, color: 'var(--oc-brand)', soft: 'var(--oc-brand-soft)',
      },
      {
        key: 'certs', label: '证书总数', value: fmt(certCount), hint: '平台累计签发与导入',
        icon: <SafetyCertificateOutlined />, color: 'var(--oc-success)', soft: 'var(--oc-success-soft)',
      },
      {
        key: 'balance', label: '账户余额',
        value: balance !== null ? (balance / 100).toFixed(2) : '—', suffix: '元',
        hint: '可用于证书与云卡消费',
        icon: <WalletOutlined />, color: 'var(--oc-warning)', soft: 'var(--oc-warning-soft)',
      },
      {
        key: 'pending', label: '待审批申请', value: fmt(pendingApps),
        hint: pendingApps > 0 ? '需要尽快处理的申请' : '暂无待处理申请',
        icon: <AuditOutlined />,
        color: pendingApps > 0 ? 'var(--oc-danger)' : 'var(--oc-brand)',
        soft: pendingApps > 0 ? 'var(--oc-danger-soft)' : 'var(--oc-brand-soft)',
      },
    ];
    if (isAdmin) {
      list.push(
        {
          key: 'users', label: '平台用户', value: fmt(userCount), hint: '平台注册账号总数',
          icon: <UserOutlined />, color: 'var(--oc-cyan)', soft: 'var(--oc-cyan-soft)',
        },
        {
          key: 'alerts', label: '近期告警', value: fmt(alertCount), hint: '最近 8 条日志中的 WARN / ERROR',
          icon: <SafetyOutlined />,
          color: alertCount > 0 ? 'var(--oc-warning)' : 'var(--oc-teal)',
          soft: alertCount > 0 ? 'var(--oc-warning-soft)' : 'var(--oc-teal-soft)',
        },
      );
    }
    return list;
  }, [caCount, certCount, balance, pendingApps, userCount, alertCount, isAdmin]);

  const quickLinks = useMemo(
    () => QUICK_LINKS.filter((q) => !q.adminOnly || isAdmin).slice(0, 4),
    [isAdmin],
  );

  const hour = new Date().getHours();
  const greeting = hour < 6 ? '凌晨好' : hour < 12 ? '上午好' : hour < 14 ? '中午好' : hour < 18 ? '下午好' : '晚上好';

  /** 日志级别分布条 */
  const distSegments = useMemo(() => {
    const total = recentLogs.length;
    if (total === 0) return [];
    return [
      { key: 'error', color: 'var(--oc-danger)', count: levelDist.error },
      { key: 'warn', color: 'var(--oc-warning)', count: levelDist.warn },
      { key: 'success', color: 'var(--oc-success)', count: levelDist.success },
      { key: 'info', color: 'var(--oc-brand)', count: levelDist.info },
    ].filter((s) => s.count > 0);
  }, [recentLogs.length, levelDist]);

  return (
    <div>
      {/* ---- 页头 ---- */}
      <div className="oc-page-head">
        <div>
          <div className="oc-page-head__title">
            {greeting}，{username || '朋友'}
          </div>
          <div className="oc-page-head__desc">
            这里汇总了证书签发、云端卡片与订单的实时状态，可快速进入常用模块。
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="oc-status-pill">
            <i className="oc-dot" />
            服务运行中
          </span>
          <Tooltip title="重新加载数据">
            <Button icon={<ReloadOutlined />} loading={loading} onClick={load}>
              刷新
            </Button>
          </Tooltip>
        </div>
      </div>

      {/* ---- 指标卡 ---- */}
      <div className="oc-metrics">
        {metrics.map((m, i) => (
          <div className="oc-metric oc-fade-up" style={{ animationDelay: `${i * 55}ms` }} key={m.key}>
            <div className="oc-metric__top">
              <span className="oc-metric__label">{m.label}</span>
              <span className="oc-metric__icon" style={{ background: m.soft, color: m.color }}>{m.icon}</span>
            </div>
            {loading ? (
              <div className="oc-skeleton" style={{ height: 34, width: '62%' }} />
            ) : (
              <div className="oc-metric__value oc-num">
                {m.value}
                {m.suffix && <small>{m.suffix}</small>}
              </div>
            )}
            <div className="oc-metric__hint">{m.hint}</div>
          </div>
        ))}
      </div>

      {/* ---- 主体两栏 ---- */}
      <div className="oc-cols">
        {/* 最近操作日志 */}
        <section className="oc-panel">
          <div className="oc-panel__head">
            <div className="oc-panel__title">
              <FileTextOutlined />
              最近操作日志
            </div>
            <Button type="link" size="small" onClick={() => navigate('/console/logs')}>
              全部日志
            </Button>
          </div>

          <div className="oc-panel__body">
            {/* 级别分布（真实统计） */}
            {!loading && distSegments.length > 0 && (
              <div style={{ padding: '4px 12px 14px' }}>
                <div className="oc-dist">
                  {distSegments.map((s) => (
                    <span
                      key={s.key}
                      className="oc-dist__seg"
                      style={{ width: `${(s.count / recentLogs.length) * 100}%`, background: s.color }}
                    />
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 14, marginTop: 8, flexWrap: 'wrap' }}>
                  {distSegments.map((s) => (
                    <span key={s.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--oc-text-3)' }}>
                      <i style={{ width: 7, height: 7, borderRadius: 2, background: s.color, display: 'inline-block' }} />
                      {s.key === 'error' ? '错误' : s.key === 'warn' ? '告警' : s.key === 'success' ? '完成' : '信息'} {s.count}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {loading ? (
              <div>
                {[0, 1, 2, 3, 4].map((i) => (
                  <div key={i} className="oc-skeleton" style={{ height: 38, margin: '8px 12px' }} />
                ))}
              </div>
            ) : recentLogs.length === 0 ? (
              <div className="oc-empty">
                <div className="oc-empty__icon"><FileTextOutlined /></div>
                <div className="oc-empty__title">暂无操作日志</div>
                <div className="oc-empty__desc">
                  完成证书签发、卡片操作或账号变更后，这里会显示最近的活动记录。
                </div>
              </div>
            ) : (
              recentLogs.map((l, i) => {
                const meta = levelMeta(l.level);
                return (
                  <div className="oc-log oc-fade-up" style={{ animationDelay: `${i * 35}ms` }} key={l.uuid}>
                    <span className="oc-log__time oc-num">{dayjs(l.created_at).format('MM-DD HH:mm')}</span>
                    <span className={`oc-pill oc-pill--${meta.cls}`}>{meta.text}</span>
                    <span className="oc-log__title" title={l.title}>{l.title || '（无标题）'}</span>
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* 侧栏 */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* 快捷入口 */}
          <section className="oc-panel">
            <div className="oc-panel__head">
              <div className="oc-panel__title">
                <AppstoreOutlined />
                快捷入口
              </div>
            </div>
            <div className="oc-panel__body">
              {quickLinks.map((q) => (
                <button type="button" className="oc-quick" key={q.key} onClick={() => navigate(q.path)}>
                  <span className="oc-quick__icon">{q.icon}</span>
                  <span className="oc-quick__label">
                    {q.label}
                    <span className="oc-quick__desc" style={{ display: 'block' }}>{q.desc}</span>
                  </span>
                  <ArrowRightOutlined className="oc-quick__arrow" />
                </button>
              ))}
            </div>
          </section>

          {/* 运行状态 */}
          <section className="oc-panel">
            <div className="oc-panel__head">
              <div className="oc-panel__title">
                <CloudServerOutlined />
                运行状态
              </div>
            </div>
            <div className="oc-panel__body">
              <div className="oc-facts">
                <div className="oc-fact">
                  <span className="oc-fact__label">服务节点</span>
                  <span className="oc-fact__value oc-num">server-card :1027</span>
                </div>
                <div className="oc-fact">
                  <span className="oc-fact__label">当前角色</span>
                  <span className="oc-fact__value">{ROLE_LABEL[role ?? 'user'] ?? '普通用户'}</span>
                </div>
                <div className="oc-fact">
                  <span className="oc-fact__label">界面主题</span>
                  <span className="oc-fact__value">{darkMode ? '深色' : '浅色'}</span>
                </div>
                <div className="oc-fact">
                  <span className="oc-fact__label">近期告警</span>
                  <span className="oc-fact__value" style={{ color: alertCount > 0 ? 'var(--oc-warning)' : 'var(--oc-success)' }}>
                    {loading ? '—' : `${alertCount} 条`}
                  </span>
                </div>
              </div>
              {/* 说明：角色与权限由服务端控制，此处仅展示当前会话信息 */}
              <div style={{ padding: '10px 12px 4px', fontSize: 12, color: 'var(--oc-text-3)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <IdcardOutlined />
                当前会话信息来自本地登录态，权限以服务端校验为准。
              </div>
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
};

export default Dashboard;
