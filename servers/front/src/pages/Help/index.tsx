import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Card, Col, Empty, Input, Menu, Row, Skeleton, Tag, Typography } from 'antd';
import { useNavigate, useParams } from 'react-router-dom';
import { BookOutlined, LockOutlined, SearchOutlined } from '@ant-design/icons';
import Markdown from '../../components/Markdown';
import { listAdminHelpDocs, listHelpDocs } from '../../api';
import { useAuthStore } from '../../store/auth';
import type { HelpDoc } from '../../types';

const { Title, Text } = Typography;

const ADMIN_ROLES = ['admin', 'super_admin'];

/**
 * 帮助中心（门户与控制台共用）。
 *
 * 用户文档公开；管理员文档由服务端 adminOnly 接口返回，
 * 前端只有在当前登录用户为管理员时才请求，非管理员既看不到入口也拿不到内容。
 */
const HelpCenter: React.FC<{ basePath: string }> = ({ basePath }) => {
  const { slug } = useParams<{ slug?: string }>();
  const navigate = useNavigate();
  const { isAuthenticated, role } = useAuthStore();
  const isAdmin = isAuthenticated && ADMIN_ROLES.includes(role || '');

  const [userDocs, setUserDocs] = useState<HelpDoc[]>([]);
  const [adminDocs, setAdminDocs] = useState<HelpDoc[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [keyword, setKeyword] = useState('');

  useEffect(() => {
    let alive = true;
    (async () => {
      setLoading(true);
      try {
        const [u, a] = await Promise.all([
          listHelpDocs(),
          isAdmin ? listAdminHelpDocs().catch(() => [] as HelpDoc[]) : Promise.resolve([] as HelpDoc[]),
        ]);
        if (!alive) return;
        setUserDocs(u);
        setAdminDocs(a);
      } catch (e: any) {
        if (alive) setError(e?.message || '加载帮助文档失败');
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => { alive = false; };
  }, [isAdmin]);

  const allDocs = useMemo(() => [...userDocs, ...adminDocs], [userDocs, adminDocs]);

  // 未指定文档时默认打开第一篇
  const current = useMemo(() => {
    if (!allDocs.length) return undefined;
    return allDocs.find((d) => `${d.audience}-${d.slug}` === slug || d.slug === slug) ?? allDocs[0];
  }, [allDocs, slug]);

  const match = (d: HelpDoc) => {
    const kw = keyword.trim().toLowerCase();
    if (!kw) return true;
    return d.title.toLowerCase().includes(kw) || d.summary.toLowerCase().includes(kw) ||
      d.content.toLowerCase().includes(kw);
  };

  const docKey = (d: HelpDoc) => `${d.audience}-${d.slug}`;

  const menuItems = [
    {
      type: 'group' as const,
      key: 'g-user',
      label: '使用指南',
      children: userDocs.filter(match).map((d) => ({ key: docKey(d), label: d.title, icon: <BookOutlined /> })),
    },
    ...(adminDocs.length ? [{
      type: 'group' as const,
      key: 'g-admin',
      label: <span>管理员文档 <Tag color="gold" style={{ marginLeft: 4 }}>仅管理员</Tag></span>,
      children: adminDocs.filter(match).map((d) => ({ key: docKey(d), label: d.title, icon: <LockOutlined /> })),
    }] : []),
  ];

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <Title level={3} style={{ margin: 0 }}>帮助中心</Title>
        <Text type="secondary">平台使用方式、配置说明与常见问题</Text>
      </div>

      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}

      <Row gutter={[20, 20]}>
        <Col xs={24} md={7} lg={6}>
          <Card styles={{ body: { padding: 12 } }} style={{ borderRadius: 12, position: 'sticky', top: 80 }}>
            <Input
              allowClear prefix={<SearchOutlined />} placeholder="搜索文档"
              value={keyword} onChange={(e) => setKeyword(e.target.value)}
              style={{ marginBottom: 8 }}
            />
            {loading ? <Skeleton active paragraph={{ rows: 6 }} /> : (
              <Menu
                mode="inline"
                selectedKeys={current ? [docKey(current)] : []}
                items={menuItems}
                style={{ borderInlineEnd: 'none' }}
                onClick={({ key }) => navigate(`${basePath}/${key}`)}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} md={17} lg={18}>
          <Card style={{ borderRadius: 12 }} styles={{ body: { padding: '28px 32px' } }}>
            {loading ? <Skeleton active paragraph={{ rows: 12 }} /> : current ? (
              <>
                {current.audience === 'admin' && (
                  <Tag color="gold" icon={<LockOutlined />} style={{ marginBottom: 12 }}>管理员文档</Tag>
                )}
                <Markdown source={current.content} />
              </>
            ) : <Empty description="暂无文档" />}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default HelpCenter;
