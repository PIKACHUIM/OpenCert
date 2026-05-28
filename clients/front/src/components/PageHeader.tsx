import React from 'react';
import { Space, Typography } from 'antd';
import { useAppStore } from '../store/appStore';

const { Title } = Typography;

interface PageHeaderProps {
  icon?: React.ReactNode;
  title: string;
  /** 标题右侧的额外内容（如标签、筛选器） */
  tags?: React.ReactNode;
  /** 右侧操作区 */
  extra?: React.ReactNode;
}

const PageHeader: React.FC<PageHeaderProps> = ({ icon, title, tags, extra }) => {
  const { darkMode } = useAppStore();

  return (
    <div
      style={{
        background: darkMode ? '#161b22' : '#fff',
        border: darkMode ? '1px solid #21262d' : '1px solid #e8e8e8',
        borderTop: '3px solid #52c41a',
        borderRadius: '6px',
        padding: '12px 20px',
        marginBottom: 16,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <Space size={12} align="center">
        {icon && <span style={{ fontSize: 18, color: darkMode ? '#c9d1d9' : '#333' }}>{icon}</span>}
        <Title level={5} style={{ margin: 0, color: darkMode ? '#c9d1d9' : '#333', fontWeight: 600 }}>
          {title}
        </Title>
        {tags}
      </Space>
      {extra && <Space size={8}>{extra}</Space>}
    </div>
  );
};

export default PageHeader;
