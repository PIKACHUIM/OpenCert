import React from 'react';
import { Space, Typography } from 'antd';
const { Title } = Typography;

interface PageHeaderProps {
  icon?: React.ReactNode;
  title: string;
  description?: React.ReactNode;
  /** 标题右侧的额外内容（如标签、筛选器） */
  tags?: React.ReactNode;
  /** 右侧操作区 */
  extra?: React.ReactNode;
}

const PageHeader: React.FC<PageHeaderProps> = ({ icon, title, description, tags, extra }) => {
  return (
    <div className="page-header">
      <div className="page-header-accent" aria-hidden="true" />
      <div className="page-header-heading">
        {icon && <span className="page-header-icon">{icon}</span>}
        <div className="page-header-copy">
          <div className="page-header-title-row">
            <Title level={5} className="page-header-title">{title}</Title>
            {tags && <div className="page-header-tags">{tags}</div>}
          </div>
          {description && <div className="page-header-description">{description}</div>}
        </div>
      </div>
      {extra && <Space size={8} className="page-header-extra">{extra}</Space>}
    </div>
  );
};

export default PageHeader;
