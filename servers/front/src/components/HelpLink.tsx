import React from 'react';
import { Button, Tooltip } from 'antd';
import { QuestionCircleOutlined } from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router-dom';

/**
 * 页面标题旁的「帮助」入口，指向帮助中心的对应文档。
 *
 * 用于替代页面内常驻的说明性提示条：说明集中维护在帮助中心，页面保持简洁。
 * doc 形如 "user-04-cloud-card" 或 "admin-05-payment-plugins"。
 */
const HelpLink: React.FC<{ doc: string; label?: string }> = ({ doc, label = '帮助' }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const base = location.pathname.startsWith('/console') ? '/console/help' : '/help';

  return (
    <Tooltip title="查看帮助文档">
      <Button type="link" size="small" icon={<QuestionCircleOutlined />}
        style={{ padding: '0 4px' }} onClick={() => navigate(`${base}/${doc}`)}>
        {label}
      </Button>
    </Tooltip>
  );
};

export default HelpLink;
