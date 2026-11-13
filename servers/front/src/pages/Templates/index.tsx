import React, { useEffect, useState } from 'react';
import { Tabs, Typography } from 'antd';
import { useSearchParams } from 'react-router-dom';
import { listCAs } from '../../api';
import type { CA } from '../../types';
import HelpLink from '../../components/HelpLink';
import IssuanceTab from './IssuanceTab';
import SubjectTab from './SubjectTab';
import ExtensionInfoTab from './ExtensionInfoTab';
import KeyUsageTab from './KeyUsageTab';
import CertExtTab from './CertExtTab';
import OidTab from './OidTab';
const { Title } = Typography;
// ---- 主页面 ----
const Templates: React.FC = () => {
  const [cas, setCAs] = useState<CA[]>([]);
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') || 'issuance';

  useEffect(() => {
    listCAs({ page: 1, page_size: 100 }).then(r => setCAs(Array.isArray(r?.items) ? r.items : [])).catch(() => {});
  }, []);

  return (
    <div>
      <Title level={4} style={{ margin: '0 0 16px' }}>
        证书模板 <HelpLink doc="admin-03-ca-templates" /> <HelpLink doc="admin-13-identity-verification" label="身份认证文档" />
      </Title>
      <Tabs
        activeKey={tab}
        onChange={(k) => setParams({ tab: k })}
        items={[
          { key: 'issuance', label: '颁发模板', children: <IssuanceTab cas={cas} /> },
          { key: 'subject', label: '主体模板', children: <SubjectTab /> },
          { key: 'extension', label: '扩展信息模板', children: <ExtensionInfoTab /> },
          { key: 'key_usage', label: '密钥用途模板', children: <KeyUsageTab /> },
          { key: 'cert_ext', label: '证书拓展模板', children: <CertExtTab /> },
          { key: 'oids', label: '自定义 OID', children: <OidTab /> },
        ]}
      />
    </div>
  );
};

export default Templates;
