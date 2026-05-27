import DocPage from '../components/DocPage'

export default function CloudPlatformPage() {
  return (
    <DocPage
      title="云端平台"
      subtitle="server-card 云端 PKI 管理平台的完整功能设计与模块划分"
      badge="Platform v2.0"
    >
      <h2>☁️ 云端平台功能全景</h2>
      <p>server-card 是 OpenCert 的云端服务组件，提供完整的 PKI 管理能力：</p>

      <div className="card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', margin: '20px 0' }}>
        {[
          { icon: '👤', title: '用户与权限', desc: '注册/登录/TOTP/RBAC 五角色' },
          { icon: '💳', title: '智能卡存储域', desc: '存储区域 + 云端智能卡管理' },
          { icon: '🏛️', title: 'CA 与证书', desc: 'CA 管理/证书颁发/存储策略' },
          { icon: '📋', title: '模板体系', desc: '6 种模板：颁发/主体/扩展/密钥用途/拓展/存储' },
          { icon: '🔒', title: 'PKI 服务', desc: 'CRL/OCSP/ACME/CT 透明度' },
          { icon: '🆔', title: 'OID 管理', desc: '60+ 预置 OID + 自定义扩展' },
          { icon: '💰', title: '订单与支付', desc: '9 状态机 + 多支付插件' },
          { icon: '🌐', title: '门户首页', desc: '产品展示 + 证书申请入口' },
        ].map(item => (
          <div key={item.title} style={{ padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color, #e2e8f0)', background: 'var(--card-bg, #f8fafc)' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>{item.icon}</div>
            <strong>{item.title}</strong>
            <p style={{ fontSize: '0.8rem', margin: '4px 0 0', opacity: 0.7 }}>{item.desc}</p>
          </div>
        ))}
      </div>

      <h2>👤 用户与权限管理</h2>

      <h3>用户功能</h3>
      <table>
        <thead><tr><th>功能</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['用户注册', '邮箱注册，邮箱验证激活'],
            ['用户登录', '邮箱+密码登录，支持 TOTP 双因素'],
            ['修改密码', '需验证旧密码'],
            ['找回密码', '邮箱验证码重置'],
            ['TOTP 认证', '绑定 TOTP 设备，登录时二次验证'],
            ['个人信息', '编辑显示名称、邮箱、头像等'],
            ['公钥对管理', '用于加密存储证书密钥'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>角色权限（RBAC）</h3>
      <table>
        <thead><tr><th>角色</th><th>权限范围</th></tr></thead>
        <tbody>
          {[
            ['super_admin', '系统级管理，所有功能'],
            ['admin', 'CA 管理、模板管理、证书审批、用户管理'],
            ['operator', '证书颁发、订单处理、吊销操作'],
            ['user', '自助功能：购买证书、管理自己的卡片和证书'],
            ['readonly', '只读访问'],
          ].map(([r, p]) => <tr key={r}><td><code>{r}</code></td><td>{p}</td></tr>)}
        </tbody>
      </table>

      <h2>💳 智能卡存储域</h2>

      <h3>存储区域管理</h3>
      <p>存储区域定义了证书密钥的物理存储位置：</p>
      <table>
        <thead><tr><th>字段</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['区域名称', '存储区域的显示名称'],
            ['存储类型', 'database（本地数据库）/ hsm（HSM 硬件）'],
            ['主密钥配置', '数据库类型：主密钥加密方案'],
            ['硬件类型', 'SoftHSM、Thales Luna、AWS CloudHSM 等'],
            ['驱动信息', 'HSM 驱动路径和配置（支持自定义驱动）'],
            ['授权信息', 'HSM 连接凭据（加密存储）'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>云端智能卡</h3>
      <table>
        <thead><tr><th>字段</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['卡片 UUID', '全局唯一标识'],
            ['所属存储区域', '关联的存储区域'],
            ['所属用户', '卡片拥有者'],
            ['PIN 码', '日常操作密码（强制加密存储）'],
            ['PUK 码', '可重置 PIN 码（强制加密存储）'],
            ['Admin Key', '最高权限密钥（强制加密存储）'],
            ['有效期', '卡片过期时间'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🏛️ CA 与证书管理</h2>

      <h3>CA 管理</h3>
      <table>
        <thead><tr><th>功能</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['导入 CA', '导入外部 CA 证书和私钥'],
            ['颁发 CA', '通过颁发功能创建新 CA（根 CA 或中间 CA）'],
            ['证书链导入', '导入完整证书链'],
            ['吊销管理', '管理当前 CA 的吊销证书列表（CRL）'],
            ['CA 状态', '启用/禁用/过期状态管理'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>证书类型支持</h3>
      <table>
        <thead><tr><th>类型</th><th>CA 颁发</th><th>外部导入</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td>X509 证书</td><td>✅</td><td>✅（必须含密钥）</td><td>完整 CA 生命周期管理</td></tr>
          <tr><td>GPG 密钥</td><td>❌</td><td>✅（必须含密钥）</td><td>仅导入，不参与 CA 操作</td></tr>
          <tr><td>SSH 密钥</td><td>❌</td><td>✅（必须含密钥）</td><td>仅导入，不参与 CA 操作</td></tr>
        </tbody>
      </table>

      <h3>证书存储策略</h3>
      <table>
        <thead><tr><th>策略</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['允许直接下载', '用户可下载证书和私钥文件'],
            ['导入云端智能卡', '证书存储到云端虚拟智能卡'],
            ['导入本地智能卡', '通过 client-card 导入本地虚拟智能卡'],
            ['导入实体智能卡', '导入物理智能卡设备'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>📋 模板体系</h2>
      <p>系统采用 6 种模板协同工作，实现灵活的证书颁发策略：</p>

      <pre>{`模板关系图：

证书颁发模板（核心）
  ├── 引用 → 主体模板（Subject DN 字段规则）
  ├── 引用 → 扩展信息模板（SAN 验证规则）
  ├── 引用 → 密钥用途模板（KU/EKU 配置）
  ├── 引用 → 证书拓展模板（CRL/OCSP/AIA/CT）
  └── 引用 → 密钥存储类型模板（存储方式/安全等级）

证书申请模板（面向用户）
  └── 基于 → 证书颁发模板
      ├── 指定具体证书模板
      ├── 指定有效期 / CA
      ├── 是否需要审批
      └── 密钥算法选择`}</pre>

      <h3>证书颁发模板</h3>
      <table>
        <thead><tr><th>字段</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['模板名称', '模板显示名称'],
            ['是否 CA', '颁发的证书是否为 CA 证书'],
            ['路径长度', 'CA 路径长度约束（pathLenConstraint）'],
            ['可选有效期', '如 30d/60d/90d/1y/2y/3y'],
            ['允许私钥类型', 'RSA2048/RSA4096/ECC_P256/ECC_P384'],
            ['可颁发 CA 列表', '允许使用哪些 CA 签发'],
            ['主体模板', '关联的主体模板'],
            ['扩展信息模板', '关联的扩展信息模板'],
            ['密钥用途模板', '关联的密钥用途模板'],
            ['证书拓展模板', '关联的证书拓展模板'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🔒 PKI 服务</h2>

      <h3>吊销服务</h3>
      <table>
        <thead><tr><th>服务</th><th>协议</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><strong>CRL</strong></td><td>RFC 5280</td><td>按 CRLInterval 独立调度，自定义路径 /pki/crl/&lt;path&gt;</td></tr>
          <tr><td><strong>OCSP</strong></td><td>RFC 6960</td><td>标准 binary 响应，/pki/ocsp/&lt;path&gt;</td></tr>
          <tr><td><strong>CAIssuer</strong></td><td>AIA</td><td>CA 证书下载 /pki/ca/&lt;path&gt;</td></tr>
        </tbody>
      </table>

      <h3>ACME 服务</h3>
      <div className="callout callout-info">
        <strong>RFC 8555 完整实现</strong>
        <p>支持 HTTP-01、DNS-01、TLS-ALPN-01 三种验证方式，多实例配置，不同 CA 和颁发模板。</p>
      </div>
      <pre>{`ACME 流程：
  1. GET  /acme/{path}/directory     → 获取目录
  2. POST /acme/{path}/new-account   → 创建账户
  3. POST /acme/{path}/new-order     → 创建订单
  4. POST /acme/{path}/authz/{id}    → 获取授权
  5. POST /acme/{path}/chall/{id}    → 完成挑战
  6. POST /acme/{path}/finalize/{id} → 签发证书
  7. POST /acme/{path}/cert/{id}     → 下载证书`}</pre>

      <h3>CT 透明度日志</h3>
      <p>RFC 6962 标准实现，支持证书提交和查询：</p>
      <ul>
        <li><code>POST /ct/submit</code> — 提交证书到 CT 日志</li>
        <li><code>GET /ct/query</code> — 查询 CT 记录</li>
      </ul>

      <h2>💰 订单与支付</h2>

      <h3>订单状态机</h3>
      <pre>{`订单状态流转（9 状态）：

  pending → paid → processing → completed
    │         │                      │
    ↓         ↓                      ↓
  cancelled  refunding → refunded   expired
                │
                ↓
             refund_failed`}</pre>

      <h3>支付插件架构</h3>
      <table>
        <thead><tr><th>渠道</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['Alipay', '支付宝当面付/网页支付'],
            ['WeChat Pay', '微信支付 Native/JSAPI'],
            ['Stripe', '国际信用卡支付'],
            ['PayPal', 'PayPal 标准支付'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🌐 门户与用户自助</h2>
      <p>门户首页提供产品展示和证书申请入口，用户自助功能包括：</p>
      <ul>
        <li>个人信息管理</li>
        <li>主体信息管理（审核流程）</li>
        <li>扩展信息管理（DNS/邮箱/HTTP 验证）</li>
        <li>购买证书 → 提交申请 → 管理员审批 → 自动签发</li>
        <li>智能卡管理</li>
        <li>证书吊销/续期</li>
        <li>TOTP 验证器</li>
      </ul>
    </DocPage>
  )
}
