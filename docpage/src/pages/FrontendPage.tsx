import DocPage from '../components/DocPage'

export default function FrontendPage() {
  return (
    <DocPage
      title="前端设计"
      subtitle="client-card 与 server-card 前端架构、技术栈、页面规划与侧边栏菜单设计"
      badge="Frontend v2.0"
    >
      <h2>🎨 前端架构总览</h2>

      <div className="card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', margin: '20px 0' }}>
        {[
          { icon: '⚛️', title: 'React 18', desc: 'TypeScript + Hooks' },
          { icon: '🐜', title: 'Ant Design 5', desc: 'UI 组件库' },
          { icon: '🐻', title: 'Zustand', desc: '轻量状态管理' },
          { icon: '🛤️', title: 'React Router v6', desc: '路由管理' },
          { icon: '🌍', title: 'i18next', desc: '国际化 中/英' },
          { icon: '⚡', title: 'Vite', desc: '构建工具' },
          { icon: '🖥️', title: 'Electron', desc: '桌面端打包' },
          { icon: '🎭', title: '主题系统', desc: '亮色/暗黑/跟随系统' },
        ].map(item => (
          <div key={item.title} style={{ padding: '12px', borderRadius: '8px', border: '1px solid var(--border-color, #e2e8f0)', background: 'var(--card-bg, #f8fafc)', textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '6px' }}>{item.icon}</div>
            <strong style={{ fontSize: '0.85rem' }}>{item.title}</strong>
            <p style={{ fontSize: '0.75rem', margin: '2px 0 0', opacity: 0.7 }}>{item.desc}</p>
          </div>
        ))}
      </div>

      <h2>📱 本地管理端侧边栏（client-card）</h2>
      <pre>{`侧边栏菜单结构：

📊 仪表盘          /dashboard
    ├── Slot 状态总览
    ├── 卡片/证书统计
    └── 最近操作

👤 用户管理         /users
    ├── 用户列表
    ├── 创建/编辑/删除
    └── 多账号切换

💳 智能卡管理       /cards
    ├── 卡片列表
    ├── 创建卡片（Local/TPM2/Cloud）
    ├── 卡片详情
    └── 证书管理 /cards/:id/certs

📜 证书总览         /certs
    ├── 全局证书列表
    ├── 按类型筛选
    └── 按卡片筛选

🔑 安全凭据         /credentials
    ├── 登录凭据 (Logins)
    ├── 安全笔记 (Notes)
    ├── 支付卡片 (Payments)
    ├── FIDO 密钥 (FIDO)
    └── 文本密钥 (TextKeys)

🔧 PKI 工具         /pki
    ├── CSR 管理 /pki/csr
    ├── 本地 CA /pki/ca
    ├── 证书签发 /pki/certs
    └── 自签名证书

🔐 TOTP 管理        /totp
    ├── TOTP 列表
    ├── 添加 TOTP
    └── 实时验证码

⚙️ 设置             /settings
    ├── 主题切换
    ├── 语言切换
    ├── IPC 配置
    └── 关于`}</pre>

      <h2>🌐 云端平台侧边栏（server-card）</h2>
      <pre>{`侧边栏菜单结构：

📊 仪表盘          /dashboard

── 我的功能 ──
💳 我的卡片         /cards
📜 我的证书         /certs
🆔 身份管理         /identity
📋 主体信息         /subject-infos
📎 扩展信息         /extension-infos
📦 证书订单         /cert-orders
🔑 云端 TOTP        /cloud-totp
💰 充值/支付        /payment
👤 个人资料         /profile

── 平台管理（admin/operator）──
🏛️ CA 管理          /ca
📜 全部证书         /all-certs
📋 颁发模板         /templates
🔐 密钥存储模板     /key-storage-templates
📝 申请模板         /cert-apply-templates
📨 证书申请审核     /cert-applications
🆔 OID 管理         /oids
👥 用户管理         /users
📊 CT 记录          /ct-records
📝 审计日志         /audit-logs
💾 存储区域         /storage-zones
🔄 吊销服务         /revocation-services
🤖 ACME 配置        /acme-configs
💳 支付插件         /payment-plugins

── 系统 ──
📋 系统日志         /logs
⚙️ 系统设置         /settings`}</pre>

      <h2>🎭 主题系统</h2>
      <table>
        <thead><tr><th>模式</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><strong>亮色模式</strong></td><td>默认白色背景，适合日间使用</td></tr>
          <tr><td><strong>暗黑模式</strong></td><td>深色背景，减少眼睛疲劳</td></tr>
          <tr><td><strong>跟随系统</strong></td><td>自动检测系统主题偏好</td></tr>
        </tbody>
      </table>

      <div className="callout callout-info">
        <strong>主题实现</strong>
        <p>使用 Zustand 持久化主题状态到 localStorage，Ant Design ConfigProvider 动态切换 algorithm。CSS 变量控制自定义样式。</p>
      </div>

      <h2>🌍 国际化（i18n）</h2>
      <table>
        <thead><tr><th>语言</th><th>文件</th><th>覆盖范围</th></tr></thead>
        <tbody>
          <tr><td>中文</td><td><code>locales/zh-CN.json</code></td><td>253 个 key</td></tr>
          <tr><td>英文</td><td><code>locales/en-US.json</code></td><td>253 个 key</td></tr>
        </tbody>
      </table>
      <p>命名空间划分：<code>nav</code>、<code>dashboard</code>、<code>cards</code>、<code>certs</code>、<code>pki</code>、<code>settings</code>、<code>credentials</code> 等。</p>

      <h2>🖥️ 部署方式</h2>
      <table>
        <thead><tr><th>方式</th><th>说明</th></tr></thead>
        <tbody>
          <tr><td><strong>Web 访问</strong></td><td>Go embed.FS 内嵌静态文件，localhost:5175 访问</td></tr>
          <tr><td><strong>Electron 桌面</strong></td><td>独立桌面应用，系统托盘图标</td></tr>
          <tr><td><strong>server-card 门户</strong></td><td>独立 Vite 构建，:1027 端口访问</td></tr>
        </tbody>
      </table>

      <h2>📐 页面设计规范</h2>
      <ul>
        <li><strong>响应式布局</strong>：支持 1024px+ 桌面端和移动端适配</li>
        <li><strong>表格操作</strong>：统一使用 Ant Design Table + 分页 + 筛选</li>
        <li><strong>表单验证</strong>：前端 + 后端双重验证</li>
        <li><strong>加载状态</strong>：Skeleton / Spin 统一加载体验</li>
        <li><strong>错误处理</strong>：ErrorBoundary + message.error 统一提示</li>
        <li><strong>权限控制</strong>：基于角色的菜单显隐和操作按钮控制</li>
      </ul>
    </DocPage>
  )
}
