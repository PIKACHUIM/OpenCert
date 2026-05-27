import DocPage from '../components/DocPage'

export default function LocalManagerPage() {
  return (
    <DocPage
      title="本地管理端"
      subtitle="client-card 本地智能卡管理端的功能设计、Slot 架构与 IPC 通信"
      badge="Client v2.0"
    >
      <h2>🖥️ 本地管理端功能全景</h2>
      <p>client-card 是运行在用户本地的智能卡管理服务，提供 REST API + IPC 双通道访问：</p>

      <div className="card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', margin: '20px 0' }}>
        {[
          { icon: '👤', title: '用户管理', desc: '本地用户 + 云端用户多账号' },
          { icon: '💳', title: '智能卡管理', desc: 'Local/TPM2/Cloud 三种 Slot' },
          { icon: '📜', title: '证书管理', desc: '导入/导出/删除/PEM/DER/PKCS12' },
          { icon: '🔧', title: 'PKI 工具', desc: 'CSR 生成/本地 CA/证书签发' },
          { icon: '🔑', title: 'TOTP 管理', desc: 'TOTP/HOTP 验证码管理' },
          { icon: '☁️', title: '云端功能', desc: '证书下发/卡片同步/注册' },
          { icon: '🔌', title: 'IPC 服务', desc: 'Named Pipe/Unix Socket 通信' },
          { icon: '🌐', title: 'Web 前端', desc: 'React + Antd + Electron' },
        ].map(item => (
          <div key={item.title} style={{ padding: '16px', borderRadius: '8px', border: '1px solid var(--border-color, #e2e8f0)', background: 'var(--card-bg, #f8fafc)' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '8px' }}>{item.icon}</div>
            <strong>{item.title}</strong>
            <p style={{ fontSize: '0.8rem', margin: '4px 0 0', opacity: 0.7 }}>{item.desc}</p>
          </div>
        ))}
      </div>

      <h2>💳 三种 Slot 架构</h2>
      <p>智能卡管理采用统一的 SlotProvider 接口，支持三种实现：</p>

      <table>
        <thead><tr><th>Slot 类型</th><th>存储位置</th><th>安全等级</th><th>特点</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Local Slot</strong></td>
            <td>本地 SQLite</td>
            <td><span className="badge badge-blue">低/中</span></td>
            <td>AES-256-GCM 加密，密码派生密钥，可导出</td>
          </tr>
          <tr>
            <td><strong>TPM2 Slot</strong></td>
            <td>TPM 芯片</td>
            <td><span className="badge badge-green">高</span></td>
            <td>主密钥由 TPM Seal 保护，绑定设备，不可导出</td>
          </tr>
          <tr>
            <td><strong>Cloud Slot</strong></td>
            <td>server-card</td>
            <td><span className="badge badge-orange">取决于服务端</span></td>
            <td>REST API 转发，私钥不离开服务器，本地缓存公钥</td>
          </tr>
        </tbody>
      </table>

      <h3>Slot 接口定义</h3>
      <pre>{`type SlotProvider interface {
    SlotID() SlotID
    SlotInfo() SlotInfo
    TokenInfo() TokenInfo
    Mechanisms() []MechanismType

    // 认证
    Login(ctx, userType, pin) error
    Logout(ctx) error
    IsLoggedIn() bool

    // 密钥操作
    FindObjects(ctx, template) ([]ObjectHandle, error)
    GetAttributes(ctx, handle, attrs) ([]Attribute, error)
    Sign(ctx, handle, mechanism, data) ([]byte, error)
    Decrypt(ctx, handle, mechanism, ciphertext) ([]byte, error)
    Encrypt(ctx, handle, mechanism, plaintext) ([]byte, error)
}`}</pre>

      <h2>📜 证书管理</h2>

      <h3>导入支持</h3>
      <table>
        <thead><tr><th>格式</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['PEM 证书', '标准 PEM 编码证书文件'],
            ['DER 证书', '二进制 DER 编码证书'],
            ['PKCS#12', '含私钥的 .p12/.pfx 文件'],
            ['私钥+证书', '分别导入私钥和证书'],
            ['纯证书', '自动匹配已有私钥'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>导出支持</h3>
      <table>
        <thead><tr><th>格式</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['PEM 格式', '证书 + 私钥 PEM 文件'],
            ['DER 格式', '二进制证书文件'],
            ['PKCS#12', '含私钥的加密容器'],
            ['仅私钥', '单独导出私钥（需 PIN 验证）'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🔧 PKI 工具</h2>

      <h3>CSR 生成与管理</h3>
      <ul>
        <li>主体信息填写（CN/O/OU/C/ST/L + 自定义 OID）</li>
        <li>扩展信息填写（SAN: DNS/IP/Email/URI）</li>
        <li>密钥存储选择（数据库/智能卡/导入）</li>
        <li>密钥用途 / 扩展密钥用途选择</li>
        <li>CSR 导出（PEM 格式）</li>
        <li>表格化管理所有 CSR 记录</li>
      </ul>

      <h3>本地 CA 管理</h3>
      <ul>
        <li>导入外部 CA 证书和私钥</li>
        <li>CA 列表管理（启用/禁用/删除）</li>
        <li>查看 CA 详情（证书链、签发数量）</li>
      </ul>

      <h3>证书签发</h3>
      <ul>
        <li>选择 CSR + CA 进行签发</li>
        <li>设置有效期、密钥用途、扩展</li>
        <li>管理已签发证书列表</li>
        <li>自签名证书生成</li>
      </ul>

      <h2>🔌 IPC 通信协议</h2>
      <p>pkcs11-mock 驱动通过 IPC 通道与 client-card 通信：</p>

      <pre>{`IPC 帧格式：
┌──────────┬──────────┬──────────────────────┐
│ Magic(4B)│ Length(4B)│ JSON Payload (变长)   │
│ 0x50 0x4B│ uint32 LE│ {"cmd":"...", ...}    │
│ 0x43 0x53│          │                       │
└──────────┴──────────┴──────────────────────┘

通信方式：
  Windows: Named Pipe (\\\\.\\pipe\\opencert-ipc)
  Linux/macOS: Unix Domain Socket (/tmp/opencert.sock)

心跳机制：
  - 30 秒间隔发送 Heartbeat
  - 3 次无响应自动重连`}</pre>

      <h3>IPC 命令列表</h3>
      <table>
        <thead><tr><th>命令</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['GetSlotList', '获取 Slot 列表'],
            ['GetSlotInfo', '获取 Slot 信息'],
            ['GetTokenInfo', '获取 Token 信息'],
            ['GetMechanismList', '获取支持的算法列表'],
            ['Login', 'PIN 验证登录'],
            ['Logout', '注销'],
            ['FindObjectsInit/FindObjects', '查找对象'],
            ['GetAttributeValue', '获取对象属性'],
            ['SignInit/Sign', '签名操作'],
            ['DecryptInit/Decrypt', '解密操作'],
            ['EncryptInit/Encrypt', '加密操作'],
            ['DigestInit/Digest', '摘要操作'],
            ['VerifyInit/Verify', '验签操作'],
            ['GenerateRandom', '生成随机数'],
            ['SeedRandom', '播种随机数'],
          ].map(([f, d]) => <tr key={f}><td><code>{f}</code></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>☁️ 云端功能</h2>

      <h3>云端证书下发</h3>
      <ul>
        <li>从 server-card 下发证书到本地智能卡</li>
        <li>支持下发到指定卡片或新建卡片</li>
        <li>自动同步证书元数据</li>
      </ul>

      <h3>卡片/证书同步</h3>
      <ul>
        <li>自动同步：定时拉取云端变更</li>
        <li>手动刷新：用户触发全量同步</li>
        <li>增量同步：基于时间戳的增量更新</li>
        <li>通过 pkcs11-mock 注册到系统 CSP</li>
      </ul>

      <h2>🔑 TOTP 管理</h2>
      <table>
        <thead><tr><th>功能</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['添加 TOTP', '支持标准 TOTP URI 格式导入'],
            ['查看验证码', '实时显示 6/8 位验证码'],
            ['算法支持', 'SHA1/SHA256/SHA512'],
            ['HOTP 支持', '基于计数器的一次性密码'],
            ['安全存储', 'TOTP 密钥加密存储在智能卡中'],
          ].map(([f, d]) => <tr key={f}><td><strong>{f}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>
    </DocPage>
  )
}
