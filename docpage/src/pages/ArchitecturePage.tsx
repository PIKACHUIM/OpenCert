import DocPage from '../components/DocPage'

export default function ArchitecturePage() {
  return (
    <DocPage
      title="系统架构"
      subtitle="三层架构设计：PKCS#11 驱动层 ↔ 本地客户端 ↔ 云端服务，各层通过标准接口解耦"
      badge="Architecture"
    >
      <h2>⬡ 整体架构</h2>
      <p>OpenCert Manager 采用三层架构，每层职责清晰，通过标准接口通信：</p>
      <pre>{`┌─────────────────────────────────────────────────────────┐
│                    应用层 (Applications)                  │
│     Firefox / Chrome / OpenSSH / GPG Agent / Windows CSP │
└──────────────────────┬──────────────────────────────────┘
                       │ PKCS#11 v2.40 标准 C 接口
┌──────────────────────▼──────────────────────────────────┐
│              pkcs11-mock (C DLL/SO/DYLIB)                │
│         PKCS#11 驱动，注册到操作系统，提供密码学接口        │
└──────────────────────┬──────────────────────────────────┘
                       │ IPC: Named Pipe (Windows)
                       │      Unix Socket (Linux/macOS)
                       │ 帧协议: "PK11" + Cmd + Len + JSON
┌──────────────────────▼──────────────────────────────────┐
│              client-card (Go :1026 + Electron)           │
│    本地管理端：智能卡管理、证书管理、TOTP、PKI 工具         │
│    ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│    │  local   │  │  tpmv2   │  │       cloud          │ │
│    │ SQLite   │  │ TPM 芯片 │  │    REST 转发          │ │
│    │ AES-256  │  │ AES-256  │  │    本地缓存           │ │
│    └──────────┘  └──────────┘  └──────────────────────┘ │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS REST API (:1027)
┌──────────────────────▼──────────────────────────────────┐
│                  server-card (Go :1027)                  │
│    云端服务：CA 管理、证书颁发、用户认证、ACME、CT          │
│    ┌──────────┐  ┌──────────┐  ┌──────────────────────┐ │
│    │PostgreSQL│  │  HSM 硬件│  │     证书存储          │ │
│    └──────────┘  └──────────┘  └──────────────────────┘ │
└─────────────────────────────────────────────────────────┘`}</pre>

      <h2>📦 组件说明</h2>
      <div className="card-grid">
        <div className="info-card" style={{ borderTop: '3px solid #f6ad55' }}>
          <div className="info-card-title" style={{ color: '#f6ad55' }}>pkcs11-mock</div>
          <div className="info-card-body">
            <p>C 语言编写的 PKCS#11 v2.40 动态库（.dll/.so/.dylib），注册到操作系统后，应用程序可通过标准 PKCS#11 接口调用密码学功能。</p>
            <ul style={{ marginTop: '0.5rem', paddingLeft: '1rem', fontSize: '0.8rem' }}>
              <li>通过 IPC（Named Pipe / Unix Socket）与 client-card 通信</li>
              <li>支持 Slot / Token / Session 管理</li>
              <li>支持签名、解密、加密、密钥生成等操作</li>
              <li>心跳机制：30 秒间隔，3 次无响应自动重连</li>
            </ul>
          </div>
        </div>
        <div className="info-card" style={{ borderTop: '3px solid #63b3ed' }}>
          <div className="info-card-title" style={{ color: '#63b3ed' }}>client-card</div>
          <div className="info-card-body">
            <p>Go 语言后端 + React 前端的 Electron 桌面应用，是整个系统的核心枢纽，监听 :1026。</p>
            <ul style={{ marginTop: '0.5rem', paddingLeft: '1rem', fontSize: '0.8rem' }}>
              <li>管理三种类型的虚拟智能卡（Local / TPM2 / Cloud）</li>
              <li>本地 SQLite（SQLCipher）数据库存储，全库加密</li>
              <li>IPC 服务端，处理 pkcs11-mock 的 PKCS#11 命令</li>
              <li>REST API :1026，供前端和 Electron 调用</li>
            </ul>
          </div>
        </div>
        <div className="info-card" style={{ borderTop: '3px solid #4fd1c5' }}>
          <div className="info-card-title" style={{ color: '#4fd1c5' }}>server-card</div>
          <div className="info-card-body">
            <p>Go 语言编写的云端服务，提供完整的 PKI 管理能力，监听 :1027。</p>
            <ul style={{ marginTop: '0.5rem', paddingLeft: '1rem', fontSize: '0.8rem' }}>
              <li>CA 证书颁发和吊销管理（CRL/OCSP）</li>
              <li>用户认证（JWT + TOTP 双因素）</li>
              <li>ACME 协议服务（RFC 8555）</li>
              <li>CT 透明度日志、订单与支付系统</li>
            </ul>
          </div>
        </div>
      </div>

      <h2>🔌 IPC 协议设计</h2>
      <p>pkcs11-mock 与 client-card 之间通过 IPC 通道通信，使用二进制帧协议：</p>
      <pre>{`帧格式：
┌──────────┬──────────┬──────────┬─────────────────┐
│  Magic   │ Command  │  Length  │   JSON Payload  │
│  4 bytes │  4 bytes │  4 bytes │    N bytes      │
│  "PK11"  │BigEndian │BigEndian │  UTF-8 JSON     │
└──────────┴──────────┴──────────┴─────────────────┘

响应格式：
{ "rv": 0, "data": { ... } }
其中 rv 为 PKCS#11 标准返回值（CKR_OK = 0）`}</pre>

      <table>
        <thead>
          <tr><th>平台</th><th>传输方式</th><th>路径</th><th>安全隔离</th></tr>
        </thead>
        <tbody>
          {[
            ['Windows', 'Named Pipe', '\\\\.\\pipe\\opencert-pkcs11', 'DACL（当前用户 + SYSTEM）'],
            ['Linux', 'Unix Domain Socket', '/tmp/opencert-pkcs11.sock', '文件权限 0600'],
            ['macOS', 'Unix Domain Socket', '/tmp/opencert-pkcs11.sock', '文件权限 0600'],
          ].map(([p, t, path, sec]) => (
            <tr key={p as string}>
              <td>{p}</td>
              <td><span className="badge badge-blue">{t}</span></td>
              <td><code>{path}</code></td>
              <td>{sec}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>💳 Slot 类型对比</h2>
      <p>所有 Slot 类型实现统一的 <code>SlotProvider</code> 接口，确保可扩展性：</p>
      <table>
        <thead>
          <tr><th>特性</th><th>Local Slot</th><th>TPM2 Slot</th><th>Cloud Slot</th></tr>
        </thead>
        <tbody>
          {[
            ['私钥存储位置', '本地 SQLite（加密）', '本地 SQLite（TPM 封装加密）', '云端服务器'],
            ['签名操作', '本地执行', '本地执行（TPM 参与解密）', '云端执行，私钥不离开服务器'],
            ['离线可用', '✅ 完全离线', '✅ 完全离线', '❌ 需要网络'],
            ['硬件保护', '❌ 纯软件', '✅ TPM 芯片保护', '✅ 服务器端保护'],
            ['跨设备使用', '❌ 仅本机', '❌ 仅本机（TPM 绑定）', '✅ 任意设备'],
            ['密钥可恢复', '取决于安全等级', '高安全性不可恢复', '✅ 云端备份'],
          ].map(([feature, local, tpm, cloud]) => (
            <tr key={feature as string}>
              <td><strong>{feature}</strong></td>
              <td>{local}</td>
              <td>{tpm}</td>
              <td>{cloud}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>🗄️ 数据模型</h2>
      <h3>💳 智能卡片管理</h3>
      <table>
        <thead>
          <tr><th>字段</th><th>类型</th><th>说明</th></tr>
        </thead>
        <tbody>
          {[
            ['card_uuid', 'uuid', '全局唯一标识'],
            ['slot_type', 'enum', 'local / tpmv2 / cloud'],
            ['card_name', 'string', '卡片显示名称'],
            ['user_uuid', 'uuid', '所属用户'],
            ['card_keys', 'JSON', '卡片密码加密信息列表（支持多用户）'],
            ['created_at', 'timestamp', '创建时间'],
            ['expires_at', 'timestamp', '有效期'],
            ['remarks', 'string', '备注信息'],
          ].map(([f, t, d]) => (
            <tr key={f as string}>
              <td><code>{f}</code></td>
              <td><span className="badge badge-teal">{t}</span></td>
              <td>{d}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>本地证书</h3>
      <table>
        <thead>
          <tr><th>字段</th><th>类型</th><th>说明</th></tr>
        </thead>
        <tbody>
          {[
            ['cert_uuid', 'uuid', '全局唯一标识'],
            ['slot_type', 'enum', 'local / tpmv2 / cloud'],
            ['card_uuid', 'uuid', '所属卡片'],
            ['cert_type', 'enum', 'x509 / ssh / gpg / totp / fido-umdf / login / secret / note / payment'],
            ['key_type', 'string', '密钥类型（RSA2048、EC256 等）'],
            ['cert_content', 'blob', '证书公开部分（PEM/公钥）'],
            ['temp_key_salt', 'blob', '临时密钥的 salt'],
            ['temp_key_enc', 'blob', '加密后的临时密钥'],
            ['private_data', 'blob', '私钥/私密数据（加密存储）'],
            ['remarks', 'string', '备注信息'],
          ].map(([f, t, d]) => (
            <tr key={f as string}>
              <td><code>{f}</code></td>
              <td><span className="badge badge-teal">{t}</span></td>
              <td>{d}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>用户管理</h3>
      <table>
        <thead>
          <tr><th>字段</th><th>类型</th><th>说明</th></tr>
        </thead>
        <tbody>
          {[
            ['user_uuid', 'uuid', '全局唯一标识'],
            ['user_type', 'enum', 'local / cloud'],
            ['display_name', 'string', '显示名称'],
            ['email', 'string', '用户邮箱'],
            ['enabled', 'bool', '是否启用'],
            ['password_hash', 'string', '本地：bcrypt 哈希；云端：留空'],
            ['cloud_url', 'string', '云端账号的 API URL 地址'],
            ['auth_key', 'blob', '云端：JWT Token；本地：HMAC(PIN, salt) AES256 加密的用户密码'],
          ].map(([f, t, d]) => (
            <tr key={f as string}>
              <td><code>{f}</code></td>
              <td><span className="badge badge-teal">{t}</span></td>
              <td>{d}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>🔐 密钥加密流程</h2>
      <pre>{`# 三层加密架构（Local / TPM2 Slot）

Layer 1: 用户密码 → Argon2id(password, salt) → 派生密钥
         派生密钥 → AES-256-GCM 加密 → 卡片主密钥（32字节随机）

Layer 2: 卡片主密钥 → HMAC-SHA256(masterKey, salt) → 临时密钥加密密钥
         临时密钥加密密钥 → AES-256-GCM 加密 → 临时密钥（每证书独立）

Layer 3: 临时密钥 → AES-256-GCM(nonce, privkey, AAD=card_uuid+cert_uuid)
         → 私钥密文

# 卡片密码支持多用户共享（card_keys JSON 列表）
{
  "keys": [
    { "type": "user",     "user_uuid": "xxx", "salt": "...", "encrypted_master": "..." },
    { "type": "card_pin", "salt": "...", "encrypted_master": "..." }
  ]
}`}</pre>

      <div className="callout callout-warning">
        <span className="callout-icon">⚠️</span>
        <div className="callout-body">
          <strong>TPM2 高安全模式</strong>
          在 TPM2 高安全模式下，card_master_key 由 TPM 内部生成并永不离开 TPM，
          私钥使用 TPM 公钥加密后存储，解密必须通过 TPM 完成，密钥不可导出或恢复。
          需要 EK 认证确保是受信任的 TPM（TPM Key Attestation）。
        </div>
      </div>

      <h2>🌐 服务端口规划</h2>
      <table>
        <thead>
          <tr><th>服务</th><th>端口</th><th>协议</th><th>说明</th></tr>
        </thead>
        <tbody>
          {[
            ['client-card REST API', '1026', 'HTTP', '本地管理端 API，仅监听 127.0.0.1'],
            ['client-card IPC', 'Named Pipe / Unix Socket', 'IPC', '供 pkcs11-mock 调用'],
            ['server-card REST API', '1027', 'HTTPS', '云端平台 API，JWT 认证'],
            ['OCSP 服务', '1027', 'HTTP', '/ocsp/<path>'],
            ['CRL 服务', '1027', 'HTTP', '/crl/<path>'],
            ['ACME 服务', '1027', 'HTTPS', '/acme/<path>'],
            ['CT 服务', '1027', 'HTTPS', '/ct/submit, /ct/query'],
          ].map(([s, p, proto, d]) => (
            <tr key={s as string}>
              <td><code>{s}</code></td>
              <td><span className="badge badge-blue">{p}</span></td>
              <td>{proto}</td>
              <td>{d}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>📁 目录结构</h2>
      <pre>{`PKCS11Driver/
├── clients/                    # client-card 本地管理端
│   ├── cmd/clients/main.go     # 启动入口
│   ├── configs/config.go       # 配置加载（YAML/ENV）
│   └── internal/
│       ├── card/               # SlotProvider 接口 + 管理器
│       │   ├── local/          # Local Slot 实现
│       │   ├── tpm2/           # TPM2 Slot 实现
│       │   └── cloud/          # Cloud Slot 实现
│       ├── crypto/             # AES/HMAC/Argon2id 工具
│       ├── ipc/                # IPC 服务（Named Pipe/Unix Socket）
│       ├── storage/            # SQLite 存储层
│       ├── tpm/                # TPM 抽象接口与平台实现
│       └── api/                # REST API Handler
├── servers/                    # server-card 云端平台
│   ├── cmd/servers/main.go     # 启动入口
│   └── internal/
│       ├── api/                # REST API Handler
│       ├── auth/               # JWT 认证
│       ├── ca/                 # CA 引擎
│       ├── cert/               # 证书颁发/管理
│       ├── template/           # 模板管理
│       ├── order/              # 订单系统
│       ├── payment/            # 支付插件
│       ├── acme/               # ACME 服务
│       ├── revoke/             # CRL/OCSP 服务
│       └── ct/                 # CT 日志
├── drivers/                    # pkcs11-mock PKCS#11 驱动
│   ├── src/                    # C 源代码
│   ├── include/                # PKCS#11 头文件
│   └── CMakeLists.txt
└── roadmap/                    # 设计文档`}</pre>

      <h2>🔑 关键设计决策</h2>
      <table>
        <thead>
          <tr><th>决策点</th><th>选择</th><th>原因</th></tr>
        </thead>
        <tbody>
          {[
            ['IPC 协议格式', 'JSON Payload', '调试方便，性能对本地 IPC 足够'],
            ['IPC 传输层', 'Named Pipe / Unix Socket', '无需网络端口，系统级安全隔离'],
            ['本地数据库', 'SQLite (SQLCipher)', '零依赖，单文件，支持全库加密'],
            ['云端数据库', 'PostgreSQL', '高并发，成熟生态'],
            ['加密方案', 'AES-256-GCM + HMAC-SHA256', '标准、安全、Go 原生支持'],
            ['密码哈希', 'Argon2id（优先）/ bcrypt（兼容）', '抗暴力破解，内存硬函数'],
            ['API 框架', 'Go 1.22 标准库 net/http', '零依赖，新 ServeMux 已足够'],
            ['前端框架', 'React 18 + Ant Design 5', '成熟生态，企业级组件'],
            ['TPM 库', 'go-tpm (Win/Linux) / Security.framework (macOS)', '官方维护，跨平台'],
          ].map(([d, c, r]) => (
            <tr key={d as string}>
              <td><strong>{d}</strong></td>
              <td><span className="badge badge-blue">{c}</span></td>
              <td style={{ fontSize: '0.8rem' }}>{r}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </DocPage>
  )
}
