import DocPage from '../components/DocPage'

interface EndpointProps {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
  path: string
  desc: string
  auth?: string
  body?: string
  response?: string
}

function Endpoint({ method, path, desc, auth, body, response }: EndpointProps) {
  return (
    <div className="api-endpoint">
      <div className="api-endpoint-header">
        <span className={`method-badge method-${method.toLowerCase()}`}>{method}</span>
        <span className="api-path">{path}</span>
        <span className="api-desc">{desc}</span>
        {auth && <span className="badge badge-teal" style={{ marginLeft: 'auto', fontSize: '0.65rem', flexShrink: 0 }}>{auth}</span>}
      </div>
      {(body || response) && (
        <div className="api-endpoint-body">
          {body && (
            <>
              <p style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', marginBottom: '0.5rem' }}>请求体：</p>
              <pre style={{ margin: 0 }}>{body}</pre>
            </>
          )}
          {response && (
            <>
              <p style={{ fontSize: '0.8rem', color: 'var(--color-text-muted)', margin: '0.75rem 0 0.5rem' }}>响应示例：</p>
              <pre style={{ margin: 0 }}>{response}</pre>
            </>
          )}
        </div>
      )}
    </div>
  )
}

export default function ApiPage() {
  return (
    <DocPage
      title="API 文档"
      subtitle="OpenCert Manager 完整 REST API 参考，涵盖本地管理端（:1026）与云端平台（:1027）两套接口"
      badge="API v2.0"
    >
      {/* ── 通用说明 ── */}
      <div className="callout callout-info">
        <span className="callout-icon">ℹ️</span>
        <div className="callout-body">
          <strong>通用说明</strong><br />
          本地管理端：<code>http://127.0.0.1:1026/api</code>，启动时自动生成随机 Bearer Token<br />
          云端平台：<code>https://your-server:1027/api</code>，使用 JWT Bearer Token 认证<br />
          成功响应：<code>{'{ "data": ... }'}</code> &nbsp;|&nbsp; 分页响应：<code>{'{ "items": [...], "total": N, "page": 1 }'}</code><br />
          错误响应：<code>{'{ "error": "描述" }'}</code>
        </div>
      </div>

      {/* ════════════════════════════════════════
          一、本地管理端 API  :1026
      ════════════════════════════════════════ */}
      <h2>🖥️ 一、本地管理端 API（:1026）</h2>

      <h3>🏥 健康检查</h3>
      <Endpoint
        method="GET" path="/api/health" desc="服务健康状态"
        response={`{ "data": { "status": "ok", "version": "2.0.0", "time": "1713100000" } }`}
      />

      <h3>📊 Slot 状态</h3>
      <Endpoint
        method="GET" path="/api/slots" desc="列出所有 Slot 状态"
        response={`{ "data": [{ "slot_id": 0, "slot_type": "local", "description": "Local Slot", "token_present": true }] }`}
      />

      <h3>👤 用户管理</h3>
      <Endpoint method="GET"    path="/api/users"        desc="用户列表" />
      <Endpoint method="POST"   path="/api/users"        desc="创建用户"
        body={`{
  "user_type": "local",
  "display_name": "张三",
  "email": "zhangsan@example.com",
  "password": "secure_password"
}`} />
      <Endpoint method="GET"    path="/api/users/{uuid}" desc="用户详情" />
      <Endpoint method="PUT"    path="/api/users/{uuid}" desc="更新用户" />
      <Endpoint method="DELETE" path="/api/users/{uuid}" desc="删除用户" />

      <h3>💳 智能卡片管理</h3>
      <Endpoint method="GET"    path="/api/cards"        desc="卡片列表" />
      <Endpoint method="POST"   path="/api/cards"        desc="创建卡片"
        body={`{
  "slot_type": "local",
  "card_name": "我的智能卡",
  "user_uuid": "user-uuid-here",
  "password": "card_password"
}`} />
      <Endpoint method="GET"    path="/api/cards/{uuid}" desc="卡片详情" />
      <Endpoint method="PUT"    path="/api/cards/{uuid}" desc="更新卡片" />
      <Endpoint method="DELETE" path="/api/cards/{uuid}" desc="删除卡片" />

      <h3>📜 证书管理</h3>
      <Endpoint method="GET"    path="/api/cards/{card_uuid}/certs"        desc="证书列表" />
      <Endpoint method="POST"   path="/api/cards/{card_uuid}/certs"        desc="导入证书"
        body={`{
  "cert_type": "x509",
  "key_type":  "ec256",
  "cert_data": "-----BEGIN CERTIFICATE-----...",
  "key_data":  "-----BEGIN PRIVATE KEY-----...",
  "password":  "card_password"
}`} />
      <Endpoint method="GET"    path="/api/cards/{card_uuid}/certs/{uuid}" desc="证书详情" />
      <Endpoint method="DELETE" path="/api/cards/{card_uuid}/certs/{uuid}" desc="删除证书" />

      <h3>🔑 密钥操作</h3>
      <Endpoint method="POST" path="/api/cards/{card_uuid}/keygen" desc="片上生成密钥对"
        body={`{ "key_type": "ec256", "password": "card_password" }`}
        response={`{ "data": { "key_id": "key-uuid", "public_key": "-----BEGIN PUBLIC KEY-----..." } }`}
      />
      <Endpoint method="POST" path="/api/cards/{card_uuid}/sign"   desc="数据签名"
        body={`{ "key_id": "key-uuid", "data": "base64-data", "mechanism": "SHA256withECDSA", "password": "card_password" }`}
      />
      <Endpoint method="POST" path="/api/cards/{card_uuid}/csr"    desc="生成 CSR（片上密钥签名）"
        body={`{ "key_id": "key-uuid", "subject": { "CN": "example.com", "O": "My Org" }, "password": "card_password" }`}
      />

      <h3>🔐 TOTP 管理（本地）</h3>
      <Endpoint method="GET"    path="/api/cards/{card_uuid}/totp" desc="TOTP 条目列表" />
      <Endpoint method="POST"   path="/api/cards/{card_uuid}/totp" desc="添加 TOTP 条目"
        body={`{
  "issuer":    "GitHub",
  "account":   "user@example.com",
  "secret":    "JBSWY3DPEHPK3PXP",
  "algorithm": "SHA1",
  "digits":    6,
  "period":    30,
  "otp_type":  "totp"
}`}
      />
      <Endpoint method="GET"    path="/api/totp/{id}/code" desc="获取当前验证码"
        response={`{ "data": { "code": "123456", "remaining": 15, "period": 30 } }`}
      />
      <Endpoint method="DELETE" path="/api/totp/{id}"      desc="删除 TOTP 条目" />

      <h3>🛠️ 本地 PKI 工具</h3>
      <Endpoint method="POST" path="/api/pki/selfsign" desc="生成自签名证书"
        body={`{
  "card_uuid":     "card-uuid",
  "password":      "card_password",
  "key_type":      "ec256",
  "subject":       { "cn": "example.com", "o": "Example Inc", "c": "CN" },
  "validity_days": 365,
  "san":           { "dns": ["example.com", "*.example.com"], "ip": ["1.2.3.4"] },
  "key_usage":     ["digital_signature", "key_encipherment"],
  "ext_key_usage": ["server_auth", "client_auth"]
}`}
      />
      <Endpoint method="POST" path="/api/pki/csr"      desc="生成 CSR" />
      <Endpoint method="POST" path="/api/pki/ca"       desc="创建本地 CA" />
      <Endpoint method="POST" path="/api/pki/ca/issue" desc="使用本地 CA 签发证书" />
      <Endpoint method="POST" path="/api/pki/convert"  desc="证书格式转换（PEM/DER/PKCS12）" />
      <Endpoint method="POST" path="/api/pki/parse"    desc="解析证书文件" />

      <h3>📋 日志与审计</h3>
      <Endpoint method="GET" path="/api/logs?offset=0&limit=20"  desc="操作日志（分页）" />
      <Endpoint method="GET" path="/api/audit?offset=0&limit=20" desc="审计日志（含哈希链完整性校验）"
        response={`{ "data": { "logs": [], "total": 100, "integrity_broken": false } }`}
      />

      {/* ════════════════════════════════════════
          二、云端平台 API  :1027
      ════════════════════════════════════════ */}
      <h2>☁️ 二、云端平台 API（:1027）</h2>

      <div className="callout callout-info">
        <span className="callout-icon">ℹ️</span>
        <div className="callout-body">
          <strong>权限级别说明</strong>：
          <span className="badge badge-blue" style={{ margin: '0 4px' }}>公开</span> 无需认证 &nbsp;|&nbsp;
          <span className="badge badge-teal" style={{ margin: '0 4px' }}>需认证</span> JWT Bearer Token &nbsp;|&nbsp;
          <span className="badge badge-orange" style={{ margin: '0 4px' }}>user+</span> 普通用户及以上 &nbsp;|&nbsp;
          <span className="badge badge-green" style={{ margin: '0 4px' }}>admin</span> 管理员
        </div>
      </div>

      <h3>🔑 认证接口</h3>
      <Endpoint method="POST"   path="/api/auth/login"    desc="用户登录，返回 JWT Token" auth="公开"
        body={`{ "username": "admin", "password": "secure_password", "totp_code": "123456" }`}
        response={`{
  "data": {
    "token":      "eyJhbGciOiJFUzI1NiIs...",
    "user_uuid":  "550e8400-e29b-41d4-a716-446655440000",
    "username":   "admin",
    "role":       "admin",
    "expires_at": "2026-04-18T17:00:00Z"
  }
}`}
      />
      <Endpoint method="POST"   path="/api/auth/register" desc="注册新用户" auth="公开"
        body={`{ "username": "newuser", "password": "secure_password", "email": "user@example.com", "display_name": "新用户" }`}
      />
      <Endpoint method="POST"   path="/api/auth/refresh"  desc="刷新 Access Token" auth="需认证" />
      <Endpoint method="DELETE" path="/api/auth/logout"   desc="登出（Token 加入黑名单）" auth="需认证" />
      <Endpoint method="PUT"    path="/api/auth/password" desc="修改密码" auth="需认证" />

      <h3>👤 用户管理（云端）</h3>
      <Endpoint method="GET" path="/api/users/me"              desc="获取当前用户信息" auth="需认证" />
      <Endpoint method="PUT" path="/api/users/me"              desc="更新个人信息" auth="需认证" />
      <Endpoint method="PUT" path="/api/users/me/pubkey"       desc="更新云端公钥（用于加密私钥备份）" auth="需认证" />
      <Endpoint method="GET" path="/api/users"                 desc="用户列表（分页）" auth="admin" />
      <Endpoint method="PUT" path="/api/users/{uuid}/role"     desc="修改用户角色" auth="admin" />
      <Endpoint method="PUT" path="/api/users/{uuid}/enabled"  desc="启用/禁用用户" auth="admin" />

      <h3>💳 云端卡片与证书</h3>
      <Endpoint method="GET"    path="/api/cards"                              desc="卡片列表" auth="需认证" />
      <Endpoint method="POST"   path="/api/cards"                              desc="创建云端智能卡" auth="user+" />
      <Endpoint method="GET"    path="/api/cards/{uuid}"                       desc="卡片详情" auth="需认证" />
      <Endpoint method="DELETE" path="/api/cards/{uuid}"                       desc="删除卡片" auth="user+" />
      <Endpoint method="GET"    path="/api/cards/{uuid}/certs"                 desc="证书列表" auth="需认证" />
      <Endpoint method="POST"   path="/api/cards/{uuid}/certs"                 desc="导入证书" auth="user+" />
      <Endpoint method="DELETE" path="/api/cards/{uuid}/certs/{cert_uuid}"     desc="删除证书" auth="user+" />
      <Endpoint method="POST"   path="/api/cards/{uuid}/keygen"                desc="云端生成密钥对" auth="需认证" />
      <Endpoint method="POST"   path="/api/cards/{uuid}/sign"                  desc="云端签名（私钥不离开服务器）" auth="需认证"
        body={`{ "cert_uuid": "cert-uuid", "data_base64": "base64数据", "algorithm": "SHA256withECDSA" }`}
      />
      <Endpoint method="POST"   path="/api/cards/{uuid}/decrypt"               desc="云端解密" auth="需认证" />
      <Endpoint method="GET"    path="/api/certs"                              desc="全局证书筛选查询" auth="需认证" />
      <Endpoint method="POST"   path="/api/certs/{uuid}/revoke"                desc="吊销证书" auth="admin" />
      <Endpoint method="POST"   path="/api/certs/{uuid}/assign"                desc="分配证书到智能卡" auth="admin" />

      <h3>🏛️ CA 管理</h3>
      <Endpoint method="GET"    path="/api/cas"                    desc="CA 列表" auth="需认证" />
      <Endpoint method="POST"   path="/api/cas"                    desc="创建自签名 CA" auth="admin"
        body={`{
  "name":         "根 CA",
  "key_type":     "ec384",
  "validity_years": 10,
  "subject": {
    "common_name":  "OpenCert Root CA",
    "organization": "Example Corp",
    "country":      "CN"
  }
}`}
      />
      <Endpoint method="GET"    path="/api/cas/{uuid}"             desc="CA 详情" auth="需认证" />
      <Endpoint method="PUT"    path="/api/cas/{uuid}"             desc="更新 CA 信息" auth="admin" />
      <Endpoint method="DELETE" path="/api/cas/{uuid}"             desc="删除 CA" auth="admin" />
      <Endpoint method="POST"   path="/api/cas/{uuid}/import-chain" desc="导入证书链" auth="admin" />
      <Endpoint method="GET"    path="/api/cas/{uuid}/revoked"     desc="吊销证书列表" auth="需认证" />
      <Endpoint method="POST"   path="/api/cas/{uuid}/revoke"      desc="吊销证书" auth="admin"
        body={`{ "serial_hex": "0a1b2c3d4e5f", "reason": 1 }`}
      />
      <Endpoint method="GET"    path="/api/cas/{uuid}/crl"         desc="下载 CRL（DER 格式）" auth="公开" />
      <Endpoint method="POST"   path="/api/cas/{uuid}/issue"       desc="签发证书" auth="admin" />

      <h3>📋 模板管理</h3>
      <p style={{ fontSize: '0.85rem', color: 'var(--color-text-muted)' }}>
        系统包含六种模板：颁发模板、主体模板、扩展信息模板、密钥用途模板、证书拓展模板、密钥存储类型模板。
      </p>

      <table>
        <thead><tr><th>模板类型</th><th>路径前缀</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['证书颁发模板', '/api/templates/issuance',    '核心模板，引用其他所有模板'],
            ['主体模板',     '/api/templates/subject',     '定义 Subject 字段规则'],
            ['扩展信息模板', '/api/templates/extension',   'SAN 字段规则与验证配置'],
            ['密钥用途模板', '/api/templates/key-usage',   'Key Usage / EKU 配置'],
            ['证书拓展模板', '/api/templates/cert-ext',    'CRL/OCSP/AIA/CT 等拓展'],
            ['密钥存储模板', '/api/templates/key-storage', '存储方式与安全等级策略'],
          ].map(([name, path, desc]) => (
            <tr key={path as string}>
              <td>{name}</td>
              <td><code>{path}</code></td>
              <td style={{ fontSize: '0.8rem' }}>{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
        每种模板均支持：<code>GET /list</code>（列表）、<code>POST /</code>（创建，admin）、
        <code>GET /{'{uuid}'}</code>（详情）、<code>DELETE /{'{uuid}'}</code>（删除，admin）。
      </p>

      <Endpoint method="POST" path="/api/templates/issuance" desc="创建证书颁发模板" auth="admin"
        body={`{
  "name":                     "标准 SSL 证书",
  "category":                 "ssl",
  "is_ca":                    false,
  "validity_options":         [365, 730, 1095],
  "allowed_key_types":        ["ec256", "ec384", "rsa2048"],
  "allowed_ca_uuids":         ["ca-uuid-1"],
  "subject_template_uuid":    "subj-tmpl-uuid",
  "extension_template_uuid":  "ext-tmpl-uuid",
  "key_usage_template_uuid":  "ku-tmpl-uuid",
  "key_storage_template_uuid":"ks-tmpl-uuid",
  "cert_ext_template_uuid":   "ce-tmpl-uuid",
  "price_cents":              9900,
  "stock":                    -1,
  "enabled":                  true
}`}
      />
      <Endpoint method="POST" path="/api/templates/key-storage" desc="创建密钥存储类型模板" auth="admin"
        body={`{
  "name":                        "高安全性模板",
  "allowed_storage_types":       ["virtual_card", "physical_card"],
  "virtual_card_security_level": "high",
  "allow_reimport":              false,
  "cloud_backup":                false,
  "allow_reissue":               false,
  "max_reissue_count":           0
}`}
      />

      <h3>🛒 订单与证书申请</h3>
      <Endpoint method="POST" path="/api/cert-orders"                          desc="创建证书订单" auth="user+"
        body={`{ "issuance_template_uuid": "tmpl-uuid", "validity_days": 365, "key_type": "ec256" }`}
      />
      <Endpoint method="GET"  path="/api/cert-orders"                          desc="证书订单列表" auth="需认证" />
      <Endpoint method="POST" path="/api/cert-applications"                    desc="提交证书申请" auth="user+"
        body={`{
  "cert_order_uuid":       "order-uuid",
  "subject_info_uuid":     "subj-info-uuid",
  "extension_info_uuids":  ["ext-info-uuid-1"],
  "key_type":              "ec256"
}`}
      />
      <Endpoint method="GET"  path="/api/cert-applications"                    desc="证书申请列表" auth="需认证" />
      <Endpoint method="PUT"  path="/api/cert-applications/{uuid}/approve"     desc="审批通过" auth="admin" />
      <Endpoint method="PUT"  path="/api/cert-applications/{uuid}/reject"      desc="审批拒绝" auth="admin" />

      <h3>📝 主体信息管理</h3>
      <Endpoint method="GET" path="/api/subject-infos"              desc="主体信息列表" auth="需认证" />
      <Endpoint method="POST" path="/api/subject-infos"             desc="创建主体信息（默认审核中）" auth="user+" />
      <Endpoint method="PUT" path="/api/subject-infos/{uuid}/approve" desc="审核通过" auth="admin" />
      <Endpoint method="PUT" path="/api/subject-infos/{uuid}/reject"  desc="审核拒绝" auth="admin" />

      <h3>🔍 扩展信息验证</h3>
      <Endpoint method="GET"  path="/api/extension-infos"                      desc="扩展信息列表" auth="需认证" />
      <Endpoint method="POST" path="/api/extension-infos"                      desc="创建扩展信息（域名/邮箱/IP）" auth="user+"
        response={`{
  "data": {
    "uuid":         "ext-info-uuid",
    "type":         "domain",
    "value":        "example.com",
    "verify_token": "opencert-verify=abc123xyz",
    "dns_record":   "_opencert.example.com TXT opencert-verify=abc123xyz",
    "status":       "pending"
  }
}`}
      />
      <Endpoint method="POST" path="/api/extension-infos/{uuid}/verify-dns"   desc="触发 DNS TXT 验证" auth="需认证" />
      <Endpoint method="POST" path="/api/extension-infos/{uuid}/verify-email" desc="提交邮箱验证码" auth="需认证" />
      <Endpoint method="DELETE" path="/api/extension-infos/{uuid}"            desc="删除扩展信息" auth="user+" />

      <h3>💰 支付系统</h3>
      <Endpoint method="POST" path="/api/payment/recharge"              desc="发起充值" auth="需认证" />
      <Endpoint method="GET"  path="/api/payment/orders"                desc="充值订单列表" auth="需认证" />
      <Endpoint method="GET"  path="/api/payment/balance"               desc="查询余额" auth="需认证"
        response={`{ "data": { "balance_cents": 50000, "total_recharged_cents": 100000, "total_consumed_cents": 50000 } }`}
      />
      <Endpoint method="POST" path="/api/payment/refund"                desc="申请退款" auth="需认证" />
      <Endpoint method="POST" path="/api/payment/callback/{channel}"    desc="支付回调（Stripe/支付宝等）" auth="公开" />
      <Endpoint method="GET"  path="/api/payment/plugins"               desc="支付插件列表" auth="admin" />
      <Endpoint method="POST" path="/api/payment/plugins"               desc="创建支付插件" auth="admin" />
      <Endpoint method="DELETE" path="/api/payment/plugins/{uuid}"      desc="删除支付插件" auth="admin" />
      <Endpoint method="PUT"  path="/api/payment/refund/{uuid}/approve" desc="审批退款" auth="admin" />

      <h3>⚙️ 其他管理接口</h3>
      <table>
        <thead><tr><th>功能</th><th>路径前缀</th><th>权限</th></tr></thead>
        <tbody>
          {[
            ['存储区域管理', '/api/storage-zones',       'admin'],
            ['OID 管理',    '/api/oids',                'admin（查询需认证）'],
            ['吊销服务配置', '/api/revocation-services', 'admin'],
            ['ACME 配置',   '/api/acme-configs',        'admin'],
            ['CT 记录管理', '/api/ct-entries',           'admin（查询需认证）'],
            ['云端 TOTP',   '/api/totp',                'user+（查询需认证）'],
          ].map(([name, path, auth]) => (
            <tr key={path as string}>
              <td>{name}</td>
              <td><code>{path}</code></td>
              <td><span className="badge badge-teal" style={{ fontSize: '0.65rem' }}>{auth}</span></td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* ════════════════════════════════════════
          三、公开服务接口
      ════════════════════════════════════════ */}
      <h2>🌐 三、公开服务接口</h2>

      <Endpoint method="GET"  path="/crl/{caUUID}"              desc="CRL 文件下载（DER 格式）" auth="公开" />
      <Endpoint method="POST" path="/ocsp/{caUUID}"             desc="OCSP 状态查询（RFC 6960）" auth="公开" />
      <Endpoint method="GET"  path="/ca/{caUUID}"               desc="CA 证书下载（PEM 格式）" auth="公开" />
      <Endpoint method="GET"  path="/acme/{path}/directory"     desc="ACME 目录" auth="公开"
        response={`{
  "newNonce":   "https://platform.example.com/acme/default/new-nonce",
  "newAccount": "https://platform.example.com/acme/default/new-account",
  "newOrder":   "https://platform.example.com/acme/default/new-order",
  "revokeCert": "https://platform.example.com/acme/default/revoke-cert"
}`}
      />
      <Endpoint method="POST" path="/acme/{path}/new-account"   desc="ACME 创建账户" auth="公开" />
      <Endpoint method="POST" path="/acme/{path}/new-order"     desc="ACME 创建订单" auth="公开" />
      <Endpoint method="POST" path="/acme/{path}/order/{id}/finalize" desc="ACME 完成订单" auth="公开" />
      <Endpoint method="GET"  path="/acme/{path}/certificate/{id}"    desc="ACME 下载证书" auth="公开" />
      <Endpoint method="POST" path="/ct/submit"                 desc="CT 证书提交（需密码认证）" auth="公开" />
      <Endpoint method="GET"  path="/ct/query"                  desc="CT 按哈希查询" auth="公开" />

      {/* ════════════════════════════════════════
          四、错误码规范
      ════════════════════════════════════════ */}
      <h2>❌ 四、错误码规范</h2>

      <h3>HTTP 状态码</h3>
      <table>
        <thead><tr><th>状态码</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['200', '成功'],
            ['201', '创建成功'],
            ['400', '请求参数错误'],
            ['401', '未认证 / Token 无效'],
            ['403', '权限不足'],
            ['404', '资源不存在'],
            ['409', '冲突（如用户名已存在）'],
            ['429', '请求过于频繁（速率限制）'],
            ['500', '服务器内部错误'],
          ].map(([code, desc]) => (
            <tr key={code}>
              <td><span className="badge badge-blue">{code}</span></td>
              <td>{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>PKCS#11 IPC 返回值</h3>
      <table>
        <thead><tr><th>返回值</th><th>名称</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['0x00000000', 'CKR_OK',                '成功'],
            ['0x00000003', 'CKR_SLOT_ID_INVALID',   '无效 Slot ID'],
            ['0x00000005', 'CKR_GENERAL_ERROR',     '通用错误'],
            ['0x00000006', 'CKR_FUNCTION_FAILED',   '函数执行失败'],
            ['0x00000030', 'CKR_DEVICE_ERROR',      '设备错误（IPC 断开）'],
            ['0x000000A0', 'CKR_PIN_INCORRECT',     'PIN 错误'],
            ['0x000000A4', 'CKR_PIN_LOCKED',        'PIN 已锁定'],
            ['0x00000100', 'CKR_USER_NOT_LOGGED_IN','用户未登录'],
            ['0x00000101', 'CKR_USER_ALREADY_LOGGED_IN', '用户已登录'],
          ].map(([code, name, desc]) => (
            <tr key={code}>
              <td><code>{code}</code></td>
              <td><code>{name}</code></td>
              <td style={{ fontSize: '0.8rem' }}>{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </DocPage>
  )
}
