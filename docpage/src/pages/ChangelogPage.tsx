import DocPage from '../components/DocPage'

export default function ChangelogPage() {
  return (
    <DocPage
      title="变更日志"
      subtitle="OpenCert Manager 各轮次开发的变更记录与关键改动"
      badge="Changelog"
    >
      <h2>📋 第四轮开发（2026-05-26）</h2>
      <p>基于安全审计和功能评估，完成 10 项关键任务：</p>

      <table>
        <thead><tr><th>任务</th><th>优先级</th><th>状态</th></tr></thead>
        <tbody>
          {[
            ['T1 · TPM EK 认证以支撑高安全性等级智能卡', 'P0', '✅'],
            ['T2 · 补全 pkcs11-mock 驱动 Digest/Verify/Random 函数族', 'P1', '✅'],
            ['T3 · GPG/SSH 在 PKCS#11 对象层的属性映射', 'P1', '✅'],
            ['T4 · client-card 前端 i18n 真实接入', 'P1', '✅'],
            ['T5 · client-card 安全凭据扩展类型完整页面', 'P1', '✅'],
            ['T6 · 三组件 E2E 联调测试', 'P0', '✅'],
            ['T7 · 安全审计与基准测试自动化', 'P0', '✅'],
            ['T8 · server-card 支付插件具体渠道实现', 'P2', '✅'],
            ['T9 · ACME TLS-ALPN-01 + 门户 React 化 + 申请审核体验', 'P2', '✅'],
            ['T10 · 文档与发布物完善', 'P1', '✅'],
          ].map(([t, p, s]) => <tr key={t}><td>{t}</td><td><span className="badge badge-blue">{p}</span></td><td>{s}</td></tr>)}
        </tbody>
      </table>

      <h3>T1 · TPM EK 认证</h3>
      <ul>
        <li>新增 <code>clients/internal/tpm/attestation.go</code> — Attestor 接口与软件 EK 实现</li>
        <li>新增 <code>servers/internal/card/attestation.go</code> — EKTrustStore + VerifyEKAttestation</li>
        <li>高安全等级强制要求真实 TPM EK 证书 + 厂商根链校验</li>
        <li>Nonce 防重放：CertifyBlob 内嵌 nonce 与服务端下发值对比</li>
      </ul>

      <h3>T2 · Digest/Verify/Random 函数族</h3>
      <ul>
        <li>新增 <code>handler_digest_verify_random.go</code> — 完整 IPC handler</li>
        <li>Digest 支持 MD5/SHA-1/SHA-256/SHA-384/SHA-512</li>
        <li>C_GenerateRandom 本地回退改用平台 CSPRNG（替代不安全的 memset(1)）</li>
        <li>C_VerifyInit 放宽机制白名单（RSA/ECDSA/EdDSA）</li>
      </ul>

      <h3>T3 · GPG/SSH 属性映射</h3>
      <ul>
        <li>新增 <code>sshkey.go</code> — SSH 公钥与 SubjectPublicKeyInfo DER 互转</li>
        <li>新增 <code>gpgkey.go</code> — OpenPGP 公钥与 SPKI DER 互转</li>
        <li>CKA_ID 派生：SHA-256(pubDER) 前 20 字节</li>
        <li>支持 RSA/ECDSA/Ed25519 三种密钥类型</li>
      </ul>

      <h3>T4 · 前端 i18n 真实接入</h3>
      <ul>
        <li>MainLayout.tsx 接入 useTranslation，菜单项动态切换</li>
        <li>Settings 页面添加语言切换功能</li>
        <li>zh-CN.json / en-US.json 253 个 key 完全一致</li>
        <li>新增 <code>check-i18n-keys.mjs</code> 校验脚本</li>
      </ul>

      <h3>T5 · 安全凭据完整页面</h3>
      <ul>
        <li>后端新增 <code>ImportCredential</code> 方法 + HTTP 路由</li>
        <li>前端 5-Tab 页面：Logins / Notes / Payments / FIDO / TextKeys</li>
        <li>使用主密钥加密任意 PrivateData</li>
      </ul>

      <h3>T6 · 三组件 E2E 联调测试</h3>
      <ul>
        <li>新增 <code>e2e_driver_ipc_test.go</code> — 驱动 ↔ client-card IPC 测试</li>
        <li>新增 <code>e2e_attestation_test.go</code> — TPM EK 认证端到端测试</li>
        <li>新增 <code>scripts/e2e-three-stack.sh</code> — 三组件启动脚本</li>
        <li>Makefile 新增 <code>make e2e</code> 目标</li>
      </ul>

      <h3>T7 · 安全审计与基准测试自动化</h3>
      <ul>
        <li>新增 <code>scripts/audit.sh</code> — gosec + govulncheck + staticcheck</li>
        <li>新增 <code>scripts/bench.sh</code> — 性能基准测试</li>
        <li>CI workflow 新增 audit/bench job</li>
      </ul>

      <h3>T8 · 支付插件渠道实现</h3>
      <ul>
        <li>实现 Alipay / WeChat Pay / Stripe / PayPal 四渠道</li>
        <li>统一 PaymentProvider 接口 + Loader + Registry</li>
        <li>各渠道独立单元测试</li>
      </ul>

      <h3>T9 · ACME TLS-ALPN-01 + 门户 + 审核</h3>
      <ul>
        <li>新增 <code>tls_alpn.go</code> — RFC 8737 TLS-ALPN-01 验证</li>
        <li>公开申请页面 <code>/apply</code>（无需登录）</li>
        <li>后端 <code>POST /api/public/cert-applications</code></li>
        <li>ACMEConfigs 页面增加 allowed_challenges 多选</li>
      </ul>

      <h3>T10 · 文档与发布物</h3>
      <ul>
        <li>CHANGELOG 文档</li>
        <li>加密流程图方案（15-CRYPTO-FLOWCHART.MD）</li>
        <li>构建脚本 / 发布 Makefile 目标</li>
      </ul>

      <hr />

      <h2>📋 第三轮开发（2026-04-17）</h2>
      <p>云端平台完善 + PKI 服务实现，共 24 项任务全部完成：</p>

      <table>
        <thead><tr><th>编号</th><th>任务</th><th>关键产物</th></tr></thead>
        <tbody>
          {[
            ['T1', 'CA 管理引擎', '创建/导入/证书链/吊销'],
            ['T2', '主体模板 CRUD', '字段规则配置'],
            ['T3', '扩展信息模板 CRUD', 'SAN 验证规则'],
            ['T4', '密钥用途模板 CRUD', 'KU/EKU 配置'],
            ['T5', '证书拓展模板 CRUD', 'CRL/OCSP/AIA/CT'],
            ['T6', '密钥存储类型模板 CRUD', '存储方式/安全等级'],
            ['T7', '证书颁发模板 CRUD', '核心模板，引用其他 5 种'],
            ['T8', '证书颁发引擎', '模板约束验证 + 自动签发'],
            ['T9', '订单系统', '9 状态机 + 支付集成'],
            ['T10', '支付插件架构', '多插件 + 余额管理'],
            ['T11', '主体信息管理', '审核流程'],
            ['T12', '扩展信息管理', 'DNS/邮箱/HTTP 验证'],
            ['T13', 'OID 管理', '60+ 预置 + 自定义'],
            ['T14', '存储区域管理', '数据库/HSM'],
            ['T15', '证书申请模板', '面向用户的申请配置'],
            ['T16', '证书申请审批', '管理员审批 → 自动签发'],
            ['T17', 'ACME 服务', 'RFC 8555 完整实现'],
            ['T18', 'CRL/OCSP 服务', 'RFC 5280/6960'],
            ['T19', 'CT 日志服务', 'RFC 6962'],
            ['T20', '吊销服务管理', '按 CA 配置路径'],
            ['T21', '前端 12 页面', 'Cards/AllCerts/OIDs 等'],
            ['T22', 'PIN 会话令牌', '15 分钟有效期'],
            ['T23', '权限检查统一', '五角色 RBAC'],
            ['T24', '预置数据 API', '模板/OID 初始化'],
          ].map(([n, t, d]) => <tr key={n}><td><code>{n}</code></td><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <hr />

      <h2>📋 早期开发（Phase 1-8）</h2>
      <p>项目基础架构搭建，包括：</p>
      <ul>
        <li><strong>Phase 1-3</strong>：项目骨架 + Local Slot + REST API</li>
        <li><strong>Phase 4-5</strong>：TPM2 Slot + Cloud Slot + server-card</li>
        <li><strong>Phase 6-7</strong>：React 前端 + pkcs11-mock C 驱动</li>
        <li><strong>Phase 8</strong>：集成测试 + CI/CD 三平台矩阵</li>
      </ul>

      <div className="callout callout-info">
        <strong>完整变更记录</strong>
        <p>详细的代码变更记录请参考项目 roadmap 目录下的 04-CHANGELOG-ROUND3.md 和 15-CHANGELOG-ROUND4.md 文件。</p>
      </div>
    </DocPage>
  )
}
