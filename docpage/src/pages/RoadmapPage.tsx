import DocPage from '../components/DocPage'

export default function RoadmapPage() {
  return (
    <DocPage
      title="开发路线图"
      subtitle="OpenCert Manager 分阶段开发计划、里程碑与版本规划"
      badge="Roadmap v2.1"
    >
      <h2>🗺️ 开发路线图总览</h2>
      <p>项目分为 11 个阶段，目前已完成 Phase 1-10，Phase 11 进行中：</p>

      <table>
        <thead><tr><th>阶段</th><th>内容</th><th>状态</th></tr></thead>
        <tbody>
          {[
            ['Phase 1', '项目骨架（目录结构/数据模型/IPC协议/存储层）', '✅'],
            ['Phase 2', 'Local Slot（密钥管理/签名/解密/多算法）', '✅'],
            ['Phase 3', 'REST API（用户/卡片/证书 CRUD + 日志）', '✅'],
            ['Phase 4', 'TPM2 Slot（Windows/Linux/macOS + 降级策略）', '✅'],
            ['Phase 5', 'Cloud Slot + server-card（JWT/云端签名/缓存）', '✅'],
            ['Phase 6', '前端界面（React/Antd/Electron/暗黑/i18n）', '✅'],
            ['Phase 7', 'pkcs11-mock（C代码/IPC客户端/28函数映射）', '✅'],
            ['Phase 8', '集成测试与 CI/CD（三平台矩阵）', '✅'],
            ['Phase 9', '云端平台完善（CA/模板/订单/支付/12页面）', '✅'],
            ['Phase 10', 'PKI 服务（ACME/CRL/OCSP/CT）', '✅'],
            ['Phase 11', '安全加固与收尾', '🚧'],
          ].map(([p, c, s]) => (
            <tr key={p}><td><strong>{p}</strong></td><td>{c}</td><td>{s}</td></tr>
          ))}
        </tbody>
      </table>

      <h2>📋 Phase 1：项目骨架 ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['目录结构搭建', 'cmd/internal/pkg/test 标准布局'],
            ['数据模型定义', 'users/cards/certificates/logs 四表'],
            ['IPC 协议设计', '二进制帧头 + JSON Payload'],
            ['SQLite 存储层', '初始化 + 迁移 + Repository'],
            ['配置加载', 'YAML/ENV 配置'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🔐 Phase 2：Local Slot ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['SlotProvider 接口', '统一抽象接口'],
            ['三层加密架构', '用户密码→主密钥→临时密钥→私钥'],
            ['密钥生成', 'RSA/ECC/EdDSA/SM2'],
            ['签名操作', 'PKCS1v15/PSS/ECDSA/EdDSA'],
            ['解密操作', 'RSA-PKCS1v15/RSA-OAEP'],
            ['加密操作', 'AES-GCM/CBC/ChaCha20'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🌐 Phase 3：REST API ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['HTTP 服务器', 'Go 1.22 标准库 net/http + ServeMux'],
            ['用户 CRUD', '创建/读取/更新/删除'],
            ['卡片 CRUD', '创建/读取/更新/删除'],
            ['证书 CRUD', '导入/读取/删除'],
            ['密钥生成 API', 'POST /api/cards/{uuid}/keygen'],
            ['统一响应格式', '{ "data": ... } / { "error": ... }'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🔒 Phase 4：TPM2 Slot ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['TPM 抽象接口', 'Seal/Unseal/Available'],
            ['Windows/Linux', 'go-tpm 库实现'],
            ['macOS', 'Security.framework CGO'],
            ['Mock 实现', '测试用'],
            ['降级策略', 'TPM 不可用时自动降级到 Local'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>☁️ Phase 5：Cloud Slot ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['server-card API', 'JWT 认证 + 卡片/证书/签名'],
            ['Cloud Slot 实现', 'REST 转发 + 本地缓存'],
            ['JWT 认证', '登录/刷新/登出'],
            ['云端签名/解密', '私钥不离开服务器'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🎨 Phase 6：前端界面 ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['React + Antd', 'Vite 构建'],
            ['页面路由', 'React Router v6'],
            ['管理页面', '仪表盘/用户/卡片/证书/PKI/TOTP'],
            ['暗黑模式', '亮色/暗黑/跟随系统'],
            ['国际化', '中/英双语 253 key'],
            ['Electron', '桌面端 + 系统托盘'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>⚙️ Phase 7：pkcs11-mock ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['IPC 客户端', 'Named Pipe / Unix Socket'],
            ['全函数映射', '28 个 PKCS#11 函数'],
            ['心跳机制', '30 秒间隔'],
            ['重连逻辑', '3 次无响应重连'],
            ['线程安全', '互斥锁保护'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🧪 Phase 8：集成测试 ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['单元测试', 'storage_test / local_slot_test'],
            ['API 端到端测试', 'api_test.go'],
            ['IPC 协议测试', 'ipc_test.go'],
            ['Cloud Slot 测试', 'cloud_slot_test.go'],
            ['CI 流水线', 'GitHub Actions 三平台矩阵'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🏛️ Phase 9：云端平台完善 ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['CA 管理引擎', '创建/导入外部CA/证书链/吊销'],
            ['模板体系', '6 种模板 CRUD + 预置数据'],
            ['证书颁发引擎', '模板约束验证 + 自动签发'],
            ['订单系统', '9 状态机'],
            ['支付集成', '多插件架构 + 余额冻结/解冻'],
            ['12 个前端页面', 'Cards/AllCerts/OIDs/StorageZones 等'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🔒 Phase 10：PKI 服务 ✅</h2>
      <table>
        <thead><tr><th>任务</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['ACME 服务', 'RFC 8555 HTTP-01/DNS-01/TLS-ALPN-01'],
            ['CRL 服务', '按 CRLInterval 独立调度 + 自定义路径'],
            ['OCSP 服务', 'RFC 6960 标准 binary 响应'],
            ['CT 日志服务', 'RFC 6962 add-chain 真实提交'],
            ['吊销服务管理', '按 CA 配置 CRL/OCSP/CAIssuer'],
          ].map(([t, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>🚧 Phase 11：安全加固与收尾</h2>
      <table>
        <thead><tr><th>任务</th><th>状态</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['TPM EK 认证', '✅', '高安全性等级智能卡 attestation'],
            ['Digest/Verify/Random', '✅', 'pkcs11-mock 函数族补全'],
            ['GPG/SSH 属性映射', '✅', 'PKCS#11 对象层映射'],
            ['i18n 真实接入', '✅', '前端动态切换中英文'],
            ['安全凭据页面', '✅', '5-Tab 通用凭据管理'],
            ['E2E 联调测试', '✅', '三组件完整链路测试'],
            ['安全审计自动化', '✅', 'audit.sh + bench.sh + CI'],
            ['支付渠道实现', '✅', 'Alipay/WeChat/Stripe/PayPal'],
            ['ACME TLS-ALPN-01', '✅', 'RFC 8737 验证'],
            ['门户 React 化', '✅', '公开申请页面 /apply'],
            ['文档与发布物', '✅', 'CHANGELOG/架构图/API文档'],
          ].map(([t, s, d]) => <tr key={t}><td><strong>{t}</strong></td><td>{s}</td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>📦 版本规划</h2>
      <table>
        <thead><tr><th>版本</th><th>内容</th><th>状态</th></tr></thead>
        <tbody>
          {[
            ['v0.1.0-beta', 'Phase 1-3：基础功能', '✅'],
            ['v0.2.0-beta', 'Phase 4-5：TPM2 + Cloud Slot', '✅'],
            ['v0.3.0-beta', 'Phase 6-7：前端 + 驱动', '✅'],
            ['v0.4.0-beta', 'Phase 8：集成测试', '✅'],
            ['v0.5.0-beta', 'Phase 9：云端平台完善', '✅'],
            ['v0.6.0-beta', 'Phase 10：PKI 服务', '✅'],
            ['v0.7.0-beta', 'Phase 11：安全加固与收尾', '🚧'],
            ['v1.0.0', '正式发布', '⬜'],
          ].map(([v, c, s]) => <tr key={v}><td><code>{v}</code></td><td>{c}</td><td>{s}</td></tr>)}
        </tbody>
      </table>

      <h2>🔄 CI/CD 流水线</h2>
      <pre>{`.github/workflows/
├── ci.yml              # 主 CI（测试/构建/安全扫描，三平台矩阵）
│   ├── ubuntu-latest   # Linux 构建 + 测试
│   ├── windows-latest  # Windows 构建 + 测试
│   └── macos-latest    # macOS 构建 + 测试
├── audit.yml           # 安全审计（gosec/govulncheck）
├── bench.yml           # 性能基准测试
└── release-beta.yml    # Beta 发布（tag v*-beta* 触发）
    └── 自动创建 pre-release + 构建产物上传`}</pre>
    </DocPage>
  )
}
