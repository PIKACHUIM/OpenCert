# OpenCert Manager — 开发路线图与里程碑

> 文档版本：v2.1.0
> 最后更新：2026-04-21

---

## 一、开发路线图总览

```mermaid
mindmap
  root((开发路线图))
    Phase 1 ✅ 项目骨架
      目录结构
      数据模型
      IPC协议
      存储层
    Phase 2 ✅ Local Slot
      密钥管理
      签名/解密
      加密层次
      多算法支持
    Phase 3 ✅ REST API
      用户CRUD
      卡片CRUD
      证书CRUD
      日志查询
    Phase 4 ✅ TPM2 Slot
      Windows TPM 2.0
      macOS Secure Enclave
      Linux TPM 2.0
      降级策略
    Phase 5 ✅ Cloud Slot
      server-card协议
      JWT认证
      云端签名/解密
      离线缓存
    Phase 6 ✅ 前端界面
      React + Antd
      Electron桌面
      暗黑模式
      国际化
    Phase 7 ✅ pkcs11-mock
      C代码完善
      IPC客户端
      全函数映射
      联调测试
    Phase 8 ✅ 集成测试
      API端到端测试
      IPC协议测试
      Cloud Slot测试
      CI/CD流水线
    Phase 9 ✅ 云端平台完善
      CA管理引擎
      模板体系（6种）
      证书颁发引擎
      订单系统（9状态机）
      支付集成
      12个前端页面补全
    Phase 10 ✅ PKI服务
      ACME服务 RFC8555
      CRL/OCSP RFC6960
      CT日志 RFC6962
      吊销服务管理
    Phase 11 🚧 安全加固与收尾
      多用户架构完善
      门户首页美化
      找回密码功能
      E2E联调测试
      安全审计
```

---

## 二、分阶段详细计划

### Phase 1：项目骨架 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| 目录结构搭建 | ✅ | cmd/internal/pkg/test 标准布局 |
| 数据模型定义 | ✅ | users/cards/certificates/logs 四表 |
| IPC 协议设计 | ✅ | 二进制帧头 + JSON Payload |
| SQLite 存储层 | ✅ | 初始化 + 迁移 + Repository |
| 配置加载 | ✅ | YAML/ENV 配置 |

### Phase 2：Local Slot 实现 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| SlotProvider 接口 | ✅ | 统一抽象接口 |
| 三层加密架构 | ✅ | 用户密码→主密钥→临时密钥→私钥 |
| 密钥生成 | ✅ | RSA/ECC/EdDSA/SM2 |
| 签名操作 | ✅ | PKCS1v15/PSS/ECDSA/EdDSA |
| 解密操作 | ✅ | RSA-PKCS1v15/RSA-OAEP |
| 加密操作 | ✅ | AES-GCM/CBC/ChaCha20 |

### Phase 3：REST API 服务 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| HTTP 服务器 | ✅ | Go 1.22 标准库 net/http |
| 用户 CRUD | ✅ | 创建/读取/更新/删除 |
| 卡片 CRUD | ✅ | 创建/读取/更新/删除 |
| 证书 CRUD | ✅ | 导入/读取/删除 |
| 密钥生成 API | ✅ | POST /api/cards/{uuid}/keygen |
| 日志查询 | ✅ | 分页 + 筛选 |
| 统一响应格式 | ✅ | { "data": ... } / { "error": ... } |

### Phase 4：TPM2 Slot 实现 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| TPM 抽象接口 | ✅ | Seal/Unseal/Available |
| Windows/Linux 实现 | ✅ | go-tpm 库 |
| macOS 实现 | ✅ | Security.framework CGO |
| Mock 实现 | ✅ | 测试用 |
| 降级策略 | ✅ | TPM 不可用时自动降级 |

### Phase 5：Cloud Slot + server-card ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| server-card API 设计 | ✅ | JWT 认证 + 卡片/证书/签名 |
| Cloud Slot 实现 | ✅ | REST 转发 + 本地缓存 |
| JWT 认证 | ✅ | 登录/刷新/登出 |
| 云端签名/解密 | ✅ | 私钥不离开服务器 |

### Phase 6：前端管理界面 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| React + Antd 搭建 | ✅ | Vite 构建 |
| 页面路由 | ✅ | React Router v6 |
| 仪表盘 | ✅ | Slot 状态总览 |
| 用户/卡片/证书管理 | ✅ | CRUD 页面 |
| PKI 工具 | ✅ | CSR/CA/签发/自签名/导入 |
| TOTP 管理 | ✅ | 添加/查看验证码 |
| 暗黑模式 | ✅ | 亮色/暗黑/跟随系统 |
| 国际化 | ✅ | 中/英双语 |
| Electron 集成 | ✅ | 桌面端 + 系统托盘 |

### Phase 7：pkcs11-mock C 代码 ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| IPC 客户端 | ✅ | Named Pipe / Unix Socket |
| 全函数映射 | ✅ | 28 个 PKCS#11 函数 |
| 心跳机制 | ✅ | 30 秒间隔 |
| 重连逻辑 | ✅ | 3 次无响应重连 |
| 线程安全 | ✅ | 互斥锁保护 |

### Phase 8：集成测试与 CI/CD ✅ 已完成

| 任务 | 状态 | 说明 |
|------|------|------|
| 单元测试 | ✅ | storage_test / local_slot_test |
| API 端到端测试 | ✅ | api_test.go |
| IPC 协议测试 | ✅ | ipc_test.go |
| Cloud Slot 测试 | ✅ | cloud_slot_test.go |
| E2E 联调测试 | 🚧 | pkcs11-mock + client-card（移至 Phase 11） |
| CI 流水线 | ✅ | GitHub Actions 三平台矩阵 |
| Beta 发布 | ✅ | tag v*-beta* 触发 |

### Phase 9：云端平台完善 ✅ 已完成（第三轮开发）

> 详见 [04-CHANGELOG-ROUND3.md](./04-CHANGELOG-ROUND3.md) T1-T24 全部完成

| 任务 | 状态 | 说明 |
|------|------|------|
| CA 管理引擎 | ✅ | 创建/导入外部CA/证书链查询/吊销 |
| 模板体系实现 | ✅ | 6 种模板 CRUD + 预置数据 API |
| 证书颁发引擎 | ✅ | 模板约束验证 + CertExtTemplate 写入 + KU/EKU 模板 |
| 订单系统 | ✅ | 9 状态机（pending→completed/refunded） |
| 支付集成 | ✅ | 多插件架构 + 余额冻结/解冻 |
| 主体/扩展信息管理 | ✅ | 审核流程 + DNS/邮箱/HTTP 验证 |
| OID 管理 | ✅ | 自定义 OID CRUD + 60+ 预置 OID |
| 存储区域管理 | ✅ | 数据库/HSM 存储 |
| 用户自助功能 | ✅ | 购买/申请/管理/TOTP |
| 12 个前端页面 | ✅ | Cards/AllCerts/OIDs/StorageZones 等 |
| 审批自动签发 | ✅ | ApproveApplication → IssueCert |
| PIN 会话令牌 | ✅ | 15 分钟有效期 + X-PIN-Session |
| 权限检查统一 | ✅ | IsAdmin/IsOperatorOrAbove 五角色 |
| 门户首页 | 🚧 | 基础页面已有，需美化 |

### Phase 10：PKI 服务 ✅ 已完成（第三轮开发）

| 任务 | 状态 | 说明 |
|------|------|------|
| ACME 服务 | ✅ | RFC 8555 HTTP-01/DNS-01 真实验证 + Finalize 签发 |
| CRL 服务 | ✅ | 按 CRLInterval 独立调度 + 自定义路径 |
| OCSP 服务 | ✅ | RFC 6960 标准 binary 响应 |
| CAIssuer 服务 | ✅ | CA 证书下载 /ca/<path> |
| CT 日志服务 | ✅ | RFC 6962 add-chain 真实提交 |
| 吊销服务管理 | ✅ | 按 CA 配置 CRL/OCSP/CAIssuer |

### Phase 11：安全加固与收尾 🚧 进行中

> 详见 [12-FIX-SUGGESTIONS.MD](./12-FIX-SUGGESTIONS.MD) 和 [13-FIX-ROADMAP.MD](./13-FIX-ROADMAP.MD)

| 任务 | 状态 | 说明 |
|------|------|------|
| client-card 多用户切换 | 🚧 | 右上角切换、多账号同时登录 |
| client-card 云端同步 | 🚧 | 自动/手动同步 + pkcs11-mock 注册 |
| client-card Dashboard TOTP | 🚧 | 卡片/表格双视图 + 翻页 |
| server-card 门户首页美化 | 🚧 | Hero + 功能卡片 + 安全特性 |
| server-card 找回密码 | 🚧 | 邮箱验证码重置密码 |
| server-card 证书申请模板补全 | 🚧 | 全字段可编辑 |
| E2E 联调测试 | ⬜ | pkcs11-mock + client-card + server-card |
| 安全审计 | ⬜ | 代码审查 + 漏洞扫描 |
| 性能优化 | ⬜ | 基准测试 + 瓶颈分析 |
| 文档完善 | ⬜ | 用户手册 + API 文档 |
| 正式发布 | ⬜ | v1.0.0 |

---

## 三、当前待解决问题

| 问题 | 优先级 | 说明 |
|------|--------|------|
| client-card 多用户切换 | 🔴 高 | 右上角切换用户、多账号同时登录管理 |
| client-card 云端同步 | 🔴 高 | 自动/手动同步 + 增量同步 + pkcs11-mock 注册 |
| E2E 联调测试 | 🔴 高 | pkcs11-mock + client-card + server-card 完整链路 |
| server-card 找回密码 | 🟡 中 | 邮箱验证码重置密码流程 |
| server-card 门户首页 | 🟡 中 | 产品展示页美化 |
| 支付插件实际集成 | 🟡 中 | 至少一个支付渠道实际可用 |
| pkcs11-mock Digest/Verify | 🟢 低 | 部分应用可能需要驱动端摘要/验签 |

---

## 四、CI/CD 流水线

```
.github/workflows/
├── ci.yml              # 主 CI（测试/构建/安全扫描，三平台矩阵）
│   ├── ubuntu-latest   # Linux 构建 + 测试
│   ├── windows-latest  # Windows 构建 + 测试
│   └── macos-latest    # macOS 构建 + 测试
└── release-beta.yml    # Beta 发布（tag v*-beta* 触发）
    └── 自动创建 pre-release + 构建产物上传
```

---

## 五、版本规划

| 版本 | 内容 | 预计时间 |
|------|------|---------|
| v0.1.0-beta | Phase 1-3：基础功能 | ✅ 已完成 |
| v0.2.0-beta | Phase 4-5：TPM2 + Cloud Slot | ✅ 已完成 |
| v0.3.0-beta | Phase 6-7：前端 + 驱动 | ✅ 已完成 |
| v0.4.0-beta | Phase 8：集成测试 | ✅ 已完成 |
| v0.5.0-beta | Phase 9：云端平台完善（第三轮） | ✅ 已完成 |
| v0.6.0-beta | Phase 10：PKI 服务（第三轮） | ✅ 已完成 |
| v0.7.0-beta | Phase 11：安全加固与收尾 | 🚧 进行中 |
| v1.0.0 | 正式发布 | ⬜ 规划中 |
