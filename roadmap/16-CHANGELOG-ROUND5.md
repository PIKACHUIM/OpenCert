# OpenCert Manager · 第五轮开发变更日志

> 执行时间：2026-06-01
> 基于计划：FIDO2/WebAuthn CCID 驱动层完整实现（A2-CCID 方案）
> 前置轮次：[15-CHANGELOG-ROUND4.md](./15-CHANGELOG-ROUND4.md)

---

## 📊 执行总览

| 任务 | 优先级 | 状态 |
|:-----|:------:|:----:|
| T1 · FIDO 驱动层 Go 包（fido.go + store.go） | P0 | ✅ |
| T2 · FIDO REST API Handler（fido_handler.go） | P0 | ✅ |
| T3 · FIDO 路由注册到 server.go | P0 | ✅ |
| T4 · FIDO C DLL 驱动（opencert_fido.c） | P0 | ✅ |
| T5 · builds.bat 加入 FIDO 构建命令 | P1 | ✅ |
| T6 · 文档更新（02-ARCHITECTURE.MD + 07-API.MD） | P1 | ✅ |

**编译验证**：Go lint 无错误 ✅ | builds.bat FIDO x64/x86 构建通过 ✅

---

## 背景：FIDO 方案选型

本轮采用 **A2-CCID 方案**：OpenCert 作为 FIDO2 软件认证器，通过 Windows PC/SC（SCardSvr）注册为虚拟智能卡设备，浏览器经由系统 WebAuthn API 调用 CCID 接口，DLL 再通过 IPC 转发到 client-card 后端，凭据数据存储在 OpenCert 本地/云端数据库中。

```
Chrome/Edge (WebAuthn)
    │ Windows WebAuthn API
    ▼
SCardSvr (PC/SC)
    │ CCID 虚拟智能卡
    ▼
OpenCertFIDO.dll (C)
    │ Named Pipe IPC
    ▼
client-card (Go :1026)
    │ fido.Store → KeyManager
    ▼
SQLite certificates 表 (cert_type=fido)
```

**方案优势**：
- 凭据数据完全存储在 OpenCert（本地 SQLite 或云端），不依赖硬件设备
- 支持跨设备同步（Cloud Slot）
- 私钥受卡片主密钥 AES-256-GCM 加密保护
- 签名计数器防重放，符合 FIDO2 规范

---

## T1 · FIDO 驱动层 Go 包

**新增文件**：
- `clients/internal/fido/fido.go` — 核心数据结构与业务逻辑
- `clients/internal/fido/store.go` — 凭据存储层（复用 certificates 表）

### fido.go 数据结构

```go
// Meta 公开元数据（存入 CertContent，JSON 编码）
type Meta struct {
    RPID            string   `json:"rp_id"`           // 依赖方 ID（域名）
    RPName          string   `json:"rp_name"`
    UserName        string   `json:"user_name"`        // 用户名
    UserDisplayName string   `json:"user_display_name"`
    UserHandle      string   `json:"user_handle"`      // base64url，用户句柄
    CredentialID    string   `json:"credential_id"`    // 凭据 ID
    Algorithm       string   `json:"algorithm"`        // ES256 / RS256
    Counter         uint32   `json:"counter"`          // 签名计数器（防重放）
    Transports      []string `json:"transports"`       // usb/nfc/ble/internal
    BackupEligible  bool     `json:"backup_eligible"`
    BackupState     bool     `json:"backup_state"`
}

// Secret 私密数据（加密存入 PrivateData）
type Secret struct {
    PrivateKeyPEM string `json:"private_key_pem"` // PKCS#8 PEM 私钥
    KeyHandle     string `json:"key_handle"`      // 硬件认证器 key handle
    PublicKeyDER  string `json:"public_key_der"`  // base64 DER 公钥
    AAGUID        string `json:"aaguid"`          // 认证器型号标识
}
```

### store.go 核心方法

| 方法 | 说明 |
|------|------|
| `Create` | 创建凭据，通过 `KeyManager.ImportCredential` 加密存储 |
| `List` | 列出卡片下所有 FIDO 凭据（过滤 `cert_type=fido`） |
| `GetByUUID` | 获取单条凭据（不含私密数据） |
| `GetSecret` | 解密返回私密数据（通过 `KeyManager.ExportCredential`） |
| `Delete` | 删除凭据 |
| `IncrementCounter` | 递增签名计数器，更新 CertContent.counter 字段 |

**设计要点**：
- 复用 `storage.Certificate` 表（`cert_type=fido`），不引入新表
- 加密策略与其他凭据一致：low=master 加密，medium=master+TPM 双层加密
- `ZeroBytes` 安全清零，防止私钥数据残留内存

---

## T2 · FIDO REST API Handler

**新增文件**：
- `clients/internal/api/fido_handler.go`

### 接口列表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/cards/{card_uuid}/fido` | 列出 FIDO 凭据 |
| POST | `/api/cards/{card_uuid}/fido` | 创建 FIDO 凭据 |
| GET | `/api/cards/{card_uuid}/fido/{uuid}` | 获取单条凭据 |
| DELETE | `/api/cards/{card_uuid}/fido/{uuid}` | 删除凭据 |
| POST | `/api/cards/{card_uuid}/fido/{uuid}/secret` | 解密查看私密数据 |
| POST | `/api/cards/{card_uuid}/fido/{uuid}/counter` | 递增签名计数器 |
| POST | `/api/cards/{card_uuid}/fido/{uuid}/pubkey` | 导出公钥（RP 注册用） |

### 创建凭据请求体

```json
{
  "rp_id":           "example.com",
  "rp_name":         "Example Corp",
  "user_name":       "alice@example.com",
  "user_display_name": "Alice",
  "user_handle":     "<base64url>",
  "credential_id":   "<uuid>",
  "algorithm":       "ES256",
  "transports":      ["internal"],
  "private_key_pem": "-----BEGIN PRIVATE KEY-----...",
  "card_password":   "card_pin",
  "remark":          "备注"
}
```

**设计要点**：
- 有私密数据（`private_key_pem` / `key_handle`）时才需要 `card_password`
- 通过 `local.New(0, card, certRepo).Login()` 解锁主密钥，操作完成后 `defer Logout()`
- `newFIDOStore()` 内部构造 `KeyManager`，与其他 handler 保持一致的依赖注入模式

---

## T3 · FIDO 路由注册

**修改文件**：
- `clients/internal/api/server.go`

在 `registerRoutes()` 中，credentials 路由之后新增 7 条 FIDO 路由：

```go
// ---- FIDO2/WebAuthn 凭据管理 ----
s.mux.HandleFunc("GET /api/cards/{card_uuid}/fido", s.handleListFIDO)
s.mux.HandleFunc("POST /api/cards/{card_uuid}/fido", s.handleCreateFIDO)
s.mux.HandleFunc("GET /api/cards/{card_uuid}/fido/{uuid}", s.handleGetFIDO)
s.mux.HandleFunc("DELETE /api/cards/{card_uuid}/fido/{uuid}", s.handleDeleteFIDO)
s.mux.HandleFunc("POST /api/cards/{card_uuid}/fido/{uuid}/secret", s.handleGetFIDOSecret)
s.mux.HandleFunc("POST /api/cards/{card_uuid}/fido/{uuid}/counter", s.handleIncrFIDOCounter)
s.mux.HandleFunc("POST /api/cards/{card_uuid}/fido/{uuid}/pubkey", s.handleExportFIDOPublicKey)
```

---

## T4 · FIDO C DLL 驱动

**新增文件**：
- `drivers/codes/fido/codes/opencert_fido.c` — FIDO 主逻辑
- `drivers/codes/fido/codes/opencert_fido.h` — 头文件
- `drivers/codes/fido/codes/OpenCertFIDO.def` — DLL 导出定义

### 核心实现

**CCID 虚拟智能卡接口**：通过 `winscard.lib` 注册为 PC/SC 设备，Windows SCardSvr 识别为 FIDO2 认证器。

**两个核心操作**：

```
MakeCredential（注册）：
  1. 浏览器调用 navigator.credentials.create()
  2. Windows WebAuthn API → SCardSvr → OpenCertFIDO.dll
  3. DLL 通过 IPC 发送 CmdFIDOMakeCredential 到 client-card
  4. client-card 调用 fido.Store.Create() 存储凭据
  5. 返回 attestation object 给浏览器

GetAssertion（认证）：
  1. 浏览器调用 navigator.credentials.get()
  2. Windows WebAuthn API → SCardSvr → OpenCertFIDO.dll
  3. DLL 通过 IPC 发送 CmdFIDOGetAssertion 到 client-card
  4. client-card 解密私钥，对 clientDataHash 签名
  5. 递增签名计数器（防重放）
  6. 返回 assertion 给浏览器
```

**注册表配置**（安装时写入）：
```
HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\OpenCert FIDO2
  ATR = <虚拟 ATR 字节串>
  Crypto Provider = OpenCertFIDO

HKLM\SOFTWARE\Microsoft\Cryptography\Calais\Readers\OpenCert FIDO2 Reader 0
  Vendor Name = OpenCert
  IFD Type = OpenCert FIDO2
```

---

## T5 · builds.bat 加入 FIDO 构建

**修改文件**：
- `drivers/builds.bat`

新增 x64 和 x86 两段 FIDO 构建命令：

```bat
echo [x64] Building FIDO...
cl.exe /nologo /O2 /W3 /LD /utf-8 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS ^
    /Icodes\csp\codes codes\fido\codes\opencert_fido.c codes\csp\codes\ipc_client.c ^
    /Fe"build\OpenCertFIDO_x64.dll" ^
    /link /DEF:codes\fido\codes\OpenCertFIDO.def winscard.lib kernel32.lib advapi32.lib /NOLOGO /DLL /MACHINE:X64
```

**构建产物**：
```
build\
  OpenCertKSP_x64.dll   OpenCertKSP_x86.dll
  OpenCertCSP_x64.dll   OpenCertCSP_x86.dll
  OpenCertFIDO_x64.dll  OpenCertFIDO_x86.dll  ← 新增
```

**复用 ipc_client.c**：FIDO DLL 复用 CSP 驱动的 IPC 客户端实现，保持 IPC 通信逻辑一致。

---

## T6 · 文档更新

**修改文件**：
- `roadmap/02-ARCHITECTURE.MD` — 版本升至 v2.2.0，新增 FIDO 驱动节点（mindmap + 组件交互图 + 目录结构）
- `roadmap/07-API.MD` — 版本升至 v2.2.0，新增 §2.10 FIDO2/WebAuthn 凭据管理 API

---

## 📈 质量指标

| 指标 | 数值 |
|------|------|
| 新增 Go 源文件 | 3 个（fido.go / store.go / fido_handler.go） |
| 新增 C 源文件 | 3 个（opencert_fido.c / .h / .def） |
| 新增 REST API 端点 | 7 个 |
| 修改文件 | 3 个（server.go / builds.bat / 02-ARCHITECTURE.MD / 07-API.MD） |
| Go lint 错误 | 0 |
| 新增数据库表 | 0（复用 certificates 表） |

---

## 🔄 与前轮的关系

本轮（Round 5）聚焦在 **FIDO2/WebAuthn 认证器能力**：
- Round 4 完成了安全凭据通用框架（`credential_handler.go` + `ImportCredential`）
- Round 5 在此基础上建立专用的 FIDO 驱动层（`internal/fido/`），提供结构化的 Meta/Secret 模型、计数器防重放、公钥导出等 FIDO 专属能力
- Round 5 新增 C DLL 驱动，通过 CCID 虚拟智能卡接入 Windows WebAuthn 生态

**下一步**：
- FIDO DLL 安装脚本（`setup/register_fido.ps1`）完善
- FIDO 凭据前端页面（`Credentials/Fido.tsx`）接入新 API 端点
- FIDO GetAssertion 签名流程端到端联调测试
- SM2/SM3 国密算法支持
