# OpenCert Manager — 客户端与服务端对齐性分析报告

> 报告版本：v1.0.0
> 生成日期：2026-09-22
> 分析对象：`servers/`（server-card，云端平台） ↔ `clients/`（client-card，本地管理端）
> 分析方式：代码级静态审查（路由表、数据模型、跨端调用点逐条比对）
> 结论等级：**部分可对齐 —— 存在 3 项硬性阻断、4 项语义错位、若干功能缺口**

---

## 一、结论摘要

服务端与客户端在**"身份凭证平面"**（卡片、证书、密钥操作、PIN 授权、同步下发、PKCS#11）应当对齐，且大部分只需补齐 3 个阻断项与 4 个契约项即可达成，**无架构级改动**；但在**"平台运营平面"**（订单、支付、模板体系、ACME、CT、用户 RBAC）客户端作为消费者，不应、也不需要对齐。

### 三项硬性阻断（P0）

| 编号 | 问题 | 影响面 |
|---|---|---|
| P0-1 | 客户端调用的 `POST /api/certificates/{uuid}/download` 在服务端**根本不存在** | 云端证书+私钥下发功能 100% 不可用 |
| P0-2 | 服务端 `sign/decrypt/importCert/deleteCert` 强制 `X-PIN-Session`，客户端**从不建立 PIN 会话** | 云端卡一旦设置 PIN，客户端所有密钥操作必然 401 |
| P0-3 | 服务端 TOTP 账号登录返回 `require_totp`（无 token），客户端**不识别该分支** | 绑定 2FA 的云端账号在客户端静默登录失败 |

### 关键量化结论

- 客户端实际调用的云端接口共 **7 条**；服务端对外暴露的 API 共 **约 130 条**。
- 客户端与服务端的**功能交集仅覆盖"云卡消费"**，未覆盖"云卡生产"（建卡、制钥、导入证书、生命周期管理）。
- 客户端全仓检索 `ListCards` / `VerifyPIN` / `X-PIN-Session` / `pin_session`（`*.go`）→ **命中 0 次**，确认为完全未实现，而非调用路径隐蔽。

---

## 二、调查范围与方法

### 2.1 范围

| 组件 | 路径 | 技术栈 |
|---|---|---|
| 服务端 | `servers/` | Go 1.22 + `net/http` 标准库 + `database/sql`（SQLite/PG/MySQL）+ JWT |
| 服务端前端 | `servers/front/` | React 19 + TS + Vite 7 + Ant Design 6 |
| 客户端 | `clients/` | Go 1.22 + `net/http` + SQLite（modernc）+ Named Pipe IPC |
| 客户端前端 | `clients/front/` | React 19 + TS + Vite 7 + Ant Design 6 |

### 2.2 方法

1. 提取服务端 `registerRoutes` 全量路由（`servers/internal/api/server.go`），按业务模块归类。
2. 提取客户端全量本地路由 + **所有指向云端的 URL 字符串**（重点：`clients/internal/card/cloud/client.go`）。
3. 逐条比对客户端调用点与服务端实现（method + path + 请求体 + 响应体 + 鉴权前置条件）。
4. 比对两端数据模型（`servers/internal/storage/models.go` ↔ `clients/internal/storage/models.go`）。
5. 对"未实现"结论做全仓反向检索，排除"实现于其它路径"的可能。

---

## 三、两端系统画像

### 3.1 服务端（server-card）能力概览

- **架构**：单进程 Go 服务，标准库 `net/http`（Go 1.22 `ServeMux` 方法+路径模式），无 Web 框架、无 ORM，手写 SQL。
- **存储**：默认 SQLite（`data/server.db`），可通过 `DATABASE_URL` 切换 PostgreSQL / MySQL。
- **鉴权**：JWT（`golang-jwt/jwt/v5`）+ RBAC（admin / operator / user / readonly）。
- **16 个内部包**：`acme` `api` `auth` `ca` `card` `ct` `issuance` `mailer` `meta` `payment` `revocation` `storage` `template` `verification` `workflow`。
- **核心强项**：CA 签发引擎、8 类模板体系、CRL/OCSP 公开服务、完整 ACME 服务端、CT 提交、订单/支付工作流、云端虚拟智能卡（远程 keygen / 导入 / 签名 / 解密 / PIN 管理）。
- **明确缺口**：EST/SCEP 无；PKCS#12 为伪实现；无 KEK/信封加密；无 HSM 驱动；**无设备心跳与命令下发**；不含 PKCS#11 实现。

### 3.2 客户端（client-card）能力概览

- **架构**：Go 后端 + REST API（`127.0.0.1:1026`）+ IPC（Named Pipe / Unix Socket）+ 内嵌 React 前端。
- **角色**：既是本地管理端，也是 **PKCS#11 后端引擎**（供 `drivers/` 下的 C 驱动 DLL 通过 IPC 调用）。
- **存储**：SQLite（`data/clients.db`），私钥 AES-256-GCM 加密 + TPM 分级保护。
- **14 个内部包**：`api` `card`(local/cloud/tpm2/tpmsc) `certprop` `crypto` `fido` `ipc` `pki` `storage` `totp` `tpm` `tray` `ui`。
- **核心强项**：4 类 Slot（local/tpm2/tpmsc/cloud）、本地 PKI（CA/CSR/自签发/签发/吊销）、证书传播到 OS 证书存储（CAPI MY）、FIDO2/WebAuthn、KSP 与 CCID 扩展命令族。
- **明确缺口**：云端 PIN 会话、云端建卡/制钥、云端证书生命周期调用、云端证书下发（接口不存在）。

---

## 四、对齐维度分析

### 4.1 接口契约对齐

#### 4.1.1 客户端 → 服务端调用清单（全量 7 条）

| # | 方法 | 路径 | 客户端位置 | 服务端实现 | 对齐 |
|---|---|---|---|---|---|
| 1 | POST | `/api/auth/login` | `cloud.Client.Login` | `handleLogin` | ⚠️ 无 `expires_at`；无 TOTP 分支 |
| 2 | POST | `/api/auth/refresh` | `cloud.Client.Refresh` | `handleRefresh` | ⚠️ 仅返回 `token` |
| 3 | GET | `/api/cards` | `cloud.Client.ListCards` | `handleListCards` | ❌ **客户端从未调用** |
| 4 | GET | `/api/cards/{uuid}/certs` | `cloud.Client.ListCerts` | `handleListCerts` | ✅ 响应 `{certs,total}` 已对齐 |
| 5 | POST | `/api/cards/{uuid}/sign` | `cloud.Client.Sign` | `handleSign` | ❌ 缺 `X-PIN-Session` |
| 6 | POST | `/api/cards/{uuid}/decrypt` | `cloud.Client.Decrypt` | `handleDecrypt` | ❌ 缺 `X-PIN-Session` |
| 7 | POST | `/api/certificates/{uuid}/download` | `cloud.Client.DownloadCertWithKey` | **不存在** | ❌ **P0-1** |

另有 1 条本地转发：`clients/internal/api/auth_handler.go` 的 `defaultCloudLoginDoer` → 云端 `/api/auth/login`。

> 结论：7 条调用中，**仅 1 条（#4）完全对齐**。

#### 4.1.2 服务端已具备但客户端未使用的关键接口

| 路径 | 功能 | 客户端应使用场景 |
|---|---|---|
| `POST /api/cards` | 创建云端卡 | 客户端"新建云卡" |
| `POST /api/cards/{uuid}/keygen` | 云端生成密钥对 | 客户端云卡制钥 |
| `POST /api/cards/{uuid}/certs` | 导入证书到云卡 | 客户端上传本地证书 |
| `DELETE /api/cards/{uuid}/certs/{cert_uuid}` | 删除云卡证书 | — |
| `POST /api/cards/{uuid}/verify-pin` | 校验 PIN 并签发会话 | **P0-2 必需** |
| `DELETE /api/cards/{uuid}/pin-session` | 结束 PIN 会话 | **P0-2 必需** |
| `POST /api/cards/{uuid}/unlock-puk` | PUK 解锁重置 PIN | 云卡 PIN 锁定自救 |
| `POST /api/cards/{uuid}/reset-admin` | AdminKey 重置卡 | 云卡彻底重置 |
| `POST /api/auth/totp-verify` | 登录 TOTP 校验 | **P0-3 必需** |
| `GET /api/certs/{uuid}/chain` | 证书链 | 云卡证书链展示 |
| `GET /api/certs/{uuid}/renew` (`POST .../renew`) | 证书续期 | 到期续期 |
| `POST /api/certs/{uuid}/revoke` | 吊销证书 | 客户端发起吊销 |
| `GET /api/cas/{uuid}/crl` | 获取 CRL | 本地吊销状态校验 |
| `GET /api/cloud-totp` 系列 | 云端 TOTP 取码 | 客户端显示云端验证码 |

### 4.2 认证与授权模型对齐

| 维度 | 服务端 | 客户端 | 判定 |
|---|---|---|---|
| 一级凭据 | 用户名 + 密码（bcrypt） | 本地密码 / 云账号密码 | ✅ |
| 二级凭据（登录） | TOTP（`users.totp_secret`） | TOTP（`users.two_fa_*`） | ⚠️ 各自独立，不互通 |
| 令牌 | JWT（默认 24h） | 本地 session token + 云端 JWT（存 `users.auth_token`） | ⚠️ 见 P1-4 |
| 卡片凭据 | 卡片 PIN / PUK / AdminKey（AES-GCM 存云端） | 本地卡：`card_keys`；云卡：**无** | ❌ 见 P0-2 / P1-1 |
| 高敏操作授权 | `X-PIN-Session`（15 min，绑定 cardUUID+userUUID） | **未实现** | ❌ |
| RBAC | admin/operator/user/readonly | admin/user/readonly/system | ⚠️ 角色集合不同 |
| 传输 | HTTPS；客户端要求 TLS 1.2+ | 但同步/下发路径硬编码 `allowInsecure=true` | ⚠️ 建议收紧 |

### 4.3 数据模型对齐

#### 4.3.1 卡片模型

| 字段/概念 | 服务端 `cards` | 客户端 `cards` | 说明 |
|---|---|---|---|
| UUID / 名称 / 备注 / 归属用户 | ✅ | ✅ | 对齐 |
| slot 类型 | ❌ 无 | ✅ local/tpm2/tpmsc/cloud | 服务端无此概念 |
| 存储区域 | ✅ `storage_zone_uuid` | ❌ 无 | 服务端独有 |
| 安全等级 | ❌ 不在卡上（在 `key_storage_templates`） | ✅ 在卡上 | **同名不同义** |
| 云端映射 | ❌ | ✅ `cloud_url` + `cloud_card_uuid` | 客户端独有 |
| PIN 重试/失败/锁定 | ✅ `pin_retries/pin_failed_count/pin_locked` | ✅ 同名字段 | ✅ 对齐（唯一完全对齐的字段组） |
| PIN/PUK/AdminKey | ✅ 云端加密 blob | ✅ `card_keys`(JSON) | 存储语义不同但概念对齐 |
| TPM 键材料 | ❌ | ✅ `tpm_cert_key_enc/salt/nv_handle`、`tpm_provider` | 客户端独有 |
| 功能开关 | ❌ | ✅ `fido_enabled/totp_enabled/credential_enabled/pin_timeout` | 客户端独有 |

#### 4.3.2 证书模型

服务端 `Certificate` 共 30 字段；客户端云卡同步仅落 6 字段：

```228:236:clients/internal/api/cloud_handler.go
		cert := &storage.Certificate{
			UUID:        cc.UUID,
			SlotType:    storage.SlotTypeCloud,
			CardUUID:    c.UUID,
			CertType:    storage.CertType(nonEmpty(cc.CertType, string(storage.CertTypeX509))),
			KeyType:     cc.KeyType,
			CertContent: cc.CertContent,
			Remark:      cc.Remark,
		}
```

丢失字段（服务端有、客户端未接收/未落库）：

```42:74:servers/internal/storage/models.go
type Certificate struct {
	UUID                string      `json:"uuid"`
	CardUUID            string      `json:"card_uuid"`
	UserUUID            string      `json:"user_uuid"` // 所属用户 UUID
	CertType            string      `json:"cert_type"` // x509/gpg/ssh
	KeyType             string      `json:"key_type"`
	CertContent         Base64Bytes `json:"cert_content"` // 公开部分
	PrivateData         Base64Bytes `json:"-"`            // 加密的私鑰，不序列化
	Remark              string      `json:"remark"`
	CAUUID              string      `json:"ca_uuid,omitempty"`
	SerialNumber        string      `json:"serial_number,omitempty"`
	SerialHex           string      `json:"serial_hex,omitempty"`
	SubjectDN           string      `json:"subject_dn,omitempty"`
	IssuerDN            string      `json:"issuer_dn,omitempty"`
	NotBefore           *time.Time  `json:"not_before,omitempty"`
	NotAfter            *time.Time  `json:"not_after,omitempty"`
	KeyUsage            int         `json:"key_usage,omitempty"`
	ExtKeyUsage         string      `json:"ext_key_usage,omitempty"`
	SANDNS              string      `json:"san_dns,omitempty"`
	SANIP               string      `json:"san_ip,omitempty"`
	SANEmail            string      `json:"san_email,omitempty"`
	SANURI              string      `json:"san_uris,omitempty"`
	CertificatePolicies string      `json:"certificate_policies,omitempty"`
	RevocationStatus    string      `json:"revocation_status"`       // active/revoked
	RevokeReason        int         `json:"revoke_reason,omitempty"`
	RevokedAt           *time.Time  `json:"revoked_at,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
	UpdatedAt           time.Time   `json:"updated_at"`
}
```

**后果**：客户端云卡证书无法显示有效期/主体/颁发者，无法做证书链构建，**无法感知吊销状态**（已吊销证书在客户端仍显示有效）。

注：客户端 `cloud.Cert` 结构体本身也未定义这些字段，属"结构体 + 落库"两处都要补。

---

## 五、问题清单

### P0-1 云端证书下发接口缺失（阻断）

**客户端实现**（假设的约定接口）：

```345:358:clients/internal/card/cloud/client.go
func (c *Client) DownloadCertWithKey(ctx context.Context, certUUID string) (*DeliveredCert, error) {
	...
	path := fmt.Sprintf("/api/certificates/%s/download", certUUID)
	if err := c.post(ctx, path, map[string]string{}, &resp); err != nil {
```

**服务端实际只有**：

```181:181:servers/internal/api/server.go
	mux.HandleFunc("GET /api/certs/{uuid}/export", s.authMiddleware(s.handleExportCert))
```

**验证**：全仓检索 `certificates/` → 服务端与 `roadmap/07-API.MD` 均**无该路径任何定义**，确认为客户端单方面假设。

**后果**：`handleCloudDeliver`（云端证书+私钥下发到本地库/本地卡）返回 502，功能全废。

**附加障碍**：即使补接口也需解决——
1. 客户端用 `POST` + JSON 取 `DeliveredCert`；服务端 export 为 `GET` + 二进制流，形态完全不同。
2. 服务端 `format=pkcs12` 是**伪实现**（返回 PEM 拼接，非真 PFX）：

```431:452:servers/internal/card/service.go
func (s *Service) ExportAsPKCS12(ctx context.Context, cert *storage.Certificate, password string) ([]byte, error) {
	// 解密私钥
	privDER, err := decryptWithMasterKey(s.masterKey, cert.PrivateData)
	...
	// 将私钥编码为 PEM
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	// 将证书编码为 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.CertContent})
	// 组合输出
	result := append(privPEM, certPEM...)
	return result, nil
}
```
   而客户端使用真 `software.sslmate.com/src/go-pkcs12` 解析 → 会解析失败。

### P0-2 PIN 会话缺失（阻断）

**服务端四个高敏操作强制校验**（`servers/internal/api/handler_card.go:127 / 151 / 206 / 247`，分别对应导入证书、删除证书、签名、解密）：

```203:208:servers/internal/api/handler_card.go
	cardUUID := r.PathValue("uuid")

	// PIN 会话校验（签名为高敏感操作，必须持有有效 PIN 会话）
	if !s.checkPINSession(w, r, cardUUID) {
		return
	}
```

**校验逻辑**：

```452:472:servers/internal/api/server.go
// checkPINSession 校验 X-PIN-Session 令牌与当前卡片 UUID 和用户 UUID 是否匹配。
// 校验失败时写回 401，并返回 false；若卡片未设置 PIN（即未启用 PIN 保护）则直接放行。
func (s *Server) checkPINSession(w http.ResponseWriter, r *http.Request, cardUUID string) bool {
	claims := claimsFromCtx(r.Context())
	// 若卡片未设置 PIN，跳过校验（兼容历史卡片）
	c, err := s.cardSvc.GetCard(r.Context(), cardUUID, claims.UserUUID)
	...
	if len(c.PINData) == 0 {
		return true
	}
	token := r.Header.Get("X-PIN-Session")
	if _, err := s.pinSessions.Verify(token, cardUUID, claims.UserUUID); err != nil {
		w.Header().Set("X-PIN-Required", "true")
		writeError(w, http.StatusUnauthorized, err.Error())
		return false
```

**客户端只带 Bearer token**：

```211:224:clients/internal/card/cloud/client.go
func (c *Client) Sign(ctx context.Context, cardUUID, certUUID, mechanism string, data []byte) ([]byte, error) {
	body := map[string]interface{}{
		"cert_uuid": certUUID,
		"mechanism": mechanism,
		"data":      data,
	}
	...
	if err := c.post(ctx, fmt.Sprintf("/api/cards/%s/sign", cardUUID), body, &resp); err != nil {
```

**验证**：客户端全仓 `*.go` 检索 `verify-pin|X-PIN-Session|VerifyPIN|pin_session` → **0 命中**。

**后果**：云端卡只要设置了 PIN，客户端所有签名/解密/证书导入/证书删除**必然 401**。"云端智能卡可用性"的致命阻断。

### P0-3 TOTP 登录分支缺失（阻断）

**服务端**：用户绑定 TOTP 时**不返回 token**。

```77:89:servers/internal/api/handler_auth.go
	// 如果用户绑定了 TOTP，返回 session_token 要求二次验证
	if user.TOTPSecret != "" {
		sessionToken, err := totpSessionStore.create(user.UUID)
		...
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"require_totp":  true,
			"session_token": sessionToken,
		})
		return
	}
```

**客户端**：不识别该字段，直接当成功处理。

```137:138:clients/internal/card/cloud/client.go
	c.SetTokenWithExpiry(resp.Token, resolveTokenExpiry(resp.ExpiresAt))
	return &resp, nil
```

**后果**：空 token 被写入 → `IsTokenExpired()` 因 `c.token == ""` 恒为 true → **登录"成功"但一切操作 401，且用户无任何提示**。云端 `/api/auth/totp-verify` 客户端从未调用。

### P1-1 "PIN"语义错位

| | 服务端 | 客户端云卡 Slot |
|---|---|---|
| PIN 含义 | 卡片自身口令（`cards.pin_data`，AES-GCM） | **平台账号密码** |
| 校验方式 | `POST /api/cards/{uuid}/verify-pin` → `X-PIN-Session` | `POST /api/auth/login` → JWT |
| 生命周期 | 15 分钟会话，绑定卡+用户 | 与 JWT 同周期 |

```128:142:clients/internal/card/cloud/slot.go
// Login 使用 PIN（格式：username:password）登录 servers。
// PIN 格式：`username:password`，例如 `alice:mypassword`
func (s *Slot) Login(ctx context.Context, userType pkcs11types.UserType, pin string) error {
	...
	// 解析 PIN：username:password
	username, password, err := parsePIN(pin)
```

客户端把 `C_Login(CKU_USER, pin)` 复用为平台登录，**只实现了一级凭据，缺二级卡 PIN**。需在契约层明确：JWT 由客户端后台用本地保存的云账号自动获取，PIN 专指云端卡 PIN。

### P1-2 卡片模型不相交

服务端 `cards` 无 `slot_type`、无 `security_level`（在模板上）；客户端 `cards` 两者皆有。同一术语"安全等级"两端定义不同：

- 服务端（`servers/internal/storage/models.go:186-193`）：high=TPM 内不可导出 / medium=本地库 TPM 密钥+云公钥加密 / low=密码+云公钥加密。
- 客户端（`clients/internal/storage/models.go:50-55`）：按私钥存储位置分级。

### P1-3 同步落库丢字段

见 4.3.2。另：去重逻辑为"仅新增"，无更新路径（源码已注明 `已存在：跳过（后续可按需实现 Update）`）。

### P1-4 Token 契约不一致

服务端登录响应：

```105:110:servers/internal/api/handler_auth.go
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":     token,
		"user_uuid": user.UUID,
		"username":  user.Username,
		"role":      user.Role,
	})
```

服务端刷新响应：

```120:120:servers/internal/api/handler_auth.go
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
```

**均不含 `expires_at`**，而客户端依赖它：

```151:160:clients/internal/card/cloud/client.go
func resolveTokenExpiry(raw string) time.Time {
	if raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t
		}
	}
	return time.Now().Add(1 * time.Hour)
```

**后果**：
1. 把 24h 的云端 token 每 1 小时误判为过期 → 每轮操作多发一次 refresh。
2. 若 `SERVER_CARD_JWT_EXPIRY_HOURS` < 1，客户端会误判仍有效而不刷新 → 401。
3. `EnsureToken` 在 token 真过期后用**过期 token** 去 refresh，必然失败，且无"用保存凭据自动重登"兜底 → 云卡签名会持续失败直到用户手动重登。

---

## 六、功能模块对齐矩阵

图例：`✅` 已对齐 ｜ `⚠️` 部分对齐 ｜ `❌` 不对齐 ｜ `➖` 客户端不涉及

| # | 功能模块 | 服务端 | 客户端 | 判定 | 差距说明 |
|---|---|---|---|---|---|
| 1 | 平台账号登录（JWT） | ✅ | ✅ | ⚠️ | 无 2FA 分支、无 `expires_at`（P0-3/P1-4） |
| 2 | 2FA / TOTP 登录 | ✅ | ✅ 各自独立 | ❌ | 不互通，不处理 `require_totp` |
| 3 | 用户 / 角色管理 | ✅ 完整 RBAC | ✅ 本地用户 | ➖ | 客户端仅持云账号凭据，不管云端用户 |
| 4 | 卡片管理 | ✅ 云卡 CRUD + EK 证明 | ✅ 本地卡 CRUD | ⚠️ | 客户端**无建卡能力**，`ListCards` 未调用，`cloud_card_uuid` 需手填 |
| 5 | PIN 校验 / 会话 | ✅ | ❌ | ❌ | **P0-2** |
| 6 | PUK 解锁 / AdminKey 重置 | ✅ | ❌（云卡） | ❌ | 云卡 PIN 锁定后客户端无自救入口 |
| 7 | 密钥对生成 | ✅ `/keygen` | ❌ 未调用 | ❌ | 不能为云卡制钥 |
| 8 | 证书列表 | ✅ | ✅ | ✅ | 包装已对齐；字段丢失（P1-3） |
| 9 | 证书导入到云卡 | ✅ | ❌ 未调用 | ❌ | — |
| 10 | 证书删除（云卡） | ✅ | ❌ 未调用 | ❌ | — |
| 11 | 云端签名 | ✅ RSA(SHA1/256/384/512/SHA3/PSS)+ECDSA+Ed25519 | ✅ 调用 | ⚠️ | 机制映射需逐条核对；被 P0-2 阻断 |
| 12 | 云端解密 | ✅ 仅 RSA | ✅ 调用 | ⚠️ | 同上；ECDSA 不支持解密（合理） |
| 13 | 证书+私钥下发 | ❌ 接口不存在 | ✅ 已实现调用 | ❌ | **P0-1** |
| 14 | 证书导出（PEM/DER/PFX） | ⚠️ PFX 伪实现 | ✅ 真 go-pkcs12 | ❌ | 需服务端补真 PKCS#12 |
| 15 | 证书生命周期（申请/审批/签发/续期/吊销） | ✅ 完整 | ❌ 未调用 | ❌ | 客户端只能只读消费 |
| 16 | 本地 CA / 自签发 | ➖ | ✅ 完整 | ➖ | 客户端独有，无需对齐 |
| 17 | CRL / OCSP / AIA | ✅ 公开服务+定时刷新 | 仅解析 URL | ⚠️ | 应拉 CRL 做本地吊销校验 |
| 18 | 证书链 | ✅ 多级 CA | ✅ 本地链解析 | ⚠️ | 云卡证书未落 `ca_uuid`，取不到链 |
| 19 | ACME / CT | ✅ 完整 | ➖ | ➖ | 平台能力 |
| 20 | 模板体系（8 类） | ✅ 完整 | ❌ 无概念 | ➖ | 建云卡时应读 `security_level`/`allow_reimport` |
| 21 | 订单 / 支付 / 余额 | ✅ 完整 | ➖ | ➖ | 不含 |
| 22 | 存储区域 / HSM | ⚠️ 仅字段占位 | ➖ | ➖ | 两端均未实现 |
| 23 | TOTP 凭据管理 | ✅ `/api/cloud-totp` | ✅ 本地 TOTP | ⚠️ | 可对接（直接取云端验证码），当前未对接 |
| 24 | FIDO2 / WebAuthn | ❌ 无 | ✅ 凭据+CCID 驱动 | ➖ | 客户端独有 |
| 25 | SSH / GPG 证书 | ✅ `cert_type` 支持 | ✅ 有解析/生成 | ⚠️ | 同步未做差异化处理 |
| 26 | 审计日志 | ✅ 链式哈希 | ✅ 链式哈希 + verify | ⚠️ | 客户端审计**不上报**云端 |
| 27 | 操作日志 | ✅ | ✅ | ➖ | 无互通 |
| 28 | 设备管理 / 心跳 / 命令下发 | ❌ **完全没有** | ➖ 无 agent | ❌ | 云端无法远程管控本地卡（架构级缺口） |
| 29 | 吊销状态同步 | ✅ `revocation_status` | ❌ 未落库 | ❌ | 已吊销证书在客户端仍显示有效 |
| 30 | 传输安全 | HTTPS / JWT | TLS1.2+，但同步路径硬编码 `allowInsecure=true` | ⚠️ | 建议收紧（`cloud_handler.go:156 / :307`） |

---

## 七、对齐改造清单

### P0 —— 打通主链路（3 项，无架构改动）

**P0-1 补云端证书下发接口**（二选一）

- 方案 A（推荐）：服务端新增 `POST /api/certificates/{uuid}/download`
  - 响应体严格对齐客户端 `DeliveredCert`：`{cert_pem, key_pem, chain_pem, algorithm, can_redeliver, serial_number, common_name, not_before, not_after}`
  - 策略校验复用 `key_storage_templates` 的 `allow_reimport` / `cloud_backup` / `allow_reissue` / `max_reissue_count`，并与 `cert_reissue_counters` 表联动
  - 权限：证书归属人或 admin；建议同时校验 `X-PIN-Session` 或要求二次密码
- 方案 B：客户端改调 `GET /api/certs/{uuid}/export?format=pkcs12`，并同步修复服务端 `ExportAsPKCS12`（引入 `go-pkcs12` 产出真 PFX）

**P0-2 补客户端 PIN 会话流程**

- `clients/internal/card/cloud/client.go` 新增 `VerifyPIN(ctx, cardUUID, pin) (token string, expiresAt time.Time, err error)`、`LogoutPINSession(...)`
- `Slot.Sign / Slot.Decrypt`：先确保会话有效（过期则自动 `verify-pin`），请求头带 `X-PIN-Session`
- 识别 401 + `X-PIN-Required: true` → 返回 `CKR_PIN_INCORRECT` / `CKR_PIN_LOCKED`，而非当前无差别错误
- 明确 `C_Login` 语义：账号密码从本地已保存的 cloud 账号读取，PIN 参数专指云端卡 PIN

**P0-3 补客户端 TOTP 登录分支**

- `Client.Login` 识别 `require_totp` / `session_token`，调用 `POST /api/auth/totp-verify` 完成二次验证
- 或将 `require_totp` 状态透传至 UI 由用户输入验证码；`handleCloudLogin` 同步改造
- 同时修复"空 token 视为成功"的判定缺陷

### P1 —— 模型与契约对齐（4 项）

**P1-1 统一"安全等级"定义**
以服务端 `key_storage_templates.security_level` 为唯一权威；客户端建云卡/同步时读取模板并映射到本地 `Card.SecurityLevel`。

**P1-2 扩 `cloud.Cert` + 同步落库字段**
补齐 `ca_uuid / serial_hex / subject_dn / issuer_dn / not_before / not_after / key_usage / san_* / revocation_status`；
把 `syncOneCloudCard` 的去重逻辑由"仅新增"改为"新增 + 更新"。

**P1-3 统一 Token 契约**
服务端 `login` / `refresh` 响应补 `expires_at`（RFC3339，客户端已按此解析）；
客户端补"token 过期后用保存凭据自动重登"兜底，并把 `expiresAt` 随 `users.auth_token` 一并持久化。

**P1-4 补客户端云卡管理闭环**
启用 `Client.ListCards`（云端拉卡 → 用户选卡 → 自动填 `cloud_card_uuid`），并补 `keygen`、`certs` 导入/删除、`unlock-puk`、`reset-admin` 的调用与 UI 入口。

### P2 —— 能力增强

| 项 | 内容 |
|---|---|
| P2-1 | 客户端接入 `/api/cloud-totp`（云端 TOTP 直接取码展示） |
| P2-2 | 同步时拉 `/api/cas/{uuid}/crl`，本地标记吊销状态 |
| P2-3 | 客户端审计日志上报云端（需服务端新增接收接口） |
| P2-4 | 收紧 `allowInsecure=true`，生产环境强制 HTTPS |
| P2-5 | 机制字符串映射表逐条对账（客户端 `Mechanisms()` 11 种 ↔ 服务端 `signRSA/signECDSA` 分支） |
| P2-6 | **架构级**：服务端新增设备注册/心跳/命令队列，客户端新增 agent 上报（若目标为"云端管控本地卡"） |

---

## 八、总结判断

### 8.1 对齐可行性分级

| 分级 | 模块范围 | 可行性 |
|---|---|---|
| **可以完全对齐** | 模块 4–14、18、20、23、25–26、30 | ✅ 仅需补 3 个 P0 + 4 个 P1，均为既有文件内扩展 |
| **应当只读对齐** | 模块 15、17、29（证书生命周期、CRL/OCSP、吊销状态） | ✅ 客户端做消费者，拉取+展示+校验 |
| **不建议对齐** | 模块 19、21、22（ACME/CT、订单支付、存储区域/HSM） | ➖ 平台运营/基础设施，无客户端对应价值 |
| **当前无法对齐** | 模块 28（设备/心跳/命令下发） | ❌ 服务端零实现，需单独立项 |
| **客户端独有** | FIDO2/WebAuthn、本地 CA/自签发、TPM 虚拟卡 | ➖ 契约中标注为"本地能力"即可 |

### 8.2 核心判断

1. **对齐的本质不是"接口数量对齐"，而是"契约语义对齐"。**
   客户端只用了 7 条云接口，缺口不在数量，而在于：**PIN 授权模型**（P0-2）、**凭据下发通道**（P0-1）、**二次验证分支**（P0-3）三处语义未定义或未实现。

2. **当前"云端智能卡"链路实际处于"只能只读消费、无法完整使用"状态。**
   可列出证书（#4 对齐），但签名/解密（#5/#6）在云端卡启用 PIN 时必然失败，下发（#7）完全不可用。

3. **"云端统一管控本地设备"这一目标在当前架构下不具备基础。**
   服务端无设备注册、无心跳、无命令队列；客户端无 agent。这是唯一需要新增架构模块的对齐项。

4. **建议的对齐边界**：客户端对齐"身份凭证平面"，服务端作为权威数据源；"平台运营平面"通过浏览器前端直接使用服务端 UI，不进入客户端。

---

## 附录 A：两端模块清单

### A.1 服务端内部包（`servers/internal/`）

| 包 | 职责 |
|---|---|
| `acme` | ACME（RFC 8555）服务端 + TLS-ALPN-01 挑战 |
| `api` | REST API、路由、中间件（JWT/RBAC/PIN 会话） |
| `auth` | JWT 签发校验、角色权限 |
| `ca` | CA 管理、证书签发引擎、CRL 生成、链导入 |
| `card` | 云端智能卡：密钥、PIN/PUK/AdminKey、签名/解密、EK 证明 |
| `ct` | 证书透明度（RFC 6962） |
| `issuance` | 颁发/续期模板服务 |
| `mailer` | SMTP 邮件 |
| `meta` | 算法、OID、主体字段元数据 |
| `payment` | 支付插件与订单/余额/退款 |
| `revocation` | CRL 缓存调度、OCSP responder、AIA |
| `storage` | DB 迁移、模型、仓储 |
| `template` | 密钥存储模板 + 校验器 |
| `verification` | 域名/邮箱/IP 验证 |
| `workflow` | 订单/申请工作流与自动签发 |

### A.2 客户端内部包（`clients/internal/`）

| 包 | 职责 |
|---|---|
| `api` | REST API、路由、中间件（认证/RBAC/限流/日志/指标） |
| `card` | Slot 与 Session 管理器、`SlotProvider` 接口 |
| `card/local` | 本地软件卡（密钥管理、加密、导出恢复） |
| `card/cloud` | 云端卡 Slot + HTTP 客户端 |
| `card/tpm2` | TPM2 Slot 与 KeyManager |
| `card/tpmsc` | Microsoft TPM 虚拟智能卡（`tpmvscmgr.exe`） |
| `certprop` | 证书传播到 OS 证书存储（CAPI MY + keyProvInfo） |
| `crypto` | AES-256-GCM / bcrypt / Argon2id / HMAC |
| `fido` | FIDO2/WebAuthn 凭据存储与编码 |
| `ipc` | PKCS#11 IPC 协议（主流程 + KSP 0x0200 + FIDO2 0x0300） |
| `pki` | 本地 CA、CSR、自签发、格式转换、SSH/GPG |
| `storage` | SQLite 数据访问、哈希链审计 |
| `totp` | TOTP（RFC 6238） |
| `tpm` | TPM Provider 抽象（Windows CNG / Linux import / mock） |
| `ui` | 前端静态资源（embed） |

---

## 附录 B：术语对照表

| 术语 | 服务端含义 | 客户端含义 | 是否同义 |
|---|---|---|---|
| 卡片 / Card | 云端虚拟智能卡（私钥存服务端） | 本地卡槽（local/tpm2/tpmsc/cloud） | ❌ |
| PIN | 卡片口令（云端加密存储） | 云卡 = 平台账号密码；本地卡 = 卡口令 | ❌ |
| PUK / AdminKey | 卡恢复凭据 | 本地卡恢复凭据 | ✅ |
| 安全等级 | 密钥可导出性策略（模板上） | 私钥存储位置（卡上） | ❌ |
| Slot | ❌ 无此概念 | 卡槽类型 | — |
| 存储区域 | `storage_zone`（database/hsm） | ❌ 无 | — |
| 云端卡映射 | ❌ 无 | `cloud_url` + `cloud_card_uuid` | — |
| 证书链 | 多级 CA 链 | 本地链解析 | ✅ |
| 审计日志 | 链式哈希 | 链式哈希 | ✅（语义同，数据不通） |

---

*报告结束。所有结论均基于代码静态审查，未进行运行时联调验证；标注为 ⚠️ 的机制映射项（模块 11/12）建议以实机联调为准。*
