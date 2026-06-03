# FIDO2 凭据加密存储流程

## 概述

OpenCert FIDO2 凭据存储在本地 SQLite 数据库中，复用 `storage.Certificate` 表（`cert_type = "fido"`）。
每条凭据关联到一张虚拟智能卡（通过 `card_uuid`），私钥通过多层加密保护。

## 存储结构

| 字段 | 内容 | 是否加密 |
|------|------|----------|
| `CertContent` | 公开元数据（RPID、用户名、CredentialID、Counter 等） | ❌ 明文 JSON |
| `PrivateData` | 私密数据（ECDSA 私钥 PEM、公钥 DER、AAGUID） | ✅ AES-256-GCM |
| `TempKeyEnc` | 加密后的临时密钥 | ✅ |
| `TempKeySalt` | 临时密钥加密盐值 | 明文 |

## 数据流架构

```
浏览器 WebAuthn
  → Windows webauthn.dll
  → USB/IP 虚拟 HID（fido-go 进程）
  → IPC Named Pipe
  → client-card Go 后端
  → fido.Store（SQLite + 加密层）
```

## 加密流程（MakeCredential）

```plantuml
@startuml FIDO MakeCredential 加密存储
skinparam backgroundColor #FEFEFE
skinparam sequenceArrowThickness 2
skinparam roundcorner 10

title FIDO2 MakeCredential 加密存储流程

participant "浏览器" as Browser
participant "fido-go\n(USB/IP)" as FG
participant "client-card\n(IPC后端)" as CC
participant "KeyManager\n(加密引擎)" as KM
participant "SQLite\n(本地数据库)" as DB
participant "TPM/CNG\n(硬件安全)" as TPM

== 1. 请求阶段 ==
Browser -> FG : WebAuthn MakeCredential\n(rpId, user, clientDataHash)
FG -> CC : IPC CmdFIDOMakeCredential\n(CBOR 请求 base64)

== 2. 密钥生成 ==
CC -> CC : 生成 EC P-256 密钥对\n(ecdsa.GenerateKey)
CC -> CC : 生成 CredentialID\n(32字节随机数)
CC -> CC : 序列化私钥 → PEM\n序列化公钥 → DER

== 3. 获取主密钥 ==
CC -> CC : findAnyLoggedInSlot()\n获取已登录的 Slot
CC -> CC : slot.MasterKey()\n获取内存中缓存的主密钥

== 4. 加密存储 ==
CC -> KM : ImportCredential(\n  cardUUID, secretData,\n  masterKey, card)

group 加密过程
  KM -> KM : tempKey = 随机32字节
  KM -> KM : tempKeySalt = 随机盐值
  KM -> KM : tempKeyAESKey =\n  HMAC-SHA256(masterKey, tempKeySalt)
  KM -> KM : tempKeyEnc =\n  AES-256-GCM(tempKeyAESKey, tempKey)
  KM -> KM : inner =\n  AES-256-GCM(tempKey, secretData)

  alt 安全等级 = medium / high（有TPM）
    KM -> TPM : NVRead(card.TPMCertKeyNVHandle, auth)
    TPM --> KM : tpmCertKey
    KM -> KM : final =\n  AES-256-GCM(tpmCertKey, inner)
    note right: 双层加密：\nmasterKey + TPM硬件密钥
  else 安全等级 = low
    KM -> KM : final = inner
    note right: 单层加密：\n仅 masterKey 保护
  end
end

KM -> DB : INSERT Certificate {\n  CertContent = meta(JSON),\n  PrivateData = final,\n  TempKeyEnc = tempKeyEnc,\n  TempKeySalt = tempKeySalt\n}

== 5. 构造响应 ==
CC -> CC : buildAuthenticatorData(\n  rpIdHash, credID, pubKey, counter=0)
CC -> CC : buildAttestationObject(\n  authData, fmt="none")
CC --> FG : attestationObject (CBOR)
FG --> Browser : 注册成功 ✅

@enduml
```

## 解密流程（GetAssertion）

```plantuml
@startuml FIDO GetAssertion 解密签名
skinparam backgroundColor #FEFEFE
skinparam sequenceArrowThickness 2
skinparam roundcorner 10

title FIDO2 GetAssertion 解密签名流程

participant "浏览器" as Browser
participant "fido-go\n(USB/IP)" as FG
participant "client-card\n(IPC后端)" as CC
participant "KeyManager\n(加密引擎)" as KM
participant "SQLite\n(本地数据库)" as DB
participant "TPM/CNG\n(硬件安全)" as TPM

== 1. 请求阶段 ==
Browser -> FG : WebAuthn GetAssertion\n(rpId, clientDataHash, allowList)
FG -> CC : IPC CmdFIDOGetAssertion\n(CBOR 请求 base64)

== 2. 查找凭据 ==
CC -> DB : 查询 cert_type="fido"\n且 RPID 匹配的凭据
DB --> CC : Certificate {\n  PrivateData, TempKeyEnc,\n  TempKeySalt, TPMPlatform\n}
CC -> CC : 匹配 allowList 中的 credentialId

== 3. 获取主密钥 ==
CC -> CC : slot.MasterKey()\n获取内存中缓存的主密钥

== 4. 解密私钥 ==
CC -> KM : ExportCredential(\n  certUUID, masterKey, card)

group 解密过程
  alt 有 TPM 层 (medium/high)
    KM -> TPM : NVRead(card.TPMCertKeyNVHandle, auth)
    TPM --> KM : tpmCertKey
    KM -> KM : inner =\n  AES-256-GCM-Decrypt(tpmCertKey, PrivateData)
    note right: 先解 TPM 外层
  else low
    KM -> KM : inner = PrivateData
  end

  KM -> KM : tempKeyAESKey =\n  HMAC-SHA256(masterKey, TempKeySalt)
  KM -> KM : tempKey =\n  AES-256-GCM-Decrypt(tempKeyAESKey, TempKeyEnc)
  KM -> KM : secretData =\n  AES-256-GCM-Decrypt(tempKey, inner)
end

KM --> CC : secretData (私钥PEM明文)

== 5. 签名 ==
CC -> CC : 解析 PEM → ecdsa.PrivateKey
CC -> CC : 递增 Counter（防重放）
CC -> CC : authData = rpIdHash + flags + counter
CC -> CC : sigData = SHA256(authData || clientDataHash)
CC -> CC : sig = ECDSA.Sign(privKey, sigData)
CC -> CC : 清零私钥内存 🔒

== 6. 构造响应 ==
CC -> CC : buildAssertionObject(\n  credential, authData, sig)
CC --> FG : assertionObject (CBOR)
FG --> Browser : 认证成功 ✅

@enduml
```

## 三级安全等级对比

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 安全等级 │ 加密层数 │ 密钥保护方式                                       │
├─────────────────────────────────────────────────────────────────────────┤
│ Low      │ 1 层     │ masterKey → HMAC → tempKey → AES-GCM(私钥)        │
│          │          │ 仅软件保护，PIN 正确即可解密                        │
├─────────────────────────────────────────────────────────────────────────┤
│ Medium   │ 2 层     │ 内层：masterKey → tempKey → AES-GCM(私钥)          │
│          │          │ 外层：TPM NV 中的 tpmCertKey → AES-GCM(内层密文)   │
│          │          │ 即使数据库被拷贝，没有 TPM 硬件也无法解密           │
├─────────────────────────────────────────────────────────────────────────┤
│ High     │ 2 层     │ 同 medium（若 TPM 可用）                            │
│          │          │ TPM 不可用时退化为 low                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## PIN 登录与 USB/IP 重启流程

```plantuml
@startuml FIDO PIN 登录流程
skinparam backgroundColor #FEFEFE
skinparam sequenceArrowThickness 2
skinparam roundcorner 10

title FIDO2 PIN 登录与 USB/IP 重启流程

participant "浏览器" as Browser
participant "Windows\nWebAuthn" as Win
participant "fido-go\n(USB/IP)" as FG
participant "PIN对话框\n(Win32)" as PIN
participant "client-card" as CC
participant "usbip.exe" as USBIP

== 首次请求（卡片未登录） ==
Browser -> Win : navigator.credentials.create()
Win -> FG : CTAP2 MakeCredential
FG -> CC : IPC CmdFIDOMakeCredential
CC --> FG : rv=54 (PIN_REQUIRED)\n+ 卡片列表 JSON

== PIN 输入 ==
FG -> PIN : PromptPIN(cards)
note right: 弹出 Win32 对话框\n选择卡片 + 输入 PIN
PIN --> FG : {cardUUID, PIN}

== 登录 ==
FG -> CC : IPC CmdFIDOLogin\n{card_uuid, pin}
CC -> CC : slot.Login(pin)\n派生 masterKey 并缓存
CC --> FG : rv=0 (成功)

== USB/IP 重启 ==
FG --> Win : 返回 0x27\n(OPERATION_DENIED)
note right: 让当前请求优雅失败

FG -> USBIP : detach -p 0
note right: 断开虚拟 USB 设备
USBIP --> FG : 成功

FG -> FG : 等待 1 秒

FG -> USBIP : attach -r 127.0.0.1 -b 2-2
note right: 重新连接虚拟 USB 设备
USBIP --> FG : 成功

== 第二次请求（卡片已登录） ==
Win -> FG : CTAP2 MakeCredential
FG -> CC : IPC CmdFIDOMakeCredential
note right: 此时 slot 已登录\nmasterKey 已缓存
CC -> CC : 生成密钥对 + 加密存储
CC --> FG : rv=0 + attestationObject
FG --> Win : 成功响应
Win --> Browser : 注册完成 ✅

@enduml
```

## 关键安全设计

1. **masterKey 来源**：用户输入 PIN → `slot.Login()` → 从卡片加密密钥派生 → 缓存在进程内存中（登录期间有效）

2. **间接加密（tempKey）**：私钥不直接用 masterKey 加密，而是：
   - 生成随机 `tempKey`（32字节）
   - 用 `HMAC-SHA256(masterKey, salt)` 派生 AES 密钥加密 `tempKey`
   - 用 `tempKey` 加密实际私钥数据
   - 好处：即使 masterKey 泄露，没有对应的 salt 也无法解密

3. **TPM 双层保护**（medium/high）：
   - 内层用 masterKey 加密
   - 外层用 TPM 硬件中存储的密钥再加密
   - 即使数据库文件被拷贝到另一台电脑，没有 TPM 硬件也无法解密

4. **内存安全**：
   - 所有密钥使用后立即 `zeroBytes()` 清零
   - 使用 `defer` 确保异常时也能清零
   - PIN 输入框内容在读取后立即清除

5. **防重放**：
   - 每次 GetAssertion 签名后递增 Counter
   - 服务端验证 Counter 单调递增，防止重放攻击

## 文件位置

| 组件 | 路径 |
|------|------|
| FIDO Store（存储层） | `clients/internal/fido/store.go` |
| KeyManager（加密引擎） | `clients/internal/card/local/keymgr.go` |
| MakeCredential 处理 | `clients/internal/ipc/handler_fido.go` |
| GetAssertion 处理 | `clients/internal/ipc/handler_fido.go` |
| IPC CTAP 代理 | `drivers/codes/fido-go/internal/client/opencert_client.go` |
| PIN 对话框 | `drivers/codes/fido-go/internal/client/pin_dialog_windows.go` |
| USB/IP 主程序 | `drivers/codes/fido-go/cmd/fido-go/main.go` |
