# TPM 加密流程实现总结

## 一、架构概览

```
┌─────────────────────────────────────────────────────────────────┐
│  前端 (Cards/index.tsx)                                          │
│  security_level: low / medium / high                            │
└────────────────────────┬────────────────────────────────────────┘
                         │ POST /api/cards { security_level }
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  API Layer (user_card_handler.go)                                │
│  → CreateCardWithCredsAndTPM(tpmProvider, args)                  │
│  → cert_handler.go: KeyManagerWithTPM.GenerateKeyPair()         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  local/keymgr.go + local/slot.go                                │
│  分流: low → encryptAndStoreCert                                 │
│        medium → encryptAndStoreCertWithTPMCertKey                │
│        high → encryptAndStoreCertWithTPMHigh                     │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  tpm.Provider 接口 (provider.go)                                 │
│  NVDefine / NVWrite / NVRead / CreateKey / LoadKey / Sign / ... │
└───────┬──────────────────────┬──────────────────────┬───────────┘
        │                      │                      │
   ┌────▼────┐          ┌─────▼─────┐         ┌─────▼─────┐
   │ Windows │          │  Linux    │         │  sw-stub  │
   │   CNG   │          │  (TODO)   │         │  (开发用)  │
   │ DPAPI+  │          │  go-tpm   │         │  文件+AES  │
   │ NCrypt  │          │  /dev/tpm │         │           │
   └─────────┘          └───────────┘         └───────────┘
```

## 二、三级安全模型

| 等级 | 私钥保护 | 签名方式 | 导出策略 |
|------|----------|----------|----------|
| **low** | masterKey AES-GCM 单层加密，存 SQLite | Go crypto 内存签名 | PIN/AdminKey 解锁后可导出 |
| **medium** | masterKey 加密 → TPM 证书密钥再加密（双层）；TPM 证书密钥存 TPM NV（Windows: DPAPI） | Go crypto 内存签名（一次性取出私钥） | 需 AdminKey + TPM 设备 |
| **high** | 私钥在 TPM 内生成，**永不出 TPM**；只有 wrapped blob 入库 | TPM 内部签名 (NCryptSignHash / tpm2.Sign) | **完全不可导出** |

---

## 三、medium 模式详细流程

### 3.1 创建卡片

```
CreateCardWithCredsAndTPM():
  1. masterKey = rand(32B)
  2. PIN/PUK/AdminKey 各自加密 masterKey → card.CardKeys[]
  3. tpmCertKey = rand(32B)                                    ← 本地随机生成
  4. nvAuth = HMAC-SHA256(masterKey, "tpm-cert-key/auth/v1")   ← NV 授权值
  5. nvHandle = tpmProvider.NVDefine("cert-key:<cardUUID>", 32, nvAuth)
  6. tpmProvider.NVWrite(nvHandle, nvAuth, tpmCertKey)          ← 主副本进 TPM
  7. card.TPMCertKeyNVHandle = nvHandle
  8. adminAES = HMAC-SHA256(adminKey, salt)
     card.TPMCertKeyEnc = AES-GCM(adminAES, tpmCertKey)        ← 应急恢复副本
```

### 3.2 生成证书（加密私钥）

```
encryptAndStoreCertWithTPMCertKey():
  1. privDER, pubDER = generateKeyPair(keyType)    ← Go crypto 生成
  2. tempKey = rand(32B)
  3. tempKeyAESKey = HMAC-SHA256(masterKey, salt)
  4. cert.TempKeyEnc = AES-GCM(tempKeyAESKey, tempKey)
  5. inner = AES-GCM(tempKey, privDER)              ← 第 1 层：masterKey 派生加密
  6. nvAuth = HMAC-SHA256(masterKey, "tpm-cert-key/auth/v1")
  7. tpmCertKey = tpmProvider.NVRead(nvHandle, nvAuth)  ← 从 TPM 取出
  8. outer = AES-GCM(tpmCertKey, inner)              ← 第 2 层：TPM 证书密钥加密
  9. cert.PrivateData = outer
  10. cert.TPMPlatform = "medium-v2"
  11. zeroize(tpmCertKey, tempKey, privDER)
```

### 3.3 签名（解密私钥）

```
slot.decryptPrivateKey() [medium-v2]:
  1. nvAuth = HMAC-SHA256(masterKey, "tpm-cert-key/auth/v1")
  2. tpmCertKey = tpmProvider.NVRead(nvHandle, nvAuth)
  3. inner = AES-GCM_Decrypt(tpmCertKey, cert.PrivateData)   ← 解外层
  4. tempKey = AES-GCM_Decrypt(HMAC(masterKey,salt), cert.TempKeyEnc)
  5. privDER = AES-GCM_Decrypt(tempKey, inner)               ← 解内层
  6. sig = rsa.SignPKCS1v15(privKey, digest)                  ← Go crypto 签名
  7. zeroize(tpmCertKey, tempKey, privDER)
```

### 3.4 安全分析

- **数据库被脱出**：拿到 cert.PrivateData（outer），无法解密——缺少 tpmCertKey（在 TPM NV 中）
- **文件系统被拷贝**（Windows）：NV 文件被 DPAPI 加密，绑定到当前 Windows 用户+机器
- **PIN 泄露**：可解出 masterKey，但还需 TPM 设备才能 NVRead → 多因子保护
- **AdminKey 泄露**：可解出 TPM 证书密钥的应急副本 → 但仍需 cert.PrivateData 和 masterKey
- **应急恢复**：AdminKey + 数据库 → 解出 tpmCertKey → 可重新 NVWrite 到新 TPM 设备

---

## 四、high 模式详细流程

### 4.1 生成证书

```
encryptAndStoreCertWithTPMHigh():
  1. alg = keyTypeToTPMAlg(req.KeyType)           ← rsa2048 → KeyAlgRSA2048
  2. auth = HMAC-SHA256(masterKey, "tpm-high-key/auth/v1" + certUUID)
  3. (wrapped, pubKey) = tpmProvider.CreateKey(alg, auth)
     ★ Windows CNG: NCryptCreatePersistedKey → FinalizeKey → 私钥永驻 TPM
  4. cert.CertContent = PEM(pubKey)
  5. cert.TPMWrappedBlob = JSON(wrapped)
     ★ wrapped.Private = keyName (CNG) 或 加密PKCS8 (sw-stub)
  6. cert.TPMPlatform = "high-v1"
  7. cert.PrivateData = nil                        ← 不存私钥明文
```

### 4.2 签名

```
slot.signWithTPM():
  1. wrapped = unmarshalWrappedKey(cert.TPMWrappedBlob)
  2. auth = HMAC-SHA256(masterKey, "tpm-high-key/auth/v1" + certUUID)
  3. handle = tpmProvider.LoadKey(wrapped, auth)
     ★ Windows CNG: NCryptOpenKey(keyName) → hKey
  4. sig = tpmProvider.Sign(handle, digest, scheme)
     ★ Windows CNG: NCryptSignHash(hKey, paddingInfo, digest)
  5. tpmProvider.FlushHandle(handle)
     ★ Windows CNG: NCryptFreeObject(hKey)
  6. return sig
  ★ 全程私钥从未以明文形式出现在 Go 进程内存
```

### 4.3 安全分析

- **数据库被脱出**：cert.TPMWrappedBlob 只有 keyName，无私钥 → 无法签名
- **文件系统被拷贝**：CNG 持久化密钥不可导出（EXPORT_POLICY=0）→ 无法迁移
- **PIN + 文件系统**：即使 masterKey 解出，NCryptOpenKey 需本机 TPM 或 SWKSP → 绑定机器
- **不可恢复**：high 卡的私钥**无法**从一台机器迁移到另一台，这是设计意图

---

## 五、Windows CNG 后端实现

### 5.1 Provider 选择策略

```go
newPlatformProvider():
  1. 尝试 "Microsoft Platform Crypto Provider" → TPM 硬件（最高安全）
  2. 失败 → "Microsoft Software Key Storage Provider" → DPAPI 保护
  3. 再失败 → NewSoftwareStub() → 文件 + AES（开发/测试用）
```

### 5.2 API 映射

| tpm.Provider 方法 | Windows 实现 |
|---|---|
| `Available()` | NCryptOpenStorageProvider 是否成功 |
| `PlatformName()` | `"windows-cng"` (PCP) / `"windows-swksp"` |
| `Seal/Unseal` | DPAPI CryptProtectData / CryptUnprotectData |
| `NVDefine` | 创建 DPAPI 保护文件 `%APPDATA%/GlobalTrusts/.../nv/<handle>.dpapi` |
| `NVWrite` | 校验 authDigest → DPAPI 加密 data → 写文件 |
| `NVRead` | 校验 authDigest → 读文件 → DPAPI 解密 |
| `NVUndefine` | 删除文件 |
| `CreateKey` | NCryptCreatePersistedKey → SetProperty(不可导出) → FinalizeKey |
| `LoadKey` | NCryptOpenKey(keyName) |
| `Sign` | NCryptSignHash(hKey, paddingInfo, digest) |
| `Decrypt` | NCryptDecrypt(hKey, ciphertext, PKCS1) |
| `FlushHandle` | NCryptFreeObject(hKey) |

### 5.3 CNG Blob → PKIX 转换

- **RSA**: 解析 `BCRYPT_RSAKEY_BLOB` (Magic=0x31415352) → 提取 Exponent + Modulus → `rsa.PublicKey` → `x509.MarshalPKIXPublicKey`
- **ECC**: 解析 `BCRYPT_ECCKEY_BLOB` (Magic=ECS1/ECS3/ECS5) → 提取 X + Y → `ecdsa.PublicKey` → `x509.MarshalPKIXPublicKey`

---

## 六、数据库字段

### cards 表（新增）

| 字段 | 类型 | 用途 |
|------|------|------|
| `tpm_cert_key_nv_handle` | INTEGER | medium: TPM NV 句柄 |
| `tpm_provider` | TEXT | 后端标识 (windows-cng / sw-stub / ...) |

### certificates 表（新增）

| 字段 | 类型 | 用途 |
|------|------|------|
| `tpm_wrapped_blob` | TEXT | high: WrappedKey JSON 序列化 |
| `tpm_cert_key_salt` | TEXT | medium-v2 版本标记 |

---

## 七、密钥派生汇总

| 派生名 | 公式 | 用途 |
|--------|------|------|
| NV 授权值 | `HMAC-SHA256(masterKey, "tpm-cert-key/auth/v1")` | medium NVRead/NVWrite |
| High Key 授权值 | `HMAC-SHA256(masterKey, "tpm-high-key/auth/v1" + certUUID)` | high LoadKey |
| AdminKey 加密 KEK | `HMAC-SHA256(adminKey, tpmCertKeySalt)` | 应急恢复副本 |
| TempKey 加密 KEK | `HMAC-SHA256(masterKey, tempKeySalt)` | 临时密钥加密 |
| NV DPAPI KEK (CNG) | Windows DPAPI 内部派生 | NV 文件保护 |

---

## 八、跨平台支持状态

| 平台 | 后端 | 状态 | NV 保护 | 密钥保护 |
|------|------|------|---------|----------|
| **Windows** | CNG (PCP/SWKSP) | ✅ 已实现 | DPAPI | NCrypt 持久化密钥（TPM 或 DPAPI） |
| **Linux** | sw-stub | ✅ 可用 | 文件 AES-GCM | 文件 AES-GCM |
| **Linux** | go-tpm (真 TPM) | 🔜 TODO | tpm2.NVWrite | tpm2.Create + Sign |
| **macOS** | sw-stub | ✅ 可用 | 文件 AES-GCM | 文件 AES-GCM |
| **macOS** | Secure Enclave | 🔜 TODO | Keychain | SecKeyCreate + Sign |

---

## 九、导出与恢复

| 操作 | low | medium | high |
|------|-----|--------|------|
| 导出私钥 | ✅ PIN/AdminKey 解锁 | ⚠️ 需 AdminKey + TPM | ❌ 禁止 |
| 卡片备份 | ✅ 完整 | ⚠️ 含应急副本，新设备需重建 NV | ❌ 无法迁移 |
| 证书导入 | ✅ | ✅ 走双层加密 | ❌ 禁止（必须 TPM 内生成） |

---

## 十、文件改动清单

| 文件 | 改动类型 |
|------|----------|
| `clients/internal/tpm/provider.go` | 重写：12 方法接口 |
| `clients/internal/tpm/swstub.go` | 新增：sw-stub 全实现 |
| `clients/internal/tpm/sign.go` | 新增：共享签名 helper |
| `clients/internal/tpm/mock.go` | 重写：内存 NV + Mock key |
| `clients/internal/tpm/tpm2_windows_cng.go` | 新增：CNG + DPAPI 后端 |
| `clients/internal/tpm/tpm2_linux.go` | 简化为 sw-stub 委托 |
| `clients/internal/tpm/tpm2_darwin*.go` | 简化为 sw-stub 委托 |
| `clients/internal/tpm/tpm2_other.go` | 简化为 sw-stub 委托 |
| `clients/internal/tpm/crypto.go` | 保留（AES-GCM 工具） |
| `clients/internal/card/local/keymgr.go` | 重写：medium/high 加密路径 |
| `clients/internal/card/local/tpm_helpers.go` | 新增：KDF + 序列化 |
| `clients/internal/card/local/slot.go` | 扩展：medium/high 解密签名 |
| `clients/internal/storage/models.go` | 扩展字段 |
| `clients/internal/storage/db.go` | Schema + 迁移 |
| `clients/internal/storage/repo.go` | CRUD 同步 |
| `clients/internal/storage/cert_repo.go` | CRUD 同步 |
| `clients/internal/api/server.go` | +tpmProvider 字段 |
| `clients/internal/api/user_card_handler.go` | 调 CreateCardWithCredsAndTPM |
| `clients/internal/api/*_handler.go` | NewKeyManagerWithTPM |
| `clients/cmd/client-card/main.go` | TPM 注入 + loadLocalSlots |
| `clients/front/src/pages/Cards/index.tsx` | 文案修正 |
