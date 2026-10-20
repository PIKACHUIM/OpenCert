# 19 - 私钥存储后端（本地 / TPM / HSM）

> 目标：让「存储区域」从占位字段变成真正可用的私钥存放位置——私钥可以放在
> **本地加密存储**、**本机 TPM**、**HSM（PKCS#11 通用接口，如 SafeNet eToken 5110）**，
> 并且接入方式模块化，新增厂商设备无需改代码。

## 1. 架构

```
                           ┌──────────────────────────────┐
   存储区域(storage_zones) │  storage_type: database/tpm/hsm
   加密参数(params_enc)    │  hsm_driver : database/tpm2/pkcs11
                           └───────────────┬──────────────┘
                                           │ keybackend.Open(Config)
                                           ▼
                     ┌─────────────────────────────────────────────┐
                     │   keybackend 驱动注册表（模块化 / 插件化）     │
                     │  database（内置）│ tpm2 │ pkcs11（任意厂商库）  │
                     └───────────────┬─────────────────────────────┘
                                     │ Provider 接口
      card.Service ──► Provider.Generate / Sign / Decrypt / Export / Destroy
                                     │
      certificates.key_backend（驱动 ID） + certificates.key_ref（设备内引用）
```

### 关键抽象（`servers/internal/keybackend`）

| 概念 | 说明 |
|---|---|
| `Kind` | 后端大类：`database` / `tpm` / `hsm` |
| `Descriptor` | 驱动元数据：名称、配置字段（前端动态渲染）、厂商预设、能力 |
| `Provider` | 已打开的后端实例：`Generate/Import/Sign/Decrypt/Export/Destroy/Info` |
| `KeyHandle` | `{Driver, Ref, Blob}`——硬件后端用 `Ref`，本地后端用 `Blob`（兼容历史列） |
| `Manager` | 按存储区域缓存 Provider（避免每次运算都重新登录设备） |

私钥从不以明文离开后端：硬件后端只把**设备内引用**（CKA_ID / CNG 密钥名）写入数据库。

## 2. 三种后端

### 2.1 本地加密存储（`database`）

- 私钥由服务端主密钥 AES-256-GCM 加密后写入 `certificates.private_data`（**与历史数据完全兼容**）；
- 支持全部算法（RSA 1024~8192、P-256/384/521、Ed25519）与全部签名/解密机制；
- 可导出（PKCS#8 / PKCS#12），适合下载型证书与需要备份私钥的场景。

### 2.2 TPM（`tpm2`）

- Windows 走 CNG 的 **Microsoft Platform Crypto Provider**：密钥在 TPM 内生成、标注不可导出、
  签名/解密在 TPM 内完成；无 TPM 时可显式选择 `software` 提供程序用于流程验证；
- 密钥容器名为 `opencert/<label>-<random>`，引用写入 `key_ref`；
- 不支持导入外部私钥（TPM 安全模型决定）；
- 非 Windows 平台未内置实现，推荐用 PKCS#11 方式接入 `tpm2-pkcs11`（已内置为驱动预设）。

### 2.3 HSM / USB 令牌（`pkcs11`）

- **纯 Go 动态加载**（Windows `LoadLibrary/GetProcAddress`，Linux/macOS `purego`），不引入 cgo，
  可对接任意厂商的 64 位 PKCS#11 模块：eToken 5110（`eTPKCS11.dll`）、SoftHSM2、YubiKey PIV、
  tpm2-pkcs11、网络 HSM 客户端等；
- 通过 `C_GetFunctionList` 取函数表，再用 `purego.RegisterFunc` 绑定所需子集
  （槽位/令牌、登录、查找、生成密钥对、创建/销毁对象、签名、解密）；
- 密钥在设备内生成（`CKA_TOKEN=true`、`CKA_SENSITIVE=true`、`CKA_EXTRACTABLE=false`），
  以随机 `CKA_ID` 作为引用；支持显式开启「导入外部私钥」以写入已有私钥；
- 签名/解密按机制映射：RSA 走 `CKM_RSA_PKCS`（本地构造 DigestInfo）/`CKM_RSA_PKCS_PSS`，
  ECDSA 走 `CKM_ECDSA`（返回 r||s，与本地实现格式一致），解密走 `CKM_RSA_PKCS`/`CKM_RSA_PKCS_OAEP`。

#### 踩坑与处理：PKCS#11 结构体布局

PKCS#11 头文件对「结构体是否 1 字节打包」没有统一约定（官方 `pkcs11.h` 只给了
`#pragma pack(push, cryptoki, 1)` 的**注释模板**）：

- 绝大多数厂商模块使用编译器默认的**自然对齐**（64 位下函数表头部偏移 = 8）；
- 本项目 `drivers/` 目录下的模块在包含 cryptoki 头前加了 `push, 1`，是**紧凑布局**（偏移 = 2）。

若按错布局解析函数表，会直接跳到错误地址导致进程崩溃；按错布局编组 `CK_ATTRIBUTE`，
设备会返回「属性模板不完整」。因此实现做了两件事：

1. **加载时自动判定**：把函数表中 `C_GetInfo/C_GetSlotList/C_Finalize/...` 的项与模块
   导出的同名符号地址逐个比对，命中的偏移即为真实布局（至少比对成功 2 个才采信，
   否则回退自然对齐并打出告警）；
2. **结构体按布局编组**：`CK_ATTRIBUTE`、`CK_MECHANISM`、`CK_INFO`、`CK_TOKEN_INFO`
   全部改为按布局手工序列化/解析，两种布局都能正确工作（LP64 平台上两者本就等价）。

已在仓库自带的 PKCS#11 模块上验证：自动识别为「1 字节打包布局」，24 个函数表项与导出符号
逐一吻合，模块信息/槽位/令牌/会话/登录/生成密钥对调用链全部打通。

## 3. 配置与使用

### 3.1 创建存储区域

管理端「服务配置 → 私钥存储区域」：

1. 选择驱动（列表由后端下发，含能力与配置字段定义）；
2. HSM 驱动可点「扫描本机 HSM」自动发现已安装的 PKCS#11 模块（内置预设：
   eToken 5110、SoftHSM2、YubiKey PIV、tpm2-pkcs11）并一键填入；
3. 填写令牌 PIN（**用主密钥加密存入 `storage_zones.params_enc`，不回显**）；
4. 「测试连接」先验证再保存；保存后可在列表中随时「检测」。

开卡时选择存储区域即可，卡内所有密钥都落在该区域。

### 3.2 扩展厂商驱动（无需改代码）

`configs/keybackends.json`（见 `keybackends.json.example`）登记自定义预设：

```json
{ "presets": [ { "id": "mytoken", "name": "自研令牌", "driver": "pkcs11",
  "params": { "library": "C:\\Vendor\\mytoken.dll" },
  "search_paths": ["C:\\Vendor\\mytoken.dll"] } ] }
```

### 3.3 新增 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/storage-zones` | 列表（含能力、参数脱敏、检测状态、关联卡片数） |
| POST/PUT/DELETE | `/api/storage-zones[/{uuid}]` | 增改删（删除前校验是否仍被卡片使用） |
| GET | `/api/storage-zones/drivers` | 驱动清单（配置字段 + 厂商预设 + 能力） |
| GET | `/api/storage-zones/scan` | 扫描本机 PKCS#11 模块并校验可用性 |
| POST | `/api/storage-zones/probe` | 用未保存的配置测试连接 |
| POST | `/api/storage-zones/{uuid}/check` | 对已保存区域做健康检查并记录结果 |

## 4. 行为变化与兼容性

- `certificates` 新增 `key_backend` / `key_ref`（默认空 = 历史数据，按本地加密存储处理，**零迁移风险**）；
- `storage_zones` 新增 `params_enc` / `capabilities` / `last_check_*`；历史 `hsm_driver` 为空时按
  `storage_type` 回填（`database`→`database`，`hsm`→`pkcs11`）；
- 卡片未指定存储区域时仍使用本地加密存储；
- 证书私钥位于 TPM/HSM 时：`ExportPrivateKeyPEM`/`ExportPKCS12`/`/certificates/{uuid}/download`
  会返回**明确的 400 错误**（硬件保护不可导出），而不是笼统的 500；
- 首次启动若没有任何存储区域，会自动创建一个「本地加密存储」区域，便于在控制台直接选择。

## 5. 测试

`go test ./...` 全绿，其中：

- `internal/keybackend/pkcs11`：
  - 结构体布局断言（`CK_ATTRIBUTE`/`CK_MECHANISM`/`CK_TOKEN_INFO` 尺寸）；
  - DigestInfo 前缀符合 RFC 8017；机制映射（含 PSS 参数、OAEP 参数、密钥类型不匹配）；
  - **真实模块加载**：加载仓库内 `pkcs11-mock.c`（`gcc -shared` 编译）验证
    布局自动判定、24 个函数表项交叉校验、模块信息/槽位/令牌/会话/登录/生成密钥对；
  - Provider 链路：配置校验 → 模块加载 → 选槽 → 登录 → 健康检查（识别到令牌与序列号）。
- `test/storage_zone_test.go`：区域参数加密与回显脱敏、按区域生成 RSA/EC 密钥、
  签名验签（PKCS#1 v1.5 / PSS / ECDSA r||s）、RSA 解密、私钥 PEM/PFX 导出、
  带私钥导入、删除清理、缺失模块与区域不匹配的报错、驱动注册表完整性。

> 在本机没有真实 eToken 时，可用环境变量 `PKCS11_TEST_MODULE` 指定 PKCS#11 模块路径来跑上述硬件用例。

## 6. 遗留

- `skf`（GM/T 0016）国密中间件、`bjca` 平台尚未接入本抽象层（可各写一个 `Provider` 接入）；
- Linux 下的 TPM 建议通过 `tpm2-pkcs11` 以 PKCS#11 方式接入，未内置 `dev/tpmrm0` 直连实现；
- HSM 后端暂未实现「密钥对象清单/对账」（设备中存在但平台已删除的孤儿密钥需要运维用厂商工具清理）；
- 硬件后端暂不支持 CSR 生成与 PKCS#10 导出（Sign 接口已可用于外部 CSR 签名）。
