// Package keybackend 定义服务端「私钥存储后端」的抽象层。
//
// 设计目标：
//   - 私钥可以存放在三种位置：本地数据库（主密钥加密）、TPM、HSM（PKCS#11 通用接口）；
//   - 上层（卡片服务、证书签发、交付链路）只依赖 Provider 接口，不感知具体硬件；
//   - 后端以「驱动」为单位注册，可从外部清单扩展（模块化 / 插件化）。
//
// 关键约定：
//   - 私钥永远是后端内部的引用（KeyHandle.Ref），服务端数据库只保存引用与被本地后端加密的密文；
//   - 硬件后端（TPM/HSM）默认不允许导出私钥，Export 会返回 ErrNotExportable；
//   - 签名结果格式与既有实现保持一致：RSA 为标准签名值，ECDSA 为 r||s 定长拼接。
package keybackend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Kind 是私钥存储后端的大类。
type Kind string

const (
	// KindDatabase 本地数据库：私钥由服务端主密钥 AES-256-GCM 加密后入库。
	KindDatabase Kind = "database"
	// KindTPM 可信平台模块：私钥在 TPM 内生成或封存，密码运算在 TPM 内完成。
	KindTPM Kind = "tpm"
	// KindHSM 硬件安全模块：通过 PKCS#11 通用接口对接（eToken 5110、SoftHSM、网络 HSM 等）。
	KindHSM Kind = "hsm"
)

// NormalizeKind 归一化存储区域类型（兼容历史数据中的 hsm/database 取值）。
func NormalizeKind(s string) Kind {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(KindTPM), "tpm2", "tpmv2":
		return KindTPM
	case string(KindHSM), "hsms", "pkcs11":
		return KindHSM
	case "", string(KindDatabase), "db", "local":
		return KindDatabase
	default:
		return Kind(s)
	}
}

// KeyHandle 定位一份私钥。两个字段互斥：
//   - Ref  ：硬件后端的设备内引用（JSON，见 EncodeRef）；
//   - Blob ：本地后端的加密私钥（对应 certificates.private_data）。
type KeyHandle struct {
	Driver string // 驱动 ID（对应 certificates.key_backend，空视为本地）
	Ref    string // hardware ref
	Blob   []byte // local encrypted blob
}

// IsHardware 判断该句柄是否指向硬件内的私钥。
func (h KeyHandle) IsHardware() bool {
	kind := NormalizeKind(h.Driver)
	return h.Ref != "" && (kind == KindTPM || kind == KindHSM)
}

// KeySpec 是生成/导入密钥时的规格。
type KeySpec struct {
	// KeyType 取值：rsa1024/rsa2048/rsa3072/rsa4096/ec256/ec384/ec521/ed25519
	KeyType string
	// Label 写入设备的对象标签（HSM/TPM 的可读标识），可为空。
	Label string
}

// KeyPair 是后端生成或导入密钥对的结果。
type KeyPair struct {
	// PublicDER 是 SubjectPublicKeyInfo DER。
	PublicDER []byte
	// Ref 是硬件后端的私钥引用（本地后端为空）。
	Ref string
	// Blob 是本地后端加密后的私钥（写入 certificates.private_data）。
	Blob []byte
	// Driver 是产生该密钥的驱动 ID。
	Driver string
	// Hardware 表示私钥是否留在硬件中（不可导出）。
	Hardware bool
	// Warning 是可选提示（例如「设备不支持该算法，已回退」）。
	Warning string
}

// Capabilities 描述某个后端的能力，用于前端展示与创建前校验。
type Capabilities struct {
	Generate    bool     `json:"generate"`     // 能否在设备/后端内生成密钥
	Import      bool     `json:"import"`       // 能否导入外部私钥
	Sign        bool     `json:"sign"`         // 能否签名
	Decrypt     bool     `json:"decrypt"`      // 能否解密
	Exportable  bool     `json:"exportable"`   // 能否导出私钥明文
	Persistent  bool     `json:"persistent"`   // 密钥是否跨重启保留
	KeyTypes    []string `json:"key_types"`    // 支持的密钥算法
	SignSchemes []string `json:"sign_schemes"` // 支持的签名机制名（与 /sign 接口一致）
	Note        string   `json:"note,omitempty"`
}

// Info 是后端运行期状态（健康检查结果）。
type Info struct {
	Driver  string       `json:"driver"`
	Kind    Kind         `json:"kind"`
	OK      bool         `json:"ok"`
	Detail  string       `json:"detail,omitempty"`
	Devices []DeviceInfo `json:"devices,omitempty"`
}

// DeviceInfo 描述后端下的一个设备/令牌。
type DeviceInfo struct {
	Name      string `json:"name,omitempty"`       // 令牌标签或设备名
	Model     string `json:"model,omitempty"`      // 型号
	Serial    string `json:"serial,omitempty"`     // 序列号
	SlotID    uint64 `json:"slot_id,omitempty"`    // PKCS#11 槽位 ID
	SlotIndex int    `json:"slot_index,omitempty"` // 槽位序号
	Number    int    `json:"object_count,omitempty"`
	Extra     string `json:"extra,omitempty"`
}

// Provider 是一个已打开的私钥后端实例，对应一个存储区域。
type Provider interface {
	// Driver 返回驱动 ID。
	Driver() string
	// Kind 返回后端大类。
	Kind() Kind
	// Capabilities 返回能力描述。
	Capabilities() Capabilities
	// Info 执行健康检查并返回设备信息。
	Info(ctx context.Context) (*Info, error)
	// Generate 在设备/后端内生成密钥对。
	Generate(ctx context.Context, spec KeySpec) (*KeyPair, error)
	// Import 将外部 PKCS#8 私钥导入后端（本地后端直接加密保存）。
	Import(ctx context.Context, privDER []byte, spec KeySpec) (*KeyPair, error)
	// Sign 使用 key 指向的私钥签名；mechanism 与 /api/cards/{uuid}/sign 一致。
	Sign(ctx context.Context, key KeyHandle, mechanism string, data []byte) ([]byte, error)
	// Decrypt 使用 key 指向的私钥解密；mechanism 取 RSA_PKCS / RSA_OAEP。
	Decrypt(ctx context.Context, key KeyHandle, mechanism string, ciphertext []byte) ([]byte, error)
	// Export 导出 PKCS#8 DER 私钥；硬件后端不支持时返回 ErrNotExportable。
	Export(ctx context.Context, key KeyHandle) ([]byte, error)
	// Destroy 销毁 key 指向的私钥（硬件对象删除或本地记录清除）。
	Destroy(ctx context.Context, key KeyHandle) error
	// Close 释放后端资源。
	Close() error
}

// 错误集合。
var (
	// ErrNotExportable 表示私钥由硬件保护，无法导出明文。
	ErrNotExportable = errors.New("该存储区域中的私钥由硬件保护，不可导出")
	// ErrNotSupported 表示后端不支持该操作。
	ErrNotSupported = errors.New("该存储区域不支持此操作")
	// ErrDriverNotFound 表示驱动未注册。
	ErrDriverNotFound = errors.New("未注册的私钥存储驱动")
	// ErrBadConfig 表示驱动配置不完整或非法。
	ErrBadConfig = errors.New("存储区域配置错误")
	// ErrZoneNotFound 表示存储区域不存在。
	ErrZoneNotFound = errors.New("存储区域不存在")
)

// IsHardware 判断驱动是否把私钥放在硬件中（TPM / HSM），此类私钥不可导出。
func IsHardware(driver string) bool {
	switch NormalizeKind(driver) {
	case KindTPM, KindHSM:
		return true
	default:
		return false
	}
}

// DriverText 返回驱动的中文名称（用于错误提示）。
func DriverText(driver string) string {
	switch NormalizeKind(driver) {
	case KindDatabase:
		return "本地加密存储"
	case KindTPM:
		return "TPM"
	case KindHSM:
		return "硬件安全模块（HSM）"
	default:
		return driver
	}
}

// KeyTypesAll 是本地后端支持的全部密钥类型。
var KeyTypesAll = []string{"rsa1024", "rsa2048", "rsa3072", "rsa4096", "ec256", "ec384", "ec521", "ed25519", "sm2"}

// SignSchemesAll 是当前 /sign 接口已支持的签名机制名。
var SignSchemesAll = []string{
	"MD5_RSA_PKCS",
	"SHA1_RSA_PKCS",
	"SHA256_RSA_PKCS",
	"SHA384_RSA_PKCS",
	"SHA512_RSA_PKCS",
	"SHA256_RSA_PSS",
	"SHA384_RSA_PSS",
	"SHA512_RSA_PSS",
	"SHA3_256_RSA_PKCS",
	"SHA3_384_RSA_PKCS",
	"SHA3_512_RSA_PKCS",
	"SHA3_256_RSA_PSS",
	"SHA3_384_RSA_PSS",
	"SHA3_512_RSA_PSS",
	"ECDSA",
	"ECDSA_SHA1",
	"ECDSA_SHA256",
	"ECDSA_SHA384",
	"ECDSA_SHA512",
	"ECDSA_SHA3_256",
	"ECDSA_SHA3_384",
	"ECDSA_SHA3_512",
	"SM2_SM3",
}

// refEnvelope 是硬件后端引用的通用信封，便于统一编解码与排障。
type refEnvelope struct {
	Driver string          `json:"driver"`
	Data   json.RawMessage `json:"data"`
}

// EncodeRef 把驱动的私有引用结构编码为可入库的字符串。
func EncodeRef(driver string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("编码私钥引用失败: %w", err)
	}
	env := refEnvelope{Driver: driver, Data: raw}
	buf, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("编码私钥引用失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodeRef 解析 EncodeRef 产生的字符串。
func DecodeRef(s string, v any) (string, error) {
	if s == "" {
		return "", fmt.Errorf("私钥引用为空")
	}
	buf, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("私钥引用不是合法的 base64: %w", err)
	}
	var env refEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return "", fmt.Errorf("私钥引用格式错误: %w", err)
	}
	if v != nil {
		if err := json.Unmarshal(env.Data, v); err != nil {
			return "", fmt.Errorf("私钥引用内容错误: %w", err)
		}
	}
	return env.Driver, nil
}

// sortedKeyTypes 返回稳定排序后的密钥类型列表（便于 UI 展示一致性）。
func sortedKeyTypes(list []string) []string {
	out := append([]string(nil), list...)
	sort.Strings(out)
	return out
}
