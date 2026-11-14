// Package tpm 提供 TPM2 / Secure Enclave 的抽象接口。
//
// Provider 抽象 TPM/Secure Enclave 能力。各方法的硬件保证由具体后端决定；
// SoftwareStub 只用于显式选择的开发/测试场景，不能作为硬件能力的替代。
//
// 默认 Provider 只返回当前平台明确实现的硬件后端。SoftwareStub 仅能通过显式调用
// NewSoftwareStub 获取，不能作为真实 TPM 的自动回退。
//
// 上层（local 包）只依赖本接口；需要硬件保证的调用方还必须确认 Provider 的后端身份。
package tpm

import (
	"crypto"
	"fmt"
)

// Platform 是 TPM 平台类型标识符。
type Platform string

const (
	TPMPlatformNone     Platform = ""
	TPMPlatformTPM2     Platform = "tpm2"
	TPMPlatformAppleT2  Platform = "apple_t2"
	TPMPlatformAppleSE  Platform = "apple_se"
	TPMPlatformMock     Platform = "mock"
	TPMPlatformSWStub   Platform = "sw-stub"
	TPMPlatformWinCNG   Platform = "windows-cng"
	TPMPlatformLinuxTPM Platform = "linux-tpm2"
)

// KeyAlg 标识 TPM 内部生成密钥的算法。
type KeyAlg string

const (
	KeyAlgRSA2048 KeyAlg = "rsa2048"
	KeyAlgRSA3072 KeyAlg = "rsa3072"
	KeyAlgRSA4096 KeyAlg = "rsa4096"
	KeyAlgECP256  KeyAlg = "ec256"
	KeyAlgECP384  KeyAlg = "ec384"
	KeyAlgECP521  KeyAlg = "ec521"
)

// SignScheme 标识 TPM 内部签名时使用的方案。
type SignScheme string

const (
	SignSchemeRSAPKCS1SHA256 SignScheme = "rsapkcs1-sha256"
	SignSchemeRSAPKCS1SHA384 SignScheme = "rsapkcs1-sha384"
	SignSchemeRSAPKCS1SHA512 SignScheme = "rsapkcs1-sha512"
	SignSchemeRSAPSSSHA256   SignScheme = "rsapss-sha256"
	SignSchemeECDSASHA256    SignScheme = "ecdsa-sha256"
	SignSchemeECDSASHA384    SignScheme = "ecdsa-sha384"
	SignSchemeECDSASHA512    SignScheme = "ecdsa-sha512"
	SignSchemeRaw            SignScheme = "raw" // 输入已经是摘要，直接用默认方案
)

// NVHandle 是 TPM NV 域中的逻辑句柄（owner-defined 范围内）。
// 真 TPM 实现里对应 0x01400000–0x017FFFFF；sw-stub 用本地文件名映射。
type NVHandle uint32

// WrappedKey 是 TPM 创建出来的非对称密钥的可持久化包装。
//
//	Public        : SubjectPublicKeyInfo DER（标准）
//	Private       : 后端私有的 wrapped blob，仅同一 TPM 可加载（sw-stub 下是 AES-GCM 包装的 PKCS#8）
//	AuthDigest    : AuthValue 的 SHA-256，用于绑定使用授权
//	Alg / Backend : 元信息
type WrappedKey struct {
	Alg        KeyAlg
	Backend    string
	Public     []byte
	Private    []byte
	AuthDigest []byte
}

// LoadedHandle 是 LoadKey 返回的会话内句柄；上层用完必须 FlushHandle。
type LoadedHandle uint32

// HardwareNVCapability 是后端对真实 TPM NV 存储能力的可选声明。
// 未实现此接口的 Provider 不得用于宣称 TPM NV 双层保护。
type HardwareNVCapability interface {
	HardwareNVStorageAvailable() bool
}

// SupportsHardwareNV 判断 Provider 是否明确声明并提供硬件 TPM NV。
func SupportsHardwareNV(provider Provider) bool {
	capability, ok := provider.(HardwareNVCapability)
	return provider != nil && ok && capability.HardwareNVStorageAvailable()
}

// HardwareKeyGenerationCapability 是后端对硬件内生成非导出密钥能力的声明。
type HardwareKeyGenerationCapability interface {
	HardwareKeyGenerationAvailable() bool
}

// SupportsHardwareKeyGeneration 判断 Provider 是否声明支持硬件密钥生成。
func SupportsHardwareKeyGeneration(provider Provider) bool {
	capability, ok := provider.(HardwareKeyGenerationCapability)
	return provider != nil && ok && provider.Available() && capability.HardwareKeyGenerationAvailable()
}

// PersistentKeyDeleter 删除 Provider 持久化的非对称密钥。
// 不能删除密钥的 Provider 不应实现此接口；调用方必须保留对应记录并报告错误。
type PersistentKeyDeleter interface {
	DeleteKey(wrapped *WrappedKey) error
}

// Provider 是 TPM/SE 的抽象接口。
type Provider interface {
	// ---- 基础 ----
	Available() bool
	PlatformName() string

	// ---- 兼容旧 API：基于"绑定密钥"的 Seal/Unseal，不绑定 NV 索引、不带授权 ----
	Seal(data []byte) (blob []byte, err error)
	Unseal(blob []byte) (data []byte, err error)

	// ---- NV 存储能力（具体后端可能使用硬件 NV 或明确标注的软件存储） ----
	// NVDefine 定义一个 NV 槽（label 仅作运维标识）。
	// authValue 是访问该槽时必须提供的口令（可为 nil 表示不限制）。
	NVDefine(label string, size int, authValue []byte) (NVHandle, error)
	// NVWrite 写入数据到指定 NV 槽，需要正确的 authValue。
	NVWrite(h NVHandle, authValue, data []byte) error
	// NVRead 从指定 NV 槽读出数据，需要正确的 authValue。数据从未离开 TPM 实现的安全域。
	NVRead(h NVHandle, authValue []byte) ([]byte, error)
	// NVUndefine 删除 NV 槽。
	NVUndefine(h NVHandle) error

	// ---- 非对称密钥能力 ----
	// CreateKey 在后端支持的安全边界内生成非对称密钥对，返回 wrapped blob 与 SPKI 公钥。
	// 真实 TPM 后端应在 TPM 内生成密钥；SoftwareStub 只作软件模拟。
	CreateKey(alg KeyAlg, authValue []byte) (wrapped *WrappedKey, pub crypto.PublicKey, err error)
	// ImportKey 按后端能力导入外部 PKCS#8 DER 私钥；不支持时必须返回明确错误。
	ImportKey(privKeyDER []byte, authValue []byte) (wrapped *WrappedKey, pub crypto.PublicKey, err error)
	// LoadKey 把 wrapped blob 加载进 TPM，得到一个仅当前会话有效的临时句柄。
	LoadKey(wrapped *WrappedKey, authValue []byte) (LoadedHandle, error)
	// Sign 在 TPM 内对 digest 做签名（对 RSA 签名时 digest 必须是 hash 后的值）。
	Sign(h LoadedHandle, digest []byte, scheme SignScheme) ([]byte, error)
	// Decrypt 在 TPM 内解密（仅 RSA，PKCS#1 v1.5 padding）。
	Decrypt(h LoadedHandle, ciphertext []byte) ([]byte, error)
	// DecryptOAEP 在 TPM 内用 RSA-OAEP (SHA-256) 解密，label 可选。
	DecryptOAEP(h LoadedHandle, ciphertext, label []byte) ([]byte, error)
	// FlushHandle 清理会话内句柄；调用后该 handle 不再可用。
	FlushHandle(h LoadedHandle) error
}

// 错误集合。
var (
	ErrNotAvailable                      = fmt.Errorf("TPM/Secure Enclave 不可用")
	ErrUnsealFailed                      = fmt.Errorf("TPM 解封失败")
	ErrNVNotFound                        = fmt.Errorf("TPM NV 槽不存在")
	ErrNVAuthFailed                      = fmt.Errorf("TPM NV 授权值校验失败")
	ErrKeyAuthFailed                     = fmt.Errorf("TPM 密钥授权值校验失败")
	ErrUnknownAlg                        = fmt.Errorf("TPM 不支持的密钥算法")
	ErrUnknownScheme                     = fmt.Errorf("TPM 不支持的签名方案")
	ErrHandleNotLoaded                   = fmt.Errorf("TPM 密钥句柄无效")
	ErrImportNotSupported                = fmt.Errorf("当前 TPM Provider 不支持导入外部私钥；请在硬件 TPM 中生成密钥")
	ErrHardwareNVUnavailable             = fmt.Errorf("当前 TPM Provider 未实现硬件 NV 存储；medium 安全级别不可用")
	ErrHardwareKeyGenerationNotAvailable = fmt.Errorf("当前 TPM Provider 未声明硬件密钥生成能力；high 安全级别不可用")
)

// NewProvider 创建当前平台默认的硬件 TPM Provider。
// 各平台在对应的 build tag 文件中实现 newPlatformProvider()；硬件后端不可用时返回错误，
// 不会自动退化为 SoftwareStub。
func NewProvider() (Provider, error) {
	return newPlatformProvider()
}
