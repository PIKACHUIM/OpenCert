// Package tpm 提供 TPM2 / Secure Enclave 的抽象接口。
//
// 接口语义参照真实 TPM 模型设计：
//   - NV 域：以 (Index, AuthValue) 形式存放对称密钥/小数据，永不出 TPM。
//   - 非对称密钥：用 CreateKey 在 TPM 内生成，得到 wrapped blob（Public+Private+AuthValue 哈希），
//     通过 LoadKey/Sign/Decrypt 在 TPM 内部完成签名/解密；私钥永远不以明文形式出现在外部。
//
// 当前提供两种后端：
//   1. SoftwareStub（默认）：用本地受保护文件 + AES-256-GCM 模拟，保持与真 TPM 完全相同的接口语义，
//      用于尚未接入真实硬件 / 开发 / 测试。PlatformName="sw-stub"。
//   2. （TODO）TPM2 真实后端：Windows 走 CNG/Platform Crypto Provider（自家 KSP 同源），
//      Linux/macOS 走 go-tpm + /dev/tpmrm0 等。完成后会替换 NewProvider 工厂。
//
// 上层（local 包）只依赖本接口，不感知后端差异。
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

// Provider 是 TPM/SE 的抽象接口。
type Provider interface {
	// ---- 基础 ----
	Available() bool
	PlatformName() string

	// ---- 兼容旧 API：基于"绑定密钥"的 Seal/Unseal，不绑定 NV 索引、不带授权 ----
	Seal(data []byte) (blob []byte, err error)
	Unseal(blob []byte) (data []byte, err error)

	// ---- NV 存储能力（用于 medium：把"证书密钥"放进 NV 域） ----
	// NVDefine 在 TPM 中定义一个 NV 槽（label 仅作运维标识）。
	// authValue 是访问该槽时必须提供的口令（可为 nil 表示不限制；medium 模式应使用 AdminKey）。
	NVDefine(label string, size int, authValue []byte) (NVHandle, error)
	// NVWrite 写入数据到指定 NV 槽，需要正确的 authValue。
	NVWrite(h NVHandle, authValue, data []byte) error
	// NVRead 从指定 NV 槽读出数据，需要正确的 authValue。数据从未离开 TPM 实现的安全域。
	NVRead(h NVHandle, authValue []byte) ([]byte, error)
	// NVUndefine 删除 NV 槽。
	NVUndefine(h NVHandle) error

	// ---- 非对称密钥能力（用于 high：私钥永不出 TPM） ----
	// CreateKey 在 TPM 内生成非对称密钥对，返回 wrapped blob 与 SPKI 公钥。
	// authValue 可为 nil；当非空时使用该密钥必须提供同样的 authValue。
	CreateKey(alg KeyAlg, authValue []byte) (wrapped *WrappedKey, pub crypto.PublicKey, err error)
	// ImportKey 将外部 PKCS#8 DER 私钥导入 TPM，设为不可导出，返回 wrapped blob 与 SPKI 公钥。
	// 导入后私钥留在 TPM 中，外部明文会被调用方清零。后续 Sign/Decrypt 走 TPM 内部完成。
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
	ErrNotAvailable    = fmt.Errorf("TPM/Secure Enclave 不可用")
	ErrUnsealFailed    = fmt.Errorf("TPM 解封失败")
	ErrNVNotFound      = fmt.Errorf("TPM NV 槽不存在")
	ErrNVAuthFailed    = fmt.Errorf("TPM NV 授权值校验失败")
	ErrKeyAuthFailed   = fmt.Errorf("TPM 密钥授权值校验失败")
	ErrUnknownAlg      = fmt.Errorf("TPM 不支持的密钥算法")
	ErrUnknownScheme   = fmt.Errorf("TPM 不支持的签名方案")
	ErrHandleNotLoaded = fmt.Errorf("TPM 密钥句柄无效")
)

// NewProvider 创建当前平台默认的 TPM Provider。
// 各平台在对应的 build tag 文件中实现 newPlatformProvider()。
// 当真实硬件不可用 / 后端尚未实现时，可在调用方退化到 NewSoftwareStub()。
func NewProvider() (Provider, error) {
	return newPlatformProvider()
}
