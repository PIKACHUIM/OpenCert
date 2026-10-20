// Package tpm 提供基于本机 TPM 的私钥存储后端。
//
// Windows：通过 CNG 的 Microsoft Platform Crypto Provider（PCP）在 TPM 内生成
// 不可导出密钥，签名/解密由 TPM 完成；无 TPM 时不会静默降级为软件实现。
//
// 其它平台：如需在 Linux 上使用 TPM，推荐以 PKCS#11 形式接入
// （tpm2-pkcs11 模块），见存储区域的 PKCS#11 驱动预设。
package tpm

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/globaltrusts/server-card/internal/keybackend"
)

func init() {
	keybackend.Register(keybackend.Descriptor{
		Driver:      keybackend.DriverTPM,
		Kind:        keybackend.KindTPM,
		Name:        "本机 TPM 2.0",
		Description: "私钥在 TPM 芯片内生成并以不可导出方式保存（Windows CNG / Platform Crypto Provider），签名与解密在 TPM 内完成。",
		Fields: []keybackend.Field{
			{Key: "provider", Label: "CNG 提供程序", Type: keybackend.FieldSelect, Default: "platform",
				Options: []string{"platform", "software"},
				Hint:    "platform=Microsoft Platform Crypto Provider（真实 TPM）；software=Microsoft Software KSP（无 TPM 时用于验证流程，安全性等价于系统密钥保护）。"},
			{Key: "key_prefix", Label: "密钥容器名前缀", Type: keybackend.FieldText, Default: "opencert/",
				Hint: "写入 CNG 的持久化密钥名前缀，便于运维识别。"},
		},
		Capabilities: keybackend.Capabilities{
			Generate:   true,
			Import:     false,
			Sign:       true,
			Decrypt:    true,
			Exportable: false,
			Persistent: true,
			KeyTypes:   []string{"rsa2048", "rsa3072", "rsa4096", "ec256", "ec384", "ec521"},
			SignSchemes: []string{
				"SHA1_RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS",
				"SHA256_RSA_PSS", "SHA384_RSA_PSS", "SHA512_RSA_PSS",
				"ECDSA", "ECDSA_SHA1", "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
			},
			Note: "私钥不可导出；密钥随 TPM/系统密钥库持久化，重装系统前请先做好证书与密钥的迁移规划",
		},
		Available:       runtime.GOOS == "windows",
		AvailableDetail: availableDetail(),
		Factory:         newProvider,
	})
}

func availableDetail() string {
	if runtime.GOOS == "windows" {
		return "Windows 下通过 CNG 访问 TPM（无需 cgo）"
	}
	return "当前平台尚未内置 TPM 后端；Linux 建议改用 PKCS#11 驱动的 tpm2-pkcs11 模块"
}

// keyRef 是写入 certificates.key_ref 的 TPM 私钥引用。
type keyRef struct {
	// ProviderName 是 CNG 提供程序名。
	ProviderName string `json:"provider"`
	// KeyName 是 CNG 持久化密钥容器名。
	KeyName string `json:"key_name"`
	// KeyType 是上层密钥类型标识（rsa2048/ec256...）。
	KeyType string `json:"key_type"`
	// PublicDER 是公钥 SPKI（base64，便于离线排障）。
	PublicDER string `json:"public_der,omitempty"`
}

type provider struct {
	params  keybackend.Params
	prefix  string
	useSoft bool

	mu    sync.Mutex
	impl  tpmImpl
	ready bool
}

// tpmImpl 是平台相关的 CNG/TPM 实现（见 cng_windows.go / unsupported.go）。
type tpmImpl interface {
	// Open 打开 CNG 提供程序。
	Open(soft bool) error
	// CreateKey 在 TPM/KSP 内生成持久化密钥，返回容器名与公钥 SPKI。
	CreateKey(keyType, name string, exportable bool) (keyName string, publicDER []byte, err error)
	// PublicKeyDER 读取持久化密钥的公钥。
	PublicKeyDER(name string) ([]byte, error)
	// Sign 使用持久化密钥签名（输入为摘要）。
	Sign(name string, scheme signScheme, digest []byte, keyType string) ([]byte, error)
	// Decrypt 使用持久化密钥解密。
	Decrypt(name string, ciphertext []byte, oaep bool) ([]byte, error)
	// Delete 删除持久化密钥。
	Delete(name string) error
	// Health 检查提供程序是否可用。
	Health() error
	// Detail 返回提供程序描述。
	Detail() string
	// Close 释放句柄。
	Close() error
}

// signScheme 是 TPM 后端的签名方案。
type signScheme struct {
	// Hash 是摘要算法名（SHA1/SHA256/SHA384/SHA512）。
	Hash string
	// PSS 表示使用 RSA-PSS 填充。
	PSS bool
	// RSA 表示 RSA 密钥（否则为 ECDSA）。
	RSA bool
}

func newProvider(_ context.Context, cfg keybackend.Config) (keybackend.Provider, error) {
	p := &provider{
		params:  cfg.Params,
		prefix:  cfg.Params.GetDefault("key_prefix", "opencert/"),
		useSoft: strings.EqualFold(cfg.Params.GetDefault("provider", "platform"), "software"),
	}
	if err := p.ensure(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *provider) Driver() string { return keybackend.DriverTPM }
func (p *provider) Kind() keybackend.Kind {
	return keybackend.KindTPM
}

func (p *provider) Capabilities() keybackend.Capabilities {
	return keybackend.Capabilities{
		Generate:   true,
		Import:     false,
		Sign:       true,
		Decrypt:    true,
		Exportable: false,
		Persistent: true,
		KeyTypes:   []string{"rsa2048", "rsa3072", "rsa4096", "ec256", "ec384", "ec521"},
		SignSchemes: []string{
			"SHA1_RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS",
			"SHA256_RSA_PSS", "SHA384_RSA_PSS", "SHA512_RSA_PSS",
			"ECDSA", "ECDSA_SHA1", "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512",
		},
		Note: "私钥不可导出；不支持导入外部私钥（TPM 设计上不允许外部私钥进入芯片）",
	}
}

func (p *provider) ensure() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ready {
		return nil
	}
	impl := newTPMImpl()
	if err := impl.Open(p.useSoft); err != nil {
		return err
	}
	p.impl = impl
	p.ready = true
	return nil
}

func (p *provider) Info(_ context.Context) (*keybackend.Info, error) {
	info := &keybackend.Info{Driver: keybackend.DriverTPM, Kind: keybackend.KindTPM}
	if err := p.ensure(); err != nil {
		info.OK = false
		info.Detail = err.Error()
		return info, nil
	}
	if err := p.impl.Health(); err != nil {
		info.OK = false
		info.Detail = err.Error()
		return info, nil
	}
	info.OK = true
	info.Detail = p.impl.Detail()
	name := "本机 TPM"
	if p.useSoft {
		name = "系统软件密钥库（无 TPM）"
	}
	info.Devices = append(info.Devices, keybackend.DeviceInfo{Name: name, Model: p.impl.Detail()})
	return info, nil
}

func (p *provider) Generate(_ context.Context, spec keybackend.KeySpec) (*keybackend.KeyPair, error) {
	if err := p.ensure(); err != nil {
		return nil, err
	}
	name := p.prefix + shortName(spec.Label, spec.KeyType)
	keyName, pubDER, err := p.impl.CreateKey(spec.KeyType, name, false)
	if err != nil {
		return nil, err
	}
	ref := keyRef{
		ProviderName: p.impl.Detail(),
		KeyName:      keyName,
		KeyType:      spec.KeyType,
		PublicDER:    base64.StdEncoding.EncodeToString(pubDER),
	}
	refStr, err := keybackend.EncodeRef(keybackend.DriverTPM, ref)
	if err != nil {
		return nil, err
	}
	return &keybackend.KeyPair{
		PublicDER: pubDER,
		Ref:       refStr,
		Driver:    keybackend.DriverTPM,
		Hardware:  !p.useSoft,
	}, nil
}

func (p *provider) Import(context.Context, []byte, keybackend.KeySpec) (*keybackend.KeyPair, error) {
	return nil, fmt.Errorf("%w: TPM 不允许导入外部私钥；请在 TPM 内生成密钥后由 CA 签发证书", keybackend.ErrNotSupported)
}

func (p *provider) Sign(_ context.Context, key keybackend.KeyHandle, mechanism string, data []byte) ([]byte, error) {
	ref, err := decodeRef(key.Ref, key.Driver)
	if err != nil {
		return nil, err
	}
	if err := p.ensure(); err != nil {
		return nil, err
	}
	plan, err := planSign(mechanism, ref.KeyType, data)
	if err != nil {
		return nil, err
	}
	return p.impl.Sign(ref.KeyName, plan.scheme, plan.digest, ref.KeyType)
}

func (p *provider) Decrypt(_ context.Context, key keybackend.KeyHandle, mechanism string, ciphertext []byte) ([]byte, error) {
	ref, err := decodeRef(key.Ref, key.Driver)
	if err != nil {
		return nil, err
	}
	if err := p.ensure(); err != nil {
		return nil, err
	}
	kt := strings.ToLower(ref.KeyType)
	if !strings.HasPrefix(kt, "rsa") {
		return nil, fmt.Errorf("TPM 后端解密仅支持 RSA 私钥（当前为 %s）", ref.KeyType)
	}
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	oaep := strings.HasPrefix(m, "RSA_OAEP")
	if !oaep && m != "" && !strings.HasPrefix(m, "RSA_PKCS") {
		return nil, fmt.Errorf("不支持的解密算法: %s", mechanism)
	}
	return p.impl.Decrypt(ref.KeyName, ciphertext, oaep)
}

func (p *provider) Export(_ context.Context, _ keybackend.KeyHandle) ([]byte, error) {
	return nil, keybackend.ErrNotExportable
}

func (p *provider) Destroy(_ context.Context, key keybackend.KeyHandle) error {
	ref, err := decodeRef(key.Ref, key.Driver)
	if err != nil {
		return err
	}
	if err := p.ensure(); err != nil {
		return err
	}
	return p.impl.Delete(ref.KeyName)
}

func (p *provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.impl != nil {
		err := p.impl.Close()
		p.impl = nil
		p.ready = false
		return err
	}
	return nil
}

// ---- 辅助 ----

type signPlan struct {
	scheme signScheme
	digest []byte
}

// planSign 把上层的 mechanism 映射为 TPM/CNG 的签名方案。
func planSign(mechanism string, keyType string, data []byte) (*signPlan, error) {
	m := strings.ToUpper(strings.TrimSpace(mechanism))
	if m == "" {
		m = "SHA256_RSA_PKCS"
	}
	kt := strings.ToLower(keyType)
	isRSA := strings.HasPrefix(kt, "rsa")
	isEC := strings.HasPrefix(kt, "ec")

	if strings.HasPrefix(m, "ECDSA") {
		if !isEC {
			return nil, fmt.Errorf("机制 %s 只能用于 EC 密钥", mechanism)
		}
		// CNG 的 ECDSA 动作为「对摘要签名」，因此统一本地计算摘要后传入
		digest := data
		if m != "ECDSA" {
			info, _, err := keybackend.MechanismDigest(m)
			if err != nil {
				return nil, err
			}
			digest = info.Digest(data)
		}
		return &signPlan{scheme: signScheme{RSA: false}, digest: digest}, nil
	}

	if !isRSA {
		return nil, fmt.Errorf("机制 %s 只能用于 RSA 密钥", mechanism)
	}
	info, _, err := keybackend.MechanismDigest(m)
	if err != nil {
		return nil, err
	}
	return &signPlan{
		scheme: signScheme{Hash: info.Name, PSS: strings.HasSuffix(m, "_PSS"), RSA: true},
		digest: info.Digest(data),
	}, nil
}

func decodeRef(raw string, driver string) (keyRef, error) {
	var out keyRef
	if driver != "" && keybackend.NormalizeKind(driver) != keybackend.KindTPM {
		return out, fmt.Errorf("私钥引用与存储区域不匹配（key_backend=%s）", driver)
	}
	if strings.TrimSpace(raw) == "" {
		return out, fmt.Errorf("证书缺少 TPM 私钥引用")
	}
	if _, err := keybackend.DecodeRef(raw, &out); err != nil {
		return out, err
	}
	return out, nil
}

func shortName(hint, keyType string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		hint = keyType
	}
	if hint == "" {
		hint = "key"
	}
	hint = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(hint)
	if len(hint) > 32 {
		hint = hint[:32]
	}
	return hint + "-" + randSuffix()
}

var _ crypto.Signer = (*rsa.PrivateKey)(nil)
