package keybackend

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
)

// 内置驱动 ID。
const (
	// DriverDatabase 本地加密存储：私钥以服务端主密钥 AES-256-GCM 加密后入库。
	DriverDatabase = "database"
	// DriverTPM 可信平台模块（Windows CNG/Platform Crypto Provider、Linux TPM2）。
	DriverTPM = "tpm2"
	// DriverPKCS11 PKCS#11 通用接口（eToken 5110、SoftHSM2、网络 HSM 等）。
	DriverPKCS11 = "pkcs11"
)

func init() {
	Register(Descriptor{
		Driver:      DriverDatabase,
		Kind:        KindDatabase,
		Name:        "本地加密存储",
		Description: "私钥由服务端主密钥（AES-256-GCM）加密后存放在服务端数据库中，密码运算在服务端完成。兼容历史数据，开箱即用。",
		Capabilities: Capabilities{
			Generate:    true,
			Import:      true,
			Sign:        true,
			Decrypt:     true,
			Exportable:  true,
			Persistent:  true,
			KeyTypes:    KeyTypesAll,
			SignSchemes: SignSchemesAll,
			Note:        "私钥以密文形式随数据库备份流转，安全等级取决于主密钥的保护方式",
		},
		Available:       true,
		AvailableDetail: "服务端内置后端，始终可用",
		Factory:         newDatabaseProvider,
	})
}

// databaseProvider 是本地加密存储后端。
//
// 私钥不以文件形式保存，而是「加密后交给调用方入库」：
//   - Generate/Import 返回的 KeyPair.Blob 由调用方写入 certificates.private_data；
//   - Sign/Decrypt/Export 通过 KeyHandle.Blob 取回密文解密后运算。
type databaseProvider struct {
	masterKey []byte
	label     string
}

func newDatabaseProvider(_ context.Context, cfg Config) (Provider, error) {
	if len(cfg.MasterKey) == 0 {
		return nil, fmt.Errorf("%w: 本地存储后端缺少服务端主密钥", ErrBadConfig)
	}
	return &databaseProvider{masterKey: cfg.MasterKey, label: cfg.Label}, nil
}

func (p *databaseProvider) Driver() string { return DriverDatabase }
func (p *databaseProvider) Kind() Kind     { return KindDatabase }

func (p *databaseProvider) Capabilities() Capabilities {
	return Capabilities{
		Generate:    true,
		Import:      true,
		Sign:        true,
		Decrypt:     true,
		Exportable:  true,
		Persistent:  true,
		KeyTypes:    KeyTypesAll,
		SignSchemes: SignSchemesAll,
	}
}

func (p *databaseProvider) Info(_ context.Context) (*Info, error) {
	return &Info{
		Driver: DriverDatabase,
		Kind:   KindDatabase,
		OK:     len(p.masterKey) > 0,
		Detail: "本地加密存储后端就绪（主密钥长度 " + fmt.Sprint(len(p.masterKey)) + " 字节）",
	}, nil
}

func (p *databaseProvider) Generate(_ context.Context, spec KeySpec) (*KeyPair, error) {
	priv, pubDER, err := GenerateKeyMaterial(spec.KeyType)
	if err != nil {
		return nil, err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	blob, err := p.encrypt(privDER)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PublicDER: pubDER,
		Blob:      blob,
		Driver:    DriverDatabase,
		Hardware:  false,
	}, nil
}

func (p *databaseProvider) Import(_ context.Context, privDER []byte, _ KeySpec) (*KeyPair, error) {
	priv, err := ParsePrivateKey(privDER)
	if err != nil {
		return nil, err
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	pub, err := PublicKeyOf(priv)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("序列化公钥失败: %w", err)
	}
	blob, err := p.encrypt(canonical)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		PublicDER: pubDER,
		Blob:      blob,
		Driver:    DriverDatabase,
		Hardware:  false,
	}, nil
}

func (p *databaseProvider) Sign(_ context.Context, key KeyHandle, mechanism string, data []byte) ([]byte, error) {
	priv, err := p.privateKey(key)
	if err != nil {
		return nil, err
	}
	return SignWithKey(priv, mechanism, data)
}

func (p *databaseProvider) Decrypt(_ context.Context, key KeyHandle, mechanism string, ciphertext []byte) ([]byte, error) {
	priv, err := p.privateKey(key)
	if err != nil {
		return nil, err
	}
	return DecryptWithKey(priv, mechanism, ciphertext)
}

func (p *databaseProvider) Export(_ context.Context, key KeyHandle) ([]byte, error) {
	priv, err := p.privateKey(key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("序列化私钥失败: %w", err)
	}
	return der, nil
}

func (p *databaseProvider) Destroy(_ context.Context, key KeyHandle) error {
	// 本地后端的私钥随证书行一起删除，无需额外清理；仅在存在硬件残留引用时提示。
	if key.Ref != "" {
		slog.Warn("本地后端收到疑似硬件引用，已忽略引用清理", "driver", key.Driver)
	}
	return nil
}

func (p *databaseProvider) Close() error { return nil }

// privateKey 取出并解密 KeyHandle 中的私钥。
func (p *databaseProvider) privateKey(key KeyHandle) (crypto.PrivateKey, error) {
	if len(key.Blob) == 0 {
		return nil, fmt.Errorf("证书没有关联的私钥")
	}
	der, err := p.decrypt(key.Blob)
	if err != nil {
		return nil, fmt.Errorf("解密私钥失败: %w", err)
	}
	return ParsePrivateKey(der)
}

func (p *databaseProvider) encrypt(data []byte) ([]byte, error) {
	gcm, err := newGCM(p.masterKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (p *databaseProvider) decrypt(blob []byte) ([]byte, error) {
	gcm, err := newGCM(p.masterKey)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}
	nonce, ciphertext := blob[:nonceSize], blob[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}
	return gcm, nil
}
