//go:build windows

package sshagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/globaltrusts/client-card/internal/card/tpmsc"
)

type cardIdentity struct {
	Identity
	reader    string
	container string
	public    crypto.PublicKey
}

// KSPBackend 用 Windows Smart Card KSP 为卡上证书签名。
type KSPBackend struct {
	Readers  func() ([]string, error)
	Provider tpmsc.SmartCardKeyProvider

	mu    sync.Mutex
	cache map[string]cardIdentity
}

// Identities 枚举读卡器上所有带私钥的证书，转换为 SSH 公钥。
func (b *KSPBackend) Identities() ([]Identity, error) {
	entries, err := b.refresh()
	if err != nil {
		return nil, err
	}
	out := make([]Identity, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Identity)
	}
	return out, nil
}

func (b *KSPBackend) refresh() ([]cardIdentity, error) {
	readers, err := b.Readers()
	if err != nil {
		return nil, err
	}
	next := make(map[string]cardIdentity)
	for _, reader := range readers {
		certs, err := tpmsc.ListCardCertificates(reader)
		if err != nil {
			return nil, err
		}
		prefix := `\\.\` + reader + `\`
		for _, cert := range certs {
			if cert.SSHPublicKey == "" || !strings.HasPrefix(cert.ContainerName, prefix) {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert.SSHPublicKey))
			if err != nil {
				continue
			}
			block, _ := pem.Decode([]byte(cert.CertPEM))
			if block == nil {
				continue
			}
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			next[string(pub.Marshal())] = cardIdentity{
				Identity:  Identity{PublicKey: pub, Comment: "opencert:" + cert.Subject},
				reader:    reader,
				container: strings.TrimPrefix(cert.ContainerName, prefix),
				public:    parsed.PublicKey,
			}
		}
	}
	b.mu.Lock()
	b.cache = next
	b.mu.Unlock()
	entries := make([]cardIdentity, 0, len(next))
	for _, e := range next {
		entries = append(entries, e)
	}
	return entries, nil
}

// Sign 用对应的 KSP 私钥签名；私钥不离开卡片。
func (b *KSPBackend) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	b.mu.Lock()
	entry, ok := b.cache[string(key.Marshal())]
	b.mu.Unlock()
	if !ok {
		if _, err := b.refresh(); err != nil {
			return nil, err
		}
		b.mu.Lock()
		entry, ok = b.cache[string(key.Marshal())]
		b.mu.Unlock()
	}
	if !ok {
		return nil, fmt.Errorf("未找到匹配的卡上身份")
	}
	provider := b.Provider
	if provider == nil {
		provider = tpmsc.NewSmartCardKeyProvider()
	}
	signer, err := provider.OpenKey(context.Background(), entry.reader, entry.container, keyTypeFor(entry.public), entry.public)
	if err != nil {
		return nil, fmt.Errorf("打开卡上私钥失败: %w", err)
	}
	if closer, ok := signer.(interface{ Close() error }); ok {
		defer closer.Close()
	}
	digest := sha256.Sum256(data)
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("卡上签名失败: %w", err)
	}
	switch entry.public.(type) {
	case *rsa.PublicKey:
		return &ssh.Signature{Format: "rsa-sha2-256", Blob: sig}, nil
	case *ecdsa.PublicKey:
		var parsed struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
			return nil, fmt.Errorf("解析 ECDSA 签名失败: %w", err)
		}
		return &ssh.Signature{
			Format: key.Type(),
			Blob:   ssh.Marshal(struct{ R, S *big.Int }{parsed.R, parsed.S}),
		}, nil
	default:
		return nil, fmt.Errorf("不支持的密钥类型")
	}
}

func keyTypeFor(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() >= 4096 {
			return "rsa4096"
		}
		return "rsa2048"
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 384:
			return "ec384"
		case 521:
			return "ec521"
		default:
			return "ec256"
		}
	default:
		return "rsa2048"
	}
}
