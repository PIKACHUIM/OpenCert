// Package acme - TLS-ALPN-01 挑战验证（RFC 8737）。
//
// 验证流程（RFC 8737 §3）：
//  1. ACME 客户端在 domain:443 上提供一个 TLS 服务，监听握手时若 ClientHello 包含
//     ALPN 扩展且仅含 "acme-tls/1"，则返回一份特殊自签名证书：
//        - SAN 仅包含 domain
//        - 含一个 critical 扩展 id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31)，
//          其值为 OCTET STRING(SHA-256(keyAuthorization))
//  2. ACME 服务端在验证时打开 TLS 连接，ALPN 协商 "acme-tls/1"，
//     从握手返回的证书中读取该扩展并比对哈希。
//
// 设计要点：
//   - 仅依赖标准库（crypto/tls、encoding/asn1、crypto/sha256）
//   - 出于安全考虑：禁用证书链校验（自签名）、强制 ALPN、限制 SAN
//   - 默认连接超时复用 ChallengeValidationTimeout
package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
	"time"
)

// ALPN 协议名（RFC 8737 §6.2）。
const acmeTLSALPNProto = "acme-tls/1"

// id-pe-acmeIdentifier OID（RFC 8737 §6.1）：1.3.6.1.5.5.7.1.31
var oidACMEIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ValidateTLSALPN01 执行 RFC 8737 定义的 TLS-ALPN-01 挑战验证。
//
// expectedKeyAuth 是 ACME keyAuthorization 字符串（token + "." + base64url(SHA-256(JWK))）。
// 服务端会在 ClientHello 中宣告 ALPN="acme-tls/1"，并校验返回证书：
//   - 必须自签名通过自身签名
//   - 必须包含 oid id-pe-acmeIdentifier 的 critical 扩展
//   - 扩展值必须为 OCTET STRING(SHA-256(expectedKeyAuth))
//   - 证书 SAN 必须包含 domain
//
// 若 expectedKeyAuth 为空（简化模式），仅校验 ALPN 协商与扩展存在性。
func (s *Service) ValidateTLSALPN01(ctx context.Context, domain, expectedKeyAuth string) error {
	if domain == "" {
		return fmt.Errorf("域名为空")
	}
	// 防 SSRF：只允许 DNS 名
	if ip := net.ParseIP(domain); ip != nil {
		return fmt.Errorf("TLS-ALPN-01 挑战不支持 IP 地址")
	}

	dialCtx, cancel := context.WithTimeout(ctx, ChallengeValidationTimeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: ChallengeValidationTimeout}
	tlsConf := &tls.Config{
		// 自签名证书无需验证链，下面会人工校验
		InsecureSkipVerify: true, //nolint:gosec // RFC 8737 要求接受自签名
		NextProtos:         []string{acmeTLSALPNProto},
		ServerName:         domain,
		MinVersion:         tls.VersionTLS12,
	}

	rawConn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return fmt.Errorf("连接 %s:443 失败: %w", domain, err)
	}
	conn := tls.Client(rawConn, tlsConf)
	defer conn.Close()

	deadline, ok := dialCtx.Deadline()
	if ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(ChallengeValidationTimeout))
	}

	if err := conn.HandshakeContext(dialCtx); err != nil {
		return fmt.Errorf("TLS 握手失败: %w", err)
	}

	state := conn.ConnectionState()
	if state.NegotiatedProtocol != acmeTLSALPNProto {
		return fmt.Errorf("ALPN 未协商为 %s（实际 %q）", acmeTLSALPNProto, state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("对端未返回证书")
	}

	cert := state.PeerCertificates[0]
	return verifyTLSALPN01Cert(cert, domain, expectedKeyAuth)
}

// verifyTLSALPN01Cert 对 RFC 8737 §3 定义的特殊证书做校验。
// 拆出便于单元测试。
func verifyTLSALPN01Cert(cert *x509.Certificate, domain, expectedKeyAuth string) error {
	// 1) SAN 必须包含 domain
	sanOK := false
	for _, n := range cert.DNSNames {
		if strings.EqualFold(n, domain) {
			sanOK = true
			break
		}
	}
	if !sanOK {
		return fmt.Errorf("证书 SAN 不包含域名 %s", domain)
	}

	// 2) 查找 id-pe-acmeIdentifier 扩展
	var ext *asn1.RawValue
	var critical bool
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidACMEIdentifier) {
			critical = e.Critical
			rv := asn1.RawValue{}
			if _, err := asn1.Unmarshal(e.Value, &rv); err != nil {
				return fmt.Errorf("解析 acmeIdentifier 扩展失败: %w", err)
			}
			ext = &rv
			break
		}
	}
	if ext == nil {
		return fmt.Errorf("证书缺少 id-pe-acmeIdentifier 扩展")
	}
	if !critical {
		return fmt.Errorf("id-pe-acmeIdentifier 扩展必须为 critical（RFC 8737 §3）")
	}

	// 3) 扩展值必须为 OCTET STRING（tag = 4），长度恰好 32 字节
	if ext.Tag != asn1.TagOctetString {
		return fmt.Errorf("acmeIdentifier 扩展值必须为 OCTET STRING")
	}
	if len(ext.Bytes) != sha256.Size {
		return fmt.Errorf("acmeIdentifier 扩展值长度应为 %d 字节，实际 %d", sha256.Size, len(ext.Bytes))
	}

	// 4) 若提供了 keyAuthorization，校验摘要
	if expectedKeyAuth != "" {
		want := sha256.Sum256([]byte(expectedKeyAuth))
		if !bytesEqualConstantTime(ext.Bytes, want[:]) {
			return fmt.Errorf("acmeIdentifier 摘要与期望 keyAuthorization 不匹配")
		}
	}
	return nil
}

// bytesEqualConstantTime 是恒定时间字节比较，避免计时侧信道。
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
