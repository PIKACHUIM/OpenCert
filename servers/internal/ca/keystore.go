package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/emmansun/gmsm/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

// ---- CA 导入材料解析 ----
//
// 支持的输入形态：
//   - 证书：PEM（可含多张，第一张为本 CA，其余为链）/ 单张 DER / PKCS#7（.p7b，只取证书）
//   - 私钥：PEM（PKCS#8 / PKCS#1 / SEC1，含 SM2）或 DER
//   - 证书加私钥打包：PKCS#12（.p12/.pfx，需密码）
//
// 解析阶段不触碰数据库与存储区域，便于单独测试。

// ImportBundle 是解析后的导入材料。
type ImportBundle struct {
	Cert     *x509.Certificate   // 本 CA 证书
	CertPEM  string              // 本 CA 证书及链的 PEM（第一张为本 CA）
	Chain    []*x509.Certificate // 其余证书（上级链）
	Key      crypto.PrivateKey   // 私钥；仅证书导入时为空
	KeyIsSM2 bool
}

// ErrBundleNeedsPassword 表示 PKCS#12 密码缺失或错误。
var ErrBundleNeedsPassword = errors.New("PKCS#12 密码错误或未提供")

// maxImportBytes 限制单次导入材料大小，防止异常大输入占用内存。
const maxImportBytes = 4 << 20

// ParseImportBundle 解析导入材料。
//
//	certData / keyData 为原始字节（PEM 或 DER）；p12Data 非空时优先按 PKCS#12 解析，
//	此时 certData / keyData 被忽略。
func ParseImportBundle(certData, keyData, p12Data []byte, p12Password string) (*ImportBundle, error) {
	if len(certData) > maxImportBytes || len(keyData) > maxImportBytes || len(p12Data) > maxImportBytes {
		return nil, fmt.Errorf("导入文件过大")
	}
	if len(p12Data) > 0 {
		return parsePKCS12Bundle(p12Data, p12Password)
	}
	certs, err := parseCertificatesAny(certData)
	if err != nil {
		return nil, err
	}
	b := &ImportBundle{Cert: certs[0], Chain: certs[1:]}
	b.CertPEM = encodeCertsPEM(certs)

	if len(bytes.TrimSpace(keyData)) > 0 {
		key, err := parsePrivateKeyData(keyData)
		if err != nil {
			return nil, err
		}
		b.Key = key
		b.KeyIsSM2 = isSM2Key(key)
	}
	return b, nil
}

func parsePKCS12Bundle(p12 []byte, password string) (*ImportBundle, error) {
	key, cert, chain, err := pkcs12.DecodeChain(p12, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, ErrBundleNeedsPassword
		}
		// 国密 PKCS#12（SM2/SM3/SM4）标准库解析不了，给出明确提示而不是笼统报错
		return nil, fmt.Errorf("解析 PKCS#12 失败（国密 SM2 证书不支持 PKCS#12，请改用 PEM 证书加私钥）: %w", err)
	}
	all := append([]*x509.Certificate{cert}, chain...)
	return &ImportBundle{
		Cert:    cert,
		CertPEM: encodeCertsPEM(all),
		Chain:   chain,
		Key:     key,
	}, nil
}

// trimTextInput 只对文本（PEM）内容去除首尾空白。
//
// 二进制 DER 绝不能裁剪：证书/私钥的最后一个字节完全可能是 0x20、0x0a 等空白字符，
// TrimSpace 会截断 DER 尾部，导致解析随机失败。
func trimTextInput(data []byte) []byte {
	if bytes.Contains(data, []byte("-----BEGIN")) {
		return bytes.TrimSpace(data)
	}
	return data
}

// parseCertificatesAny 依次按 PEM 多证书 / PKCS#7 / 单张 DER 解析，返回至少一张证书。
func parseCertificatesAny(data []byte) ([]*x509.Certificate, error) {
	data = trimTextInput(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("证书内容为空")
	}

	// PEM：可能含多张 CERTIFICATE，也可能是 PKCS7 块
	if bytes.Contains(data, []byte("-----BEGIN")) {
		var certs []*x509.Certificate
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			switch block.Type {
			case "CERTIFICATE":
				c, _, err := parseCertificateAny(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("解析证书失败: %w", err)
				}
				certs = append(certs, c)
			case "PKCS7", "CMS":
				cs, err := certsFromPKCS7(block.Bytes)
				if err != nil {
					return nil, err
				}
				certs = append(certs, cs...)
			}
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("PEM 中没有找到证书")
		}
		return orderChain(certs), nil
	}

	// DER：先试单张证书，再试 PKCS#7
	if c, _, err := parseCertificateAny(data); err == nil {
		return []*x509.Certificate{c}, nil
	}
	cs, err := certsFromPKCS7(data)
	if err != nil {
		return nil, fmt.Errorf("无法识别的证书格式（支持 PEM / DER / PKCS#7）")
	}
	return orderChain(cs), nil
}

func certsFromPKCS7(der []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(der)
	if err != nil {
		return nil, fmt.Errorf("解析 PKCS#7 失败: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("PKCS#7 中没有证书")
	}
	out := make([]*x509.Certificate, 0, len(p7.Certificates))
	for _, c := range p7.Certificates {
		out = append(out, fromGMCertificate(c))
	}
	return out, nil
}

// orderChain 把"自己"放在第一位：PKCS#7 / 乱序 PEM 的第一张未必是目标 CA。
// 规则：找到不是任何其他证书颁发者的那张（叶子 CA）；找不到（自签单张）时保持原序。
func orderChain(certs []*x509.Certificate) []*x509.Certificate {
	if len(certs) <= 1 {
		return certs
	}
	issuesOther := func(c *x509.Certificate) bool {
		for _, o := range certs {
			if o != c && bytes.Equal(o.RawIssuer, c.RawSubject) && !bytes.Equal(o.Raw, c.Raw) {
				return true
			}
		}
		return false
	}
	var leaf *x509.Certificate
	for _, c := range certs {
		if !issuesOther(c) {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return certs
	}
	out := []*x509.Certificate{leaf}
	for _, c := range certs {
		if c != leaf {
			out = append(out, c)
		}
	}
	return out
}

func encodeCertsPEM(certs []*x509.Certificate) string {
	var sb strings.Builder
	for _, c := range certs {
		sb.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return sb.String()
}

// parsePrivateKeyData 解析 PEM 或 DER 私钥。加密的 PEM 私钥不支持（给出明确提示）。
func parsePrivateKeyData(data []byte) (crypto.PrivateKey, error) {
	data = trimTextInput(data)
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("私钥内容为空")
	}
	der := data
	if bytes.Contains(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("无效的私钥 PEM")
		}
		if strings.Contains(block.Type, "ENCRYPTED") {
			return nil, fmt.Errorf("暂不支持加密的私钥文件，请先解密，或改用 PKCS#12 导入")
		}
		der = block.Bytes
	}
	key, err := parsePrivateKeyAny(der)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	return key, nil
}

// ---- 存储区域落地 ----

// ZoneKeyImporter 把外部私钥（PKCS#8 DER）导入指定存储区域。
//
// 本地数据库区域应返回 ErrUseLocalKeyGen（由 ca 包用主密钥加密入库）；
// 硬件区域导入成功后返回引用与可立即用于签名的 signer，
// 不支持导入的区域应返回带明确原因的错误。
type ZoneKeyImporter func(ctx context.Context, zoneUUID, keyType string, privDER []byte) (
	keyRef string, keyBackend string, err error)

// SetZoneKeyImporter 注入存储区域私钥导入器。
func (s *Service) SetZoneKeyImporter(imp ZoneKeyImporter) {
	s.zoneKeyImp = imp
}

// verifyBundle 校验导入材料自身的一致性：是 CA 证书、私钥与证书匹配、SM2 不与其它算法混用。
func verifyBundle(b *ImportBundle) error {
	if !b.Cert.IsCA {
		return fmt.Errorf("导入的证书不是 CA 证书（BasicConstraints.IsCA=false）")
	}
	if b.Key == nil {
		return nil
	}
	if err := verifyKeyPair(b.Cert, b.Key); err != nil {
		return fmt.Errorf("公私钥不匹配: %w", err)
	}
	if isSM2Key(b.Key) != isSM2PublicKey(b.Cert.PublicKey) {
		return fmt.Errorf("SM2 私钥与证书不匹配（SM2 证书必须由 SM2 密钥对应）")
	}
	return nil
}
