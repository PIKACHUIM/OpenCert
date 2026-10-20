package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// errNotSigner 表示传入的私钥不支持签名。
var errNotSigner = errors.New("私钥不支持签名操作")

// ---- X.509 的国密分派层 ----
//
// 标准库不认识 SM2 密钥与 SM2WithSM3 签名算法，凡是可能涉及 SM2 的
// 证书 / CSR 生成与解析都经过这里：命中 SM2 用 gmsm 的 smx509，
// 其余算法仍走标准库，行为完全不变。

// isSM2Key 判断私钥或公钥是否为 SM2。
func isSM2Key(key any) bool {
	switch k := key.(type) {
	case *sm2.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return k.Curve == sm2.P256()
	case *ecdsa.PublicKey:
		return k.Curve == sm2.P256()
	}
	return false
}

// createCertificateAny 分派证书签发：签发者或被签发公钥是 SM2 时使用 smx509。
// signer 接受 crypto.PrivateKey，内部断言为 crypto.Signer（调用方已校验）。
func createCertificateAny(randSrc io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.PrivateKey) ([]byte, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}
	s, ok := signer.(crypto.Signer)
	if !ok {
		return nil, errNotSigner
	}
	if !isSM2Key(s.Public()) && !isSM2Key(pub) {
		return x509.CreateCertificate(randSrc, template, parent, pub, s)
	}
	return smx509.CreateCertificate(randSrc, toGMCertificate(template), toGMCertificate(parent), pub, s)
}

// createCSRAny 分派 CSR 生成。
func createCSRAny(randSrc io.Reader, template *x509.CertificateRequest, signer crypto.Signer) ([]byte, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}
	// smx509.CreateCertificateRequest 直接接收标准库模板（gmsm 内部自行处理 SM2 签名字段）
	return smx509.CreateCertificateRequest(randSrc, template, signer)
}

// parseCSRAny 解析 CSR（DER），支持 SM2 请求；返回标准库结构便于业务代码统一访问。
func parseCSRAny(der []byte) (*x509.CertificateRequest, error) {
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		return csr, nil
	}
	gmCSR, err := smx509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	return &x509.CertificateRequest{
		Raw:                gmCSR.Raw,
		Signature:          gmCSR.Signature,
		SignatureAlgorithm: gmCSR.SignatureAlgorithm,
		PublicKeyAlgorithm: gmCSR.PublicKeyAlgorithm,
		PublicKey:          gmCSR.PublicKey,
		Subject:            gmCSR.Subject,
		Attributes:         gmCSR.Attributes,
		Extensions:         gmCSR.Extensions,
		ExtraExtensions:    gmCSR.ExtraExtensions,
		DNSNames:           gmCSR.DNSNames,
		EmailAddresses:     gmCSR.EmailAddresses,
		IPAddresses:        gmCSR.IPAddresses,
		URIs:               gmCSR.URIs,
	}, nil
}

// checkCSRSignatureAny 校验证书请求的自签名；SM2 请求由 smx509 校验。
func checkCSRSignatureAny(der []byte) error {
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		return csr.CheckSignature()
	}
	gmCSR, err := smx509.ParseCertificateRequest(der)
	if err != nil {
		return err
	}
	return gmCSR.CheckSignature()
}

// parseCertificateAny 解析证书（DER），SM2 证书回退到 smx509。
func parseCertificateAny(der []byte) (*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(der); err == nil {
		return cert, nil
	}
	gmCert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return fromGMCertificate(gmCert), nil
}

// marshalPKCS8Any 序列化私钥为 PKCS#8，SM2 走国密库。
func marshalPKCS8Any(priv crypto.PrivateKey) ([]byte, error) {
	if isSM2Key(priv) {
		return smx509.MarshalPKCS8PrivateKey(priv)
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// parsePKCS8Any 解析 PKCS#8 私钥，支持 SM2（其余算法由 smx509 内部回退标准库）。
func parsePKCS8Any(der []byte) (crypto.PrivateKey, error) {
	return smx509.ParsePKCS8PrivateKey(der)
}

// toGMCertificate 在标准库证书与国密证书之间转换指针（两者布局一致）。
func toGMCertificate(c *x509.Certificate) *smx509.Certificate {
	if c == nil {
		return nil
	}
	return (*smx509.Certificate)(c)
}

// fromGMCertificate 把国密证书转换为标准库证书指针。
func fromGMCertificate(c *smx509.Certificate) *x509.Certificate {
	if c == nil {
		return nil
	}
	return (*x509.Certificate)(c)
}
