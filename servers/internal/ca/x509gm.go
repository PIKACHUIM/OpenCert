// Package ca - X.509 生成与解析的国密分派层。
//
// Go 标准库 crypto/x509 不支持 SM2 密钥与 SM2WithSM3 签名，因此当参与方
// （签发者 CA、被签发的公钥）中任意一方是 SM2 时，必须改用 gmsm 的 smx509。
// smx509.Certificate 定义为 `type Certificate x509.Certificate`，与
// smx509.RevocationList 均可与标准库类型直接做类型转换，因此这里不需要
// 逐字段拷贝，只需在两种类型之间转换指针类型。
//
// 本文件集中封装 SM2 / 标准算法的分支判断，其余业务代码只调用这里的
// 分派函数（createCertificate、createRevocationListAny、
// parseCertificateAny 等），不直接引用 smx509。
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/emmansun/gmsm/smx509"
)

// needsSM2Signing 判断签发是否需要走国密路径。
//
// 判定条件：签发者私钥是 SM2，或被签发公钥是 SM2。
// SM2 与标准算法不能混用（GM/T 0015 要求 SM2 证书由 SM2 CA 签发），
// 调用方应在此之前已校验两者一致，这里只需任一方命中即走国密路径。
//
// 注意：signer.Public() 返回的是公钥（*ecdsa.PublicKey），必须用
// isSM2PublicKey 判定，不能用只认私钥类型的 isSM2Key——否则 CRL 等
// 不传入 pub 参数（pub=nil）的调用会误判为非 SM2，继而落到标准库
// x509.CreateRevocationList，对 sm2.P256() 曲线报 "unknown elliptic
// curve" 错误。
func needsSM2Signing(signer crypto.Signer, pub crypto.PublicKey) bool {
	if signer != nil && isSM2PublicKey(signer.Public()) {
		return true
	}
	if pub != nil && isSM2PublicKey(pub) {
		return true
	}
	return false
}

// createCertificate 分派证书签发：SM2 走 smx509，其余走标准库。
//
// template/parent 必须是 *x509.Certificate；signer 可以是任意 crypto.Signer
// （SM2 私钥需先用 asSM2Signer 包装）。
func createCertificate(randSrc io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}
	if !needsSM2Signing(signer, pub) {
		der, err := x509.CreateCertificate(randSrc, template, parent, pub, signer)
		if err != nil {
			return nil, fmt.Errorf("签发证书失败: %w", err)
		}
		return der, nil
	}
	der, err := smx509.CreateCertificate(randSrc, toGMCertificate(template), toGMCertificate(parent), pub, signer)
	if err != nil {
		return nil, fmt.Errorf("SM2 签发证书失败: %w", err)
	}
	return der, nil
}

// createRevocationListAny 分派 CRL 生成：SM2 走 smx509，其余走标准库。
func createRevocationListAny(randSrc io.Reader, template *x509.RevocationList, issuer *x509.Certificate, signer crypto.Signer) ([]byte, error) {
	if randSrc == nil {
		randSrc = rand.Reader
	}
	if !needsSM2Signing(signer, nil) {
		der, err := x509.CreateRevocationList(randSrc, template, issuer, signer)
		if err != nil {
			return nil, fmt.Errorf("生成 CRL 失败: %w", err)
		}
		return der, nil
	}
	der, err := smx509.CreateRevocationList(randSrc, template, toGMCertificate(issuer), signer)
	if err != nil {
		return nil, fmt.Errorf("SM2 生成 CRL 失败: %w", err)
	}
	return der, nil
}

// parseCertificateAny 解析证书 DER：先按标准库解析，签名算法无法识别
// （典型是 SM2WithSM3）时回退到 smx509。
//
// 返回值统一转换为标准库 *x509.Certificate，便于业务代码统一访问字段；
// 第二个返回值标记该证书是否为 SM2 签名。
func parseCertificateAny(der []byte) (*x509.Certificate, bool, error) {
	if cert, err := x509.ParseCertificate(der); err == nil {
		return cert, false, nil
	}
	gmCert, err := smx509.ParseCertificate(der)
	if err != nil {
		return nil, false, fmt.Errorf("解析证书失败（标准库与国密库均不支持）: %w", err)
	}
	return fromGMCertificate(gmCert), true, nil
}

// parseCSRAny 解析 PKCS#10 请求 DER，支持 SM2 请求。
func parseCSRAny(der []byte) (*x509.CertificateRequest, error) {
	if csr, err := x509.ParseCertificateRequest(der); err == nil {
		return csr, nil
	}
	gmCSR, err := smx509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("解析证书请求失败: %w", err)
	}
	// smx509.CertificateRequest 与标准库字段布局不完全一致（取决于版本），
	// 这里只拷贝业务代码实际使用的字段，避免依赖内部表示。
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

// marshalPublicKeyAny 序列化公钥为 PKIX DER，SM2 走 smx509。
func marshalPublicKeyAny(pub crypto.PublicKey) ([]byte, error) {
	if isSM2PublicKey(pub) {
		return smx509.MarshalPKIXPublicKey(pub)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// marshalPrivateKeyAnyImpl 序列化私钥为 PKCS#8 DER，SM2 走 smx509。
func marshalPrivateKeyAnyImpl(priv crypto.PrivateKey) ([]byte, error) {
	if isSM2Key(priv) {
		return smx509.MarshalPKCS8PrivateKey(priv)
	}
	return x509.MarshalPKCS8PrivateKey(priv)
}

// parsePrivateKeyAnyImpl 解析 PKCS#8 私钥 DER，支持 SM2
// （smx509.ParsePKCS8PrivateKey 内部会自动识别 SM2 OID 并回退到标准库处理其它类型）。
func parsePrivateKeyAnyImpl(der []byte) (crypto.PrivateKey, error) {
	return smx509.ParsePKCS8PrivateKey(der)
}
