// Package test - 国密 SM2 端到端测试：CA 创建、证书签发、CRL、OCSP 响应。
//
// 重点验证签名语义：smx509/gmsm 要求 crypto.Signer.Sign 原样接收
// sm2.DefaultSM2SignerOpts 并在内部完成 SM3(Z‖TBS) 预处理，任何在适配层
// 把 opts 替换为 nil 的实现都会产出无法通过 gmsm 自身校验的签名——因此
// 这里始终用 gmsm 的校验函数闭环验证，而不是只看"是否返回 nil error"。
package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/revocation"
	"golang.org/x/crypto/ocsp"
)

// oidSM2WithSM3Test 与 ca/revocation 包内常量定义一致（1.2.156.10197.1.501）。
var oidSM2WithSM3Test = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}

// mustDecodeCert 解析 PEM 证书为 smx509.Certificate（兼容标准库与 SM2）。
func mustDecodeCert(t *testing.T, certPEM string) *smx509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatalf("PEM 解码失败")
	}
	cert, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析证书失败: %v", err)
	}
	return cert
}

// TestSM2_CreateCA_SelfSigned 创建 SM2 自签根 CA，并校验自签名的正确性。
func TestSM2_CreateCA_SelfSigned(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	root, err := svc.CreateCA(ctx, &ca.CACreateParams{
		Name:      "SM2 测试根 CA",
		Subject:   pkix.Name{CommonName: "SM2 Root CA"},
		KeyType:   "sm2",
		ValidDays: 3650,
	})
	if err != nil {
		t.Fatalf("创建 SM2 根 CA 失败: %v", err)
	}
	if root.KeyType != "sm2" {
		t.Errorf("KeyType = %q, want sm2", root.KeyType)
	}
	if root.SigAlg != "SM2WithSM3" {
		t.Errorf("SigAlg = %q, want SM2WithSM3", root.SigAlg)
	}

	cert := mustDecodeCert(t, root.CertPEM)
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("SM2 自签名校验失败（签名语义可能有误）: %v", err)
	}
}

// TestSM2_IssueCert_UnderSM2CA 用 SM2 根 CA 签发 SM2 终端证书，并校验签名链。
func TestSM2_IssueCert_UnderSM2CA(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	root, err := svc.CreateCA(ctx, &ca.CACreateParams{
		Name:      "SM2 签发测试 CA",
		Subject:   pkix.Name{CommonName: "SM2 Issuing CA"},
		KeyType:   "sm2",
		ValidDays: 3650,
	})
	if err != nil {
		t.Fatalf("创建 SM2 CA 失败: %v", err)
	}

	resp, err := svc.IssueCert(ctx, &ca.IssueRequest{
		CAUUID:    root.UUID,
		Subject:   pkix.Name{CommonName: "sm2.example.com"},
		KeyType:   "sm2",
		ValidDays: 365,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		DNSNames:  []string{"sm2.example.com"},
	})
	if err != nil {
		t.Fatalf("签发 SM2 证书失败: %v", err)
	}
	if len(resp.PrivateEnc) == 0 {
		t.Error("签发响应未返回加密私钥")
	}

	leaf := mustDecodeCert(t, resp.CertPEM)
	caCert := mustDecodeCert(t, root.CertPEM)
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("SM2 终端证书签名校验失败: %v", err)
	}
}

// TestSM2_CRL_SignatureValid 验证 SM2 CA 生成的 CRL 签名能被 SM2 公钥直接校验。
//
// smx509 未提供 CRL 的解析/校验辅助函数，这里直接用 encoding/asn1 解析
// 外层结构（字段布局与签名算法无关，能正常解析），再用
// sm2.VerifyASN1WithSM2 按 SM2WithSM3 的语义（原始 TBS 字节 + 默认用户 ID）
// 手工校验签名。
func TestSM2_CRL_SignatureValid(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	root, err := svc.CreateCA(ctx, &ca.CACreateParams{
		Name:      "SM2 CRL 测试 CA",
		Subject:   pkix.Name{CommonName: "SM2 CRL CA"},
		KeyType:   "sm2",
		ValidDays: 3650,
	})
	if err != nil {
		t.Fatalf("创建 SM2 CA 失败: %v", err)
	}
	if err := svc.RevokeCert(ctx, root.UUID, "01AB", 1); err != nil {
		t.Fatalf("吊销证书失败: %v", err)
	}

	crlDER, err := svc.GenerateCRL(ctx, root.UUID)
	if err != nil {
		t.Fatalf("生成 CRL 失败: %v", err)
	}

	caCert := mustDecodeCert(t, root.CertPEM)
	pub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CA 公钥类型不是 SM2（*ecdsa.PublicKey）: %T", caCert.PublicKey)
	}

	var rl struct {
		TBSCertList        asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	if _, err := asn1.Unmarshal(crlDER, &rl); err != nil {
		t.Fatalf("解析 CRL 外层结构失败: %v", err)
	}
	if !rl.SignatureAlgorithm.Algorithm.Equal(oidSM2WithSM3Test) {
		t.Fatalf("CRL 签名算法 OID = %v, want SM2WithSM3", rl.SignatureAlgorithm.Algorithm)
	}
	if !sm2.VerifyASN1WithSM2(pub, nil, rl.TBSCertList.FullBytes, rl.Signature.Bytes) {
		t.Fatalf("SM2 CRL 签名校验失败")
	}
}

// TestSM2_OCSP_ResponseValid 验证 SM2 CA 的 OCSP 响应能被正确生成且签名可校验。
func TestSM2_OCSP_ResponseValid(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	caSvc := ca.NewService(db, testMasterKey)
	revSvc := revocation.NewService(db, caSvc)
	ctx := context.Background()

	root, err := caSvc.CreateCA(ctx, &ca.CACreateParams{
		Name:      "SM2 OCSP 测试 CA",
		Subject:   pkix.Name{CommonName: "SM2 OCSP CA"},
		KeyType:   "sm2",
		ValidDays: 3650,
	})
	if err != nil {
		t.Fatalf("创建 SM2 CA 失败: %v", err)
	}

	caCert := mustDecodeCert(t, root.CertPEM)
	stdCACert := (*x509.Certificate)(caCert)

	reqDER, err := ocsp.CreateRequest(stdCACert, stdCACert, &ocsp.RequestOptions{})
	if err != nil {
		t.Fatalf("构造 OCSP 请求失败: %v", err)
	}
	respDER, err := revSvc.CreateOCSPResponseDER(ctx, root.UUID, reqDER)
	if err != nil {
		t.Fatalf("生成 OCSP 响应失败: %v", err)
	}
	if len(respDER) == 0 {
		t.Fatal("OCSP 响应为空")
	}

	// 解出最外层 responseBytes，再解出 BasicOCSPResponse，校验签名算法 OID
	// 与签名本身（signed 内容是 TBSResponseData 的原始 DER 字节）。
	var outer struct {
		Status   asn1.Enumerated
		Response struct {
			ResponseType asn1.ObjectIdentifier
			Response     []byte
		} `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(respDER, &outer); err != nil {
		t.Fatalf("解析 OCSP 外层响应失败: %v", err)
	}

	var basic struct {
		TBSResponseData    asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		t.Fatalf("解析 BasicOCSPResponse 失败: %v", err)
	}
	if !basic.SignatureAlgorithm.Algorithm.Equal(oidSM2WithSM3Test) {
		t.Fatalf("OCSP 响应签名算法 OID = %v, want SM2WithSM3", basic.SignatureAlgorithm.Algorithm)
	}
	pub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("CA 公钥类型不是 SM2: %T", caCert.PublicKey)
	}
	if !sm2.VerifyASN1WithSM2(pub, nil, basic.TBSResponseData.FullBytes, basic.Signature.Bytes) {
		t.Fatalf("SM2 OCSP 响应签名校验失败")
	}
}
