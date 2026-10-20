// Package test - CA 创建与导入测试：多种导入格式、存储区域落地、公开标记、重复导入。
package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/globaltrusts/server-card/internal/ca"
)

// genCAMaterial 生成一张自签 CA 证书与私钥，返回 DER 证书、PKCS#8 私钥 DER 和私钥对象。
func genCAMaterial(t *testing.T, cn string) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, keyDER, key
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func pemKey(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestImportCA_PEMWithKey(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()
	cert, keyDER, _ := genCAMaterial(t, "导入根 CA")

	b, err := ca.ParseImportBundle([]byte(pemCert(cert)), []byte(pemKey(keyDER)), nil, "")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	got, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "PEM 导入", Bundle: b})
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if got.KeySource != "imported" || len(got.PrivateEnc) == 0 {
		t.Errorf("带私钥导入应加密入库: source=%s enc=%d", got.KeySource, len(got.PrivateEnc))
	}
	if got.KeyType != "ec256" {
		t.Errorf("算法识别错误: %s", got.KeyType)
	}
	// 导入的 CA 应能直接用于签发
	if _, err := svc.CAKeySigner(ctx, got); err != nil {
		t.Errorf("导入的 CA 应有可用私钥: %v", err)
	}
	// 重复导入同一张证书应被拒绝
	if _, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "重复", Bundle: b}); err == nil {
		t.Error("重复导入同一 CA 应失败")
	}
}

func TestImportCA_CertOnly(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()
	cert, _, _ := genCAMaterial(t, "外部 CA")

	b, err := ca.ParseImportBundle([]byte(pemCert(cert)), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "仅证书", Bundle: b, StorageZoneUUID: "ignored"})
	if err != nil {
		t.Fatalf("仅证书导入失败: %v", err)
	}
	if got.KeySource != "external" || len(got.PrivateEnc) != 0 {
		t.Errorf("仅证书不应有私钥: %+v", got.KeySource)
	}
	if _, err := svc.CAKeySigner(ctx, got); err == nil {
		t.Error("仅证书导入的 CA 不应能签发")
	}
}

func TestImportCA_DER(t *testing.T) {
	t.Parallel()
	cert, keyDER, _ := genCAMaterial(t, "DER CA")
	b, err := ca.ParseImportBundle(cert.Raw, keyDER, nil, "")
	if err != nil {
		t.Fatalf("DER 证书 + DER 私钥应可解析: %v", err)
	}
	if b.Key == nil || b.Cert.Subject.CommonName != "DER CA" {
		t.Errorf("解析结果不正确")
	}
}

func TestImportCA_PKCS12(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()
	cert, _, key := genCAMaterial(t, "P12 CA")

	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "secret")
	if err != nil {
		t.Fatalf("打包 PKCS#12 失败: %v", err)
	}
	if _, err := ca.ParseImportBundle(nil, nil, pfx, "wrong"); err == nil || !strings.Contains(err.Error(), "密码") {
		t.Errorf("密码错误应提示密码问题，实际: %v", err)
	}
	b, err := ca.ParseImportBundle(nil, nil, pfx, "secret")
	if err != nil {
		t.Fatalf("PKCS#12 解析失败: %v", err)
	}
	got, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "P12 导入", Bundle: b})
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if len(got.PrivateEnc) == 0 {
		t.Error("PKCS#12 导入应带私钥")
	}
}

func TestImportCA_RejectsBadInput(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()

	// 非 CA 证书
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(leafDER)
	b, err := ca.ParseImportBundle([]byte(pemCert(leaf)), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "非 CA", Bundle: b}); err == nil {
		t.Error("非 CA 证书应被拒绝")
	}

	// 公私钥不匹配
	cert, _, _ := genCAMaterial(t, "A")
	_, otherKeyDER, _ := genCAMaterial(t, "B")
	mismatch, err := ca.ParseImportBundle([]byte(pemCert(cert)), []byte(pemKey(otherKeyDER)), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "不匹配", Bundle: mismatch}); err == nil {
		t.Error("公私钥不匹配应被拒绝")
	}

	// 空内容 / 乱码 / 加密私钥
	if _, err := ca.ParseImportBundle(nil, nil, nil, ""); err == nil {
		t.Error("空内容应失败")
	}
	if _, err := ca.ParseImportBundle([]byte("garbage"), nil, nil, ""); err == nil {
		t.Error("乱码应失败")
	}
	encKey := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
	if _, err := ca.ParseImportBundle([]byte(pemCert(cert)), []byte(encKey), nil, ""); err == nil ||
		!strings.Contains(err.Error(), "加密") {
		t.Errorf("加密私钥应给出明确提示，实际 %v", err)
	}
}

func TestImportCA_ChainOrdering(t *testing.T) {
	t.Parallel()
	// 根 + 中间：把根放在前面，解析后应识别中间 CA（不签发任何其它证书的那张）为本 CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "链根"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)

	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "链中间"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, _ := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	inter, _ := x509.ParseCertificate(interDER)

	b, err := ca.ParseImportBundle([]byte(pemCert(root)+pemCert(inter)), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Cert.Subject.CommonName != "链中间" {
		t.Errorf("应把链末端的中间 CA 识别为本 CA，实际 %s", b.Cert.Subject.CommonName)
	}
	if len(b.Chain) != 1 || b.Chain[0].Subject.CommonName != "链根" {
		t.Errorf("链内容不正确: %d", len(b.Chain))
	}
}

func TestCAUpdate_PublicFlag(t *testing.T) {
	t.Parallel()
	db := setupServerDB(t)
	svc := ca.NewService(db, testMasterKey)
	ctx := context.Background()
	cert, keyDER, _ := genCAMaterial(t, "公开测试")
	b, _ := ca.ParseImportBundle([]byte(pemCert(cert)), []byte(pemKey(keyDER)), nil, "")
	got, err := svc.ImportCA(ctx, &ca.ImportCAParams{Name: "公开测试", Bundle: b})
	if err != nil {
		t.Fatal(err)
	}
	if got.IsPublic {
		t.Fatal("新导入的 CA 默认不应公开")
	}
	yes := true
	if err := svc.Update(ctx, got.UUID, "公开测试", "active", &yes); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	reloaded, _ := svc.GetByUUID(ctx, got.UUID)
	if !reloaded.IsPublic {
		t.Error("is_public 应被更新为 true")
	}
	// 不传 is_public 时不应改变
	if err := svc.Update(ctx, got.UUID, "改名", "active", nil); err != nil {
		t.Fatal(err)
	}
	reloaded, _ = svc.GetByUUID(ctx, got.UUID)
	if !reloaded.IsPublic || reloaded.Name != "改名" {
		t.Errorf("未传 is_public 时应保持原值: public=%v name=%s", reloaded.IsPublic, reloaded.Name)
	}
	// 非法状态 / 不存在的 CA
	if err := svc.Update(ctx, got.UUID, "x", "weird", nil); err == nil {
		t.Error("非法状态应被拒绝")
	}
	if err := svc.Update(ctx, "no-such", "x", "active", nil); err == nil {
		t.Error("更新不存在的 CA 应报错")
	}
}
