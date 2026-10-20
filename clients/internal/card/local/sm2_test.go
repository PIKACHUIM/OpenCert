package local

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// TestGenerateSM2KeyPair 验证 SM2 密钥对生成与 PKCS#8 / PKIX 编解码可互逆。
func TestGenerateSM2KeyPair(t *testing.T) {
	privDER, pubDER, err := generateSM2()
	if err != nil {
		t.Fatalf("generateSM2: %v", err)
	}
	if len(privDER) == 0 || len(pubDER) == 0 {
		t.Fatal("生成的密钥 DER 为空")
	}

	priv, err := parseGMPKCS8(privDER)
	if err != nil {
		t.Fatalf("解析 SM2 私钥: %v", err)
	}
	key, ok := priv.(*sm2.PrivateKey)
	if !ok {
		t.Fatalf("私钥类型不是 SM2: %T", priv)
	}

	pub, err := parseGMPKIX(pubDER)
	if err != nil {
		t.Fatalf("解析 SM2 公钥: %v", err)
	}
	if ecKey, ok := pub.(*ecdsa.PublicKey); !ok || ecKey.Curve != sm2.P256() {
		t.Fatalf("公钥曲线不是 SM2: %T", pub)
	}
	if key.Curve != sm2.P256() {
		t.Fatal("SM2 私钥曲线应为 sm2p256v1")
	}
}

// TestParsePrivateKeySM2 验证通用私钥解析路径能识别 SM2（CKM_SM2 签名入口依赖它）。
func TestParsePrivateKeySM2(t *testing.T) {
	privDER, _, err := generateSM2()
	if err != nil {
		t.Fatalf("generateSM2: %v", err)
	}
	key, err := parsePrivateKey(privDER)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	if _, ok := asSM2PrivateKey(key); !ok {
		t.Fatalf("parsePrivateKey 未识别 SM2，得到 %T", key)
	}
}

// TestSM2SignAndVerify 验证签名为 r‖s 格式，且篡改原文后验签失败。
func TestSM2SignAndVerify(t *testing.T) {
	privDER, _, err := generateSM2()
	if err != nil {
		t.Fatalf("generateSM2: %v", err)
	}
	parsed, err := parsePrivateKey(privDER)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	key, ok := asSM2PrivateKey(parsed)
	if !ok {
		t.Fatal("未得到 SM2 私钥")
	}

	msg := []byte("OpenCert SM2 signature test")
	sig, err := signData(key, pkcs11types.Mechanism{Type: pkcs11types.CKM_SM2}, msg)
	if err != nil {
		t.Fatalf("signData: %v", err)
	}
	if len(sig) != sm2RawSigLen {
		t.Fatalf("SM2 签名长度应为 %d，实际 %d", sm2RawSigLen, len(sig))
	}
	if !sm2VerifyRaw(&key.PublicKey, msg, sig) {
		t.Fatal("SM2 验签应成功")
	}
	if sm2VerifyRaw(&key.PublicKey, []byte("tampered"), sig) {
		t.Fatal("篡改原文后验签不应通过")
	}

	// 非 CKM_SM2 机制应被拒绝，避免调用方误用（例如传已哈希数据）
	if _, err := signData(key, pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA}, msg); err == nil {
		t.Fatal("SM2 私钥使用 CKM_ECDSA 应返回错误")
	}
}

// TestSM2EncryptDecrypt 验证 SM2 加解密（C1C3C2）往返。
func TestSM2EncryptDecrypt(t *testing.T) {
	privDER, _, err := generateSM2()
	if err != nil {
		t.Fatalf("generateSM2: %v", err)
	}
	parsed, err := parseGMPKCS8(privDER)
	if err != nil {
		t.Fatalf("parseGMPKCS8: %v", err)
	}
	key := parsed.(*sm2.PrivateKey)

	plaintext := []byte("national cryptography")
	ciphertext, err := encryptData(&key.PublicKey, pkcs11types.Mechanism{Type: pkcs11types.CKM_SM2}, plaintext)
	if err != nil {
		t.Fatalf("encryptData: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("密文不应与明文相同")
	}
	out, err := decryptData(key, pkcs11types.Mechanism{Type: pkcs11types.CKM_SM2}, ciphertext)
	if err != nil {
		t.Fatalf("decryptData: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("解密结果不一致: %q", out)
	}
}

// TestSM4CBCRoundTrip 验证 SM4-CBC + PKCS#7 往返以及错误密码返回错误。
func TestSM4CBCRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 16)
	iv := bytes.Repeat([]byte{0x22}, 16)
	plaintext := []byte("SM4 block cipher test payload")

	ciphertext, err := sm4EncryptCBC(key, iv, plaintext)
	if err != nil {
		t.Fatalf("sm4EncryptCBC: %v", err)
	}
	if len(ciphertext)%16 != 0 {
		t.Fatalf("SM4-CBC 密文长度应为块大小整数倍，实际 %d", len(ciphertext))
	}
	out, err := sm4DecryptCBC(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("sm4DecryptCBC: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("SM4-CBC 解密结果不一致: %q", out)
	}

	wrongKey := bytes.Repeat([]byte{0x33}, 16)
	if _, err := sm4DecryptCBC(wrongKey, iv, ciphertext); err == nil {
		t.Fatal("错误密钥解密应失败")
	}
}

// TestSM4GCMRoundTrip 验证 SM4-GCM 往返与认证标签校验。
func TestSM4GCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 16)
	nonce := bytes.Repeat([]byte{0x55}, 12)
	plaintext := []byte("SM4-GCM payload")
	aad := []byte("header")

	ciphertext, err := sm4EncryptGCM(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("sm4EncryptGCM: %v", err)
	}
	out, err := sm4DecryptGCM(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("sm4DecryptGCM: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("SM4-GCM 解密结果不一致: %q", out)
	}

	// 篡改最后一个字节（标签）后必须校验失败
	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := sm4DecryptGCM(key, nonce, ciphertext, aad); err == nil {
		t.Fatal("认证标签被篡改应校验失败")
	}
}

// TestSM3Digest 验证 SM3 摘要长度与已知向量。
func TestSM3Digest(t *testing.T) {
	h := sm3.New()
	h.Write([]byte("abc"))
	got := h.Sum(nil)
	if len(got) != 32 {
		t.Fatalf("SM3 摘要长度应为 32，实际 %d", len(got))
	}
	want := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if fmtHex(got) != want {
		t.Fatalf("SM3(\"abc\") 结果不正确: %s", fmtHex(got))
	}
}

// fmtHex 把字节序列格式化为小写十六进制。
func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0F])
	}
	return string(out)
}

// TestIsGMMechanism 确保 TPM 卡的机制过滤逻辑覆盖全部国密机制。
func TestIsGMMechanism(t *testing.T) {
	gm := []pkcs11types.MechanismType{
		pkcs11types.CKM_SM2_KEY_PAIR_GEN,
		pkcs11types.CKM_SM2,
		pkcs11types.CKM_SM3,
		pkcs11types.CKM_SM4_CBC,
		pkcs11types.CKM_SM4_GCM,
	}
	for _, m := range gm {
		if !IsGMMechanism(m) {
			t.Fatalf("机制 0x%X 应判定为国密", uint32(m))
		}
	}
	if IsGMMechanism(pkcs11types.CKM_ECDSA) || IsGMMechanism(pkcs11types.CKM_SHA256) {
		t.Fatal("标准机制不应判定为国密")
	}
}

// TestKeyTypeAndCurveParams 验证 CKA_KEY_TYPE / CKA_EC_PARAMS 的国密映射。
func TestKeyTypeAndCurveParams(t *testing.T) {
	if got := keyTypeToBytes("sm2"); len(got) != 4 || got[3] != 0x02 {
		t.Fatalf("sm2 的 CKA_KEY_TYPE 不正确: %v", got)
	}
	if got := ecParamsForKeyType("sm2"); !bytes.Equal(got, pkcs11types.CurveSM2DER) {
		t.Fatalf("sm2 的 CKA_EC_PARAMS 不正确: %v", got)
	}
	if got := keyTypeToBits("sm2"); got != 256 {
		t.Fatalf("sm2 的位数应为 256，实际 %d", got)
	}
}

// TestSM2SignRandomness 确认签名使用随机数（同输入两次签名不同），
// 避免误用确定性派生实现。
func TestSM2SignRandomness(t *testing.T) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey: %v", err)
	}
	msg := []byte("randomness")
	s1, err := sm2SignRaw(key, msg)
	if err != nil {
		t.Fatalf("第一次签名失败: %v", err)
	}
	s2, err := sm2SignRaw(key, msg)
	if err != nil {
		t.Fatalf("第二次签名失败: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("两次 SM2 签名结果相同，随机数可能未生效")
	}
}
