package local

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// newSecretSlot 构造一个已登录的最小 Slot，用于对称密钥对象测试。
// 对称密钥不落库，因此不需要 CardRepo / CertRepo。
func newSecretSlot() *Slot {
	return &Slot{
		slotID:     1,
		card:       &storage.Card{UUID: "test-card", SlotType: storage.SlotTypeLocal},
		objects:    map[pkcs11types.ObjectHandle]*storage.Certificate{},
		nextHandle: 1,
		secretKeys: map[pkcs11types.ObjectHandle]*secretKeyObject{},
		secretNext: secretHandleBase,
		loggedIn:   true,
	}
}

// sm4SecretTemplate 构造创建 SM4 密钥对象的属性模板。
func sm4SecretTemplate(key []byte, label string, sensitive bool) []pkcs11types.Attribute {
	return []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32ToBytes(uint32(pkcs11types.CKO_SECRET_KEY))},
		{Type: pkcs11types.CKA_KEY_TYPE, Value: uint32ToBytes(uint32(pkcs11types.CKK_SM4))},
		{Type: pkcs11types.CKA_VALUE, Value: key},
		{Type: pkcs11types.CKA_LABEL, Value: []byte(label)},
		{Type: pkcs11types.CKA_SENSITIVE, Value: boolToBytes(sensitive)},
	}
}

// packedGCM 按驱动的打包格式生成 GCM 机制参数。
func packedGCM(iv, aad []byte, tagBits uint32) []byte {
	out := make([]byte, 12+len(iv)+len(aad))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(iv)))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(aad)))
	binary.BigEndian.PutUint32(out[8:12], tagBits)
	copy(out[12:], iv)
	copy(out[12+len(iv):], aad)
	return out
}

// TestSecretKeyCreateAndAttributes 验证创建、属性读取与敏感值隐藏。
func TestSecretKeyCreateAndAttributes(t *testing.T) {
	s := newSecretSlot()
	key := []byte("0123456789abcdef")

	handle, err := s.CreateObject(context.Background(), sm4SecretTemplate(key, "sm4-key", false))
	if err != nil {
		t.Fatalf("创建 SM4 密钥对象失败: %v", err)
	}
	if handle < secretHandleBase {
		t.Fatalf("对称密钥句柄应位于独立区段，实际 %d", handle)
	}

	attrs, err := s.GetAttributes(context.Background(), handle, []pkcs11types.AttributeType{
		pkcs11types.CKA_CLASS, pkcs11types.CKA_KEY_TYPE, pkcs11types.CKA_VALUE,
		pkcs11types.CKA_VALUE_LEN, pkcs11types.CKA_LABEL, pkcs11types.CKA_EXTRACTABLE,
	})
	if err != nil {
		t.Fatalf("读取属性失败: %v", err)
	}
	got := map[pkcs11types.AttributeType][]byte{}
	for _, a := range attrs {
		got[a.Type] = a.Value
	}
	if binary.BigEndian.Uint32(got[pkcs11types.CKA_CLASS]) != uint32(pkcs11types.CKO_SECRET_KEY) {
		t.Error("CKA_CLASS 不是 CKO_SECRET_KEY")
	}
	if binary.BigEndian.Uint32(got[pkcs11types.CKA_KEY_TYPE]) != uint32(pkcs11types.CKK_SM4) {
		t.Error("CKA_KEY_TYPE 不是 CKK_SM4")
	}
	if string(got[pkcs11types.CKA_VALUE]) != string(key) {
		t.Error("非敏感密钥应能读回明文")
	}
	if binary.BigEndian.Uint32(got[pkcs11types.CKA_VALUE_LEN]) != 16 {
		t.Error("CKA_VALUE_LEN 应为 16")
	}

	// 敏感密钥：不可读回明文
	sensHandle, err := s.CreateObject(context.Background(), sm4SecretTemplate(key, "sm4-sensitive", true))
	if err != nil {
		t.Fatalf("创建敏感密钥失败: %v", err)
	}
	sensAttrs, _ := s.GetAttributes(context.Background(), sensHandle, []pkcs11types.AttributeType{
		pkcs11types.CKA_VALUE, pkcs11types.CKA_EXTRACTABLE,
	})
	for _, a := range sensAttrs {
		if a.Type == pkcs11types.CKA_VALUE && len(a.Value) != 0 {
			t.Error("敏感密钥不应返回明文")
		}
		if a.Type == pkcs11types.CKA_EXTRACTABLE && (len(a.Value) == 0 || a.Value[0] != 0) {
			t.Error("敏感密钥应不可导出")
		}
	}
}

// TestSecretKeySM4CBC 验证 SM4-CBC 加解密与错误 IV 的拒绝。
func TestSecretKeySM4CBC(t *testing.T) {
	s := newSecretSlot()
	handle, err := s.CreateObject(context.Background(), sm4SecretTemplate([]byte("0123456789abcdef"), "cbc", false))
	if err != nil {
		t.Fatalf("创建密钥失败: %v", err)
	}
	iv := []byte("abcdefghijklmnop")
	mech := pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_CBC, Parameter: iv}
	plaintext := []byte("SM4-CBC secret key object test")

	ct, err := s.Encrypt(context.Background(), handle, mech, plaintext)
	if err != nil {
		t.Fatalf("SM4-CBC 加密失败: %v", err)
	}
	if len(ct)%16 != 0 {
		t.Fatalf("密文长度应为块大小整数倍，实际 %d", len(ct))
	}
	pt, err := s.Decrypt(context.Background(), handle, mech, ct)
	if err != nil {
		t.Fatalf("SM4-CBC 解密失败: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("解密结果不一致: %q", pt)
	}

	// IV 长度非法应被拒绝
	if _, err := s.Encrypt(context.Background(), handle,
		pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_CBC, Parameter: []byte("short")}, plaintext); err == nil {
		t.Error("非法 IV 长度应返回错误")
	}
}

// TestSecretKeySM4GCM 验证 SM4-GCM 打包参数、AAD 校验与篡改检测。
func TestSecretKeySM4GCM(t *testing.T) {
	s := newSecretSlot()
	handle, err := s.CreateObject(context.Background(), sm4SecretTemplate([]byte("0123456789abcdef"), "gcm", false))
	if err != nil {
		t.Fatalf("创建密钥失败: %v", err)
	}
	iv := []byte("123456789012")
	aad := []byte("header")
	mech := pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_GCM, Parameter: packedGCM(iv, aad, 128)}
	plaintext := []byte("SM4-GCM payload")

	ct, err := s.Encrypt(context.Background(), handle, mech, plaintext)
	if err != nil {
		t.Fatalf("SM4-GCM 加密失败: %v", err)
	}
	pt, err := s.Decrypt(context.Background(), handle, mech, ct)
	if err != nil {
		t.Fatalf("SM4-GCM 解密失败: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("解密结果不一致: %q", pt)
	}

	// AAD 不一致必须失败
	otherAAD := pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_GCM, Parameter: packedGCM(iv, []byte("other"), 128)}
	if _, err := s.Decrypt(context.Background(), handle, otherAAD, ct); err == nil {
		t.Error("AAD 不一致应解密失败")
	}

	// 篡改密文末字节必须失败
	ct[len(ct)-1] ^= 0xFF
	if _, err := s.Decrypt(context.Background(), handle, mech, ct); err == nil {
		t.Error("密文被篡改应解密失败")
	}

	// 参数不完整应被拒绝
	if _, err := s.Encrypt(context.Background(), handle,
		pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_GCM, Parameter: []byte{1, 2, 3}}, plaintext); err == nil {
		t.Error("GCM 参数不完整应返回错误")
	}
}

// TestSecretKeyLifecycle 验证查找、销毁与机制不匹配。
func TestSecretKeyLifecycle(t *testing.T) {
	s := newSecretSlot()
	ctx := context.Background()
	handle, err := s.CreateObject(ctx, sm4SecretTemplate([]byte("0123456789abcdef"), "lifecycle", false))
	if err != nil {
		t.Fatalf("创建密钥失败: %v", err)
	}

	// 按 CKA_CLASS 查找到对称密钥
	handles, err := s.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32ToBytes(uint32(pkcs11types.CKO_SECRET_KEY))},
	})
	if err != nil {
		t.Fatalf("FindObjects 失败: %v", err)
	}
	found := false
	for _, h := range handles {
		if h == handle {
			found = true
		}
	}
	if !found {
		t.Fatal("未找到刚创建的对称密钥对象")
	}

	// 以证书类查找不应命中
	certHandles, _ := s.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32ToBytes(uint32(pkcs11types.CKO_CERTIFICATE))},
	})
	for _, h := range certHandles {
		if h == handle {
			t.Fatal("对称密钥不应出现在证书类查询结果中")
		}
	}

	// 机制与密钥类型不匹配
	if _, err := s.Encrypt(ctx, handle,
		pkcs11types.Mechanism{Type: pkcs11types.CKM_RSA_PKCS}, []byte("x")); err == nil {
		t.Error("SM4 密钥使用 RSA 机制应返回错误")
	}

	// 销毁后对象不可用
	if err := s.DestroyObject(ctx, handle); err != nil {
		t.Fatalf("销毁对象失败: %v", err)
	}
	if _, err := s.Encrypt(ctx, handle,
		pkcs11types.Mechanism{Type: pkcs11types.CKM_SM4_CBC, Parameter: []byte("abcdefghijklmnop")}, []byte("x")); err == nil {
		t.Error("销毁后的句柄不应可用")
	}

	// 密钥长度非法
	if _, err := s.CreateObject(ctx, sm4SecretTemplate([]byte("short"), "bad", false)); err == nil {
		t.Error("非法密钥长度应返回错误")
	}
}

// TestSecretKeyAESCBC 验证同一对象模型下 AES-CBC 也可用（补齐此前声明的机制）。
func TestSecretKeyAESCBC(t *testing.T) {
	s := newSecretSlot()
	tpl := []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32ToBytes(uint32(pkcs11types.CKO_SECRET_KEY))},
		{Type: pkcs11types.CKA_KEY_TYPE, Value: uint32ToBytes(uint32(pkcs11types.CKK_AES))},
		{Type: pkcs11types.CKA_VALUE, Value: []byte("0123456789abcdef")},
	}
	handle, err := s.CreateObject(context.Background(), tpl)
	if err != nil {
		t.Fatalf("创建 AES 密钥失败: %v", err)
	}
	mech := pkcs11types.Mechanism{Type: pkcs11types.CKM_AES_CBC, Parameter: []byte("abcdefghijklmnop")}
	ct, err := s.Encrypt(context.Background(), handle, mech, []byte("aes cbc payload"))
	if err != nil {
		t.Fatalf("AES-CBC 加密失败: %v", err)
	}
	pt, err := s.Decrypt(context.Background(), handle, mech, ct)
	if err != nil {
		t.Fatalf("AES-CBC 解密失败: %v", err)
	}
	if string(pt) != "aes cbc payload" {
		t.Fatalf("AES-CBC 解密结果不一致: %q", pt)
	}
}
