package pkcs11

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// testModulePath 返回可用于测试的 PKCS#11 模块路径。
//
// 优先使用环境变量 PKCS11_TEST_MODULE；否则探测本机常见位置
// （Windows 下可由仓库内 drivers/codes/csp 的 pkcs11-mock.c 编译得到）。
func testModulePath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("PKCS11_TEST_MODULE"); p != "" {
		return p
	}
	candidates := []string{
		filepath.Join(os.TempDir(), "pkcs11mock", "pkcs11-mock.dll"),
		`C:\Windows\System32\eTPKCS11.dll`,
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("未找到可用的 PKCS#11 模块，跳过（可用 PKCS11_TEST_MODULE 指定路径）")
	return ""
}

// TestLoadModuleInfoAndSlots 验证动态库加载、函数表解析与槽位/令牌结构体布局。
func TestLoadModuleInfoAndSlots(t *testing.T) {
	path := testModulePath(t)

	m, err := LoadModule(path)
	if err != nil {
		t.Fatalf("加载 PKCS#11 模块失败: %v", err)
	}
	defer ReleaseModule(path)

	info, err := m.LibraryInfo()
	if err != nil {
		t.Fatalf("C_GetInfo 失败（结构体布局或函数表序号可能不正确）: %v", err)
	}
	if info.Manufacturer == "" {
		t.Fatalf("CK_INFO.ManufacturerID 为空，说明字段偏移与 C 结构体不一致")
	}
	t.Logf("模块信息: 厂商=%q 描述=%q Cryptoki=%d.%d 布局=%s",
		info.Manufacturer, info.Description, info.CryptokiMajor, info.CryptokiMinor, m.LayoutNote())

	slots, err := m.ListSlots()
	if err != nil {
		t.Fatalf("C_GetSlotList 失败: %v", err)
	}
	if len(slots) == 0 {
		t.Fatalf("未枚举到任何槽位")
	}
	t.Logf("枚举到 %d 个槽位", len(slots))
	for _, s := range slots {
		t.Logf("  槽位 #%d id=%d 描述=%q 厂商=%q 有令牌=%v 标签=%q 序列号=%q 型号=%q",
			s.Index, s.ID, s.Description, s.Manufacturer, s.TokenPresent,
			s.Token.Label, s.Token.Serial, s.Token.Model)
		if s.TokenPresent && s.Token.Label == "" {
			t.Errorf("槽位 %d 报告有令牌但标签为空，CK_TOKEN_INFO 布局可能有误", s.Index)
		}
	}
}

// TestSessionLoginAndGenerateKeyPair 验证会话、登录、对象查找与密钥生成的调用链。
func TestSessionLoginAndGenerateKeyPair(t *testing.T) {
	path := testModulePath(t)

	m, err := LoadModule(path)
	if err != nil {
		t.Fatalf("加载模块失败: %v", err)
	}
	defer ReleaseModule(path)

	slots, err := m.ListSlots()
	if err != nil || len(slots) == 0 {
		t.Fatalf("枚举槽位失败: %v", err)
	}
	target := slots[0]

	sess, err := m.OpenSession(target.ID, "1234", target.Token.LoginRequired)
	if err != nil {
		t.Fatalf("打开会话/登录失败: %v", err)
	}
	defer sess.Close()

	// 对象查找（返回 0 个也不视为失败——不同模块对象集合不同）
	handles, err := sess.FindObjects(newAttrBuffer(m.layout).addULong(ckaClass, ckoPrivateKey), 8)
	if err != nil {
		t.Fatalf("C_FindObjects* 调用失败: %v", err)
	}
	t.Logf("按 CKO_PRIVATE_KEY 查到 %d 个对象", len(handles))

	// 生成密钥对：这是对函数表序号（C_GenerateKeyPair）与属性模板封送的最强校验
	gen, err := sess.GenerateKeyPair(KeyGenRequest{
		KeyType:     "rsa2048",
		Label:       "opencert/test",
		ID:          []byte{1, 2, 3, 4},
		Extractable: false,
	})
	if err != nil {
		if errors.Is(err, errAttrMissing) {
			// 桩模块（如 pkcs11-mock）会接受 C_GenerateKeyPair 但不提供真实密钥属性，
			// 此时调用链已经走通，只记录即可。
			t.Logf("模块未提供公钥属性（桩实现），但 C_GenerateKeyPair 调用链已走通: %v", err)
			return
		}
		t.Fatalf("C_GenerateKeyPair 调用失败: %v", err)
	}
	if gen.PublicH == 0 || gen.PrivateH == 0 {
		t.Fatalf("C_GenerateKeyPair 返回了空句柄: pub=%d priv=%d", gen.PublicH, gen.PrivateH)
	}
	t.Logf("生成密钥对成功: pub=%d priv=%d 公钥长度=%d", gen.PublicH, gen.PrivateH, len(gen.PublicDER))
}

// TestMechanismMapping 验证上层算法名到 Cryptoki 机制的映射与 DigestInfo 构造。
func TestMechanismMapping(t *testing.T) {
	for _, packed := range []bool{false, true} {
		l := newLayout(packed)
		name := "自然对齐"
		if packed {
			name = "1字节打包"
		}
		t.Run(name, func(t *testing.T) { testMechanismMapping(t, l) })
	}
}

func testMechanismMapping(t *testing.T, l layout) {
	// RSA PKCS#1 v1.5：本地摘要 + DigestInfo，走 CKM_RSA_PKCS
	req, err := buildSignRequest(l, "SHA256_RSA_PKCS", "rsa2048", []byte("hello"))
	if err != nil {
		t.Fatalf("映射 SHA256_RSA_PKCS 失败: %v", err)
	}
	if req.mech.mechanism() != ckmRSAPKCS {
		t.Errorf("SHA256_RSA_PKCS 应映射为 CKM_RSA_PKCS(0x%X)，实际 0x%X",
			uint64(ckmRSAPKCS), uint64(req.mech.mechanism()))
	}
	// DigestInfo = SEQUENCE{ SEQUENCE{ OID, NULL }, OCTET STRING(32) }
	if len(req.input) != 19+32 {
		t.Errorf("DigestInfo 长度异常: %d（期望 51）", len(req.input))
	}
	if req.input[0] != 0x30 {
		t.Errorf("DigestInfo 应以 SEQUENCE(0x30) 开头，实际 0x%02X", req.input[0])
	}

	// RSA-PSS：需要机制参数（哈希/MGF/盐长度）
	pss, err := buildSignRequest(l, "SHA256_RSA_PSS", "rsa2048", []byte("hello"))
	if err != nil {
		t.Fatalf("映射 SHA256_RSA_PSS 失败: %v", err)
	}
	if pss.mech.mechanism() != ckmRSAPKCSPSS || len(pss.mech.paramBytes()) == 0 {
		t.Errorf("RSA-PSS 机制或参数缺失: mech=0x%X param=%d",
			uint64(pss.mech.mechanism()), len(pss.mech.paramBytes()))
	}
	params := pss.mech.paramBytes()
	saltLen := l.readULong(params[2*l.ulongSize:])
	if saltLen != 32 {
		t.Errorf("RSA-PSS 盐长度应为摘要长度 32，实际 %d", saltLen)
	}

	// ECDSA：本地摘要 + CKM_ECDSA，输出与软件实现一致（r||s）
	ec, err := buildSignRequest(l, "ECDSA_SHA256", "ec256", []byte("hello"))
	if err != nil {
		t.Fatalf("映射 ECDSA_SHA256 失败: %v", err)
	}
	if ec.mech.mechanism() != ckmECDSA || len(ec.input) != 32 {
		t.Errorf("ECDSA 映射异常: mech=0x%X 摘要长度=%d", uint64(ec.mech.mechanism()), len(ec.input))
	}

	// 密钥类型与机制不匹配时必须报错
	if _, err := buildSignRequest(l, "ECDSA_SHA256", "rsa2048", []byte("x")); err == nil {
		t.Error("RSA 密钥 + ECDSA 机制应返回错误")
	}
	if _, err := buildSignRequest(l, "SHA256_RSA_PKCS", "ec256", []byte("x")); err == nil {
		t.Error("EC 密钥 + RSA 机制应返回错误")
	}

	// 解密机制
	oaep, err := buildDecryptMechanism(l, "RSA_OAEP")
	if err != nil {
		t.Fatalf("映射 RSA_OAEP 失败: %v", err)
	}
	if oaep.mech.mechanism() != ckmRSAPKCSOAEP || len(oaep.mech.paramBytes()) == 0 {
		t.Errorf("RSA_OAEP 机制或参数缺失: mech=0x%X", uint64(oaep.mech.mechanism()))
	}
	// OAEP 参数结构必须按布局分配：打包时为 24 字节（Win），自然对齐为 32 字节
	if got, want := len(oaep.mech.paramBytes()), l.paramStructSize(3); got != want {
		t.Errorf("OAEP 参数长度 %d，期望 %d", got, want)
	}
	pkcs1, err := buildDecryptMechanism(l, "RSA_PKCS")
	if err != nil || pkcs1.mech.mechanism() != ckmRSAPKCS {
		t.Errorf("RSA_PKCS 映射异常: %v", err)
	}
}

// TestStructLayout 校验关键结构体与 C 结构体布局一致（Windows: CK_ULONG=4，LP64: 8）。
func TestStructLayout(t *testing.T) {
	ulongSize := int(unsafe.Sizeof(ckULong(0)))
	ptrSize := int(unsafe.Sizeof(uintptr(0)))

	// CK_ATTRIBUTE = { CK_ULONG type; void* pValue; CK_ULONG ulValueLen; }
	wantAttr := alignUp(ulongSize, ptrSize) + ptrSize + ulongSize
	wantAttr = alignUp(wantAttr, ptrSize)
	if got := int(unsafe.Sizeof(ckAttribute{})); got != wantAttr {
		t.Errorf("CK_ATTRIBUTE 大小不一致: got=%d want=%d（CK_ULONG=%d 字节）", got, wantAttr, ulongSize)
	}
	// CK_MECHANISM = { CK_ULONG mechanism; void* pParameter; CK_ULONG ulParameterLen; }
	if got := int(unsafe.Sizeof(ckMechanism{})); got != wantAttr {
		t.Errorf("CK_MECHANISM 大小不一致: got=%d want=%d", got, wantAttr)
	}
	// CK_TOKEN_INFO 在 Windows(x64, ulong=4) 为 160 字节，LP64 为 208 字节
	wantToken := 160
	if ulongSize == 8 {
		wantToken = 208
	}
	if got := int(unsafe.Sizeof(ckTokenInfo{})); got != wantToken {
		t.Errorf("CK_TOKEN_INFO 大小不一致: got=%d want=%d", got, wantToken)
	}
}

func alignUp(v, a int) int {
	if v%a == 0 {
		return v
	}
	return v + a - v%a
}

// TestDigestInfoPrefix 校验 DigestInfo 前缀与 RFC 8017 一致（以 SHA-256 为例）。
func TestDigestInfoPrefix(t *testing.T) {
	der, err := digestInfoDER("SHA256", make([]byte, 32))
	if err != nil {
		t.Fatalf("构造 DigestInfo 失败: %v", err)
	}
	// 标准前缀：30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
	wantPrefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	if !bytes.HasPrefix(der, wantPrefix) {
		t.Errorf("DigestInfo 前缀不符合 RFC 8017\n实际: %x\n期望: %x", der, wantPrefix)
	}
}
