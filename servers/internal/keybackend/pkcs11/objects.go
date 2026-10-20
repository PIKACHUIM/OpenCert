package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"
)

// 属性读取时的内部错误。
var (
	errAttrSensitive = errors.New("属性为敏感属性，不可读")
	errAttrMissing   = errors.New("对象不具备该属性")
)

// ---- 属性读取 ----

// Attribute 读取对象的一个属性值。
func (s *Session) Attribute(hObject ckULong, typ ckULong) ([]byte, error) {
	if s.m.fns.getAttributeVal == nil {
		return nil, fmt.Errorf("模块不支持 C_GetAttributeValue")
	}
	l := s.m.layout
	buf := newAttrBuffer(l).add(typ, nil)
	ptr, count := buf.serialize()
	rv := s.m.fns.getAttributeVal(s.handle, hObject, ptr, count)
	runtime.KeepAlive(buf)
	switch rv {
	case ckrOK:
	case ckrAttributeSensitive:
		return nil, errAttrSensitive
	case ckrAttributeTypeInvalid:
		return nil, errAttrMissing
	default:
		return nil, ckError("C_GetAttributeValue", rv)
	}
	n := int(buf.valueLenFromRaw(0))
	if n == int(l.ulongMax()) || n < 0 {
		return nil, errAttrSensitive
	}
	if n == 0 {
		return []byte{}, nil
	}
	val := make([]byte, n)
	buf.setValue(0, val)
	buf.writeValueLen(0, ckULong(n))
	ptr, count = buf.serialize()
	rv = s.m.fns.getAttributeVal(s.handle, hObject, ptr, count)
	runtime.KeepAlive(buf)
	if rv != ckrOK {
		return nil, ckError("C_GetAttributeValue", rv)
	}
	got := int(buf.valueLenFromRaw(0))
	if got < 0 || got > n {
		got = n
	}
	return val[:got], nil
}

// AttributeULong 读取一个 CK_ULONG 属性。
func (s *Session) AttributeULong(hObject ckULong, typ ckULong) (ckULong, error) {
	raw, err := s.Attribute(hObject, typ)
	if err != nil {
		return 0, err
	}
	if len(raw) < s.m.layout.ulongSize {
		return 0, fmt.Errorf("属性长度不足（%d 字节）", len(raw))
	}
	return s.m.layout.readULong(raw), nil
}

// ---- 对象查找 ----

// FindObjects 按模板查找对象句柄（最多 max 个）。
func (s *Session) FindObjects(tmpl *attrBuffer, max int) ([]ckULong, error) {
	if s.m.fns.findObjectsInit == nil || s.m.fns.findObjects == nil {
		return nil, fmt.Errorf("模块不支持 C_FindObjects*")
	}
	if max <= 0 {
		max = 16
	}
	var ptr unsafe.Pointer
	var count ckULong
	if tmpl != nil && tmpl.count() > 0 {
		ptr, count = tmpl.serialize()
	}
	rv := s.m.fns.findObjectsInit(s.handle, ptr, count)
	runtime.KeepAlive(tmpl)
	if rv != ckrOK {
		return nil, ckError("C_FindObjectsInit", rv)
	}
	defer func() {
		if s.m.fns.findObjectsFinal != nil {
			_ = s.m.fns.findObjectsFinal(s.handle)
		}
	}()

	var all []ckULong
	for {
		buf := make([]ckULong, max)
		var got ckULong
		if rv := s.m.fns.findObjects(s.handle, &buf[0], ckULong(max), &got); rv != ckrOK {
			return nil, ckError("C_FindObjects", rv)
		}
		if got == 0 {
			break
		}
		all = append(all, buf[:got]...)
		if len(all) >= 256 {
			break
		}
	}
	return all, nil
}

// ---- 对象创建与销毁 ----

// CreateObject 创建对象并返回句柄。
func (s *Session) CreateObject(tmpl *attrBuffer) (ckULong, error) {
	if s.m.fns.createObject == nil {
		return 0, fmt.Errorf("模块不支持 C_CreateObject")
	}
	ptr, count := tmpl.serialize()
	var h ckULong
	rv := s.m.fns.createObject(s.handle, ptr, count, &h)
	runtime.KeepAlive(tmpl)
	if rv != ckrOK {
		return 0, ckError("C_CreateObject", rv)
	}
	return h, nil
}

// DestroyObject 删除对象。
func (s *Session) DestroyObject(hObject ckULong) error {
	if s.m.fns.destroyObject == nil {
		return fmt.Errorf("模块不支持 C_DestroyObject")
	}
	if rv := s.m.fns.destroyObject(s.handle, hObject); rv != ckrOK {
		return ckError("C_DestroyObject", rv)
	}
	return nil
}

// ---- 签名与解密 ----

// Sign 单步签名；返回值格式由 token 决定（RSA 为定长签名，ECDSA 为 r||s）。
func (s *Session) Sign(hKey ckULong, mech *mechBuffer, data []byte) ([]byte, error) {
	if s.m.fns.signInit == nil || s.m.fns.sign == nil {
		return nil, fmt.Errorf("模块不支持 C_Sign*")
	}
	var pData *byte
	if len(data) > 0 {
		pData = &data[0]
	}
	if rv := s.m.fns.signInit(s.handle, mech.ptr(), hKey); rv != ckrOK {
		return nil, ckError("C_SignInit", rv)
	}
	runtime.KeepAlive(mech)
	runtime.KeepAlive(data)

	var sigLen ckULong
	rv := s.m.fns.sign(s.handle, pData, ckULong(len(data)), nil, &sigLen)
	runtime.KeepAlive(data)
	if rv != ckrOK && (sigLen == 0 || sigLen == s.m.layout.ulongMax()) {
		return nil, ckError("C_Sign", rv)
	}
	if sigLen == 0 || sigLen > 1<<16 {
		return nil, fmt.Errorf("C_Sign 返回的签名长度异常（%d）", sigLen)
	}
	sig := make([]byte, int(sigLen))
	rv = s.m.fns.sign(s.handle, pData, ckULong(len(data)), &sig[0], &sigLen)
	runtime.KeepAlive(data)
	if rv != ckrOK {
		return nil, ckError("C_Sign", rv)
	}
	return sig[:int(sigLen)], nil
}

// Decrypt 单步解密。
func (s *Session) Decrypt(hKey ckULong, mech *mechBuffer, ciphertext []byte) ([]byte, error) {
	if s.m.fns.decryptInit == nil || s.m.fns.decrypt == nil {
		return nil, fmt.Errorf("模块不支持 C_Decrypt*")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("密文为空")
	}
	if rv := s.m.fns.decryptInit(s.handle, mech.ptr(), hKey); rv != ckrOK {
		return nil, ckError("C_DecryptInit", rv)
	}
	runtime.KeepAlive(mech)
	runtime.KeepAlive(ciphertext)

	var outLen ckULong
	rv := s.m.fns.decrypt(s.handle, &ciphertext[0], ckULong(len(ciphertext)), nil, &outLen)
	runtime.KeepAlive(ciphertext)
	if rv != ckrOK && (outLen == 0 || outLen == s.m.layout.ulongMax()) {
		return nil, ckError("C_Decrypt", rv)
	}
	if outLen == 0 || outLen > 1<<20 {
		return nil, fmt.Errorf("C_Decrypt 返回的明文长度异常（%d）", outLen)
	}
	out := make([]byte, int(outLen))
	rv = s.m.fns.decrypt(s.handle, &ciphertext[0], ckULong(len(ciphertext)), &out[0], &outLen)
	runtime.KeepAlive(ciphertext)
	if rv != ckrOK {
		return nil, ckError("C_Decrypt", rv)
	}
	return out[:int(outLen)], nil
}

// ---- 密钥生成 ----

// KeyGenRequest 是在令牌内生成密钥对的请求。
type KeyGenRequest struct {
	KeyType     string // rsa1024/rsa2048/rsa3072/rsa4096/ec256/ec384/ec521
	Label       string
	ID          []byte // CKA_ID
	Extractable bool   // 是否允许导出私钥（默认 false）
}

// GeneratedKey 是在令牌内生成的密钥对句柄。
type GeneratedKey struct {
	PublicDER []byte
	PublicKey any
	PublicH   ckULong
	PrivateH  ckULong
}

// GenerateKeyPair 在令牌内生成密钥对，并读回公钥。
func (s *Session) GenerateKeyPair(req KeyGenRequest) (*GeneratedKey, error) {
	if s.m.fns.generateKeyPair == nil {
		return nil, fmt.Errorf("模块不支持 C_GenerateKeyPair")
	}
	pub := newAttrBuffer(s.m.layout).addULong(ckaClass, ckoPublicKey).addBool(ckaToken, true).
		addString(ckaLABEL, req.Label).add(ckaID, req.ID)
	priv := newAttrBuffer(s.m.layout).addULong(ckaClass, ckoPrivateKey).addBool(ckaToken, true).
		addBool(ckaPrivate, true).addBool(ckaSensitive, true).
		addBool(ckaExtractable, req.Extractable).
		addString(ckaLABEL, req.Label).add(ckaID, req.ID)

	var mech ckULong
	switch kt := normalKeyType(req.KeyType); {
	case kt == "rsa":
		bits, err := rsaBits(req.KeyType)
		if err != nil {
			return nil, err
		}
		mech = ckmRSAPKCSKeyPairGen
		pub.addULong(ckaKeyType, ckkRSA).addULong(ckaModulusBits, ckULong(bits)).
			add(ckaPublicExponent, []byte{0x01, 0x00, 0x01}).
			addBool(ckaVerify, true).addBool(ckaEncrypt, true).addBool(ckaWrap, true)
		priv.addULong(ckaKeyType, ckkRSA).addBool(ckaSign, true).
			addBool(ckaDecrypt, true).addBool(ckaUnwrap, true)
	case kt == "ec":
		oid, err := curveOID(req.KeyType)
		if err != nil {
			return nil, err
		}
		mech = ckmECKeyPairGen
		pub.addULong(ckaKeyType, ckkEC).add(ckaEcParams, oid).
			addBool(ckaVerify, true).addBool(ckaDerive, true)
		priv.addULong(ckaKeyType, ckkEC).addBool(ckaSign, true).addBool(ckaDerive, true)
	default:
		return nil, fmt.Errorf("令牌不支持生成 %s 密钥", req.KeyType)
	}

	pubPtr, pubCount := pub.serialize()
	privPtr, privCount := priv.serialize()
	mechBuf := newMechBuffer(s.m.layout, mech, nil)
	var hPub, hPriv ckULong
	rv := s.m.fns.generateKeyPair(s.handle, mechBuf.ptr(),
		pubPtr, pubCount, privPtr, privCount, &hPub, &hPriv)
	runtime.KeepAlive(pub)
	runtime.KeepAlive(priv)
	runtime.KeepAlive(mechBuf)
	if rv != ckrOK {
		return nil, ckError("C_GenerateKeyPair", rv)
	}

	pubDER, pubKey, err := s.readPublicKey(hPub, req.KeyType)
	if err != nil {
		return nil, err
	}
	return &GeneratedKey{PublicDER: pubDER, PublicKey: pubKey, PublicH: hPub, PrivateH: hPriv}, nil
}

// readPublicKey 从公钥对象读回标准 SPKI DER。
func (s *Session) readPublicKey(hPub ckULong, keyType string) ([]byte, any, error) {
	switch normalKeyType(keyType) {
	case "rsa":
		mod, err := s.Attribute(hPub, ckaModulus)
		if err != nil {
			return nil, nil, fmt.Errorf("读取 RSA 模数失败: %w", err)
		}
		exp, err := s.Attribute(hPub, ckaPublicExponent)
		if err != nil {
			return nil, nil, fmt.Errorf("读取 RSA 公钥指数失败: %w", err)
		}
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(mod),
			E: int(new(big.Int).SetBytes(exp).Int64()),
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		return der, pub, err
	case "ec":
		raw, err := s.Attribute(hPub, ckaEcPoint)
		if err != nil {
			return nil, nil, fmt.Errorf("读取 EC 公钥点失败: %w", err)
		}
		curve, err := curveByName(keyType)
		if err != nil {
			return nil, nil, err
		}
		pt, err := parseECPoint(raw)
		if err != nil {
			return nil, nil, err
		}
		x, y := elliptic.Unmarshal(curve, pt)
		if x == nil {
			return nil, nil, fmt.Errorf("EC 公钥点无法解析（长度 %d）", len(pt))
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		der, err := x509.MarshalPKIXPublicKey(pub)
		return der, pub, err
	default:
		return nil, nil, fmt.Errorf("不支持的密钥类型: %s", keyType)
	}
}

// parseECPoint 兼容两种 EC_POINT 编码：DER OCTET STRING 包裹 或 裸点。
func parseECPoint(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("EC 公钥点为空")
	}
	if raw[0] == 0x04 {
		return raw, nil
	}
	var inner []byte
	if _, err := asn1.Unmarshal(raw, &inner); err == nil && len(inner) > 0 {
		return inner, nil
	}
	return raw, nil
}

// ---- 私钥导入 ----

// ImportPrivateKeyRequest 是导入外部私钥的请求。
type ImportPrivateKeyRequest struct {
	PrivDER []byte
	KeyType string
	Label   string
	ID      []byte
}

// ImportPrivateKey 把 PKCS#8 私钥导入令牌，并创建配套公钥对象。
// 返回私钥对象的句柄与公钥 SPKI DER。
func (s *Session) ImportPrivateKey(req ImportPrivateKeyRequest) (*GeneratedKey, string, error) {
	privKey, err := keybackendParseKey(req.PrivDER)
	if err != nil {
		return nil, "", err
	}
	pub, err := keybackendPublicKey(privKey)
	if err != nil {
		return nil, "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("序列化公钥失败: %w", err)
	}

	// 先创建私钥对象（安全属性尽量收紧，失败时降级重试）
	hPriv, err := s.createPrivateKeyObject(privKey, req, true)
	var warning string
	if err != nil {
		hPriv, err = s.createPrivateKeyObject(privKey, req, false)
		if err != nil {
			return nil, "", err
		}
		warning = "该令牌不支持创建「敏感且不可导出」的私钥对象，已降级为 CKA_SENSITIVE=false；" +
			"建议改用「设备内生成密钥」以获得更高安全性"
	}

	// 创建公钥对象（部分令牌在导入私钥时不会自动建立公钥对象）
	var hPub ckULong
	if pubTmpl, perr := s.publicKeyTemplate(pub, req); perr == nil {
		if h, cerr := s.CreateObject(pubTmpl); cerr == nil {
			hPub = h
		}
	}

	return &GeneratedKey{PublicDER: pubDER, PublicKey: pub, PublicH: hPub, PrivateH: hPriv}, warning, nil
}

func (s *Session) createPrivateKeyObject(privKey any, req ImportPrivateKeyRequest, sensitive bool) (ckULong, error) {
	l := newAttrsFor(s.m.layout).addULong(ckaClass, ckoPrivateKey).addBool(ckaToken, true).
		addBool(ckaPrivate, true).addBool(ckaSensitive, sensitive).
		addBool(ckaExtractable, false).
		addString(ckaLABEL, req.Label).add(ckaID, req.ID)

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		if len(k.Primes) < 2 {
			return 0, fmt.Errorf("RSA 私钥缺少素因子")
		}
		l.addULong(ckaKeyType, ckkRSA).
			add(ckaModulus, k.N.Bytes()).
			add(ckaPublicExponent, big.NewInt(int64(k.E)).Bytes()).
			add(ckaPrivateExponent, k.D.Bytes()).
			add(ckaPrime1, k.Primes[0].Bytes()).
			add(ckaPrime2, k.Primes[1].Bytes())
		if k.Precomputed.Dp != nil {
			l.add(ckaExponent1, k.Precomputed.Dp.Bytes())
		}
		if k.Precomputed.Dq != nil {
			l.add(ckaExponent2, k.Precomputed.Dq.Bytes())
		}
		if k.Precomputed.Qinv != nil {
			l.add(ckaCoefficient, k.Precomputed.Qinv.Bytes())
		}
		l.addBool(ckaSign, true).addBool(ckaDecrypt, true).addBool(ckaUnwrap, true)
	case *ecdsa.PrivateKey:
		oid, err := curveOIDByCurve(k.Curve)
		if err != nil {
			return 0, err
		}
		l.addULong(ckaKeyType, ckkEC).add(ckaEcParams, oid).
			add(ckaValue, k.D.Bytes()).
			addBool(ckaSign, true).addBool(ckaDerive, true)
	default:
		return 0, fmt.Errorf("令牌导入暂不支持 %T 类型的私钥", privKey)
	}
	return s.CreateObject(l)
}

func (s *Session) publicKeyTemplate(pub any, req ImportPrivateKeyRequest) (*attrBuffer, error) {
	l := newAttrsFor(s.m.layout).addULong(ckaClass, ckoPublicKey).addBool(ckaToken, true).
		addString(ckaLABEL, req.Label).add(ckaID, req.ID)
	switch k := pub.(type) {
	case *rsa.PublicKey:
		l.addULong(ckaKeyType, ckkRSA).
			add(ckaModulus, k.N.Bytes()).
			add(ckaPublicExponent, big.NewInt(int64(k.E)).Bytes()).
			addBool(ckaVerify, true).addBool(ckaEncrypt, true).addBool(ckaWrap, true)
	case *ecdsa.PublicKey:
		oid, err := curveOIDByCurve(k.Curve)
		if err != nil {
			return nil, err
		}
		pt := elliptic.Marshal(k.Curve, k.X, k.Y)
		wrapped, err := asn1.Marshal(pt)
		if err != nil {
			return nil, err
		}
		l.addULong(ckaKeyType, ckkEC).add(ckaEcParams, oid).add(ckaEcPoint, wrapped).
			addBool(ckaVerify, true).addBool(ckaDerive, true)
	default:
		return nil, fmt.Errorf("不支持的公钥类型: %T", pub)
	}
	return l, nil
}

// newAttrsFor 按布局创建属性缓冲区。
func newAttrsFor(l layout) *attrBuffer { return newAttrBuffer(l) }
