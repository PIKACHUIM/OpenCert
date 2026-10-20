package local

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// secretHandleBase 是对称密钥对象的句柄起点。
// 证书对象的句柄由 loadObjects 从 1 开始按顺序分配并可能重置，
// 因此对称密钥使用独立的高位区段，避免重载后句柄冲突。
const secretHandleBase = 0x40000000

// secretKeyObject 是进程内的对称密钥对象（CKO_SECRET_KEY）。
//
// 设计取舍：对称密钥不落库。PKCS#11 里 CKA_TOKEN=false 的会话对象本就只在
// 会话期有效，且明文密钥入库会削弱卡片"密钥不可导出"的模型；因此这里只保存
// 在内存中，槽位重启后需要调用方重新导入。
type secretKeyObject struct {
	keyType     pkcs11types.KeyType
	value       []byte
	label       string
	id          []byte
	sensitive   bool
	extractable bool
}

// secretParamPacked 是驱动把 CK_GCM_PARAMS 打包后的自描述格式：
//
//	[4B ivLen][4B aadLen][4B tagBits][iv][aad]（大端）
//
// CK_GCM_PARAMS 内含指针，不能跨进程直接传递，必须由驱动重新打包。
const secretParamHeaderLen = 12

// createSecretKeyLocked 依据 C_CreateObject 的属性模板创建对称密钥对象。
// 调用方必须已持有 s.mu 写锁并完成登录校验。
func (s *Slot) createSecretKeyLocked(template []pkcs11types.Attribute) (pkcs11types.ObjectHandle, error) {
	var (
		keyType     = pkcs11types.CKK_SM4
		hasKeyType  bool
		value       []byte
		label       string
		id          []byte
		sensitive   bool
		extractable = true
	)
	for _, a := range template {
		switch a.Type {
		case pkcs11types.CKA_KEY_TYPE:
			if len(a.Value) == 4 {
				keyType = pkcs11types.KeyType(binary.BigEndian.Uint32(a.Value))
				hasKeyType = true
			}
		case pkcs11types.CKA_VALUE:
			value = a.Value
		case pkcs11types.CKA_LABEL:
			label = string(a.Value)
		case pkcs11types.CKA_ID:
			id = a.Value
		case pkcs11types.CKA_SENSITIVE:
			sensitive = boolAttr(a.Value)
		case pkcs11types.CKA_EXTRACTABLE:
			extractable = boolAttr(a.Value)
		}
	}
	_ = hasKeyType // 未显式指定时按 SM4 处理（驱动只有国密对称机制）

	switch keyType {
	case pkcs11types.CKK_SM4, pkcs11types.CKK_AES:
	default:
		return 0, fmt.Errorf("%w: 不支持的对称密钥类型 0x%X", pkcs11types.CKR_ATTRIBUTE_VALUE_INVALID, uint32(keyType))
	}
	if len(value) != 16 && len(value) != 24 && len(value) != 32 {
		return 0, fmt.Errorf("%w: 对称密钥长度必须是 16/24/32 字节，实际 %d",
			pkcs11types.CKR_ATTRIBUTE_VALUE_INVALID, len(value))
	}

	// 敏感密钥默认不可导出；显式设置 CKA_EXTRACTABLE=false 时即使未标 SENSITIVE 也不返回明文
	if sensitive {
		extractable = false
	}

	if s.secretKeys == nil {
		s.secretKeys = make(map[pkcs11types.ObjectHandle]*secretKeyObject)
	}
	if s.secretNext < secretHandleBase {
		s.secretNext = secretHandleBase
	}
	handle := pkcs11types.ObjectHandle(s.secretNext)
	s.secretNext++
	s.secretKeys[handle] = &secretKeyObject{
		keyType:     keyType,
		value:       append([]byte(nil), value...),
		label:       label,
		id:          append([]byte(nil), id...),
		sensitive:   sensitive,
		extractable: extractable,
	}
	return handle, nil
}

// lookupSecretKey 返回对称密钥对象（调用方需持有读锁）。
func (s *Slot) lookupSecretKey(handle pkcs11types.ObjectHandle) (*secretKeyObject, bool) {
	k, ok := s.secretKeys[handle]
	return k, ok
}

// buildSecretKeyAttributes 组装对称密钥对象的属性。
func buildSecretKeyAttributes(k *secretKeyObject, attrTypes []pkcs11types.AttributeType) []pkcs11types.Attribute {
	out := make([]pkcs11types.Attribute, 0, len(attrTypes))
	for _, t := range attrTypes {
		attr := pkcs11types.Attribute{Type: t}
		switch t {
		case pkcs11types.CKA_CLASS:
			attr.Value = uint32ToBytes(uint32(pkcs11types.CKO_SECRET_KEY))
		case pkcs11types.CKA_KEY_TYPE:
			attr.Value = uint32ToBytes(uint32(k.keyType))
		case pkcs11types.CKA_LABEL:
			attr.Value = []byte(k.label)
		case pkcs11types.CKA_ID:
			attr.Value = append([]byte(nil), k.id...)
		case pkcs11types.CKA_VALUE:
			// 敏感或不可导出的密钥不返回明文，与硬件令牌行为一致
			if k.sensitive || !k.extractable {
				attr.Value = nil
			} else {
				attr.Value = append([]byte(nil), k.value...)
			}
		case pkcs11types.CKA_VALUE_LEN:
			attr.Value = uint32ToBytes(uint32(len(k.value)))
		case pkcs11types.CKA_SENSITIVE:
			attr.Value = boolToBytes(k.sensitive)
		case pkcs11types.CKA_EXTRACTABLE:
			attr.Value = boolToBytes(k.extractable)
		case pkcs11types.CKA_TOKEN:
			attr.Value = boolToBytes(false)
		case pkcs11types.CKA_ENCRYPT, pkcs11types.CKA_DECRYPT:
			attr.Value = boolToBytes(true)
		case pkcs11types.CKA_WRAP, pkcs11types.CKA_UNWRAP, pkcs11types.CKA_SIGN, pkcs11types.CKA_VERIFY,
			pkcs11types.CKA_DERIVE:
			attr.Value = boolToBytes(false)
		case pkcs11types.CKA_MODIFIABLE:
			attr.Value = boolToBytes(true)
		default:
			attr.Value = nil
		}
		out = append(out, attr)
	}
	return out
}

// matchSecretKey 判断对称密钥对象是否匹配查找模板。
func matchSecretKey(k *secretKeyObject, template []pkcs11types.Attribute) bool {
	for _, a := range template {
		switch a.Type {
		case pkcs11types.CKA_CLASS:
			if len(a.Value) != 4 || binary.BigEndian.Uint32(a.Value) != uint32(pkcs11types.CKO_SECRET_KEY) {
				return false
			}
		case pkcs11types.CKA_KEY_TYPE:
			if len(a.Value) != 4 || pkcs11types.KeyType(binary.BigEndian.Uint32(a.Value)) != k.keyType {
				return false
			}
		case pkcs11types.CKA_LABEL:
			if string(a.Value) != k.label {
				return false
			}
		case pkcs11types.CKA_ID:
			if !bytes.Equal(a.Value, k.id) {
				return false
			}
		}
	}
	return true
}

// secretKeySize 返回对象大小（不含被隐藏的明文长度，避免侧信道泄露）。
func secretKeySize(k *secretKeyObject) uint32 {
	return uint32(len(k.value) + len(k.label) + len(k.id))
}

// cryptSecretKey 用对称密钥执行加密或解密；mechanism.Parameter 承载机制参数。
func cryptSecretKey(k *secretKeyObject, mechanism pkcs11types.Mechanism, in []byte, encrypt bool) ([]byte, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("%w: 输入为空", pkcs11types.CKR_DATA_LEN_RANGE)
	}
	if k.keyType == pkcs11types.CKK_SM4 {
		switch mechanism.Type {
		case pkcs11types.CKM_SM4_CBC:
			iv, err := requireIV(mechanism.Parameter)
			if err != nil {
				return nil, err
			}
			if encrypt {
				return sm4EncryptCBC(k.value, iv, in)
			}
			return sm4DecryptCBC(k.value, iv, in)
		case pkcs11types.CKM_SM4_GCM:
			iv, aad, tagBits, err := parsePackedGCM(mechanism.Parameter)
			if err != nil {
				return nil, err
			}
			if tagBits != 0 && tagBits != 128 {
				return nil, fmt.Errorf("%w: 仅支持 128 位 GCM 认证标签", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
			}
			if encrypt {
				return sm4EncryptGCM(k.value, iv, in, aad)
			}
			return sm4DecryptGCM(k.value, iv, in, aad)
		default:
			return nil, fmt.Errorf("%w: SM4 密钥不支持机制 0x%X", pkcs11types.CKR_MECHANISM_INVALID, uint32(mechanism.Type))
		}
	}

	// AES：覆盖此前已对外声明但未实现的机制
	switch mechanism.Type {
	case pkcs11types.CKM_AES_CBC:
		iv, err := requireIV(mechanism.Parameter)
		if err != nil {
			return nil, err
		}
		return aesCBC(k.value, iv, in, encrypt)
	case pkcs11types.CKM_AES_GCM:
		iv, aad, tagBits, err := parsePackedGCM(mechanism.Parameter)
		if err != nil {
			return nil, err
		}
		if tagBits != 0 && tagBits != 128 {
			return nil, fmt.Errorf("%w: 仅支持 128 位 GCM 认证标签", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
		}
		return aesGCM(k.value, iv, in, aad, encrypt)
	default:
		return nil, fmt.Errorf("%w: AES 密钥不支持机制 0x%X", pkcs11types.CKR_MECHANISM_INVALID, uint32(mechanism.Type))
	}
}

// requireIV 校验 CBC 的 16 字节 IV 参数。
func requireIV(param []byte) ([]byte, error) {
	if len(param) != 16 {
		return nil, fmt.Errorf("%w: CBC 需要 16 字节 IV", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
	}
	return param, nil
}

// parsePackedGCM 解析驱动打包后的 GCM 参数。
func parsePackedGCM(param []byte) (iv, aad []byte, tagBits uint32, err error) {
	if len(param) < secretParamHeaderLen {
		return nil, nil, 0, fmt.Errorf("%w: GCM 参数缺失", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
	}
	ivLen := binary.BigEndian.Uint32(param[0:4])
	aadLen := binary.BigEndian.Uint32(param[4:8])
	tagBits = binary.BigEndian.Uint32(param[8:12])
	rest := param[secretParamHeaderLen:]
	if uint64(len(rest)) < uint64(ivLen)+uint64(aadLen) {
		return nil, nil, 0, fmt.Errorf("%w: GCM 参数长度不一致", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
	}
	iv = rest[:ivLen]
	aad = rest[ivLen : ivLen+aadLen]
	if len(iv) < 12 {
		return nil, nil, 0, fmt.Errorf("%w: GCM IV 至少 12 字节", pkcs11types.CKR_MECHANISM_PARAM_INVALID)
	}
	return iv, aad, tagBits, nil
}

// aesCBC 执行 AES-CBC + PKCS#7。
func aesCBC(key, iv, in []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pkcs11types.CKR_KEY_SIZE_RANGE, err)
	}
	if encrypt {
		// 补位：CBC 模式要求输入长度为块大小的整数倍
		pad := block.BlockSize() - len(in)%block.BlockSize()
		buf := make([]byte, len(in)+pad)
		copy(buf, in)
		for i := len(in); i < len(buf); i++ {
			buf[i] = byte(pad)
		}
		out := make([]byte, len(buf))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, buf)
		return out, nil
	}
	if len(in)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: 密文长度不是块大小整数倍", pkcs11types.CKR_ENCRYPTED_DATA_LEN_RANGE)
	}
	out := make([]byte, len(in))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, in)
	// 去补位并校验
	pad := int(out[len(out)-1])
	if pad == 0 || pad > block.BlockSize() || pad > len(out) {
		return nil, fmt.Errorf("%w: 填充无效", pkcs11types.CKR_ENCRYPTED_DATA_INVALID)
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("%w: 填充无效", pkcs11types.CKR_ENCRYPTED_DATA_INVALID)
		}
	}
	return out[:len(out)-pad], nil
}

// aesGCM 执行 AES-GCM。
func aesGCM(key, iv, in, aad []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pkcs11types.CKR_KEY_SIZE_RANGE, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", pkcs11types.CKR_MECHANISM_PARAM_INVALID, err)
	}
	if encrypt {
		return gcm.Seal(nil, iv, in, aad), nil
	}
	out, err := gcm.Open(nil, iv, in, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: 认证标签校验失败", pkcs11types.CKR_ENCRYPTED_DATA_INVALID)
	}
	return out, nil
}

// boolAttr 解析 PKCS#11 的 CK_BBOOL（1 字节，非 0 即真）。
func boolAttr(v []byte) bool {
	return len(v) > 0 && v[0] != 0
}

// boolToBytes 编码 CK_BBOOL。
func boolToBytes(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
