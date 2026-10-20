// Package pkcs11 是 Cryptoki（PKCS#11 v2.40）的纯 Go 动态加载绑定与最小实现，
// 用于把任意厂商的 PKCS#11 模块（eToken 5110 的 eTPKCS11.dll、SoftHSM2、网络 HSM 等）
// 接入服务端私钥存储后端。
//
// 实现要点：
//   - 不依赖 cgo：Windows 用 LoadLibrary/GetProcAddress，Linux/macOS 用 purego.Dlopen/Dlsym；
//   - 通过 C_GetFunctionList 取函数表，再用 purego.RegisterFunc 逐个注册为 Go 函数；
//   - 只实现本项目需要的子集（槽位/令牌枚举、登录、查找、生成密钥对、创建对象、签名、解密）。
//
// 平台注意：CK_ULONG 在 Windows 上为 unsigned long（4 字节），在 LP64 平台为 8 字节，
// 因此 ckULong 按平台别名定义，结构体布局由 Go 的字段对齐规则自动与 C 保持一致。
package pkcs11

// CK_VERSION
type ckVersion struct {
	Major byte
	Minor byte
}

// CK_INFO
type ckInfo struct {
	CryptokiVersion    ckVersion
	ManufacturerID     [32]byte
	Flags              ckFlags
	LibraryDescription [32]byte
	LibraryVersion     ckVersion
}

// CK_SLOT_INFO
type ckSlotInfo struct {
	SlotDescription [64]byte
	ManufacturerID  [32]byte
	Flags           ckFlags
	HardwareVersion ckVersion
	FirmwareVersion ckVersion
}

// CK_TOKEN_INFO
type ckTokenInfo struct {
	Label                [32]byte
	ManufacturerID       [32]byte
	Model                [16]byte
	SerialNumber         [16]byte
	Flags                ckFlags
	UlMaxSessionCount    ckULong
	UlSessionCount       ckULong
	UlMaxRwSessionCount  ckULong
	UlRwSessionCount     ckULong
	UlMaxPinLen          ckULong
	UlMinPinLen          ckULong
	UlTotalPublicMemory  ckULong
	UlFreePublicMemory   ckULong
	UlTotalPrivateMemory ckULong
	UlFreePrivateMemory  ckULong
	HardwareVersion      ckVersion
	FirmwareVersion      ckVersion
	UtcTime              [16]byte
}

// CK_SESSION_INFO
type ckSessionInfo struct {
	SlotID        ckULong
	State         ckULong
	Flags         ckFlags
	UlDeviceError ckULong
}

// CK_MECHANISM
type ckMechanism struct {
	Mechanism      ckULong
	PParameter     uintptr
	UlParameterLen ckULong
}

// CK_MECHANISM_INFO
type ckMechanismInfo struct {
	UlMinKeySize ckULong
	UlMaxKeySize ckULong
	Flags        ckFlags
}

// CK_ATTRIBUTE
type ckAttribute struct {
	Type       ckULong
	PValue     uintptr
	UlValueLen ckULong
}

// CK_RSA_PKCS_OAEP_PARAMS
type ckRsaPkcsOaepParams struct {
	HashAlg         ckULong
	Mgf             ckULong
	Source          ckULong
	PSourceData     uintptr
	UlSourceDataLen ckULong
}

// CK_RSA_PKCS_PSS_PARAMS
type ckRsaPkcsPssParams struct {
	HashAlg   ckULong
	Mgf       ckULong
	UlSaltLen ckULong
}

// ---- 返回值 CKR_* ----

const (
	ckrOK                       ckULong = 0x00000000
	ckrCancel                   ckULong = 0x00000001
	ckrHostMemory               ckULong = 0x00000002
	ckrSlotIDInvalid            ckULong = 0x00000003
	ckrGeneralError             ckULong = 0x00000005
	ckrFunctionFailed           ckULong = 0x00000006
	ckrArgumentsBad             ckULong = 0x00000007
	ckrAttributeReadOnly        ckULong = 0x00000010
	ckrAttributeSensitive       ckULong = 0x00000011
	ckrAttributeTypeInvalid     ckULong = 0x00000012
	ckrAttributeValueInvalid    ckULong = 0x00000013
	ckrActionProhibited         ckULong = 0x0000001B
	ckrDataInvalid              ckULong = 0x00000020
	ckrDataLenRange             ckULong = 0x00000021
	ckrDeviceError              ckULong = 0x00000030
	ckrDeviceMemory             ckULong = 0x00000031
	ckrDeviceRemoved            ckULong = 0x00000032
	ckrEncryptedDataInvalid     ckULong = 0x00000040
	ckrEncryptedDataLenRange    ckULong = 0x00000041
	ckrFunctionCanceled         ckULong = 0x00000050
	ckrFunctionNotSupported     ckULong = 0x00000054
	ckrKeyHandleInvalid         ckULong = 0x00000060
	ckrKeySizeRange             ckULong = 0x00000062
	ckrKeyTypeInconsistent      ckULong = 0x00000063
	ckrKeyFunctionNotPermitted  ckULong = 0x00000068
	ckrKeyUnextractable         ckULong = 0x0000006A
	ckrMechanismInvalid         ckULong = 0x00000070
	ckrMechanismParamInvalid    ckULong = 0x00000071
	ckrObjectHandleInvalid      ckULong = 0x00000082
	ckrOperationActive          ckULong = 0x00000090
	ckrOperationNotInitialized  ckULong = 0x00000091
	ckrPinIncorrect             ckULong = 0x000000A0
	ckrPinInvalid               ckULong = 0x000000A1
	ckrPinLenRange              ckULong = 0x000000A2
	ckrPinExpired               ckULong = 0x000000A3
	ckrPinLocked                ckULong = 0x000000A4
	ckrSessionClosed            ckULong = 0x000000B0
	ckrSessionCount             ckULong = 0x000000B1
	ckrSessionHandleInvalid     ckULong = 0x000000B3
	ckrSessionReadOnly          ckULong = 0x000000B5
	ckrSignatureInvalid         ckULong = 0x000000C0
	ckrSignatureLenRange        ckULong = 0x000000C1
	ckrTemplateIncomplete       ckULong = 0x000000D0
	ckrTemplateInconsistent     ckULong = 0x000000D1
	ckrTokenNotPresent          ckULong = 0x000000E0
	ckrTokenNotRecognized       ckULong = 0x000000E1
	ckrTokenWriteProtected      ckULong = 0x000000E2
	ckrUserAlreadyLoggedIn      ckULong = 0x00000100
	ckrUserNotLoggedIn          ckULong = 0x00000101
	ckrUserPinNotInitialized    ckULong = 0x00000102
	ckrUserTypeInvalid          ckULong = 0x00000103
	ckrUserAnotherAlreadyLogged ckULong = 0x00000104
	ckrCryptokiNotInitialized   ckULong = 0x00000190
	ckrCryptokiAlreadyInit      ckULong = 0x00000191
	ckrFunctionRejected         ckULong = 0x00000200
)

// ---- 属性 CKA_* ----

const (
	ckaClass            ckULong = 0x0000
	ckaToken            ckULong = 0x0001
	ckaPrivate          ckULong = 0x0002
	ckaLABEL            ckULong = 0x0003
	ckaApplication      ckULong = 0x0004
	ckaValue            ckULong = 0x0011
	ckaObjectID         ckULong = 0x0012
	ckaCertificateType  ckULong = 0x0080
	ckaIssuer           ckULong = 0x0081
	ckaSerialNumber     ckULong = 0x0082
	ckaKeyType          ckULong = 0x0100
	ckaSubject          ckULong = 0x0101
	ckaID               ckULong = 0x0102
	ckaSensitive        ckULong = 0x0103
	ckaEncrypt          ckULong = 0x0104
	ckaDecrypt          ckULong = 0x0105
	ckaWrap             ckULong = 0x0106
	ckaUnwrap           ckULong = 0x0107
	ckaSign             ckULong = 0x0108
	ckaSignRecover      ckULong = 0x0109
	ckaVerify           ckULong = 0x010A
	ckaDerive           ckULong = 0x010C
	ckaModulus          ckULong = 0x0120
	ckaModulusBits      ckULong = 0x0121
	ckaPublicExponent   ckULong = 0x0122
	ckaPrivateExponent  ckULong = 0x0123
	ckaPrime1           ckULong = 0x0124
	ckaPrime2           ckULong = 0x0125
	ckaExponent1        ckULong = 0x0126
	ckaExponent2        ckULong = 0x0127
	ckaCoefficient      ckULong = 0x0128
	ckaEcParams         ckULong = 0x0180
	ckaEcPoint          ckULong = 0x0181
	ckaExtractable      ckULong = 0x0162
	ckaLocal            ckULong = 0x0163
	ckaNeverExtractable ckULong = 0x0164
	ckaAlwaysSensitive  ckULong = 0x0165
	ckaModifiable       ckULong = 0x0170
)

// ---- 对象类 CKO_* ----

const (
	ckoData        ckULong = 0x0000
	ckoCertificate ckULong = 0x0001
	ckoPublicKey   ckULong = 0x0002
	ckoPrivateKey  ckULong = 0x0003
	ckoSecretKey   ckULong = 0x0004
)

// ---- 密钥类型 CKK_* ----

const (
	ckkRSA       ckULong = 0x0000
	ckkEC        ckULong = 0x0003
	ckkECEdwards ckULong = 0x0040
)

// ---- 用户类型 CKU_* ----

const (
	ckuSO              ckULong = 0
	ckuUser            ckULong = 1
	ckuContextSpecific ckULong = 2
)

// ---- 令牌标志 CKF_* ----

const (
	ckfRNG                 ckFlags = 0x00000001
	ckfWriteProtected      ckFlags = 0x00000002
	ckfLoginRequired       ckFlags = 0x00000004
	ckfUserPinInitialized  ckFlags = 0x00000008
	ckfRestoreKeyNotNeeded ckFlags = 0x00000020
	ckfClockOnToken        ckFlags = 0x00000040
	ckfProtectedAuthPath   ckFlags = 0x00000100
	ckfDualCryptoOps       ckFlags = 0x00000200
	ckfTokenInitialized    ckFlags = 0x00000400
	ckfUserPinCountLow     ckFlags = 0x00010000
	ckfUserPinFinalTry     ckFlags = 0x00020000
	ckfUserPinLocked       ckFlags = 0x00040000
	ckfUserPinToBeChanged  ckFlags = 0x00080000
	ckfSoPinCountLow       ckFlags = 0x00100000
	ckfSoPinFinalTry       ckFlags = 0x00200000
	ckfSoPinLocked         ckFlags = 0x00400000
	ckfSoPinToBeChanged    ckFlags = 0x00800000
)

// ---- 会话标志 ----

const (
	ckfRW            ckFlags = 0x00000002
	ckfSerialSession ckFlags = 0x00000004
)

// ---- 机制 CKM_* ----

const (
	ckmRSAPKCSKeyPairGen ckULong = 0x00000000
	ckmRSAPKCS           ckULong = 0x00000001
	ckmMD5RSAPKCS        ckULong = 0x00000005
	ckmSHA1RSAPKCS       ckULong = 0x00000006
	ckmRSAPKCSOAEP       ckULong = 0x00000009
	ckmRSAPKCSPSS        ckULong = 0x0000000D
	ckmSHA256RSAPKCS     ckULong = 0x00000040
	ckmSHA384RSAPKCS     ckULong = 0x00000041
	ckmSHA512RSAPKCS     ckULong = 0x00000042
	ckmSHA256RSAPKCSPSS  ckULong = 0x00000043
	ckmSHA384RSAPKCSPSS  ckULong = 0x00000044
	ckmSHA512RSAPKCSPSS  ckULong = 0x00000045
	ckmSHA3_256RSAPKCS   ckULong = 0x00000060
	ckmECKeyPairGen      ckULong = 0x00001040
	ckmECDSA             ckULong = 0x00001041
	ckmECDSASHA1         ckULong = 0x00001042
	ckmECDSASHA256       ckULong = 0x00001044
	ckmECDSASHA384       ckULong = 0x00001045
	ckmECDSASHA512       ckULong = 0x00001046
)

// ---- OAEP / MGF 常量 ----

const (
	ckzDataSpecified ckULong = 0x00000001

	ckgMGF1SHA1   ckULong = 0x00000001
	ckgMGF1SHA256 ckULong = 0x00000002
	ckgMGF1SHA384 ckULong = 0x00000003
	ckgMGF1SHA512 ckULong = 0x00000004
)

// ckRVText 返回常见错误码的中文说明。
func ckRVText(rv ckULong) string {
	switch rv {
	case ckrOK:
		return "成功"
	case ckrHostMemory:
		return "主机内存不足"
	case ckrSlotIDInvalid:
		return "槽位 ID 无效"
	case ckrGeneralError:
		return "通用错误"
	case ckrFunctionFailed:
		return "函数执行失败"
	case ckrArgumentsBad:
		return "参数错误"
	case ckrAttributeReadOnly:
		return "属性只读"
	case ckrAttributeSensitive:
		return "属性敏感不可读"
	case ckrAttributeTypeInvalid:
		return "属性类型无效"
	case ckrAttributeValueInvalid:
		return "属性值无效"
	case ckrActionProhibited:
		return "设备禁止该操作"
	case ckrDataInvalid:
		return "输入数据无效"
	case ckrDataLenRange:
		return "输入数据长度不合法"
	case ckrDeviceError:
		return "设备错误"
	case ckrDeviceMemory:
		return "设备内存不足"
	case ckrDeviceRemoved:
		return "设备已移除"
	case ckrEncryptedDataInvalid:
		return "密文无效"
	case ckrEncryptedDataLenRange:
		return "密文长度不合法"
	case ckrFunctionNotSupported:
		return "设备不支持该功能"
	case ckrKeyHandleInvalid:
		return "密钥句柄无效"
	case ckrKeySizeRange:
		return "密钥长度超出设备范围"
	case ckrKeyTypeInconsistent:
		return "密钥类型与机制不匹配"
	case ckrKeyFunctionNotPermitted:
		return "密钥用途不允许该操作"
	case ckrKeyUnextractable:
		return "密钥不可导出"
	case ckrMechanismInvalid:
		return "设备不支持该机制"
	case ckrMechanismParamInvalid:
		return "机制参数无效"
	case ckrObjectHandleInvalid:
		return "对象句柄无效"
	case ckrOperationActive:
		return "上一个操作尚未结束"
	case ckrOperationNotInitialized:
		return "操作未初始化"
	case ckrPinIncorrect:
		return "PIN 错误"
	case ckrPinInvalid:
		return "PIN 无效"
	case ckrPinLenRange:
		return "PIN 长度不合法"
	case ckrPinExpired:
		return "PIN 已过期"
	case ckrPinLocked:
		return "PIN 已锁定"
	case ckrSessionClosed:
		return "会话已关闭"
	case ckrSessionCount:
		return "会话数超限"
	case ckrSessionHandleInvalid:
		return "会话句柄无效"
	case ckrSessionReadOnly:
		return "会话为只读"
	case ckrSignatureInvalid:
		return "签名无效"
	case ckrSignatureLenRange:
		return "签名长度不合法"
	case ckrTemplateIncomplete:
		return "属性模板缺少必需项"
	case ckrTemplateInconsistent:
		return "属性模板存在冲突"
	case ckrTokenNotPresent:
		return "未检测到令牌（请插入设备）"
	case ckrTokenNotRecognized:
		return "令牌无法识别"
	case ckrTokenWriteProtected:
		return "令牌写保护"
	case ckrUserAlreadyLoggedIn:
		return "用户已登录"
	case ckrUserNotLoggedIn:
		return "用户未登录"
	case ckrUserPinNotInitialized:
		return "用户 PIN 未初始化"
	case ckrUserTypeInvalid:
		return "用户类型无效"
	case ckrCryptokiNotInitialized:
		return "Cryptoki 未初始化"
	case ckrCryptokiAlreadyInit:
		return "Cryptoki 已初始化"
	default:
		return "未知错误"
	}
}
