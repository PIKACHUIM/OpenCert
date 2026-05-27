// Package pkcs11types 定义 PKCS#11 标准的 Go 类型映射。
// 对应 PKCS#11 v3.1 规范中的核心数据类型。
package pkcs11types

import "fmt"

// ---- 基础类型 ----

// CKRv 是 PKCS#11 函数返回值类型（CK_RV）。
type CKRv uint32

// PKCS#11 标准返回码。
const (
	CKR_OK                          CKRv = 0x00000000
	CKR_CANCEL                      CKRv = 0x00000001
	CKR_HOST_MEMORY                 CKRv = 0x00000002
	CKR_SLOT_ID_INVALID             CKRv = 0x00000003
	CKR_GENERAL_ERROR               CKRv = 0x00000005
	CKR_FUNCTION_FAILED             CKRv = 0x00000006
	CKR_ARGUMENTS_BAD               CKRv = 0x00000007
	CKR_NO_EVENT                    CKRv = 0x00000008
	CKR_NEED_TO_CREATE_THREADS      CKRv = 0x00000009
	CKR_CANT_LOCK                   CKRv = 0x0000000A
	CKR_ATTRIBUTE_READ_ONLY         CKRv = 0x00000010
	CKR_ATTRIBUTE_SENSITIVE         CKRv = 0x00000011
	CKR_ATTRIBUTE_TYPE_INVALID      CKRv = 0x00000012
	CKR_ATTRIBUTE_VALUE_INVALID     CKRv = 0x00000013
	CKR_DATA_INVALID                CKRv = 0x00000020
	CKR_DATA_LEN_RANGE              CKRv = 0x00000021
	CKR_DEVICE_ERROR                CKRv = 0x00000030
	CKR_DEVICE_MEMORY               CKRv = 0x00000031
	CKR_DEVICE_REMOVED              CKRv = 0x00000032
	CKR_ENCRYPTED_DATA_INVALID      CKRv = 0x00000040
	CKR_ENCRYPTED_DATA_LEN_RANGE    CKRv = 0x00000041
	CKR_FUNCTION_CANCELED           CKRv = 0x00000050
	CKR_FUNCTION_NOT_PARALLEL       CKRv = 0x00000051
	CKR_FUNCTION_NOT_SUPPORTED      CKRv = 0x00000054
	CKR_KEY_HANDLE_INVALID          CKRv = 0x00000060
	CKR_KEY_SIZE_RANGE              CKRv = 0x00000062
	CKR_KEY_TYPE_INCONSISTENT       CKRv = 0x00000063
	CKR_KEY_NOT_NEEDED              CKRv = 0x00000064
	CKR_KEY_CHANGED                 CKRv = 0x00000065
	CKR_KEY_NEEDED                  CKRv = 0x00000066
	CKR_KEY_INDIGESTIBLE            CKRv = 0x00000067
	CKR_KEY_FUNCTION_NOT_PERMITTED  CKRv = 0x00000068
	CKR_KEY_NOT_WRAPPABLE           CKRv = 0x00000069
	CKR_KEY_UNEXTRACTABLE           CKRv = 0x0000006A
	CKR_MECHANISM_INVALID           CKRv = 0x00000070
	CKR_MECHANISM_PARAM_INVALID     CKRv = 0x00000071
	CKR_OBJECT_HANDLE_INVALID       CKRv = 0x00000082
	CKR_OPERATION_ACTIVE            CKRv = 0x00000090
	CKR_OPERATION_NOT_INITIALIZED   CKRv = 0x00000091
	CKR_PIN_INCORRECT               CKRv = 0x000000A0
	CKR_PIN_INVALID                 CKRv = 0x000000A1
	CKR_PIN_LEN_RANGE               CKRv = 0x000000A2
	CKR_PIN_EXPIRED                 CKRv = 0x000000A3
	CKR_PIN_LOCKED                  CKRv = 0x000000A4
	CKR_SESSION_CLOSED              CKRv = 0x000000B0
	CKR_SESSION_COUNT               CKRv = 0x000000B1
	CKR_SESSION_HANDLE_INVALID      CKRv = 0x000000B3
	CKR_SESSION_PARALLEL_NOT_SUPPORTED CKRv = 0x000000B4
	CKR_SESSION_READ_ONLY           CKRv = 0x000000B5
	CKR_SESSION_EXISTS              CKRv = 0x000000B6
	CKR_SESSION_READ_ONLY_EXISTS    CKRv = 0x000000B7
	CKR_SESSION_READ_WRITE_SO_EXISTS CKRv = 0x000000B8
	CKR_SIGNATURE_INVALID           CKRv = 0x000000C0
	CKR_SIGNATURE_LEN_RANGE         CKRv = 0x000000C1
	CKR_TEMPLATE_INCOMPLETE         CKRv = 0x000000D0
	CKR_TEMPLATE_INCONSISTENT       CKRv = 0x000000D1
	CKR_TOKEN_NOT_PRESENT           CKRv = 0x000000E0
	CKR_TOKEN_NOT_RECOGNIZED        CKRv = 0x000000E1
	CKR_TOKEN_WRITE_PROTECTED       CKRv = 0x000000E2
	CKR_UNWRAPPING_KEY_HANDLE_INVALID CKRv = 0x000000F0
	CKR_UNWRAPPING_KEY_SIZE_RANGE   CKRv = 0x000000F1
	CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT CKRv = 0x000000F2
	CKR_USER_ALREADY_LOGGED_IN      CKRv = 0x00000100
	CKR_USER_NOT_LOGGED_IN          CKRv = 0x00000101
	CKR_USER_PIN_NOT_INITIALIZED    CKRv = 0x00000102
	CKR_USER_TYPE_INVALID           CKRv = 0x00000103
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN CKRv = 0x00000104
	CKR_USER_TOO_MANY_TYPES         CKRv = 0x00000105
	CKR_WRAPPED_KEY_INVALID         CKRv = 0x00000110
	CKR_WRAPPED_KEY_LEN_RANGE       CKRv = 0x00000112
	CKR_WRAPPING_KEY_HANDLE_INVALID CKRv = 0x00000113
	CKR_WRAPPING_KEY_SIZE_RANGE     CKRv = 0x00000114
	CKR_WRAPPING_KEY_TYPE_INCONSISTENT CKRv = 0x00000115
	CKR_RANDOM_SEED_NOT_SUPPORTED   CKRv = 0x00000120
	CKR_RANDOM_NO_RNG               CKRv = 0x00000121
	CKR_DOMAIN_PARAMS_INVALID       CKRv = 0x00000130
	CKR_BUFFER_TOO_SMALL            CKRv = 0x00000150
	CKR_SAVED_STATE_INVALID         CKRv = 0x00000160
	CKR_INFORMATION_SENSITIVE       CKRv = 0x00000170
	CKR_STATE_UNSAVEABLE            CKRv = 0x00000180
	CKR_CRYPTOKI_NOT_INITIALIZED    CKRv = 0x00000190
	CKR_CRYPTOKI_ALREADY_INITIALIZED CKRv = 0x00000191
	CKR_MUTEX_BAD                   CKRv = 0x000001A0
	CKR_MUTEX_NOT_LOCKED            CKRv = 0x000001A1
	CKR_VENDOR_DEFINED              CKRv = 0x80000000
)

// Error 实现 error 接口，方便在 Go 代码中使用。
func (rv CKRv) Error() string {
	if name, ok := rvNames[rv]; ok {
		return name
	}
	return fmt.Sprintf("CKR_UNKNOWN(0x%08X)", uint32(rv))
}

// rvNames 是返回码到名称的映射表。
var rvNames = map[CKRv]string{
	CKR_OK:                       "CKR_OK",
	CKR_CANCEL:                   "CKR_CANCEL",
	CKR_HOST_MEMORY:              "CKR_HOST_MEMORY",
	CKR_SLOT_ID_INVALID:          "CKR_SLOT_ID_INVALID",
	CKR_GENERAL_ERROR:            "CKR_GENERAL_ERROR",
	CKR_FUNCTION_FAILED:          "CKR_FUNCTION_FAILED",
	CKR_ARGUMENTS_BAD:            "CKR_ARGUMENTS_BAD",
	CKR_PIN_INCORRECT:            "CKR_PIN_INCORRECT",
	CKR_PIN_INVALID:              "CKR_PIN_INVALID",
	CKR_PIN_LEN_RANGE:            "CKR_PIN_LEN_RANGE",
	CKR_PIN_EXPIRED:              "CKR_PIN_EXPIRED",
	CKR_PIN_LOCKED:               "CKR_PIN_LOCKED",
	CKR_SESSION_HANDLE_INVALID:   "CKR_SESSION_HANDLE_INVALID",
	CKR_SESSION_CLOSED:           "CKR_SESSION_CLOSED",
	CKR_USER_NOT_LOGGED_IN:       "CKR_USER_NOT_LOGGED_IN",
	CKR_USER_ALREADY_LOGGED_IN:   "CKR_USER_ALREADY_LOGGED_IN",
	CKR_TOKEN_NOT_PRESENT:        "CKR_TOKEN_NOT_PRESENT",
	CKR_OBJECT_HANDLE_INVALID:    "CKR_OBJECT_HANDLE_INVALID",
	CKR_MECHANISM_INVALID:        "CKR_MECHANISM_INVALID",
	CKR_SIGNATURE_INVALID:        "CKR_SIGNATURE_INVALID",
	CKR_BUFFER_TOO_SMALL:         "CKR_BUFFER_TOO_SMALL",
	CKR_FUNCTION_NOT_SUPPORTED:   "CKR_FUNCTION_NOT_SUPPORTED",
	CKR_CRYPTOKI_NOT_INITIALIZED: "CKR_CRYPTOKI_NOT_INITIALIZED",
	CKR_VENDOR_DEFINED:                     "CKR_VENDOR_DEFINED",
	CKR_OPERATION_ACTIVE:                   "CKR_OPERATION_ACTIVE",
	CKR_OPERATION_NOT_INITIALIZED:          "CKR_OPERATION_NOT_INITIALIZED",
	CKR_SESSION_READ_ONLY:                  "CKR_SESSION_READ_ONLY",
	CKR_SESSION_EXISTS:                     "CKR_SESSION_EXISTS",
	CKR_SESSION_READ_ONLY_EXISTS:           "CKR_SESSION_READ_ONLY_EXISTS",
	CKR_SESSION_READ_WRITE_SO_EXISTS:       "CKR_SESSION_READ_WRITE_SO_EXISTS",
	CKR_USER_TYPE_INVALID:                  "CKR_USER_TYPE_INVALID",
	CKR_USER_ANOTHER_ALREADY_LOGGED_IN:     "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
	CKR_USER_PIN_NOT_INITIALIZED:           "CKR_USER_PIN_NOT_INITIALIZED",
	CKR_DEVICE_REMOVED:                     "CKR_DEVICE_REMOVED",
	CKR_DEVICE_ERROR:                       "CKR_DEVICE_ERROR",
	CKR_CANT_LOCK:                          "CKR_CANT_LOCK",
}

// ---- Slot / Token 类型 ----

// SlotID 是 PKCS#11 Slot 标识符。
type SlotID uint32

// SessionHandle 是 PKCS#11 会话句柄。
type SessionHandle uint32

// ObjectHandle 是 PKCS#11 对象句柄。
type ObjectHandle uint32

// MechanismType 是 PKCS#11 算法类型。
type MechanismType uint32

// 常用算法类型。
const (
	CKM_RSA_PKCS           MechanismType = 0x00000001
	CKM_RSA_PKCS_OAEP      MechanismType = 0x00000009
	CKM_RSA_PKCS_PSS       MechanismType = 0x0000000D
	CKM_SHA1_RSA_PKCS      MechanismType = 0x00000006
	CKM_SHA256_RSA_PKCS    MechanismType = 0x00000040
	CKM_SHA384_RSA_PKCS    MechanismType = 0x00000041
	CKM_SHA512_RSA_PKCS    MechanismType = 0x00000042
	CKM_SHA256_RSA_PKCS_PSS MechanismType = 0x00000043
	CKM_ECDSA              MechanismType = 0x00001041
	CKM_ECDSA_SHA256       MechanismType = 0x00001044
	CKM_ECDSA_SHA384       MechanismType = 0x00001045
	CKM_ECDSA_SHA512       MechanismType = 0x00001046
	CKM_AES_CBC            MechanismType = 0x00001082
	CKM_AES_GCM            MechanismType = 0x00001087
	CKM_SHA_1              MechanismType = 0x00000220
	CKM_SHA256             MechanismType = 0x00000250
	CKM_SHA384             MechanismType = 0x00000260
	CKM_SHA512             MechanismType = 0x00000270

	// 扩展算法类型
	CKM_RSA_PKCS_KEY_PAIR_GEN MechanismType = 0x00000000
	CKM_SHA1_RSA_PKCS_PSS    MechanismType = 0x0000000E
	CKM_SHA384_RSA_PKCS_PSS  MechanismType = 0x00000044
	CKM_SHA512_RSA_PKCS_PSS  MechanismType = 0x00000045
	CKM_EC_KEY_PAIR_GEN      MechanismType = 0x00001040
	CKM_EDDSA                MechanismType = 0x00001057 // Ed25519/Ed448
	CKM_SHA3_256             MechanismType = 0x000002B0
	CKM_SHA3_384             MechanismType = 0x000002C0
	CKM_SHA3_512             MechanismType = 0x000002D0
	CKM_MD5                  MechanismType = 0x00000210
	CKM_CHACHA20_POLY1305    MechanismType = 0x00004021
	// 国密算法
	CKM_SM2_KEY_PAIR_GEN     MechanismType = 0x80000201
	CKM_SM2                  MechanismType = 0x80000202
	CKM_SM3                  MechanismType = 0x80000210
	CKM_SM4_CBC              MechanismType = 0x80000221
	CKM_SM4_GCM              MechanismType = 0x80000222
)

// AttributeType 是 PKCS#11 属性类型。
type AttributeType uint32

// 常用属性类型。
const (
	CKA_CLASS              AttributeType = 0x00000000
	CKA_TOKEN              AttributeType = 0x00000001
	CKA_PRIVATE            AttributeType = 0x00000002
	CKA_LABEL              AttributeType = 0x00000003
	CKA_APPLICATION        AttributeType = 0x00000010
	CKA_VALUE              AttributeType = 0x00000011
	CKA_OBJECT_ID          AttributeType = 0x00000012
	CKA_CERTIFICATE_TYPE   AttributeType = 0x00000080
	CKA_ISSUER             AttributeType = 0x00000081
	CKA_SERIAL_NUMBER      AttributeType = 0x00000082
	CKA_AC_ISSUER          AttributeType = 0x00000083
	CKA_OWNER              AttributeType = 0x00000084
	CKA_ATTR_TYPES         AttributeType = 0x00000085
	CKA_TRUSTED            AttributeType = 0x00000086
	CKA_KEY_TYPE           AttributeType = 0x00000100
	CKA_SUBJECT            AttributeType = 0x00000101
	CKA_ID                 AttributeType = 0x00000102
	CKA_SENSITIVE          AttributeType = 0x00000103
	CKA_ENCRYPT            AttributeType = 0x00000104
	CKA_DECRYPT            AttributeType = 0x00000105
	CKA_WRAP               AttributeType = 0x00000106
	CKA_UNWRAP             AttributeType = 0x00000107
	CKA_SIGN               AttributeType = 0x00000108
	CKA_SIGN_RECOVER       AttributeType = 0x00000109
	CKA_VERIFY             AttributeType = 0x0000010A
	CKA_VERIFY_RECOVER     AttributeType = 0x0000010B
	CKA_DERIVE             AttributeType = 0x0000010C
	CKA_START_DATE         AttributeType = 0x00000110
	CKA_END_DATE           AttributeType = 0x00000111
	CKA_MODULUS            AttributeType = 0x00000120
	CKA_MODULUS_BITS       AttributeType = 0x00000121
	CKA_PUBLIC_EXPONENT    AttributeType = 0x00000122
	CKA_PRIVATE_EXPONENT   AttributeType = 0x00000123
	CKA_EC_PARAMS          AttributeType = 0x00000180
	CKA_EC_POINT           AttributeType = 0x00000181
	CKA_EXTRACTABLE        AttributeType = 0x00000162
	CKA_LOCAL              AttributeType = 0x00000163
	CKA_PUBLIC_KEY_INFO    AttributeType = 0x00000129
	CKA_NEVER_EXTRACTABLE  AttributeType = 0x00000164
	CKA_ALWAYS_SENSITIVE   AttributeType = 0x00000165
	CKA_KEY_GEN_MECHANISM  AttributeType = 0x00000166
	CKA_MODIFIABLE         AttributeType = 0x00000170
	CKA_COPYABLE           AttributeType = 0x00000171
	CKA_DESTROYABLE        AttributeType = 0x00000172
	CKA_EC_PARAMS_OID      AttributeType = 0x00000180
)

// ObjectClass 是 PKCS#11 对象类型。
type ObjectClass uint32

const (
	CKO_DATA              ObjectClass = 0x00000000
	CKO_CERTIFICATE       ObjectClass = 0x00000001
	CKO_PUBLIC_KEY        ObjectClass = 0x00000002
	CKO_PRIVATE_KEY       ObjectClass = 0x00000003
	CKO_SECRET_KEY        ObjectClass = 0x00000004
	CKO_HW_FEATURE        ObjectClass = 0x00000005
	CKO_DOMAIN_PARAMETERS ObjectClass = 0x00000006
	CKO_MECHANISM         ObjectClass = 0x00000007
)

// UserType 是 PKCS#11 用户类型。
type UserType uint32

const (
	CKU_SO   UserType = 0 // 安全官员
	CKU_USER UserType = 1 // 普通用户
)

// SessionState 是 PKCS#11 会话状态。
type SessionState uint32

const (
	CKS_RO_PUBLIC_SESSION  SessionState = 0
	CKS_RO_USER_FUNCTIONS  SessionState = 1
	CKS_RW_PUBLIC_SESSION  SessionState = 2
	CKS_RW_USER_FUNCTIONS  SessionState = 3
	CKS_RW_SO_FUNCTIONS    SessionState = 4
)

// Attribute 是 PKCS#11 属性（类型+值）。
type Attribute struct {
	Type  AttributeType `json:"type"`
	Value []byte        `json:"value"`
}

// Mechanism 是 PKCS#11 算法参数。
type Mechanism struct {
	Type      MechanismType `json:"type"`
	Parameter []byte        `json:"parameter,omitempty"`
}

// SlotInfo 是 Slot 信息结构。
type SlotInfo struct {
	SlotID      SlotID `json:"slot_id"`
	Description string `json:"description"`
	Manufacturer string `json:"manufacturer"`
	Flags       uint32 `json:"flags"`
	TokenPresent bool  `json:"token_present"`
}

// TokenInfo 是 Token 信息结构。
type TokenInfo struct {
	Label          string `json:"label"`
	Manufacturer   string `json:"manufacturer"`
	Model          string `json:"model"`
	SerialNumber   string `json:"serial_number"`
	Flags          uint32 `json:"flags"`
	MaxPinLen      uint32 `json:"max_pin_len"`
	MinPinLen      uint32 `json:"min_pin_len"`
	TotalPublicMem uint32 `json:"total_public_mem"`
	FreePublicMem  uint32 `json:"free_public_mem"`
	TotalPrivateMem uint32 `json:"total_private_mem"`
	FreePrivateMem uint32 `json:"free_private_mem"`
}

// Token 标志位。
const (
	CKF_RNG                  uint32 = 0x00000001
	CKF_WRITE_PROTECTED      uint32 = 0x00000002
	CKF_LOGIN_REQUIRED       uint32 = 0x00000004
	CKF_USER_PIN_INITIALIZED uint32 = 0x00000008
	CKF_TOKEN_INITIALIZED    uint32 = 0x00000400
	CKF_TOKEN_PRESENT        uint32 = 0x00000001 // Slot 标志
	CKF_REMOVABLE_DEVICE     uint32 = 0x00000002 // Slot 标志
	CKF_HW_SLOT              uint32 = 0x00000004 // Slot 标志
)

// Session 标志位。
const (
	CKF_RW_SESSION      uint32 = 0x00000002
	CKF_SERIAL_SESSION  uint32 = 0x00000004
)
