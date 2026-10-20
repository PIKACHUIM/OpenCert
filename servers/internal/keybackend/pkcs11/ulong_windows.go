//go:build windows

package pkcs11

// ckULong 对应 PKCS#11 的 CK_ULONG。
// Windows 上 CK_ULONG 是 unsigned long（4 字节），与 LP64 平台不同。
type ckULong = uint32

// ckFlags 对应 CK_FLAGS。
type ckFlags = uint32
