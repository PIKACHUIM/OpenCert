//go:build !windows

package pkcs11

// ckULong 对应 PKCS#11 的 CK_ULONG。
// LP64 平台（Linux/macOS）上 CK_ULONG 是 unsigned long（8 字节）。
type ckULong = uint64

// ckFlags 对应 CK_FLAGS。
type ckFlags = uint64
