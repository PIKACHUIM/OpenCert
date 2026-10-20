//go:build !windows

package tpm

import "fmt"

// unsupportedImpl 是非 Windows 平台的占位实现。
//
// Linux 上的 TPM 支持建议通过 PKCS#11 驱动接入（tpm2-pkcs11 模块），
// 这样无需为每个发行版维护不同的 TPM 栈（tpm2-tss / dev/tpmrm0 等）。
type unsupportedImpl struct{}

func newTPMImpl() tpmImpl { return &unsupportedImpl{} }

func (u *unsupportedImpl) Open(bool) error {
	return fmt.Errorf("当前平台（非 Windows）尚未内置 TPM 后端；" +
		"请在存储区域中选择 PKCS#11 驱动并指向 tpm2-pkcs11 模块（libtpm2_pkcs11.so）")
}

func (u *unsupportedImpl) Detail() string { return "平台不支持" }

func (u *unsupportedImpl) Health() error { return fmt.Errorf("平台不支持") }

func (u *unsupportedImpl) Close() error { return nil }

func (u *unsupportedImpl) Delete(string) error { return fmt.Errorf("平台不支持") }

func (u *unsupportedImpl) PublicKeyDER(string) ([]byte, error) {
	return nil, fmt.Errorf("平台不支持")
}

func (u *unsupportedImpl) CreateKey(string, string, bool) (string, []byte, error) {
	return "", nil, fmt.Errorf("平台不支持")
}

func (u *unsupportedImpl) Sign(string, signScheme, []byte, string) ([]byte, error) {
	return nil, fmt.Errorf("平台不支持")
}

func (u *unsupportedImpl) Decrypt(string, []byte, bool) ([]byte, error) {
	return nil, fmt.Errorf("平台不支持")
}
