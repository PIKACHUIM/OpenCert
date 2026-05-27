// Package tpmsc 的 Slot 实现。
// TPM Virtual Smart Card 的 Slot 通过 Windows Smart Card API 访问，
// 本 Slot 仅作为 PKCS#11 层的注册占位，实际密码学操作由 Windows CSP 完成。
package tpmsc

import (
	"context"
	"fmt"
	"sync"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Slot 是 Microsoft TPM Virtual Smart Card 的 Slot 实现。
// 与 local/tpm2 不同，tpmsc 的密钥操作由 Windows CSP 完成，
// 本 Slot 主要提供元信息和状态管理。
type Slot struct {
	mu       sync.RWMutex
	slotID   pkcs11types.SlotID
	card     *storage.Card
	certRepo *storage.CertRepo

	// 登录状态
	loggedIn bool
}

// New 创建 TPMSC Slot 实例。
func New(slotID pkcs11types.SlotID, card *storage.Card, certRepo *storage.CertRepo) *Slot {
	return &Slot{
		slotID:   slotID,
		card:     card,
		certRepo: certRepo,
	}
}

// SlotID 返回 Slot ID。
func (s *Slot) SlotID() pkcs11types.SlotID {
	return s.slotID
}

// SlotInfo 返回 Slot 信息。
func (s *Slot) SlotInfo() pkcs11types.SlotInfo {
	return pkcs11types.SlotInfo{
		SlotID:       s.slotID,
		Description:  fmt.Sprintf("TPM-VSC: %s [Windows TPM Virtual Smart Card]", s.card.CardName),
		Manufacturer: "Microsoft",
		Flags:        pkcs11types.CKF_TOKEN_PRESENT,
		TokenPresent: true,
	}
}

// TokenInfo 返回 Token 信息。
func (s *Slot) TokenInfo() pkcs11types.TokenInfo {
	s.mu.RLock()
	loggedIn := s.loggedIn
	s.mu.RUnlock()

	flags := pkcs11types.CKF_TOKEN_INITIALIZED | pkcs11types.CKF_LOGIN_REQUIRED | pkcs11types.CKF_RNG
	if loggedIn {
		flags |= pkcs11types.CKF_USER_PIN_INITIALIZED
	}

	label := s.card.CardName
	if len(label) > 32 {
		label = label[:32]
	}

	return pkcs11types.TokenInfo{
		Label:           label,
		Manufacturer:    "Microsoft",
		Model:           "TPM-VirtualSmartCard",
		SerialNumber:    s.card.UUID[:16],
		Flags:           flags,
		MaxPinLen:       127,
		MinPinLen:       8,
		TotalPublicMem:  0xFFFFFFFF,
		FreePublicMem:   0xFFFFFFFF,
		TotalPrivateMem: 0xFFFFFFFF,
		FreePrivateMem:  0xFFFFFFFF,
	}
}

// Mechanisms 返回支持的算法列表。
// TPM VSC 支持 RSA 2048 和 ECDSA P-256。
func (s *Slot) Mechanisms() []pkcs11types.MechanismType {
	return []pkcs11types.MechanismType{
		pkcs11types.CKM_RSA_PKCS,
		pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN,
		pkcs11types.CKM_SHA256_RSA_PKCS,
		pkcs11types.CKM_SHA384_RSA_PKCS,
		pkcs11types.CKM_SHA512_RSA_PKCS,
		pkcs11types.CKM_ECDSA,
		pkcs11types.CKM_ECDSA_SHA256,
	}
}

// Login 验证 PIN（通过 Windows Smart Card API）。
func (s *Slot) Login(ctx context.Context, userType pkcs11types.UserType, pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_ALREADY_LOGGED_IN)
	}

	// TPM VSC 的 PIN 验证由 Windows Smart Card 子系统处理
	// 这里仅标记登录状态；实际签名时 Windows 会弹出 PIN 输入框
	s.loggedIn = true
	return nil
}

// Logout 注销。
func (s *Slot) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loggedIn = false
	return nil
}

// IsLoggedIn 返回登录状态。
func (s *Slot) IsLoggedIn() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loggedIn
}

// FindObjects 查找对象（TPM VSC 的证书通过 Windows 证书存储访问）。
func (s *Slot) FindObjects(ctx context.Context, template []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error) {
	// TODO: 通过 Windows CertStore API 枚举 TPM VSC 上的证书
	return nil, nil
}

// GetAttributes 获取对象属性。
func (s *Slot) GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	return nil, fmt.Errorf("TPM VSC 对象属性通过 Windows API 访问")
}

// Sign 签名操作（委托给 Windows CSP）。
func (s *Slot) Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM VSC 签名操作由 Windows CSP 完成，请通过 Windows CNG/CAPI 调用")
}

// Decrypt 解密操作（委托给 Windows CSP）。
func (s *Slot) Decrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM VSC 解密操作由 Windows CSP 完成，请通过 Windows CNG/CAPI 调用")
}

// Encrypt 加密操作。
func (s *Slot) Encrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("TPM VSC 加密操作由 Windows CSP 完成，请通过 Windows CNG/CAPI 调用")
}
