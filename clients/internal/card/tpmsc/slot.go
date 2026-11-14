// Package tpmsc 提供 Windows TPM Virtual Smart Card 的 fail-closed PKCS#11 Slot。
// 由于 Smart Card/CNG/CAPI provider 尚未接入，此 Slot 不声明 token 或算法能力。
package tpmsc

import (
	"context"
	"fmt"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Slot 是尚未接入 Windows TPM VSC 密码学 Provider 的占位实现。
type Slot struct {
	slotID pkcs11types.SlotID
	card   *storage.Card
}

// New 创建 TPMSC Slot 实例。该 Slot 不提供密码学能力。
func New(slotID pkcs11types.SlotID, card *storage.Card, _ *storage.CertRepo) *Slot {
	return &Slot{slotID: slotID, card: card}
}

// SlotID 返回 Slot ID。
func (s *Slot) SlotID() pkcs11types.SlotID {
	return s.slotID
}

// SlotInfo 返回未检测到可用 token 的 Slot 信息。
func (s *Slot) SlotInfo() pkcs11types.SlotInfo {
	cardName := ""
	if s.card != nil {
		cardName = s.card.CardName
	}
	return pkcs11types.SlotInfo{
		SlotID:       s.slotID,
		Description:  fmt.Sprintf("TPM-VSC: %s [provider unavailable]", cardName),
		Manufacturer: "Microsoft",
	}
}

// TokenInfo 返回零值信息，因为此 Slot 尚未连接实际 Token。
func (s *Slot) TokenInfo() pkcs11types.TokenInfo { return pkcs11types.TokenInfo{} }

// Mechanisms 返回空列表；VSC 密码学 Provider 尚未实现。
func (s *Slot) Mechanisms() []pkcs11types.MechanismType { return nil }

// unsupported 返回 PKCS#11 标准未实现错误，避免对调用方伪报成功。
func unsupported() error {
	return fmt.Errorf("%w: Windows TPM VSC provider 尚未接入", pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
}

// Login 在 PIN 校验能力接入前拒绝登录。
func (s *Slot) Login(_ context.Context, _ pkcs11types.UserType, _ string) error {
	return unsupported()
}

// Logout 在认证会话能力接入前拒绝注销操作。
func (s *Slot) Logout(_ context.Context) error { return unsupported() }

// IsLoggedIn 在 Provider 未实现时始终返回 false。
func (s *Slot) IsLoggedIn() bool { return false }

// FindObjects 在 Windows 证书枚举接入前拒绝查询。
func (s *Slot) FindObjects(_ context.Context, _ []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error) {
	return nil, unsupported()
}

// GetAttributes 在对象属性访问接入前拒绝查询。
func (s *Slot) GetAttributes(_ context.Context, _ pkcs11types.ObjectHandle, _ []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	return nil, unsupported()
}

// Sign 在 Windows CNG/CAPI Provider 接入前拒绝签名。
func (s *Slot) Sign(_ context.Context, _ pkcs11types.ObjectHandle, _ pkcs11types.Mechanism, _ []byte) ([]byte, error) {
	return nil, unsupported()
}

// Decrypt 在 Windows CNG/CAPI Provider 接入前拒绝解密。
func (s *Slot) Decrypt(_ context.Context, _ pkcs11types.ObjectHandle, _ pkcs11types.Mechanism, _ []byte) ([]byte, error) {
	return nil, unsupported()
}

// Encrypt 在对象与机制能力接入前拒绝加密。
func (s *Slot) Encrypt(_ context.Context, _ pkcs11types.ObjectHandle, _ pkcs11types.Mechanism, _ []byte) ([]byte, error) {
	return nil, unsupported()
}
