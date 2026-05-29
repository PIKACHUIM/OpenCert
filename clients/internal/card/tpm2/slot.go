// Package tpm2 实现 TPM2/Secure Enclave 智能卡 Slot。
// 在 Local Slot 基础上，增加 TPM 绑定：主密钥被 TPM Seal 保护。
//
// 加密层次：
//
//	用户密码
//	    │
//	    ▼ HMAC(password, salt) → AES-256-GCM
//	卡片主密钥 (32字节)
//	    │
//	    ▼ TPM Seal（绑定到当前设备）
//	TPM 封装的主密钥 blob（存储在 tpm_private_blob 字段）
//	    │
//	    ▼ HMAC(masterKey, salt) → AES-256-GCM
//	临时密钥
//	    │
//	    ▼ AES-256-GCM
//	私钥 DER 数据
package tpm2

import (
	"context"
	"fmt"
	"sync"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"

	// 复用 local slot 的签名/解密/属性逻辑
	"github.com/globaltrusts/client-card/internal/card/local"
)

// Slot 是 TPM2 智能卡的 Slot 实现。
// 复用 local.Slot 的大部分逻辑，重写 unlockMasterKey。
type Slot struct {
	mu       sync.RWMutex
	slotID   pkcs11types.SlotID
	card     *storage.Card
	certRepo *storage.CertRepo
	tpmProv  tpm.Provider

	// 登录状态
	loggedIn  bool
	masterKey []byte

	// 委托给 local.Slot 处理签名/解密/属性等操作
	localSlot *local.Slot
}

// New 创建 TPM2 Slot 实例。
func New(slotID pkcs11types.SlotID, card *storage.Card, certRepo *storage.CertRepo, tpmProv tpm.Provider) *Slot {
	localSlot := local.New(slotID, card, certRepo)
	return &Slot{
		slotID:    slotID,
		card:      card,
		certRepo:  certRepo,
		tpmProv:   tpmProv,
		localSlot: localSlot,
	}
}

// SlotID 返回 Slot ID。
func (s *Slot) SlotID() pkcs11types.SlotID {
	return s.slotID
}

// SlotInfo 返回 Slot 信息（标注 TPM2）。
func (s *Slot) SlotInfo() pkcs11types.SlotInfo {
	return pkcs11types.SlotInfo{
		SlotID:       s.slotID,
		Description:  fmt.Sprintf("TPM2 Card: %s [%s]", s.card.CardName, s.tpmProv.PlatformName()),
		Manufacturer: "GlobalTrusts",
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
		Manufacturer:    "GlobalTrusts",
		Model:           fmt.Sprintf("TPM2Card-%s", s.tpmProv.PlatformName()),
		SerialNumber:    s.card.UUID[:16],
		Flags:           flags,
		MaxPinLen:       64,
		MinPinLen:       4,
		TotalPublicMem:  0xFFFFFFFF,
		FreePublicMem:   0xFFFFFFFF,
		TotalPrivateMem: 0xFFFFFFFF,
		FreePrivateMem:  0xFFFFFFFF,
	}
}

// Mechanisms 返回支持的算法列表（与 local slot 相同）。
func (s *Slot) Mechanisms() []pkcs11types.MechanismType {
	return s.localSlot.Mechanisms()
}

// Login 验证卡片密码，通过 TPM Unseal 解锁主密钥。
func (s *Slot) Login(ctx context.Context, userType pkcs11types.UserType, pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_ALREADY_LOGGED_IN)
	}

	masterKey, err := s.unlockMasterKey(pin)
	if err != nil {
		return fmt.Errorf("%w: %v", pkcs11types.CKR_PIN_INCORRECT, err)
	}

	// 将主密钥注入 local slot，复用其 loadObjects 逻辑
	if err := s.localSlot.LoginWithMasterKey(ctx, masterKey); err != nil {
		zeroBytes(masterKey)
		return fmt.Errorf("加载证书对象失败: %w", err)
	}

	s.masterKey = masterKey
	s.loggedIn = true
	return nil
}

// Logout 注销，清除主密钥。
func (s *Slot) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroBytes(s.masterKey)
	s.masterKey = nil
	s.loggedIn = false
	return s.localSlot.Logout(ctx)
}

// IsLoggedIn 返回登录状态。
func (s *Slot) IsLoggedIn() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loggedIn
}

// FindObjects 委托给 local slot。
func (s *Slot) FindObjects(ctx context.Context, template []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error) {
	return s.localSlot.FindObjects(ctx, template)
}

// GetAttributes 委托给 local slot。
func (s *Slot) GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	return s.localSlot.GetAttributes(ctx, handle, attrs)
}

// Sign 委托给 local slot。
func (s *Slot) Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	return s.localSlot.Sign(ctx, handle, mechanism, data)
}

// Decrypt 委托给 local slot。
func (s *Slot) Decrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error) {
	return s.localSlot.Decrypt(ctx, handle, mechanism, ciphertext)
}

// Encrypt 委托给 local slot。
func (s *Slot) Encrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error) {
	return s.localSlot.Encrypt(ctx, handle, mechanism, plaintext)
}

// MasterKey 返回已解锁的主密钥副本（供 API 层使用）。
func (s *Slot) MasterKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.loggedIn {
		return nil
	}
	cp := make([]byte, len(s.masterKey))
	copy(cp, s.masterKey)
	return cp
}

// ReloadObjects 在已登录状态下重新从数据库加载证书到内存缓存。
func (s *Slot) ReloadObjects(ctx context.Context) error {
	return s.localSlot.ReloadObjects(ctx)
}

// ---- 内部方法 ----

// unlockMasterKey 通过 PIN 解密主密钥，再用 TPM Unseal 验证绑定。
//
// TPM2 卡片的 CardKeyEntry 中：
//   - EncMasterKey 存储的是 TPM Seal 后的主密钥 blob
//   - 先用 HMAC(pin, salt) 解密得到 TPM blob，再 TPM Unseal 得到真正的主密钥
func (s *Slot) unlockMasterKey(pin string) ([]byte, error) {
	pinBytes := []byte(pin)

	for _, entry := range s.card.CardKeys {
		// 1. 用 HMAC(pin, salt) 解密得到 TPM blob
		aesKey := cryptoutil.HMACSHA256(pinBytes, entry.Salt)
		tpmBlob, err := cryptoutil.DecryptAES256GCM(aesKey, entry.EncMasterKey)
		if err != nil {
			continue // 密码不匹配，尝试下一条
		}

		// 2. TPM Unseal 得到真正的主密钥
		masterKey, err := s.tpmProv.Unseal(tpmBlob)
		if err != nil {
			continue // TPM 解封失败（可能是不同设备）
		}

		return masterKey, nil
	}

	return nil, fmt.Errorf("密码错误或 TPM 设备不匹配")
}

// zeroBytes 清零字节切片。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
