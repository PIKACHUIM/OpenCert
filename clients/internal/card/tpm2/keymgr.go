// Package tpm2 - TPM2 密钥管理。
// 在 local.KeyManager 基础上，增加 TPM Seal 保护主密钥。
package tpm2

import (
	"context"
	"fmt"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/google/uuid"
)

// KeyManager 提供 TPM2 卡片的密钥管理操作。
type KeyManager struct {
	certRepo *storage.CertRepo
	cardRepo *storage.CardRepo
	tpmProv  tpm.Provider
	// 复用 local.KeyManager 的密钥生成逻辑
	localMgr *local.KeyManager
}

// NewKeyManager 创建 TPM2 密钥管理器。
func NewKeyManager(certRepo *storage.CertRepo, cardRepo *storage.CardRepo, tpmProv tpm.Provider) *KeyManager {
	return &KeyManager{
		certRepo: certRepo,
		cardRepo: cardRepo,
		tpmProv:  tpmProv,
		localMgr: local.NewKeyManager(certRepo, cardRepo),
	}
}

// CreateCard 创建一张新的 TPM2 智能卡。
// 主密钥先被 TPM Seal，再被 PIN 加密存储。
func (m *KeyManager) CreateCard(ctx context.Context, userUUID, cardName, pin, cardPassword, remark string) (*storage.Card, error) {
	// 1. 生成 32 字节随机主密钥
	masterKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	defer zeroBytes(masterKey)

	// 2. TPM Seal 主密钥
	tpmBlob, err := m.tpmProv.Seal(masterKey)
	if err != nil {
		return nil, fmt.Errorf("TPM Seal 主密钥失败: %w", err)
	}

	card := &storage.Card{
		UUID:     uuid.New().String(),
		SlotType: storage.SlotTypeTPM2,
		CardName: cardName,
		UserUUID: userUUID,
		Remark:   remark,
	}

	// 3. 用 PIN 加密 TPM blob
	pinEntry, err := encryptTPMBlob(tpmBlob, []byte(pin), "pin", "")
	if err != nil {
		return nil, fmt.Errorf("加密 TPM blob（PIN）失败: %w", err)
	}
	card.CardKeys = append(card.CardKeys, *pinEntry)

	// 4. 如果设置了卡片密码，额外加密一份
	if cardPassword != "" {
		cardEntry, err := encryptTPMBlob(tpmBlob, []byte(cardPassword), "card", "")
		if err != nil {
			return nil, fmt.Errorf("加密 TPM blob（卡片密码）失败: %w", err)
		}
		card.CardKeys = append(card.CardKeys, *cardEntry)
	}

	if err := m.cardRepo.Create(ctx, card); err != nil {
		return nil, fmt.Errorf("保存卡片失败: %w", err)
	}

	return card, nil
}

// GenerateKeyPair 在指定 TPM2 卡片中生成密钥对并存储。
// masterKey 是已解锁的卡片主密钥（通过 TPM Unseal 获得）。
func (m *KeyManager) GenerateKeyPair(ctx context.Context, req local.KeyGenRequest, masterKey []byte, card *storage.Card) (*local.KeyGenResult, error) {
	// 复用 local.KeyManager 的密钥生成逻辑（私钥加密方式相同）
	return m.localMgr.GenerateKeyPair(ctx, req, masterKey, card)
}

// ImportPrivateKey 导入私钥到 TPM2 卡片。
func (m *KeyManager) ImportPrivateKey(ctx context.Context, req local.KeyGenRequest, masterKey, privDER, pubDER []byte) (*local.KeyGenResult, error) {
	return m.localMgr.ImportPrivateKey(ctx, req, masterKey, privDER, pubDER)
}

// encryptTPMBlob 用密码加密 TPM blob，生成一条 CardKeyEntry。
// 注意：EncMasterKey 字段存储的是加密后的 TPM blob，而非主密钥本身。
func encryptTPMBlob(tpmBlob, password []byte, keyType, userUUID string) (*storage.CardKeyEntry, error) {
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, err
	}

	// AES 密钥 = HMAC(password, salt)
	aesKey := cryptoutil.HMACSHA256(password, salt)
	encBlob, err := cryptoutil.EncryptAES256GCM(aesKey, tpmBlob)
	if err != nil {
		return nil, err
	}

	return &storage.CardKeyEntry{
		KeyType:      keyType,
		UserUUID:     userUUID,
		Salt:         salt,
		EncMasterKey: encBlob, // 实际存储的是加密的 TPM blob
	}, nil
}
