// Package fido-umdf - store.go 提供 FIDO 凭据的存储层，复用 storage.Certificate 表。
package fido

import (
	"context"
	"fmt"

	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
)

// Store 管理 FIDO 凭据的持久化存储。
// 复用 storage.Certificate 表（cert_type = "fido-umdf"），不引入新表。
type Store struct {
	certRepo *storage.CertRepo
	cardRepo *storage.CardRepo
	km       *local.KeyManager
}

// NewStore 创建 FIDO 存储实例。
func NewStore(certRepo *storage.CertRepo, cardRepo *storage.CardRepo, km *local.KeyManager) *Store {
	return &Store{
		certRepo: certRepo,
		cardRepo: cardRepo,
		km:       km,
	}
}

// Create 创建一条 FIDO 凭据。
// meta 是公开元数据，secret 是私密数据（可为 nil），masterKey 是卡片主密钥（secret 非空时必填）。
func (s *Store) Create(ctx context.Context, cardUUID string, meta *Meta, secret *Secret, masterKey []byte, card *storage.Card) (*Entry, error) {
	if err := ValidateMeta(meta); err != nil {
		return nil, err
	}

	// 编码公开元数据
	metaBytes, err := EncodeMeta(meta)
	if err != nil {
		return nil, err
	}

	// 编码私密数据（可选）
	var secretBytes []byte
	if secret != nil {
		secretBytes, err = EncodeSecret(secret)
		if err != nil {
			return nil, err
		}
		defer ZeroBytes(secretBytes)
	}

	// 通过 KeyManager 导入凭据（负责加密 secretBytes）
	cert, err := s.km.ImportCredential(ctx, local.CredentialRequest{
		CardUUID:   cardUUID,
		CertType:   storage.CertTypeFIDO,
		KeyType:    "fido2",
		PublicMeta: metaBytes,
		SecretData: secretBytes,
	}, masterKey, card)
	if err != nil {
		return nil, fmt.Errorf("保存 FIDO 凭据失败: %w", err)
	}

	return certToEntry(cert, meta), nil
}

// List 列出指定卡片下的所有 FIDO 凭据（不含私密数据）。
func (s *Store) List(ctx context.Context, cardUUID string) ([]Entry, error) {
	// 先精确匹配，再尝试前缀匹配（兼容旧数据中截断的 card_uuid）
	certs, err := s.certRepo.ListByCard(ctx, cardUUID)
	if err != nil {
		return nil, fmt.Errorf("查询 FIDO 凭据列表失败: %w", err)
	}

	// 如果精确匹配没有 FIDO 凭据，尝试用前缀匹配（旧数据可能只存了前16字符）
	hasFIDO := false
	for _, c := range certs {
		if c.CertType == storage.CertTypeFIDO {
			hasFIDO = true
			break
		}
	}
	if !hasFIDO && len(cardUUID) > 16 {
		// 用前16字符前缀查询
		prefix := cardUUID[:16]
		prefixCerts, err2 := s.certRepo.ListByCardPrefix(ctx, prefix)
		if err2 == nil && len(prefixCerts) > 0 {
			certs = append(certs, prefixCerts...)
		}
	}

	var entries []Entry
	for _, c := range certs {
		if c.CertType != storage.CertTypeFIDO {
			continue
		}
		meta, err := DecodeMeta(c.CertContent)
		if err != nil {
			// 元数据损坏时跳过，不中断整个列表
			continue
		}
		entries = append(entries, *certToEntry(c, meta))
	}
	return entries, nil
}

// GetByUUID 根据 UUID 获取 FIDO 凭据（不含私密数据）。
func (s *Store) GetByUUID(ctx context.Context, certUUID string) (*Entry, error) {
	cert, err := s.certRepo.GetByUUID(ctx, certUUID)
	if err != nil {
		return nil, fmt.Errorf("查询 FIDO 凭据失败: %w", err)
	}
	if cert == nil || cert.CertType != storage.CertTypeFIDO {
		return nil, nil
	}
	meta, err := DecodeMeta(cert.CertContent)
	if err != nil {
		return nil, fmt.Errorf("解码 FIDO 元数据失败: %w", err)
	}
	return certToEntry(cert, meta), nil
}

// GetSecret 解密并返回 FIDO 凭据的私密数据。
// masterKey 是卡片主密钥，用于解密。
func (s *Store) GetSecret(ctx context.Context, certUUID string, masterKey []byte, card *storage.Card) (*Secret, error) {
	secretBytes, err := s.km.ExportCredential(ctx, certUUID, masterKey, card)
	if err != nil {
		return nil, fmt.Errorf("解密 FIDO 私密数据失败: %w", err)
	}
	if len(secretBytes) == 0 {
		return &Secret{}, nil
	}
	defer ZeroBytes(secretBytes)
	return DecodeSecret(secretBytes)
}

// Delete 删除指定 FIDO 凭据。
func (s *Store) Delete(ctx context.Context, certUUID string) error {
	if err := s.certRepo.Delete(ctx, certUUID); err != nil {
		return fmt.Errorf("删除 FIDO 凭据失败: %w", err)
	}
	return nil
}

// IncrementCounter 递增 FIDO 签名计数器（防重放攻击）。
// 通过更新 CertContent 中的 counter 字段实现。
func (s *Store) IncrementCounter(ctx context.Context, certUUID string) (uint32, error) {
	cert, err := s.certRepo.GetByUUID(ctx, certUUID)
	if err != nil || cert == nil {
		return 0, fmt.Errorf("凭据不存在: %w", err)
	}
	if cert.CertType != storage.CertTypeFIDO {
		return 0, fmt.Errorf("不是 FIDO 凭据")
	}

	meta, err := DecodeMeta(cert.CertContent)
	if err != nil {
		return 0, fmt.Errorf("解码元数据失败: %w", err)
	}

	meta.Counter++

	newMetaBytes, err := EncodeMeta(meta)
	if err != nil {
		return 0, fmt.Errorf("编码元数据失败: %w", err)
	}

	cert.CertContent = newMetaBytes
	if err := s.certRepo.Update(ctx, cert); err != nil {
		return 0, fmt.Errorf("更新计数器失败: %w", err)
	}

	return meta.Counter, nil
}

// ---- 内部辅助 ----

// certToEntry 将 storage.Certificate 转换为 fido.Entry。
func certToEntry(cert *storage.Certificate, meta *Meta) *Entry {
	return &Entry{
		UUID:      cert.UUID,
		CardUUID:  cert.CardUUID,
		Meta:      *meta,
		KeyType:   cert.KeyType,
		Remark:    cert.Remark,
		CreatedAt: cert.CreatedAt,
		UpdatedAt: cert.UpdatedAt,
	}
}
