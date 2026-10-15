package local

import (
	"context"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"github.com/globaltrusts/client-card/internal/pki"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// 本文件实现 card.PINManager / card.ObjectManager / card.KeyPairGenerator，
// 供 IPC 层响应 C_InitPIN / C_SetPIN / C_CreateObject / C_DestroyObject /
// C_SetAttributeValue / C_GetObjectSize / C_GenerateKeyPair。
//
// 对象模型说明：本实现中一条 certificates 记录同时承载
// CKO_CERTIFICATE / CKO_PUBLIC_KEY / CKO_PRIVATE_KEY 三种视图（见 slot.go 的
// buildAttributes 与 matchAttr），因此公钥与私钥返回同一个对象句柄。

// ---- PIN 管理 ----

// SetPIN 校验 oldPIN 后用 newPIN 重新加密卡片主密钥（C_SetPIN 语义）。
func (s *Slot) SetPIN(ctx context.Context, oldPIN, newPIN string) error {
	if newPIN == "" {
		return fmt.Errorf("%w: 新 PIN 不能为空", pkcs11types.CKR_PIN_LEN_RANGE)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn || len(s.masterKey) == 0 {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}

	// 用旧 PIN 解开主密钥即视为校验通过
	unlocked, err := s.unlockMasterKey(oldPIN)
	if err != nil {
		return fmt.Errorf("%w", pkcs11types.CKR_PIN_INCORRECT)
	}
	zeroBytes(unlocked)

	return s.rewrapPINLocked(ctx, newPIN)
}

// SetUserPIN 使用已解锁的主密钥直接设置用户 PIN（C_InitPIN 语义，需 SO/管理员会话）。
func (s *Slot) SetUserPIN(ctx context.Context, newPIN string) error {
	if newPIN == "" {
		return fmt.Errorf("%w: 新 PIN 不能为空", pkcs11types.CKR_PIN_LEN_RANGE)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn || len(s.masterKey) == 0 {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	return s.rewrapPINLocked(ctx, newPIN)
}

// rewrapPINLocked 用 newPIN 重新加密主密钥并覆盖 "pin" 条目。
// 调用方必须已持有 s.mu 写锁。
func (s *Slot) rewrapPINLocked(ctx context.Context, newPIN string) error {
	if s.cardRepo == nil {
		return fmt.Errorf("%w: 缺少 CardRepo，无法持久化 PIN", pkcs11types.CKR_FUNCTION_FAILED)
	}

	entry, err := encryptMasterKey(s.masterKey, []byte(newPIN), "pin", "")
	if err != nil {
		return fmt.Errorf("%w: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}

	replaced := false
	for i := range s.card.CardKeys {
		if s.card.CardKeys[i].KeyType == "pin" {
			s.card.CardKeys[i] = *entry
			replaced = true
			break
		}
	}
	if !replaced {
		s.card.CardKeys = append(s.card.CardKeys, *entry)
	}

	// PIN 已变更：清除锁定与失败计数
	s.card.PINLocked = false
	s.card.PINFailedCount = 0
	if err := s.cardRepo.Update(ctx, s.card); err != nil {
		return fmt.Errorf("%w: 保存卡片失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	return nil
}

// ---- 对象管理 ----

// CreateObject 依据属性模板创建对象。
// 支持 CKO_CERTIFICATE（X.509 DER/PEM）与 CKO_DATA（任意数据，如备注项）。
func (s *Slot) CreateObject(ctx context.Context, template []pkcs11types.Attribute) (pkcs11types.ObjectHandle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn {
		return 0, fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	if s.certRepo == nil {
		return 0, fmt.Errorf("%w: 缺少 CertRepo", pkcs11types.CKR_FUNCTION_FAILED)
	}

	var (
		class    uint32
		hasClass bool
		value    []byte
		label    []byte
	)
	for _, a := range template {
		switch a.Type {
		case pkcs11types.CKA_CLASS:
			if len(a.Value) == 4 {
				class = binary.BigEndian.Uint32(a.Value)
				hasClass = true
			}
		case pkcs11types.CKA_VALUE:
			value = a.Value
		case pkcs11types.CKA_LABEL:
			label = a.Value
		}
	}
	if !hasClass && len(value) == 0 {
		return 0, fmt.Errorf("%w: 模板缺少 CKA_CLASS / CKA_VALUE", pkcs11types.CKR_TEMPLATE_INCOMPLETE)
	}

	certType := storage.CertTypeNote
	keyType := "imported"
	content := value
	switch pkcs11types.ObjectClass(class) {
	case pkcs11types.CKO_CERTIFICATE:
		certType = storage.CertTypeX509
		keyType = "imported-cert"
		// CKO_CERTIFICATE 的 CKA_VALUE 应为 DER；兼容传 PEM 的调用方
		if der, ok := pemToDERIfPEM(value); ok {
			content = der
		}
		if err := pki.ValidateCertDER(content); err != nil {
			return 0, fmt.Errorf("%w: 不是合法的 X.509 证书: %v", pkcs11types.CKR_ATTRIBUTE_VALUE_INVALID, err)
		}
	case pkcs11types.CKO_DATA:
		certType = storage.CertTypeNote
		keyType = "data"
	case pkcs11types.CKO_PUBLIC_KEY:
		certType = storage.CertTypeNote
		keyType = "public-key"
	default:
		// 私钥/对称密钥需经「安全凭据」路径导入（REST API），此处不静默伪造成功
		return 0, fmt.Errorf("%w: 不支持的 CKA_CLASS=0x%X", pkcs11types.CKR_ATTRIBUTE_VALUE_INVALID, class)
	}

	if len(content) == 0 {
		return 0, fmt.Errorf("%w: CKA_VALUE 不能为空", pkcs11types.CKR_ATTRIBUTE_VALUE_INVALID)
	}

	cert := &storage.Certificate{
		SlotType:    s.card.SlotType,
		CardUUID:    s.card.UUID,
		CertType:    certType,
		KeyType:     keyType,
		CertContent: content,
		Remark:      string(label),
	}
	if cert.SlotType == "" {
		cert.SlotType = storage.SlotTypeLocal
	}
	if err := s.certRepo.Create(ctx, cert); err != nil {
		return 0, fmt.Errorf("%w: 创建对象失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}

	if err := s.loadObjects(ctx); err != nil {
		return 0, fmt.Errorf("%w: 刷新对象缓存失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	handle, ok := s.handleForCertLocked(cert.UUID)
	if !ok {
		return 0, fmt.Errorf("%w: 新对象未出现在缓存中", pkcs11types.CKR_FUNCTION_FAILED)
	}
	return handle, nil
}

// DestroyObject 删除句柄对应的对象。
// 注意：一条记录同时承载证书与私钥视图，因此删除后该密钥对整体不可用。
func (s *Slot) DestroyObject(ctx context.Context, handle pkcs11types.ObjectHandle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	cert, ok := s.objects[handle]
	if !ok {
		return fmt.Errorf("%w", pkcs11types.CKR_OBJECT_HANDLE_INVALID)
	}
	if s.certRepo == nil {
		return fmt.Errorf("%w: 缺少 CertRepo", pkcs11types.CKR_FUNCTION_FAILED)
	}
	if err := s.certRepo.Delete(ctx, cert.UUID); err != nil {
		return fmt.Errorf("%w: 删除对象失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	return s.loadObjects(ctx)
}

// SetAttributes 更新对象属性，当前仅支持 CKA_LABEL（映射到记录的备注）。
func (s *Slot) SetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.Attribute) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	cert, ok := s.objects[handle]
	if !ok {
		return fmt.Errorf("%w", pkcs11types.CKR_OBJECT_HANDLE_INVALID)
	}

	changed := false
	for _, a := range attrs {
		switch a.Type {
		case pkcs11types.CKA_LABEL:
			cert.Remark = string(a.Value)
			changed = true
		default:
			return fmt.Errorf("%w: 属性 0x%X 只读或不可设置", pkcs11types.CKR_ATTRIBUTE_READ_ONLY, uint32(a.Type))
		}
	}
	if !changed {
		return nil
	}
	if s.certRepo == nil {
		return fmt.Errorf("%w: 缺少 CertRepo", pkcs11types.CKR_FUNCTION_FAILED)
	}
	if err := s.certRepo.Update(ctx, cert); err != nil {
		return fmt.Errorf("%w: 保存属性失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	if err := s.loadObjects(ctx); err != nil {
		return fmt.Errorf("%w: 刷新对象缓存失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	return nil
}

// ObjectSize 返回对象大小（公开内容 + 私密内容 + 标签）。
func (s *Slot) ObjectSize(_ context.Context, handle pkcs11types.ObjectHandle) (uint32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, ok := s.objects[handle]
	if !ok {
		return 0, fmt.Errorf("%w", pkcs11types.CKR_OBJECT_HANDLE_INVALID)
	}
	size := len(cert.CertContent) + len(cert.PrivateData) + len(cert.Remark)
	return uint32(size), nil
}

// ---- 密钥对生成 ----

// GenerateKeyPair 在卡片内生成密钥对（C_GenerateKeyPair）。
// C 驱动只传递机制、不传递模板，因此 RSA 默认 2048 位、EC 默认 P-256。
func (s *Slot) GenerateKeyPair(ctx context.Context, mechanism pkcs11types.MechanismType) (pkcs11types.ObjectHandle, pkcs11types.ObjectHandle, error) {
	keyType, err := keyTypeFromMechanism(mechanism)
	if err != nil {
		return 0, 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.loggedIn || len(s.masterKey) == 0 {
		return 0, 0, fmt.Errorf("%w", pkcs11types.CKR_USER_NOT_LOGGED_IN)
	}
	if s.certRepo == nil {
		return 0, 0, fmt.Errorf("%w: 缺少 CertRepo", pkcs11types.CKR_FUNCTION_FAILED)
	}

	km := NewKeyManager(s.certRepo, s.cardRepo)
	if s.tpmProv != nil {
		km = NewKeyManagerWithTPM(s.certRepo, s.cardRepo, s.tpmProv)
	}

	// GenerateKeyPair 内部会销毁传入的主密钥缓冲区，这里传副本以免影响会话状态
	masterKey := make([]byte, len(s.masterKey))
	copy(masterKey, s.masterKey)
	defer zeroBytes(masterKey)

	res, err := km.GenerateKeyPair(ctx, KeyGenRequest{
		CardUUID: s.card.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  keyType,
		Remark:   "PKCS#11 生成密钥",
	}, masterKey, s.card)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: 生成密钥对失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}

	if err := s.loadObjects(ctx); err != nil {
		return 0, 0, fmt.Errorf("%w: 刷新对象缓存失败: %v", pkcs11types.CKR_FUNCTION_FAILED, err)
	}
	handle, ok := s.handleForCertLocked(res.CertUUID)
	if !ok {
		return 0, 0, fmt.Errorf("%w: 新密钥未出现在缓存中", pkcs11types.CKR_FUNCTION_FAILED)
	}
	// 同一记录同时暴露公钥/私钥视图，故两个句柄一致
	return handle, handle, nil
}

// keyTypeFromMechanism 把 PKCS#11 密钥对生成机制映射为卡片密钥类型。
func keyTypeFromMechanism(m pkcs11types.MechanismType) (string, error) {
	switch m {
	case pkcs11types.CKM_RSA_PKCS_KEY_PAIR_GEN:
		return "rsa2048", nil
	case pkcs11types.CKM_EC_KEY_PAIR_GEN:
		return "ec256", nil
	case pkcs11types.CKM_EDDSA:
		return "ed25519", nil
	case pkcs11types.CKM_SM2_KEY_PAIR_GEN:
		return "ec256", nil
	default:
		return "", fmt.Errorf("%w: 不支持密钥对生成机制 0x%X", pkcs11types.CKR_MECHANISM_INVALID, uint32(m))
	}
}

// handleForCertLocked 在对象缓存中查找指定证书 UUID 对应的句柄。
// 调用方必须已持有 s.mu（读或写锁）。
func (s *Slot) handleForCertLocked(certUUID string) (pkcs11types.ObjectHandle, bool) {
	for handle, cert := range s.objects {
		if cert.UUID == certUUID {
			return handle, true
		}
	}
	return 0, false
}

// pemToDERIfPEM 若数据是 PEM 证书则返回其 DER 内容；否则 ok=false。
func pemToDERIfPEM(data []byte) ([]byte, bool) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, false
	}
	return block.Bytes, true
}
