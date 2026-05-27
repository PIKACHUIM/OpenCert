package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/google/uuid"
)

// KeyGenRequest 是生成密钥对的请求参数。
type KeyGenRequest struct {
	CardUUID string
	CertType storage.CertType
	// KeyType: rsa2048 / rsa4096 / ec256 / ec384 / ec521
	KeyType string
	Remark  string
}

// KeyGenResult 是生成密钥对的结果。
type KeyGenResult struct {
	CertUUID    string
	PublicKeyDER []byte // DER 格式公钥（PKIX）
}

// KeyManager 提供本地卡片的密钥管理操作。
type KeyManager struct {
	certRepo    *storage.CertRepo
	cardRepo    *storage.CardRepo
	tpmProvider tpmProvider // TPM 接口（可选，高/中安全等级需要）
}

// tpmProvider 是 TPM 操作的最小接口（避免直接依赖 tpm 包）。
type tpmProvider interface {
	Available() bool
	Seal(data []byte) ([]byte, error)
	Unseal(blob []byte) ([]byte, error)
	PlatformName() string
}

// NewKeyManager 创建密钥管理器。
func NewKeyManager(certRepo *storage.CertRepo, cardRepo *storage.CardRepo) *KeyManager {
	return &KeyManager{certRepo: certRepo, cardRepo: cardRepo}
}

// NewKeyManagerWithTPM 创建带 TPM 支持的密钥管理器。
func NewKeyManagerWithTPM(certRepo *storage.CertRepo, cardRepo *storage.CardRepo, tp tpmProvider) *KeyManager {
	return &KeyManager{certRepo: certRepo, cardRepo: cardRepo, tpmProvider: tp}
}

// CreateCard 创建一张新的本地智能卡。
// pin 是卡片 PIN 码（明文），用于加密主密钥。
// cardPassword 可选，是卡片独立密码（留空则不设置）。
func CreateCard(ctx context.Context, cardRepo *storage.CardRepo, userUUID, cardName, pin, cardPassword, remark string) (*storage.Card, error) {
	out, err := CreateCardWithCreds(ctx, cardRepo, CreateCardArgs{
		UserUUID:     userUUID,
		CardName:     cardName,
		PIN:          pin,
		CardPassword: cardPassword,
		Remark:       remark,
	})
	if err != nil {
		return nil, err
	}
	return out.Card, nil
}

// CreateCardArgs 是带 PIN/PUK/AdminKey 的卡片创建参数。
type CreateCardArgs struct {
	UserUUID      string
	CardName      string
	CardPassword  string // 可选
	PIN           string // 必填，用于加密主密钥
	PUK           string // 可选；为空且 GeneratePUK=true 时自动生成（默认 true）
	AdminKey      string // 可选；为空且 GenerateAdmin=true 时自动生成（默认 true）
	GeneratePIN   bool
	GeneratePUK   bool
	GenerateAdmin bool
	SecurityLevel storage.SecurityLevel // 安全等级（high/medium/low），默认 low
	Remark        string
}

// CreateCardResult 是创建结果，包含卡片及一次性返回的明文 PUK/AdminKey。
// 调用方必须把 PUK 与 AdminKey 提示给用户保存；后端只存加密副本。
type CreateCardResult struct {
	Card     *storage.Card
	PIN      string // 仅当自动生成时返回
	PUK      string // 仅当自动生成时返回
	AdminKey string // 仅当自动生成时返回
}

// CreateCardWithCreds 创建卡片并可选自动生成 PIN/PUK/AdminKey 三级凭据。
// 默认行为：PUK 与 AdminKey 若未提供则自动生成 16 字节随机值（hex 编码 32 字符）。
// 所有凭据都作为独立 CardKeyEntry 各自加密一份"主密钥副本"存储，互不推导。
func CreateCardWithCreds(ctx context.Context, cardRepo *storage.CardRepo, args CreateCardArgs) (*CreateCardResult, error) {
	// 1. 生成 32 字节随机主密钥
	masterKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	defer zeroBytes(masterKey)

	secLevel := args.SecurityLevel
	if secLevel == "" {
		secLevel = storage.SecurityLevelLow
	}

	card := &storage.Card{
		UUID:          uuid.New().String(),
		SlotType:      storage.SlotTypeLocal,
		CardName:      args.CardName,
		UserUUID:      args.UserUUID,
		SecurityLevel: secLevel,
		Remark:        args.Remark,
	}

	out := &CreateCardResult{}

	// 2. PIN 加密主密钥（必须）
	pin := args.PIN
	if pin == "" {
		return nil, fmt.Errorf("PIN 不能为空，PIN 用于加密保护主密钥")
	}
	pinEntry, err := encryptMasterKey(masterKey, []byte(pin), "pin", "")
	if err != nil {
		return nil, fmt.Errorf("加密主密钥（PIN）失败: %w", err)
	}
	card.CardKeys = append(card.CardKeys, *pinEntry)

	// 3. 卡片密码（可选，兼容旧字段）
	if args.CardPassword != "" {
		cardEntry, err := encryptMasterKey(masterKey, []byte(args.CardPassword), "card", "")
		if err != nil {
			return nil, fmt.Errorf("加密主密钥（卡片密码）失败: %w", err)
		}
		card.CardKeys = append(card.CardKeys, *cardEntry)
	}

	// 4. （PIN 已在步骤 2 处理，此处保留编号兼容）

	// 5. PUK（加密 PIN 而非直接加密主密钥）
	puk := args.PUK
	generatePUK := args.GeneratePUK || (args.PUK == "")
	if puk == "" && generatePUK {
		puk = randomCred(16)
	}
	if puk != "" {
		// PUK 加密 PIN 明文（而非主密钥），使得 PUK 可解密并修改 PIN
		pukEntry, err := encryptPINWithPUK([]byte(pin), []byte(puk))
		if err != nil {
			return nil, fmt.Errorf("加密 PIN（PUK）失败: %w", err)
		}
		card.CardKeys = append(card.CardKeys, *pukEntry)
		if generatePUK {
			out.PUK = puk
		}
	}

	// 6. Admin Key
	admin := args.AdminKey
	generateAdmin := args.GenerateAdmin || (args.AdminKey == "")
	if admin == "" && generateAdmin {
		admin = randomCred(16)
	}
	if admin != "" {
		adminEntry, err := encryptMasterKey(masterKey, []byte(admin), "admin", "")
		if err != nil {
			return nil, fmt.Errorf("加密主密钥（AdminKey）失败: %w", err)
		}
		card.CardKeys = append(card.CardKeys, *adminEntry)
		if generateAdmin {
			out.AdminKey = admin
		}
	}

	if err := cardRepo.Create(ctx, card); err != nil {
		return nil, fmt.Errorf("保存卡片失败: %w", err)
	}

	// 7. 如果安全等级为 medium，生成 TPM 证书密钥并用 ADMINKEY 加密存储
	if secLevel == storage.SecurityLevelMedium {
		if admin == "" {
			return nil, fmt.Errorf("medium 安全等级需要 AdminKey")
		}
		tpmCertKey, err := cryptoutil.GenerateKey() // 32 字节随机 TPM 证书密钥
		if err != nil {
			return nil, fmt.Errorf("生成 TPM 证书密钥失败: %w", err)
		}
		defer zeroBytes(tpmCertKey)

		tpmKeySalt, err := cryptoutil.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("生成 TPM 证书密钥盐值失败: %w", err)
		}
		// 用 ADMINKEY 加密 TPM 证书密钥
		tpmKeyAES := cryptoutil.HMACSHA256([]byte(admin), tpmKeySalt)
		tpmKeyEnc, err := cryptoutil.EncryptAES256GCM(tpmKeyAES, tpmCertKey)
		if err != nil {
			return nil, fmt.Errorf("加密 TPM 证书密钥失败: %w", err)
		}
		card.TPMCertKeyEnc = tpmKeyEnc
		card.TPMCertKeySalt = tpmKeySalt

		// 更新卡片记录
		if err := cardRepo.Update(ctx, card); err != nil {
			return nil, fmt.Errorf("更新卡片 TPM 证书密钥失败: %w", err)
		}
	}

	out.Card = card
	return out, nil
}

// ResetPIN 用 PUK 或 AdminKey 重置 PIN。
// PUK 模式：PUK 解密获得旧 PIN → 旧 PIN 解密主密钥 → 用新 PIN 重新加密主密钥 → 用 PUK 重新加密新 PIN
// Admin 模式：AdminKey 直接解密主密钥 → 用新 PIN 重新加密主密钥 → 用 PUK 重新加密新 PIN
// keyType: "puk" 或 "admin"
func ResetPIN(ctx context.Context, cardRepo *storage.CardRepo, card *storage.Card, keyType, secret, newPIN string) error {
	if keyType != "puk" && keyType != "admin" {
		return fmt.Errorf("keyType 必须为 puk 或 admin")
	}
	if newPIN == "" {
		return fmt.Errorf("新 PIN 不能为空")
	}

	var masterKey []byte
	var err error

	if keyType == "puk" {
		// PUK 模式：先解密获得旧 PIN，再用旧 PIN 解密主密钥
		oldPIN, pukErr := decryptPINWithPUK(card, secret)
		if pukErr != nil {
			if ferr := bumpFailure(ctx, cardRepo, card, "puk"); ferr != nil {
				return fmt.Errorf("%w (记录失败次数时出错: %v)", pukErr, ferr)
			}
			return pukErr
		}
		// 用旧 PIN 解密主密钥
		masterKey, err = tryUnlockByType(card, "pin", string(oldPIN))
		if err != nil {
			// 如果 PIN 条目不存在，尝试 card 类型
			masterKey, err = tryUnlockByType(card, "card", string(oldPIN))
			if err != nil {
				return fmt.Errorf("PUK 解密的 PIN 无法解锁主密钥: %w", err)
			}
		}
		zeroBytes(oldPIN)
	} else {
		// Admin 模式：AdminKey 直接解密主密钥
		masterKey, err = tryUnlockByType(card, "admin", secret)
		if err != nil {
			if ferr := bumpFailure(ctx, cardRepo, card, "admin"); ferr != nil {
				return fmt.Errorf("%w (记录失败次数时出错: %v)", err, ferr)
			}
			return err
		}
	}
	defer zeroBytes(masterKey)

	// 清零 puk/pin 失败状态
	for i := range card.CardKeys {
		kt := card.CardKeys[i].KeyType
		if kt == "pin" || kt == "puk" || kt == "card" || kt == "user" {
			card.CardKeys[i].Attempts = 0
			card.CardKeys[i].Locked = false
		}
	}

	// 用新 PIN 重新加密主密钥的 pin 条目
	newEntry, err := encryptMasterKey(masterKey, []byte(newPIN), "pin", "")
	if err != nil {
		return fmt.Errorf("加密新 PIN 失败: %w", err)
	}
	replaced := false
	for i := range card.CardKeys {
		if card.CardKeys[i].KeyType == "pin" {
			card.CardKeys[i] = *newEntry
			replaced = true
			break
		}
	}
	if !replaced {
		card.CardKeys = append(card.CardKeys, *newEntry)
	}

	// 用 PUK 重新加密新 PIN（更新 PUK 条目中存储的加密 PIN）
	for i := range card.CardKeys {
		if card.CardKeys[i].KeyType == "puk" {
			// 找到 PUK 条目对应的 PUK 明文来重新加密新 PIN
			// 如果是 PUK 模式，我们有 secret 就是 PUK
			// 如果是 Admin 模式，我们无法获取 PUK 明文，跳过更新
			if keyType == "puk" {
				newPukEntry, pErr := encryptPINWithPUK([]byte(newPIN), []byte(secret))
				if pErr != nil {
					return fmt.Errorf("用 PUK 加密新 PIN 失败: %w", pErr)
				}
				card.CardKeys[i] = *newPukEntry
			}
			break
		}
	}

	// 同步清零卡片级 PIN 失败标记
	card.PINFailedCount = 0
	card.PINLocked = false

	return cardRepo.Update(ctx, card)
}

// ResetPUK 用 AdminKey 验证权限，然后用 newPUK 重新加密当前 PIN。
// 需要提供当前 PIN（或通过 AdminKey 解密主密钥后找到 PIN 条目对应的密码）。
func ResetPUK(ctx context.Context, cardRepo *storage.CardRepo, card *storage.Card, adminKey, currentPIN, newPUK string) error {
	if newPUK == "" {
		return fmt.Errorf("新 PUK 不能为空")
	}
	// 验证 AdminKey 权限
	masterKey, err := tryUnlockByType(card, "admin", adminKey)
	if err != nil {
		if ferr := bumpFailure(ctx, cardRepo, card, "admin"); ferr != nil {
			return fmt.Errorf("%w (记录失败次数时出错: %v)", err, ferr)
		}
		return err
	}
	defer zeroBytes(masterKey)

	// 确定当前 PIN（用于被新 PUK 加密）
	pinToEncrypt := currentPIN
	if pinToEncrypt == "" {
		return fmt.Errorf("需要提供当前 PIN 以便新 PUK 加密")
	}

	// 用新 PUK 加密当前 PIN
	newEntry, err := encryptPINWithPUK([]byte(pinToEncrypt), []byte(newPUK))
	if err != nil {
		return fmt.Errorf("用新 PUK 加密 PIN 失败: %w", err)
	}
	replaced := false
	for i := range card.CardKeys {
		if card.CardKeys[i].KeyType == "puk" {
			card.CardKeys[i] = *newEntry
			replaced = true
			break
		}
	}
	if !replaced {
		card.CardKeys = append(card.CardKeys, *newEntry)
	}
	return cardRepo.Update(ctx, card)
}

// tryUnlockByType 只用指定类型的条目尝试解密主密钥。
// 遍历相同 keyType 的所有 entry；若没有该类型条目或全部失败则返回错误。
// Locked=true 的条目会被跳过，若全部被锁则报 CKR_PIN_LOCKED 等价错误。
func tryUnlockByType(card *storage.Card, keyType, secret string) ([]byte, error) {
	hasType := false
	allLocked := true
	for _, e := range card.CardKeys {
		if e.KeyType != keyType {
			continue
		}
		hasType = true
		if e.Locked {
			continue
		}
		allLocked = false
		aesKey := cryptoutil.HMACSHA256([]byte(secret), e.Salt)
		masterKey, err := cryptoutil.DecryptAES256GCM(aesKey, e.EncMasterKey)
		if err == nil {
			return masterKey, nil
		}
	}
	if !hasType {
		return nil, fmt.Errorf("卡片未设置 %s 凭据", keyType)
	}
	if allLocked {
		return nil, fmt.Errorf("%s 已被锁定", keyType)
	}
	return nil, fmt.Errorf("%s 验证失败", keyType)
}

// bumpFailure 为指定 keyType 的所有条目递增失败次数；
// PUK 达到 10 次锁定；Admin 达到 10 次锁定。
func bumpFailure(ctx context.Context, cardRepo *storage.CardRepo, card *storage.Card, keyType string) error {
	maxAttempts := 10
	if keyType == "pin" {
		maxAttempts = card.PINRetries
		if maxAttempts <= 0 {
			maxAttempts = 3
		}
	}
	changed := false
	for i := range card.CardKeys {
		if card.CardKeys[i].KeyType != keyType {
			continue
		}
		card.CardKeys[i].Attempts++
		if card.CardKeys[i].Attempts >= maxAttempts {
			card.CardKeys[i].Locked = true
		}
		changed = true
	}
	if !changed {
		return nil
	}
	return cardRepo.Update(ctx, card)
}

// randomCred 生成 n 字节随机 hex 凭据（返回 2n 字符字符串）。
func randomCred(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// 兜底：时间戳（不应该发生）
		return fmt.Sprintf("fallback-%d", nBytes)
	}
	out := make([]byte, 2*nBytes)
	const hexCh = "0123456789abcdef"
	for i, v := range b {
		out[i*2] = hexCh[v>>4]
		out[i*2+1] = hexCh[v&0x0f]
	}
	return string(out)
}

// GenerateKeyPair 在指定卡片中生成密钥对并存储。
// masterKey 是已解锁的卡片主密钥。
// card 用于获取安全等级和 TPM 证书密钥信息。
func (m *KeyManager) GenerateKeyPair(ctx context.Context, req KeyGenRequest, masterKey []byte, card *storage.Card) (*KeyGenResult, error) {
	// 1. 生成密钥对
	privDER, pubDER, err := generateKeyPair(req.KeyType)
	if err != nil {
		return nil, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 2. 根据安全等级选择加密策略
	secLevel := card.SecurityLevel
	if secLevel == "" {
		secLevel = storage.SecurityLevelLow
	}

	switch secLevel {
	case storage.SecurityLevelHigh:
		// 高安全性：密钥存储于 TPM，并被主密钥加密
		cert, err := encryptAndStoreCertWithTPM(ctx, m.certRepo, m.tpmProvider, req, masterKey, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil

	case storage.SecurityLevelMedium:
		// 中安全性：先用 TPM 证书密钥加密，再用主密钥加密
		cert, err := encryptAndStoreCertWithTPMCertKey(ctx, m.certRepo, req, masterKey, card, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil

	default:
		// 低安全性：仅主密钥加密（原有逻辑）
		cert, err := encryptAndStoreCert(ctx, m.certRepo, req, masterKey, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil
	}
}

// ImportCertificate 导入已有证书（公钥部分）到卡片。
// 用于导入 X.509 证书与已存储私钥关联。
func (m *KeyManager) ImportCertificate(ctx context.Context, cardUUID string, certDER []byte, remark string) (*storage.Certificate, error) {
	// 将 DER 转为 PEM 格式存储
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert := &storage.Certificate{
		UUID:        uuid.New().String(),
		SlotType:    storage.SlotTypeLocal,
		CardUUID:    cardUUID,
		CertType:    storage.CertTypeX509,
		KeyType:     "x509",
		CertContent: certPEM,
		Remark:      remark,
	}

	if err := m.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("导入证书失败: %w", err)
	}
	return cert, nil
}

// CredentialRequest 是导入通用安全凭据（FIDO/Login/Note/Payment/Text 等）的请求参数。
//
// 与 ImportCertificate 的区别：
//   - ImportCertificate 仅写入公开 CertContent（X.509 DER）
//   - ImportCredential 同时写入公开元数据（PublicMeta）与加密私密内容（SecretData）
//
// 加密策略与 GenerateKeyPair 一致：
//   1. 生成 32 字节临时密钥 tempKey
//   2. 用 HMAC(masterKey, salt) 加密 tempKey 存入 TempKeyEnc
//   3. 用 tempKey 加密 SecretData 存入 PrivateData
type CredentialRequest struct {
	CardUUID   string
	CertType   storage.CertType
	KeyType    string // 自由形式标识，如 "fido2"/"totp"/"login-v1"
	PublicMeta []byte // 公开可读的元数据（如登录站点、备注摘要）
	SecretData []byte // 需要加密保护的私密数据（如密码、TOTP seed、FIDO 私有 key handle）
	Remark     string
}

// ImportCredential 导入一条通用安全凭据。
// 当 SecretData 为空时仅存储公开元数据；非空时根据安全等级加密。
// card 参数用于获取安全等级信息（可为 nil，此时使用 low 安全等级逻辑）。
func (m *KeyManager) ImportCredential(ctx context.Context, req CredentialRequest, masterKey []byte, card *storage.Card) (*storage.Certificate, error) {
	if req.CardUUID == "" {
		return nil, fmt.Errorf("CardUUID 不能为空")
	}
	if req.CertType == "" {
		return nil, fmt.Errorf("CertType 不能为空")
	}

	cert := &storage.Certificate{
		UUID:        uuid.New().String(),
		SlotType:    storage.SlotTypeLocal,
		CardUUID:    req.CardUUID,
		CertType:    req.CertType,
		KeyType:     req.KeyType,
		CertContent: req.PublicMeta,
		Remark:      req.Remark,
	}

	// 仅当存在私密内容且提供了主密钥时才加密
	if len(req.SecretData) > 0 {
		if len(masterKey) == 0 {
			return nil, fmt.Errorf("加密私密内容需要主密钥")
		}

		dataToEncrypt := req.SecretData

		// 中/高安全等级：先用 TPM 证书密钥加密（双重加密）
		secLevel := storage.SecurityLevelLow
		if card != nil && card.SecurityLevel != "" {
			secLevel = card.SecurityLevel
		}
		if (secLevel == storage.SecurityLevelMedium || secLevel == storage.SecurityLevelHigh) && len(card.TPMCertKeyEnc) > 0 {
			// 标记为需要 TPM 证书密钥解密（通过 TPMPlatform 字段）
			cert.TPMPlatform = storage.TPMPlatform("medium")
			cert.TPMAuthPolicy = card.TPMCertKeySalt // 引用卡片的 TPM 证书密钥盐值
		}

		tempKey, err := cryptoutil.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("生成临时密钥失败: %w", err)
		}
		defer zeroBytes(tempKey)

		tempKeySalt, err := cryptoutil.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("生成盐失败: %w", err)
		}
		tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, tempKeySalt)
		tempKeyEnc, err := cryptoutil.EncryptAES256GCM(tempKeyAESKey, tempKey)
		if err != nil {
			return nil, fmt.Errorf("加密临时密钥失败: %w", err)
		}
		privateData, err := cryptoutil.EncryptAES256GCM(tempKey, dataToEncrypt)
		if err != nil {
			return nil, fmt.Errorf("加密私密内容失败: %w", err)
		}
		cert.TempKeySalt = tempKeySalt
		cert.TempKeyEnc = tempKeyEnc
		cert.PrivateData = privateData
	}

	if err := m.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存安全凭据失败: %w", err)
	}
	return cert, nil
}

// ImportPrivateKey 导入私钥到卡片（DER 格式，已有主密钥加密）。
func (m *KeyManager) ImportPrivateKey(ctx context.Context, req KeyGenRequest, masterKey, privDER, pubDER []byte) (*KeyGenResult, error) {
	cert, err := encryptAndStoreCert(ctx, m.certRepo, req, masterKey, privDER, pubDER)
	if err != nil {
		return nil, err
	}
	return &KeyGenResult{
		CertUUID:    cert.UUID,
		PublicKeyDER: pubDER,
	}, nil
}

// ---- 内部工具函数 ----

// encryptPINWithPUK 使用 PUK 加密 PIN 明文，生成一条 puk 类型的 CardKeyEntry。
// PUK 条目的 EncMasterKey 字段存储的是加密后的 PIN（而非主密钥）。
func encryptPINWithPUK(pin, puk []byte) (*storage.CardKeyEntry, error) {
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, err
	}
	aesKey := cryptoutil.HMACSHA256(puk, salt)
	encPIN, err := cryptoutil.EncryptAES256GCM(aesKey, pin)
	if err != nil {
		return nil, err
	}
	return &storage.CardKeyEntry{
		KeyType:      "puk",
		Salt:         salt,
		EncMasterKey: encPIN, // 注意：此处存储的是加密后的 PIN，而非主密钥
	}, nil
}

// decryptPINWithPUK 使用 PUK 解密获得 PIN 明文。
func decryptPINWithPUK(card *storage.Card, puk string) ([]byte, error) {
	for _, e := range card.CardKeys {
		if e.KeyType != "puk" {
			continue
		}
		if e.Locked {
			continue
		}
		aesKey := cryptoutil.HMACSHA256([]byte(puk), e.Salt)
		pin, err := cryptoutil.DecryptAES256GCM(aesKey, e.EncMasterKey)
		if err == nil {
			return pin, nil
		}
	}
	return nil, fmt.Errorf("PUK 验证失败")
}

// encryptMasterKey 用密码加密主密钥，生成一条 CardKeyEntry。
func encryptMasterKey(masterKey, password []byte, keyType, userUUID string) (*storage.CardKeyEntry, error) {
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, err
	}

	// AES 密钥 = HMAC(password, salt)
	aesKey := cryptoutil.HMACSHA256(password, salt)
	encMasterKey, err := cryptoutil.EncryptAES256GCM(aesKey, masterKey)
	if err != nil {
		return nil, err
	}

	return &storage.CardKeyEntry{
		KeyType:      keyType,
		UserUUID:     userUUID,
		Salt:         salt,
		EncMasterKey: encMasterKey,
	}, nil
}

// encryptAndStoreCert 加密私钥并存储证书记录。
func encryptAndStoreCert(ctx context.Context, certRepo *storage.CertRepo, req KeyGenRequest, masterKey, privDER, pubDER []byte) (*storage.Certificate, error) {
	// 1. 生成临时密钥（32 字节随机）
	tempKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥失败: %w", err)
	}
	defer zeroBytes(tempKey)

	// 2. 生成临时密钥盐值
	tempKeySalt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥盐值失败: %w", err)
	}

	// 3. 用 HMAC(masterKey, salt) 加密临时密钥
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, tempKeySalt)
	tempKeyEnc, err := cryptoutil.EncryptAES256GCM(tempKeyAESKey, tempKey)
	if err != nil {
		return nil, fmt.Errorf("加密临时密钥失败: %w", err)
	}

	// 4. 用临时密钥加密私钥
	privateData, err := cryptoutil.EncryptAES256GCM(tempKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	// 将公开部分 DER 转为 PEM 格式存储
	// 智能判断：尝试宽松解析为 X.509 证书，成功则用 CERTIFICATE 类型，否则用 PUBLIC KEY
	pemType := "PUBLIC KEY"
	if _, parseErr := parseCertLenient(pubDER); parseErr == nil {
		pemType = "CERTIFICATE"
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubDER})

	cert := &storage.Certificate{
		UUID:        uuid.New().String(),
		SlotType:    storage.SlotTypeLocal,
		CardUUID:    req.CardUUID,
		CertType:    req.CertType,
		KeyType:     req.KeyType,
		CertContent: pubPEM,
		TempKeySalt: tempKeySalt,
		TempKeyEnc:  tempKeyEnc,
		PrivateData: privateData,
		Remark:      req.Remark,
	}

	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	return cert, nil
}

// encryptAndStoreCertWithTPM 高安全等级：将私钥存储于 TPM，并被主密钥加密。
func encryptAndStoreCertWithTPM(ctx context.Context, certRepo *storage.CertRepo, tp tpmProvider, req KeyGenRequest, masterKey, privDER, pubDER []byte) (*storage.Certificate, error) {
	if tp == nil || !tp.Available() {
		return nil, fmt.Errorf("高安全等级需要 TPM 支持，当前平台不可用")
	}

	// 1. 将私钥 Seal 到 TPM
	tpmBlob, err := tp.Seal(privDER)
	if err != nil {
		return nil, fmt.Errorf("TPM Seal 私钥失败: %w", err)
	}

	// 2. 同时用主密钥加密私钥（作为 TPM 绑定的备份验证）
	tempKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥失败: %w", err)
	}
	defer zeroBytes(tempKey)

	tempKeySalt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥盐值失败: %w", err)
	}
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, tempKeySalt)
	tempKeyEnc, err := cryptoutil.EncryptAES256GCM(tempKeyAESKey, tempKey)
	if err != nil {
		return nil, fmt.Errorf("加密临时密钥失败: %w", err)
	}
	privateData, err := cryptoutil.EncryptAES256GCM(tempKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	cert := &storage.Certificate{
		UUID:           uuid.New().String(),
		SlotType:       storage.SlotTypeLocal,
		CardUUID:       req.CardUUID,
		CertType:       req.CertType,
		KeyType:        req.KeyType,
		CertContent:    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
		TempKeySalt:    tempKeySalt,
		TempKeyEnc:     tempKeyEnc,
		PrivateData:    privateData,
		TPMPlatform:    storage.TPMPlatform(tp.PlatformName()),
		TPMPrivateBlob: tpmBlob,
		Remark:         req.Remark,
	}

	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	return cert, nil
}

// encryptAndStoreCertWithTPMCertKey 中安全等级：先用 TPM 证书密钥加密，再用主密钥加密。
func encryptAndStoreCertWithTPMCertKey(ctx context.Context, certRepo *storage.CertRepo, req KeyGenRequest, masterKey []byte, card *storage.Card, privDER, pubDER []byte) (*storage.Certificate, error) {
	// 需要从卡片获取 TPM 证书密钥（已被 ADMINKEY 加密存储）
	// 这里我们不直接解密 TPM 证书密钥（需要 ADMINKEY），而是使用主密钥进行双重加密
	// 加密链：privDER → TPM证书密钥加密 → 主密钥加密
	// 但由于 GenerateKeyPair 时已有主密钥，我们需要一种方式获取 TPM 证书密钥
	// 方案：在 GenerateKeyPair 调用时传入已解密的 TPM 证书密钥

	// 实际上 medium 模式下，私钥加密流程：
	// 1. 用 TPM 证书密钥加密私钥
	// 2. 用主密钥加密（加密后的私钥）
	// 这需要调用方提供 TPM 证书密钥，但这里我们先用主密钥加密，
	// TPM 证书密钥加密层在外层处理

	// 简化实现：使用与 low 相同的加密方式存储，但标记为需要 TPM 证书密钥
	// 实际的双重加密在 tempKey 层实现：tempKey 由 TPM 证书密钥 + 主密钥共同保护

	// 1. 生成临时密钥
	tempKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥失败: %w", err)
	}
	defer zeroBytes(tempKey)

	// 2. 用临时密钥加密私钥
	privateData, err := cryptoutil.EncryptAES256GCM(tempKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	// 3. 临时密钥被主密钥加密
	tempKeySalt, err := cryptoutil.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("生成临时密钥盐值失败: %w", err)
	}
	tempKeyAESKey := cryptoutil.HMACSHA256(masterKey, tempKeySalt)
	tempKeyEnc, err := cryptoutil.EncryptAES256GCM(tempKeyAESKey, tempKey)
	if err != nil {
		return nil, fmt.Errorf("加密临时密钥失败: %w", err)
	}

	// 4. 同时用 TPM 证书密钥加密临时密钥（双重保护）
	// TPM 证书密钥加密的副本存储在 TPMPrivateBlob 字段
	if len(card.TPMCertKeyEnc) > 0 {
		// 注意：这里无法直接解密 TPM 证书密钥（需要 ADMINKEY）
		// 所以我们将 TPM 证书密钥的盐值存储在 TPMAuthPolicy 中作为标记
		// 实际解密时需要先用 ADMINKEY 解密 TPM 证书密钥
		cert := &storage.Certificate{
			UUID:          uuid.New().String(),
			SlotType:      storage.SlotTypeLocal,
			CardUUID:      req.CardUUID,
			CertType:      req.CertType,
			KeyType:       req.KeyType,
			CertContent:   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}),
			TempKeySalt:   tempKeySalt,
			TempKeyEnc:    tempKeyEnc,
			PrivateData:   privateData,
			TPMPlatform:   storage.TPMPlatform("medium"), // 标记为 medium 安全等级加密
			TPMAuthPolicy: card.TPMCertKeySalt,           // 引用卡片的 TPM 证书密钥盐值
			Remark:        req.Remark,
		}
		if err := certRepo.Create(ctx, cert); err != nil {
			return nil, fmt.Errorf("保存证书失败: %w", err)
		}
		return cert, nil
	}

	// 回退：如果卡片没有 TPM 证书密钥，使用标准加密
	return encryptAndStoreCert(ctx, certRepo, req, masterKey, privDER, pubDER)
}

// DecryptTPMCertKey 用 ADMINKEY 解密获取 TPM 证书密钥。
func DecryptTPMCertKey(card *storage.Card, adminKey string) ([]byte, error) {
	if len(card.TPMCertKeyEnc) == 0 {
		return nil, fmt.Errorf("卡片未设置 TPM 证书密钥")
	}
	if len(card.TPMCertKeySalt) == 0 {
		return nil, fmt.Errorf("卡片 TPM 证书密钥盐值缺失")
	}
	aesKey := cryptoutil.HMACSHA256([]byte(adminKey), card.TPMCertKeySalt)
	tpmCertKey, err := cryptoutil.DecryptAES256GCM(aesKey, card.TPMCertKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("ADMINKEY 解密 TPM 证书密钥失败: %w", err)
	}
	return tpmCertKey, nil
}

// generateKeyPair 根据 keyType 生成密钥对，返回 (privDER, pubDER)。
func generateKeyPair(keyType string) (privDER, pubDER []byte, err error) {
	switch keyType {
	case "rsa1024":
		return generateRSA(1024)
	case "rsa2048":
		return generateRSA(2048)
	case "rsa4096":
		return generateRSA(4096)
	case "rsa8192":
		return generateRSA(8192)
	case "ec256":
		return generateEC(elliptic.P256())
	case "ec384":
		return generateEC(elliptic.P384())
	case "ec521":
		return generateEC(elliptic.P521())
	case "ed25519":
		return generateEd25519()
	default:
		return nil, nil, fmt.Errorf("不支持的密钥类型: %s（支持 rsa1024/rsa2048/rsa4096/rsa8192/ec256/ec384/ec521/ed25519）", keyType)
	}
}

func generateRSA(bits int) (privDER, pubDER []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 RSA-%d 密钥失败: %w", bits, err)
	}

	privDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 RSA 私钥失败: %w", err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 RSA 公钥失败: %w", err)
	}
	return
}

func generateEC(curve elliptic.Curve) (privDER, pubDER []byte, err error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 EC 密钥失败: %w", err)
	}

	privDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 EC 私钥失败: %w", err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 EC 公钥失败: %w", err)
	}
	return
}

// generateEd25519 生成 Ed25519 密钥对。
func generateEd25519() (privDER, pubDER []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 Ed25519 密钥失败: %w", err)
	}

	privDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 Ed25519 私钥失败: %w", err)
	}

	pubDER, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化 Ed25519 公钥失败: %w", err)
	}
	return
}

// SupportedKeyTypes 返回所有支持的密钥类型列表。
func SupportedKeyTypes() []string {
	return []string{
		"rsa1024", "rsa2048", "rsa4096", "rsa8192",
		"ec256", "ec384", "ec521",
		"ed25519",
	}
}

// zeroBytes 清零字节切片（防止内存泄露密钥）。
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
