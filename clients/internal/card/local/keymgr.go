package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/internal/tpm"
	"github.com/google/uuid"
)

// KeyGenRequest 是生成密钥对的请求参数。
type KeyGenRequest struct {
	CardUUID string
	CertType storage.CertType
	// KeyType: rsa2048 / rsa4096 / ec256 / ec384 / ec521 / ed25519
	KeyType string
	Remark  string
}

// KeyGenResult 是生成密钥对的结果。
type KeyGenResult struct {
	CertUUID     string
	PublicKeyDER []byte // DER 格式公钥（PKIX）
}

// KeyManager 提供本地卡片的密钥管理操作。
type KeyManager struct {
	certRepo    *storage.CertRepo
	cardRepo    *storage.CardRepo
	tpmProvider tpm.Provider // TPM 接口（可选，medium/high 安全等级需要）
}

// NewKeyManager 创建无 TPM 支持的密钥管理器（仅 low 等级可用）。
func NewKeyManager(certRepo *storage.CertRepo, cardRepo *storage.CardRepo) *KeyManager {
	return &KeyManager{certRepo: certRepo, cardRepo: cardRepo}
}

// NewKeyManagerWithTPM 创建带 TPM 支持的密钥管理器（medium/high 等级需要）。
func NewKeyManagerWithTPM(certRepo *storage.CertRepo, cardRepo *storage.CardRepo, tp tpm.Provider) *KeyManager {
	return &KeyManager{certRepo: certRepo, cardRepo: cardRepo, tpmProvider: tp}
}

// TPM 返回当前注入的 TPM Provider；可为 nil。
func (m *KeyManager) TPM() tpm.Provider { return m.tpmProvider }

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
//
// 当 secLevel == medium 时，必须提供 tpmProv（通过 Server.SetTPMProvider 注入），
// 函数会调用 tpm.NVDefine + NVWrite 把"TPM 证书密钥"放入 TPM NV 域，
// 同时把 AdminKey 加密的应急恢复副本写入 card.TPMCertKeyEnc。
func CreateCardWithCreds(ctx context.Context, cardRepo *storage.CardRepo, args CreateCardArgs) (*CreateCardResult, error) {
	return CreateCardWithCredsAndTPM(ctx, cardRepo, nil, args)
}

// CreateCardWithCredsAndTPM 是 CreateCardWithCreds 的 TPM 注入版本。
// medium / high 等级必须传入非 nil 的 tpmProv，否则返回错误。
func CreateCardWithCredsAndTPM(ctx context.Context, cardRepo *storage.CardRepo, tpmProv tpm.Provider, args CreateCardArgs) (*CreateCardResult, error) {
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

	// medium / high 都需要 TPM Provider；high 在 CreateCard 阶段不直接生成密钥（密钥生成在 GenerateKeyPair）
	// 但仍然记录 Provider 名以便后续校验一致性。
	if (secLevel == storage.SecurityLevelMedium || secLevel == storage.SecurityLevelHigh) &&
		(tpmProv == nil || !tpmProv.Available()) {
		return nil, fmt.Errorf("%s 安全等级需要可用的 TPM Provider", secLevel)
	}

	card := &storage.Card{
		UUID:          uuid.New().String(),
		SlotType:      storage.SlotTypeLocal,
		CardName:      args.CardName,
		UserUUID:      args.UserUUID,
		Enabled:       true,
		SecurityLevel: secLevel,
		Remark:        args.Remark,
	}
	if tpmProv != nil {
		card.TPMProvider = tpmProv.PlatformName()
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

	// 5. PUK
	puk := args.PUK
	generatePUK := args.GeneratePUK || (args.PUK == "")
	if puk == "" && generatePUK {
		puk = randomCred(16)
	}
	if puk != "" {
		pukEntry, err := encryptMasterKey(masterKey, []byte(puk), "puk", "")
		if err != nil {
			return nil, fmt.Errorf("加密主密钥（PUK）失败: %w", err)
		}
		card.CardKeys = append(card.CardKeys, *pukEntry)
		if generatePUK {
			out.PUK = puk
		}
	}

	// 6. AdminKey
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

	// 7. medium / high：初始化 TPM 保护资产
	// - medium：生成对称"TPM 证书密钥"存入 NV，用于双层加密证书私钥
	// - high  ：同样初始化 NV（用于凭据加密）；保护密钥在首次 ImportKey 时按需创建
	if secLevel == storage.SecurityLevelMedium || secLevel == storage.SecurityLevelHigh {
		if admin == "" {
			return nil, fmt.Errorf("%s 安全等级需要 AdminKey（用于应急恢复）", secLevel)
		}

		tpmCertKey, err := cryptoutil.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("生成 TPM 证书密钥失败: %w", err)
		}
		defer zeroBytes(tpmCertKey)

		nvAuth := deriveTPMCertKeyAuth(masterKey)
		defer zeroBytes(nvAuth)
		nvHandle, err := tpmProv.NVDefine("cert-key:"+card.UUID, len(tpmCertKey), nvAuth)
		if err != nil {
			return nil, fmt.Errorf("TPM NV 分配失败: %w", err)
		}
		if err := tpmProv.NVWrite(nvHandle, nvAuth, tpmCertKey); err != nil {
			_ = tpmProv.NVUndefine(nvHandle)
			return nil, fmt.Errorf("TPM NV 写入失败: %w", err)
		}
		card.TPMCertKeyNVHandle = uint32(nvHandle)

		tpmKeySalt, err := cryptoutil.GenerateSalt()
		if err != nil {
			return nil, fmt.Errorf("生成 TPM 证书密钥盐值失败: %w", err)
		}
		tpmKeyAES := cryptoutil.HMACSHA256([]byte(admin), tpmKeySalt)
		tpmKeyEnc, err := cryptoutil.EncryptAES256GCM(tpmKeyAES, tpmCertKey)
		if err != nil {
			return nil, fmt.Errorf("加密 TPM 证书密钥应急副本失败: %w", err)
		}
		card.TPMCertKeyEnc = tpmKeyEnc
		card.TPMCertKeySalt = tpmKeySalt

		if err := cardRepo.Update(ctx, card); err != nil {
			_ = tpmProv.NVUndefine(nvHandle)
			return nil, fmt.Errorf("更新卡片 TPM 元数据失败: %w", err)
		}
	}

	out.Card = card
	return out, nil
}

// ResetPIN 用 PUK 或 AdminKey 重置 PIN。
// PUK 模式：PUK 直接解密主密钥 → 用新 PIN 重新加密主密钥
// Admin 模式：AdminKey 直接解密主密钥 → 用新 PIN 重新加密主密钥
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
		// PUK 模式：PUK 直接解密主密钥（与 Admin 一致）
		masterKey, err = tryUnlockByType(card, "puk", secret)
		if err != nil {
			if ferr := bumpFailure(ctx, cardRepo, card, "puk"); ferr != nil {
				return fmt.Errorf("%w (记录失败次数时出错: %v)", err, ferr)
			}
			return err
		}
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

	// 同步清零卡片级 PIN 失败标记
	card.PINFailedCount = 0
	card.PINLocked = false

	return cardRepo.Update(ctx, card)
}

// ResetPUK 用 AdminKey 验证权限，然后用 newPUK 重新加密主密钥。
// AdminKey 解密主密钥 → 用新 PUK 重新加密主密钥（PUK 与 PIN/Admin 统一架构）
func ResetPUK(ctx context.Context, cardRepo *storage.CardRepo, card *storage.Card, adminKey, currentPIN, newPUK string) error {
	if newPUK == "" {
		return fmt.Errorf("新 PUK 不能为空")
	}
	// 验证 AdminKey 权限并解密主密钥
	masterKey, err := tryUnlockByType(card, "admin", adminKey)
	if err != nil {
		if ferr := bumpFailure(ctx, cardRepo, card, "admin"); ferr != nil {
			return fmt.Errorf("%w (记录失败次数时出错: %v)", err, ferr)
		}
		return err
	}
	defer zeroBytes(masterKey)

	// 用新 PUK 加密主密钥（与 PIN/Admin 统一逻辑）
	newEntry, err := encryptMasterKey(masterKey, []byte(newPUK), "puk", "")
	if err != nil {
		return fmt.Errorf("用新 PUK 加密主密钥失败: %w", err)
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
	secLevel := card.SecurityLevel
	if secLevel == "" {
		secLevel = storage.SecurityLevelLow
	}

	switch secLevel {
	case storage.SecurityLevelHigh:
		// 高安全等级：在 TPM 内生成非对称密钥对，私钥永不出 TPM。
		if m.tpmProvider == nil || !m.tpmProvider.Available() {
			return nil, fmt.Errorf("high 安全等级需要可用的 TPM Provider")
		}
		cert, err := encryptAndStoreCertWithTPMHigh(ctx, m.certRepo, m.tpmProvider, req, masterKey)
		if err != nil {
			return nil, err
		}
		// 公钥从 wrapped blob 中读出（CertContent 已是 PEM）
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: derFromPEM(cert.CertContent)}, nil

	case storage.SecurityLevelMedium:
		// 中安全等级：本地生成密钥对 → master 加密 → TPM 证书密钥再加密
		if m.tpmProvider == nil || !m.tpmProvider.Available() {
			return nil, fmt.Errorf("medium 安全等级需要可用的 TPM Provider")
		}
		privDER, pubDER, err := generateKeyPair(req.KeyType)
		if err != nil {
			return nil, fmt.Errorf("生成密钥对失败: %w", err)
		}
		defer zeroBytes(privDER)
		cert, err := encryptAndStoreCertWithTPMCertKey(ctx, m.certRepo, m.tpmProvider, req, masterKey, card, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil

	default:
		// 低安全等级：仅主密钥加密（原有逻辑）
		privDER, pubDER, err := generateKeyPair(req.KeyType)
		if err != nil {
			return nil, fmt.Errorf("生成密钥对失败: %w", err)
		}
		defer zeroBytes(privDER)
		cert, err := encryptAndStoreCert(ctx, m.certRepo, req, masterKey, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil
	}
}

// derFromPEM 从 PEM 块中提取 DER；若已是 DER 则原样返回。
func derFromPEM(b []byte) []byte {
	if blk, _ := pem.Decode(b); blk != nil {
		return blk.Bytes
	}
	return b
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
// 当 SecretData 为空时仅存储公开元数据；非空时根据安全等级加密：
//   - low    ：仅 master 加密
//   - medium ：master 加密 + TPM 证书密钥再加密（双层）
//   - high   ：拒绝（凭据导入与 high 卡的"私钥永不出 TPM"语义冲突）
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

	if len(req.SecretData) > 0 {
		if len(masterKey) == 0 {
			return nil, fmt.Errorf("加密私密内容需要主密钥")
		}

		secLevel := storage.SecurityLevelLow
		if card != nil && card.SecurityLevel != "" {
			secLevel = card.SecurityLevel
		}

		// 1. 生成 tempKey，master 加密
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

		// 2. tempKey 加密私密数据 → inner
		inner, err := cryptoutil.EncryptAES256GCM(tempKey, req.SecretData)
		if err != nil {
			return nil, fmt.Errorf("加密私密内容失败: %w", err)
		}

		final := inner
		// 3. medium / high：从 TPM NV 读出证书密钥再加密一层
		if secLevel == storage.SecurityLevelMedium || secLevel == storage.SecurityLevelHigh {
			if m.tpmProvider == nil || !m.tpmProvider.Available() {
				return nil, fmt.Errorf("%s 卡片需要 TPM Provider", secLevel)
			}
			if card.TPMCertKeyNVHandle == 0 {
				return nil, fmt.Errorf("%s 卡片 TPM NV 句柄缺失", secLevel)
			}
			nvAuth := deriveTPMCertKeyAuth(masterKey)
			defer zeroBytes(nvAuth)
			tpmCertKey, err := m.tpmProvider.NVRead(tpm.NVHandle(card.TPMCertKeyNVHandle), nvAuth)
			if err != nil {
				return nil, fmt.Errorf("读取 TPM 证书密钥失败: %w", err)
			}
			defer zeroBytes(tpmCertKey)
			outer, err := cryptoutil.EncryptAES256GCM(tpmCertKey, inner)
			if err != nil {
				return nil, fmt.Errorf("TPM 证书密钥加密失败: %w", err)
			}
			final = outer
			cert.TPMPlatform = storage.TPMPlatform(tpmPlatformMediumV2)
			mark := sha256.Sum256([]byte("medium-v2/" + card.UUID))
			cert.TPMCertKeySalt = mark[:]
		}

		cert.TempKeySalt = tempKeySalt
		cert.TempKeyEnc = tempKeyEnc
		cert.PrivateData = final
	}

	if err := m.certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存安全凭据失败: %w", err)
	}
	return cert, nil
}

// ImportPrivateKey 导入私钥到卡片。
//
//   - low    ：master 加密
//   - medium ：master 加密 + TPM 证书密钥再加密
//   - high   ：用 TPM 芯片内的"保护密钥"加密导入的私钥（混合加密：TPM RSA 加密 AES key → AES 加密 privDER）
//              解密时必须经过 TPM 芯片解密 AES key，私钥受 TPM 硬件保护
func (m *KeyManager) ImportPrivateKey(ctx context.Context, req KeyGenRequest, masterKey, privDER, pubDER []byte) (*KeyGenResult, error) {
	card, err := m.cardRepo.GetByUUID(ctx, req.CardUUID)
	if err != nil {
		return nil, fmt.Errorf("查询卡片失败: %w", err)
	}
	if card == nil {
		return nil, fmt.Errorf("卡片不存在: %s", req.CardUUID)
	}
	secLevel := card.SecurityLevel
	if secLevel == "" {
		secLevel = storage.SecurityLevelLow
	}
	switch secLevel {
	case storage.SecurityLevelHigh:
		// 用 TPM 保护密钥加密导入的私钥（混合加密）
		if m.tpmProvider == nil || !m.tpmProvider.Available() {
			return nil, fmt.Errorf("high 卡片需要可用的 TPM Provider")
		}
		cert, err := importPrivateKeyWithTPMWrapping(ctx, m.certRepo, m.tpmProvider, req, masterKey, card, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil

	case storage.SecurityLevelMedium:
		if m.tpmProvider == nil || !m.tpmProvider.Available() {
			return nil, fmt.Errorf("medium 卡片需要 TPM Provider")
		}
		cert, err := encryptAndStoreCertWithTPMCertKey(ctx, m.certRepo, m.tpmProvider, req, masterKey, card, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil
	default:
		cert, err := encryptAndStoreCert(ctx, m.certRepo, req, masterKey, privDER, pubDER)
		if err != nil {
			return nil, err
		}
		return &KeyGenResult{CertUUID: cert.UUID, PublicKeyDER: pubDER}, nil
	}
}

// importPrivateKeyWithTPMWrapping 用 TPM 保护密钥（RSA-2048）混合加密导入的证书私钥。
//
// 流程：
//  1. 获取或创建 TPM 保护密钥（wrapping key）——存为 card 上的内部证书
//  2. 生成随机 AES-256 密钥
//  3. AES-GCM(aesKey, privDER) → encPrivDER
//  4. TPM RSA 加密 aesKey（TPM.LoadKey → TPM.Encrypt? 不行，我们用公钥直接加密）
//     实际上：TPM 的 wrapping key 公钥是已知的，直接用 Go rsa.EncryptOAEP 加密 aesKey
//     解密时：TPM.LoadKey → TPM.Decrypt(encAESKey) → aesKey → 解密 privDER
//  5. 存储 cert.PrivateData = encPrivDER, cert.TPMPrivateBlob = encAESKey
//
// 这样 privDER 只有经过 TPM 才能解密（因为 aesKey 被 TPM RSA 公钥加密，私钥在 TPM 内）。
func importPrivateKeyWithTPMWrapping(ctx context.Context, certRepo *storage.CertRepo, tp tpm.Provider, req KeyGenRequest, masterKey []byte, card *storage.Card, privDER, pubDER []byte) (*storage.Certificate, error) {
	// 1. 获取或创建保护密钥
	wrappingKey, err := getOrCreateWrappingKey(ctx, certRepo, tp, masterKey, card)
	if err != nil {
		return nil, fmt.Errorf("获取 TPM 保护密钥失败: %w", err)
	}

	// 2. 解析保护密钥公钥（用于 RSA 加密 AES key）
	wkPub, err := x509.ParsePKIXPublicKey(wrappingKey.Public)
	if err != nil {
		return nil, fmt.Errorf("解析保护密钥公钥失败: %w", err)
	}
	rsaPub, ok := wkPub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("保护密钥必须是 RSA（当前: %T）", wkPub)
	}

	// 3. 生成随机 AES-256 密钥
	aesKey, err := cryptoutil.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("生成 AES 密钥失败: %w", err)
	}
	defer zeroBytes(aesKey)

	// 4. AES-GCM 加密 privDER
	encPrivDER, err := cryptoutil.EncryptAES256GCM(aesKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("AES 加密私钥失败: %w", err)
	}

	// 5. 用保护密钥公钥 RSA PKCS#1 v1.5 加密 AES key
	// 注意：使用 PKCS1v15 而非 OAEP，因为 TPM/PCP 硬件密钥不支持 OAEP scheme
	encAESKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, aesKey)
	if err != nil {
		return nil, fmt.Errorf("RSA 加密 AES 密钥失败: %w", err)
	}

	// 6. 存储
	pemType := "PUBLIC KEY"
	if _, parseErr := parseCertLenient(pubDER); parseErr == nil {
		pemType = "CERTIFICATE"
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubDER})

	cert := &storage.Certificate{
		UUID:           uuid.New().String(),
		SlotType:       storage.SlotTypeLocal,
		CardUUID:       req.CardUUID,
		CertType:       req.CertType,
		KeyType:        req.KeyType,
		CertContent:    pubPEM,
		PrivateData:    encPrivDER,          // AES 加密的私钥
		TPMPrivateBlob: encAESKey,           // TPM RSA 加密的 AES key
		TPMPlatform:    storage.TPMPlatform("high-import-v1"),
		Remark:         req.Remark,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	return cert, nil
}

// getOrCreateWrappingKey 获取卡片的 TPM 保护密钥；如果不存在则在 TPM 芯片内创建一个。
// 保护密钥以"内部证书"形式存储（CertType=internal, KeyType=wrapping-key）。
func getOrCreateWrappingKey(ctx context.Context, certRepo *storage.CertRepo, tp tpm.Provider, masterKey []byte, card *storage.Card) (*tpm.WrappedKey, error) {
	// 查找已有的 wrapping key
	certs, err := certRepo.ListByCard(ctx, card.UUID)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if string(c.CertType) == "internal" && c.KeyType == "wrapping-key" && len(c.TPMWrappedBlob) > 0 {
			return unmarshalWrappedKey(c.TPMWrappedBlob)
		}
	}

	// 不存在则创建
	wrapAuth := deriveTPMHighKeyAuth(masterKey, "wrapping-key:"+card.UUID)
	defer zeroBytes(wrapAuth)
	wrapped, _, err := tp.CreateKey(tpm.KeyAlgRSA2048, wrapAuth)
	if err != nil {
		return nil, fmt.Errorf("TPM 创建保护密钥失败: %w", err)
	}
	wkJSON, err := marshalWrappedKey(wrapped)
	if err != nil {
		return nil, err
	}

	// 存为内部证书
	internalCert := &storage.Certificate{
		UUID:           uuid.New().String(),
		SlotType:       storage.SlotTypeLocal,
		CardUUID:       card.UUID,
		CertType:       "internal",
		KeyType:        "wrapping-key",
		TPMPlatform:    storage.TPMPlatform(tpmPlatformHighV1),
		TPMWrappedBlob: wkJSON,
		CertContent:    wrapped.Public,
		Remark:         "TPM 保护密钥（用于加密导入的证书私钥）",
	}
	if err := certRepo.Create(ctx, internalCert); err != nil {
		return nil, fmt.Errorf("保存保护密钥记录失败: %w", err)
	}
	return wrapped, nil
}

// ---- 内部工具函数 ----

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

// encryptAndStoreCertWithTPMHigh 高安全等级：直接在 TPM 内生成非对称密钥对，私钥永不出 TPM。
//
// 数据流：
//
//	tpm.CreateKey(alg, auth=HMAC(masterKey, certUUID))
//	  → wrapped blob 入库 cert.TPMWrappedBlob
//	  → 公钥 PEM 入库 cert.CertContent
//	签名时：tpm.LoadKey(wrapped, auth) → tpm.Sign(handle, digest, scheme) → tpm.FlushHandle(handle)
//	私钥从未以明文形式出现在 Go 进程内存（真 TPM 接入后）。
func encryptAndStoreCertWithTPMHigh(ctx context.Context, certRepo *storage.CertRepo, tp tpm.Provider, req KeyGenRequest, masterKey []byte) (*storage.Certificate, error) {
	alg, err := keyTypeToTPMAlg(req.KeyType)
	if err != nil {
		return nil, err
	}
	certUUID := uuid.New().String()
	auth := deriveTPMHighKeyAuth(masterKey, certUUID)
	defer zeroBytes(auth)

	wrapped, _, err := tp.CreateKey(alg, auth)
	if err != nil {
		return nil, fmt.Errorf("TPM CreateKey 失败: %w", err)
	}
	wrappedJSON, err := marshalWrappedKey(wrapped)
	if err != nil {
		return nil, err
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrapped.Public})

	cert := &storage.Certificate{
		UUID:           certUUID,
		SlotType:       storage.SlotTypeLocal,
		CardUUID:       req.CardUUID,
		CertType:       req.CertType,
		KeyType:        req.KeyType,
		CertContent:    pubPEM,
		TPMPlatform:    storage.TPMPlatform(tpmPlatformHighV1),
		TPMWrappedBlob: wrappedJSON,
		Remark:         req.Remark,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	return cert, nil
}

// encryptAndStoreCertWithTPMCertKey 中安全等级：master 加密 → TPM 证书密钥再加密。
//
// 数据流：
//
//	privDER → AES-GCM(tempKey) → inner
//	tempKey → AES-GCM(HMAC(masterKey, salt)) → cert.TempKeyEnc
//	tpmCertKey ← tpm.NVRead(card.TPMCertKeyNVHandle, auth=HMAC(masterKey,...))   // 一次性
//	outer = AES-GCM(tpmCertKey, inner)                                            // TPM 证书密钥外层加密
//	cert.PrivateData = outer
//
// 解密时反向：tpmCertKey ← NVRead → 解 outer → 用 masterKey 解 tempKey → 解 privDER。
// 这样数据库被脱出后，没有 TPM 也无法解密私钥；同时主密钥（PIN 解出）即可在 TPM 上验证。
func encryptAndStoreCertWithTPMCertKey(ctx context.Context, certRepo *storage.CertRepo, tp tpm.Provider, req KeyGenRequest, masterKey []byte, card *storage.Card, privDER, pubDER []byte) (*storage.Certificate, error) {
	if card.TPMCertKeyNVHandle == 0 {
		return nil, fmt.Errorf("medium 卡片 TPM NV 句柄未初始化（请确认创建卡片时 TPM Provider 可用）")
	}

	// 1. 生成 tempKey 并用 master 加密
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

	// 2. 第一层：tempKey 加密私钥（与 low 等级一致，得到 inner）
	inner, err := cryptoutil.EncryptAES256GCM(tempKey, privDER)
	if err != nil {
		return nil, fmt.Errorf("master 层加密私钥失败: %w", err)
	}

	// 3. 第二层：从 TPM NV 读出 TPM 证书密钥，再加密 inner 得到 outer
	nvAuth := deriveTPMCertKeyAuth(masterKey)
	defer zeroBytes(nvAuth)
	tpmCertKey, err := tp.NVRead(tpm.NVHandle(card.TPMCertKeyNVHandle), nvAuth)
	if err != nil {
		return nil, fmt.Errorf("读取 TPM 证书密钥失败: %w", err)
	}
	defer zeroBytes(tpmCertKey)
	outer, err := cryptoutil.EncryptAES256GCM(tpmCertKey, inner)
	if err != nil {
		return nil, fmt.Errorf("TPM 证书密钥加密失败: %w", err)
	}

	// 4. 落库
	pemType := "PUBLIC KEY"
	if _, parseErr := parseCertLenient(pubDER); parseErr == nil {
		pemType = "CERTIFICATE"
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: pubDER})

	// cert.TPMCertKeySalt 写入一个 32 字节"版本/cardUUID 摘要"作为标记，方便迁移期识别
	mark := sha256.Sum256([]byte("medium-v2/" + card.UUID))
	cert := &storage.Certificate{
		UUID:           uuid.New().String(),
		SlotType:       storage.SlotTypeLocal,
		CardUUID:       req.CardUUID,
		CertType:       req.CertType,
		KeyType:        req.KeyType,
		CertContent:    pubPEM,
		TempKeySalt:    tempKeySalt,
		TempKeyEnc:     tempKeyEnc,
		PrivateData:    outer,
		TPMPlatform:    storage.TPMPlatform(tpmPlatformMediumV2),
		TPMCertKeySalt: mark[:],
		Remark:         req.Remark,
	}
	if err := certRepo.Create(ctx, cert); err != nil {
		return nil, fmt.Errorf("保存证书失败: %w", err)
	}
	return cert, nil
}

// DecryptMediumPrivateData 在 medium 模式下解密 cert.PrivateData，
// 返回内层（master 加密层）的密文 inner。供 slot 与 keymgr 共用。
func DecryptMediumPrivateData(tp tpm.Provider, card *storage.Card, cert *storage.Certificate, masterKey []byte) ([]byte, error) {
	if tp == nil || !tp.Available() {
		return nil, fmt.Errorf("medium 卡片解密需要 TPM Provider")
	}
	if card.TPMCertKeyNVHandle == 0 {
		return nil, fmt.Errorf("medium 卡片 TPM NV 句柄缺失")
	}
	nvAuth := deriveTPMCertKeyAuth(masterKey)
	defer zeroBytes(nvAuth)
	tpmCertKey, err := tp.NVRead(tpm.NVHandle(card.TPMCertKeyNVHandle), nvAuth)
	if err != nil {
		return nil, fmt.Errorf("读取 TPM 证书密钥失败: %w", err)
	}
	defer zeroBytes(tpmCertKey)
	inner, err := cryptoutil.DecryptAES256GCM(tpmCertKey, cert.PrivateData)
	if err != nil {
		return nil, fmt.Errorf("TPM 证书密钥解密失败: %w", err)
	}
	return inner, nil
}

// DecryptTPMCertKey 用 ADMINKEY 解密 TPM 证书密钥的"应急恢复副本"。
//
// 注意：medium 模式正常运行时由 PIN 解出的主密钥派生 NV authValue 来读取 TPM 证书密钥，
// 不需要 AdminKey。本函数仅用于以下场景：
//  1. 用户忘记 PIN/PUK，但 AdminKey 还在 → 配合 AdminKey 重置 PIN 后恢复
//  2. TPM 设备更换，需要把证书密钥重新写入新设备的 NV
//  3. 调试 / 数据迁移
func DecryptTPMCertKey(card *storage.Card, adminKey string) ([]byte, error) {
	if len(card.TPMCertKeyEnc) == 0 {
		return nil, fmt.Errorf("卡片未设置 TPM 证书密钥应急副本")
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
