// Package cloud 实现 Cloud Slot。
// 通过 HTTP 与 servers 通信，签名/解密在服务端执行，私钥不离开服务器。
//
// Cloud Slot 工作流：
//  1. Login：POST /api/auth/login → 获取 JWT，缓存到内存
//  2. FindObjects：GET /api/cards/{uuid}/certs → 缓存证书列表到内存
//  3. Sign：POST /api/cards/{uuid}/sign → 发送数据，服务端签名返回
//  4. Decrypt：POST /api/cards/{uuid}/decrypt → 服务端解密返回
package cloud

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Slot 是 Cloud Slot 实现。
// 通过 HTTP 客户端与 servers（OpenCert Platform）通信。
type Slot struct {
	mu     sync.RWMutex
	slotID pkcs11types.SlotID
	card   *storage.Card // 本地 SQLite 中的卡片记录（含 cloud_url、auth_token）
	client *Client

	// 登录状态
	loggedIn bool
	userUUID string

	// 证书对象缓存：handle -> Cert
	objects    map[pkcs11types.ObjectHandle]*Cert
	nextHandle uint32

	// 离线缓存
	cachedCerts  []*Cert       // 缓存的证书列表（公开部分，不含私钥）
	cacheTime    time.Time     // 缓存时间
	cacheTTL     time.Duration // 缓存 TTL，默认 24 小时
	networkAvail bool          // 网络是否可用
}

// New 创建 Cloud Slot 实例。
// allowInsecure 控制是否允许非 HTTPS 连接（仅开发环境）。
func New(slotID pkcs11types.SlotID, card *storage.Card, allowInsecure bool) (*Slot, error) {
	client, err := NewClient(card.CloudURL, allowInsecure)
	if err != nil {
		return nil, fmt.Errorf("创建 Cloud Slot 失败: %w", err)
	}
	return &Slot{
		slotID:       slotID,
		card:         card,
		client:       client,
		objects:      make(map[pkcs11types.ObjectHandle]*Cert),
		nextHandle:   1,
		cacheTTL:     24 * time.Hour,
		networkAvail: true,
	}, nil
}

// SlotID 返回 Slot ID。
func (s *Slot) SlotID() pkcs11types.SlotID {
	return s.slotID
}

// SlotInfo 返回 Slot 信息。
func (s *Slot) SlotInfo() pkcs11types.SlotInfo {
	return pkcs11types.SlotInfo{
		SlotID:       s.slotID,
		Description:  fmt.Sprintf("Cloud Card: %s [%s]", s.card.CardName, s.card.CloudURL),
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

	flags := pkcs11types.CKF_TOKEN_INITIALIZED | pkcs11types.CKF_LOGIN_REQUIRED
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
		Model:           "CloudCard-v1",
		SerialNumber:    s.card.UUID[:min(16, len(s.card.UUID))],
		Flags:           flags,
		MaxPinLen:       64,
		MinPinLen:       4,
		TotalPublicMem:  0xFFFFFFFF,
		FreePublicMem:   0xFFFFFFFF,
		TotalPrivateMem: 0xFFFFFFFF,
		FreePrivateMem:  0xFFFFFFFF,
	}
}

// Mechanisms 返回支持的算法列表（云端支持的算法）。
func (s *Slot) Mechanisms() []pkcs11types.MechanismType {
	return []pkcs11types.MechanismType{
		pkcs11types.CKM_RSA_PKCS,
		pkcs11types.CKM_RSA_PKCS_OAEP,
		pkcs11types.CKM_RSA_PKCS_PSS,
		pkcs11types.CKM_SHA256_RSA_PKCS,
		pkcs11types.CKM_SHA384_RSA_PKCS,
		pkcs11types.CKM_SHA512_RSA_PKCS,
		pkcs11types.CKM_SHA256_RSA_PKCS_PSS,
		pkcs11types.CKM_ECDSA,
		pkcs11types.CKM_ECDSA_SHA256,
		pkcs11types.CKM_ECDSA_SHA384,
		pkcs11types.CKM_ECDSA_SHA512,
	}
}

// Login 使用 PIN（格式：username:password）登录 servers。
// PIN 格式：`username:password`，例如 `alice:mypassword`
func (s *Slot) Login(ctx context.Context, userType pkcs11types.UserType, pin string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loggedIn {
		return fmt.Errorf("%w", pkcs11types.CKR_USER_ALREADY_LOGGED_IN)
	}

	// 解析 PIN：username:password
	username, password, err := parsePIN(pin)
	if err != nil {
		return fmt.Errorf("%w: %v", pkcs11types.CKR_PIN_INCORRECT, err)
	}

	// 登录 servers
	resp, err := s.client.Login(ctx, username, password)
	if err != nil {
		if IsNetworkError(err) {
			s.networkAvail = false
			slog.Warn("Cloud Slot 网络不可用，登录失败", "error", err)
		}
		return fmt.Errorf("%w: %v", pkcs11types.CKR_PIN_INCORRECT, err)
	}

	s.userUUID = resp.UserUUID
	s.loggedIn = true
	s.networkAvail = true

	// 预加载证书列表
	if err := s.loadObjects(ctx); err != nil {
		slog.Warn("Cloud Slot 加载证书失败，尝试使用缓存", "error", err)
		// 加载失败时尝试使用离线缓存
		if len(s.cachedCerts) > 0 {
			s.loadFromCache()
			slog.Info("Cloud Slot 使用离线缓存", "count", len(s.cachedCerts))
		} else {
			s.loggedIn = false
			s.userUUID = ""
			return fmt.Errorf("加载云端证书失败且无缓存: %w", err)
		}
	}

	return nil
}

// Logout 注销，清除 Token 和缓存。
func (s *Slot) Logout(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.client.SetToken("")
	s.loggedIn = false
	s.userUUID = ""
	s.objects = make(map[pkcs11types.ObjectHandle]*Cert)
	s.nextHandle = 1
	return nil
}

// IsLoggedIn 返回登录状态。
func (s *Slot) IsLoggedIn() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loggedIn
}

// FindObjects 根据属性模板查找对象。
// 网络不可用时返回缓存数据。
func (s *Slot) FindObjects(ctx context.Context, template []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 尝试刷新缓存（如果 TTL 过期且网络可用）
	if s.networkAvail && s.isCacheExpired() {
		go s.tryRefreshCache()
	}

	var result []pkcs11types.ObjectHandle
	for handle, cert := range s.objects {
		if matchCloudTemplate(cert, template) {
			result = append(result, handle)
		}
	}
	return result, nil
}

// GetAttributes 获取对象属性。
func (s *Slot) GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrTypes []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	return buildCloudAttributes(cert, attrTypes)
}

// Sign 请求 servers 使用云端私钥签名。
// 网络不可用时返回 CKR_DEVICE_REMOVED。
func (s *Slot) Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	netAvail := s.networkAvail
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	if !netAvail {
		return nil, pkcs11types.CKR_DEVICE_REMOVED
	}

	// 确保 Token 有效
	if err := s.client.EnsureToken(ctx); err != nil {
		s.mu.Lock()
		s.networkAvail = false
		s.mu.Unlock()
		return nil, pkcs11types.CKR_TOKEN_NOT_RECOGNIZED
	}

	mechStr := mechanismToString(mechanism.Type)
	sig, err := s.client.Sign(ctx, s.card.CloudCardUUID, cert.UUID, mechStr, data)
	if err != nil {
		if IsNetworkError(err) {
			s.mu.Lock()
			s.networkAvail = false
			s.mu.Unlock()
			return nil, pkcs11types.CKR_DEVICE_REMOVED
		}
		return nil, err
	}

	return sig, nil
}

// Decrypt 请求 servers 使用云端私钥解密。
// 网络不可用时返回 CKR_DEVICE_REMOVED。
func (s *Slot) Decrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error) {
	s.mu.RLock()
	cert, ok := s.objects[handle]
	netAvail := s.networkAvail
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("对象句柄 %d 不存在", handle)
	}

	if !netAvail {
		return nil, pkcs11types.CKR_DEVICE_REMOVED
	}

	// 确保 Token 有效
	if err := s.client.EnsureToken(ctx); err != nil {
		s.mu.Lock()
		s.networkAvail = false
		s.mu.Unlock()
		return nil, pkcs11types.CKR_TOKEN_NOT_RECOGNIZED
	}

	mechStr := mechanismToString(mechanism.Type)
	plain, err := s.client.Decrypt(ctx, s.card.CloudCardUUID, cert.UUID, mechStr, ciphertext)
	if err != nil {
		if IsNetworkError(err) {
			s.mu.Lock()
			s.networkAvail = false
			s.mu.Unlock()
			return nil, pkcs11types.CKR_DEVICE_REMOVED
		}
		return nil, err
	}

	return plain, nil
}

// Encrypt 云端不支持加密（使用公钥本地加密）。
func (s *Slot) Encrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("Cloud Slot 不支持加密操作（请使用公钥本地加密）")
}

// ---- 内部方法 ----

// loadObjects 从 servers 加载证书列表到内存缓存。
func (s *Slot) loadObjects(ctx context.Context) error {
	certs, err := s.client.ListCerts(ctx, s.card.CloudCardUUID)
	if err != nil {
		if IsNetworkError(err) {
			s.networkAvail = false
		}
		return err
	}

	s.networkAvail = true
	s.objects = make(map[pkcs11types.ObjectHandle]*Cert)
	s.nextHandle = 1

	for _, cert := range certs {
		handle := pkcs11types.ObjectHandle(s.nextHandle)
		s.objects[handle] = cert
		s.nextHandle++
	}

	// 更新离线缓存
	s.cachedCerts = certs
	s.cacheTime = time.Now()
	slog.Debug("Cloud Slot 证书缓存已更新", "count", len(certs))

	return nil
}

// loadFromCache 从离线缓存加载证书到对象映射。
func (s *Slot) loadFromCache() {
	s.objects = make(map[pkcs11types.ObjectHandle]*Cert)
	s.nextHandle = 1

	for _, cert := range s.cachedCerts {
		handle := pkcs11types.ObjectHandle(s.nextHandle)
		s.objects[handle] = cert
		s.nextHandle++
	}
}

// isCacheExpired 检查缓存是否已过期。
func (s *Slot) isCacheExpired() bool {
	if s.cacheTime.IsZero() {
		return true
	}
	return time.Since(s.cacheTime) > s.cacheTTL
}

// tryRefreshCache 尝试在后台刷新缓存。
func (s *Slot) tryRefreshCache() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.loadObjects(ctx); err != nil {
		slog.Warn("Cloud Slot 后台刷新缓存失败", "error", err)
		if IsNetworkError(err) {
			s.networkAvail = false
		}
	} else {
		s.networkAvail = true
		slog.Debug("Cloud Slot 缓存已后台刷新")
	}
}

// SetCacheTTL 设置缓存 TTL。
func (s *Slot) SetCacheTTL(ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheTTL = ttl
}

// IsCached 返回当前数据是否来自缓存。
func (s *Slot) IsCached() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.networkAvail && len(s.cachedCerts) > 0
}

// IsNetworkAvailable 返回网络是否可用。
func (s *Slot) IsNetworkAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.networkAvail
}

// parsePIN 解析 PIN 格式：username:password。
func parsePIN(pin string) (username, password string, err error) {
	for i, c := range pin {
		if c == ':' {
			return pin[:i], pin[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("PIN 格式错误，应为 username:password")
}

// mechanismToString 将 PKCS#11 算法类型转换为 servers 字符串。
func mechanismToString(t pkcs11types.MechanismType) string {
	switch t {
	case pkcs11types.CKM_ECDSA:
		return "ECDSA"
	case pkcs11types.CKM_ECDSA_SHA256:
		return "ECDSA_SHA256"
	case pkcs11types.CKM_ECDSA_SHA384:
		return "ECDSA_SHA384"
	case pkcs11types.CKM_ECDSA_SHA512:
		return "ECDSA_SHA512"
	case pkcs11types.CKM_SHA256_RSA_PKCS:
		return "SHA256_RSA_PKCS"
	case pkcs11types.CKM_SHA384_RSA_PKCS:
		return "SHA384_RSA_PKCS"
	case pkcs11types.CKM_SHA512_RSA_PKCS:
		return "SHA512_RSA_PKCS"
	case pkcs11types.CKM_SHA256_RSA_PKCS_PSS:
		return "SHA256_RSA_PSS"
	case pkcs11types.CKM_RSA_PKCS_PSS:
		return "RSA_PKCS_PSS"
	case pkcs11types.CKM_RSA_PKCS:
		return "RSA_PKCS"
	case pkcs11types.CKM_RSA_PKCS_OAEP:
		return "RSA_OAEP"
	default:
		return fmt.Sprintf("UNKNOWN_0x%X", uint32(t))
	}
}

// matchCloudTemplate 检查云端证书是否匹配属性模板。
func matchCloudTemplate(cert *Cert, template []pkcs11types.Attribute) bool {
	for _, attr := range template {
		if !matchCloudAttr(cert, attr) {
			return false
		}
	}
	return true
}

func matchCloudAttr(cert *Cert, attr pkcs11types.Attribute) bool {
	switch attr.Type {
	case pkcs11types.CKA_CLASS:
		if len(attr.Value) < 4 {
			return false
		}
		class := pkcs11types.ObjectClass(binary.BigEndian.Uint32(attr.Value))
		switch class {
		case pkcs11types.CKO_CERTIFICATE:
			return cert.CertType == "x509"
		case pkcs11types.CKO_PRIVATE_KEY:
			return true // 云端私钥始终存在
		case pkcs11types.CKO_PUBLIC_KEY:
			return len(cert.CertContent) > 0
		}
		return false
	case pkcs11types.CKA_LABEL:
		return string(attr.Value) == cert.Remark || string(attr.Value) == cert.UUID
	case pkcs11types.CKA_ID:
		return string(attr.Value) == cert.UUID[:min(len(cert.UUID), len(attr.Value))]
	case pkcs11types.CKA_TOKEN:
		return len(attr.Value) > 0 && attr.Value[0] == 1
	}
	return true
}

// buildCloudAttributes 构建云端证书的属性列表。
func buildCloudAttributes(cert *Cert, attrTypes []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error) {
	result := make([]pkcs11types.Attribute, 0, len(attrTypes))
	for _, t := range attrTypes {
		attr := pkcs11types.Attribute{Type: t}
		switch t {
		case pkcs11types.CKA_CLASS:
			attr.Value = uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))
		case pkcs11types.CKA_LABEL:
			attr.Value = []byte(cert.Remark)
		case pkcs11types.CKA_ID:
			attr.Value = []byte(cert.UUID)
		case pkcs11types.CKA_VALUE:
			attr.Value = cert.CertContent
		case pkcs11types.CKA_TOKEN:
			attr.Value = []byte{1}
		case pkcs11types.CKA_PRIVATE:
			attr.Value = []byte{1}
		case pkcs11types.CKA_SENSITIVE:
			attr.Value = []byte{1}
		case pkcs11types.CKA_EXTRACTABLE:
			attr.Value = []byte{0} // 云端私钥不可导出
		case pkcs11types.CKA_SIGN:
			attr.Value = []byte{1}
		case pkcs11types.CKA_DECRYPT:
			attr.Value = []byte{1}
		default:
			attr.Value = nil
		}
		result = append(result, attr)
	}
	return result, nil
}

func uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
