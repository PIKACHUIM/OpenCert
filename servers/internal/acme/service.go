// Package acme 提供 ACME 协议服务（RFC 8555）。
package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/storage"
)

// Config 是 ACME 服务实例配置。
type Config struct {
	UUID             string `json:"uuid"`
	Path             string `json:"path"`              // 路径前缀（如 "letsencrypt"）
	CAUUID           string `json:"ca_uuid"`            // 关联的 CA
	IssuanceTmplUUID string `json:"issuance_tmpl_uuid"` // 关联的颁发模板
	Enabled          bool   `json:"enabled"`
}

// Account 是 ACME 账户。
type Account struct {
	UUID      string    `json:"uuid"`
	ConfigID  string    `json:"config_id"`
	KeyID     string    `json:"key_id"`     // JWK Thumbprint
	PublicKey string    `json:"public_key"` // JWK JSON
	Contact   string    `json:"contact"`    // JSON 数组
	Status    string    `json:"status"`     // valid/deactivated/revoked
	CreatedAt time.Time `json:"created_at"`
}

// Order 是 ACME 订单。
type Order struct {
	UUID           string     `json:"uuid"`
	AccountUUID    string     `json:"account_uuid"`
	Status         string     `json:"status"` // pending/ready/processing/valid/invalid
	Identifiers    string     `json:"identifiers"` // JSON 数组 [{"type":"dns","value":"example.com"}]
	NotBefore      *time.Time `json:"not_before,omitempty"`
	NotAfter       *time.Time `json:"not_after,omitempty"`
	CertURL        string     `json:"cert_url,omitempty"`
	FinalizeURL    string     `json:"finalize_url"`
	Expires        time.Time  `json:"expires"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Authorization 是 ACME 授权。
type Authorization struct {
	UUID        string    `json:"uuid"`
	OrderUUID   string    `json:"order_uuid"`
	Identifier  string    `json:"identifier"` // JSON {"type":"dns","value":"example.com"}
	Status      string    `json:"status"`     // pending/valid/invalid/deactivated/expired/revoked
	Expires     time.Time `json:"expires"`
	CreatedAt   time.Time `json:"created_at"`
}

// Challenge 是 ACME 挑战。
type Challenge struct {
	UUID          string     `json:"uuid"`
	AuthzUUID     string     `json:"authz_uuid"`
	Type          string     `json:"type"`   // http-01/dns-01
	Token         string     `json:"token"`
	Status        string     `json:"status"` // pending/processing/valid/invalid
	ValidatedAt   *time.Time `json:"validated_at,omitempty"`
	ErrorJSON     string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// Service 是 ACME 服务。
type Service struct {
	db    *storage.DB
	caSvc *ca.Service // 用于 Finalize 时签发证书（可选，未注入时 Finalize 失败）
}

// NewService 创建 ACME 服务。
func NewService(db *storage.DB) *Service {
	return &Service{db: db}
}

// SetCASvc 注入 CA 签发服务（在 main.go 装配阶段调用以避免循环依赖）。
func (s *Service) SetCASvc(caSvc *ca.Service) {
	s.caSvc = caSvc
}

// ---- ACME 配置管理 ----

// CreateConfig 创建 ACME 服务实例配置。
func (s *Service) CreateConfig(ctx context.Context, cfg *Config) error {
	if cfg.Path == "" {
		return fmt.Errorf("ACME 路径不能为空")
	}
	cfg.UUID = uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_configs (uuid, path, ca_uuid, issuance_tmpl_uuid, enabled)
		 VALUES (?, ?, ?, ?, ?)`,
		cfg.UUID, cfg.Path, cfg.CAUUID, cfg.IssuanceTmplUUID, boolToInt(cfg.Enabled),
	)
	return err
}

// ListConfigs 查询所有 ACME 配置。
func (s *Service) ListConfigs(ctx context.Context) ([]*Config, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, path, ca_uuid, issuance_tmpl_uuid, enabled FROM acme_configs ORDER BY path`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*Config
	for rows.Next() {
		c := &Config{}
		var enabled int
		if err := rows.Scan(&c.UUID, &c.Path, &c.CAUUID, &c.IssuanceTmplUUID, &enabled); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

// GetConfigByPath 按路径查询 ACME 配置。
func (s *Service) GetConfigByPath(ctx context.Context, path string) (*Config, error) {
	c := &Config{}
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, path, ca_uuid, issuance_tmpl_uuid, enabled FROM acme_configs WHERE path = ? AND enabled = 1`, path,
	).Scan(&c.UUID, &c.Path, &c.CAUUID, &c.IssuanceTmplUUID, &enabled)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ACME 服务不存在: %s", path)
	}
	c.Enabled = enabled == 1
	return c, err
}

// DeleteConfig 删除 ACME 配置。
func (s *Service) DeleteConfig(ctx context.Context, cfgUUID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM acme_configs WHERE uuid = ?`, cfgUUID)
	return err
}

// ---- ACME 账户 ----

// CreateAccount 创建 ACME 账户。
func (s *Service) CreateAccount(ctx context.Context, acct *Account) error {
	acct.UUID = uuid.New().String()
	acct.Status = "valid"
	acct.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_accounts (uuid, config_id, key_id, public_key, contact, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		acct.UUID, acct.ConfigID, acct.KeyID, acct.PublicKey, acct.Contact, acct.Status, acct.CreatedAt,
	)
	return err
}

// GetAccountByKeyID 按 KeyID 查询账户。
func (s *Service) GetAccountByKeyID(ctx context.Context, keyID string) (*Account, error) {
	acct := &Account{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, config_id, key_id, public_key, contact, status, created_at
		 FROM acme_accounts WHERE key_id = ?`, keyID,
	).Scan(&acct.UUID, &acct.ConfigID, &acct.KeyID, &acct.PublicKey, &acct.Contact, &acct.Status, &acct.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ACME 账户不存在")
	}
	return acct, err
}

// GetAccountByUUID 按 UUID 查询账户。
func (s *Service) GetAccountByUUID(ctx context.Context, acctUUID string) (*Account, error) {
	acct := &Account{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, config_id, key_id, public_key, contact, status, created_at
		 FROM acme_accounts WHERE uuid = ?`, acctUUID,
	).Scan(&acct.UUID, &acct.ConfigID, &acct.KeyID, &acct.PublicKey, &acct.Contact, &acct.Status, &acct.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ACME 账户不存在: %s", acctUUID)
	}
	return acct, err
}

// ---- ACME 订单 ----

// CreateOrder 创建 ACME 订单。
func (s *Service) CreateOrder(ctx context.Context, order *Order) error {
	order.UUID = uuid.New().String()
	order.Status = "pending"
	order.Expires = time.Now().Add(7 * 24 * time.Hour) // 7 天过期
	order.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_orders (uuid, account_uuid, status, identifiers, not_before, not_after, finalize_url, expires, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		order.UUID, order.AccountUUID, order.Status, order.Identifiers,
		order.NotBefore, order.NotAfter, order.FinalizeURL, order.Expires, order.CreatedAt,
	)
	return err
}

// GetOrder 按 UUID 查询订单。
func (s *Service) GetOrder(ctx context.Context, orderUUID string) (*Order, error) {
	o := &Order{}
	var notBefore, notAfter sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, account_uuid, status, identifiers, not_before, not_after, cert_url, finalize_url, expires, created_at
		 FROM acme_orders WHERE uuid = ?`, orderUUID,
	).Scan(&o.UUID, &o.AccountUUID, &o.Status, &o.Identifiers, &notBefore, &notAfter,
		&o.CertURL, &o.FinalizeURL, &o.Expires, &o.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ACME 订单不存在: %s", orderUUID)
	}
	if notBefore.Valid {
		o.NotBefore = &notBefore.Time
	}
	if notAfter.Valid {
		o.NotAfter = &notAfter.Time
	}
	return o, err
}

// UpdateOrderStatus 更新订单状态。
func (s *Service) UpdateOrderStatus(ctx context.Context, orderUUID, status, certURL string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = ?, cert_url = ? WHERE uuid = ?`,
		status, certURL, orderUUID,
	)
	return err
}

// ---- ACME 授权与挑战 ----

// CreateAuthorization 创建授权。
func (s *Service) CreateAuthorization(ctx context.Context, authz *Authorization) error {
	authz.UUID = uuid.New().String()
	authz.Status = "pending"
	authz.Expires = time.Now().Add(7 * 24 * time.Hour)
	authz.CreatedAt = time.Now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_authorizations (uuid, order_uuid, identifier, status, expires, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		authz.UUID, authz.OrderUUID, authz.Identifier, authz.Status, authz.Expires, authz.CreatedAt,
	)
	return err
}

// CreateChallenge 创建挑战。
func (s *Service) CreateChallenge(ctx context.Context, ch *Challenge) error {
	ch.UUID = uuid.New().String()
	ch.Status = "pending"
	ch.CreatedAt = time.Now()

	// 生成随机 token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("生成 token 失败: %w", err)
	}
	ch.Token = base64.RawURLEncoding.EncodeToString(tokenBytes)

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO acme_challenges (uuid, authz_uuid, type, token, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		ch.UUID, ch.AuthzUUID, ch.Type, ch.Token, ch.Status, ch.CreatedAt,
	)
	return err
}

// GetChallenge 按 UUID 查询挑战。
func (s *Service) GetChallenge(ctx context.Context, chUUID string) (*Challenge, error) {
	ch := &Challenge{}
	var validatedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, authz_uuid, type, token, status, validated_at, error, created_at
		 FROM acme_challenges WHERE uuid = ?`, chUUID,
	).Scan(&ch.UUID, &ch.AuthzUUID, &ch.Type, &ch.Token, &ch.Status, &validatedAt, &ch.ErrorJSON, &ch.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("ACME 挑战不存在: %s", chUUID)
	}
	if validatedAt.Valid {
		ch.ValidatedAt = &validatedAt.Time
	}
	return ch, err
}

// ValidateChallenge 标记挑战为已验证。
func (s *Service) ValidateChallenge(ctx context.Context, chUUID string) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = 'valid', validated_at = ? WHERE uuid = ? AND status = 'pending'`,
		now, chUUID,
	)
	return err
}

// GenerateNonce 生成 ACME Nonce。
func (s *Service) GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(nonceBytes), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- ACME 挑战真实验证（HTTP-01 / DNS-01）----

// ChallengeValidationTimeout 是单次挑战验证的总超时。
const ChallengeValidationTimeout = 15 * time.Second

// ValidateHTTP01 执行 RFC 8555 §8.3 定义的 HTTP-01 挑战验证：
//
//	GET http://{domain}/.well-known/acme-challenge/{token}
//	响应体必须等于 keyAuthorization = token + "." + base64url(SHA-256(accountKey))
//
// keyAuth 是调用方提供的 keyAuthorization 期望值（由上层根据账户公钥计算）。
// 若 keyAuth 为空（简化场景），则仅要求响应体以 token 开头。
func (s *Service) ValidateHTTP01(ctx context.Context, domain, token, keyAuth string) error {
	if domain == "" {
		return fmt.Errorf("域名为空")
	}
	if token == "" {
		return fmt.Errorf("token 为空")
	}

	// 构造 URL，域名做粗粒度校验避免 SSRF（仅允许 DNS 名，不允许 IP）
	if ip := net.ParseIP(domain); ip != nil {
		return fmt.Errorf("HTTP-01 挑战不支持 IP 地址")
	}
	u := &url.URL{
		Scheme: "http",
		Host:   domain,
		Path:   "/.well-known/acme-challenge/" + token,
	}

	reqCtx, cancel := context.WithTimeout(ctx, ChallengeValidationTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "GlobalTrusts-ACME/1.0")

	client := &http.Client{
		Timeout: ChallengeValidationTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP-01 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP-01 响应非 200: %d", resp.StatusCode)
	}
	// 读取至多 4KB 响应体，避免恶意超大响应
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	content := strings.TrimSpace(string(body))
	if keyAuth != "" {
		if content != keyAuth {
			return fmt.Errorf("响应体与 keyAuthorization 不匹配")
		}
	} else {
		if !strings.HasPrefix(content, token) {
			return fmt.Errorf("响应体未以 token 开头")
		}
	}
	return nil
}

// ValidateDNS01 执行 RFC 8555 §8.4 定义的 DNS-01 挑战验证：
//
//	查询 _acme-challenge.{domain} TXT 记录
//	记录值必须等于 base64url(SHA-256(keyAuthorization))
//
// expected 是期望的 TXT 记录值（由上层计算）。若 expected 为空，则只要存在 TXT 记录即通过（简化模式）。
func (s *Service) ValidateDNS01(ctx context.Context, domain, expected string) error {
	if domain == "" {
		return fmt.Errorf("域名为空")
	}
	reqCtx, cancel := context.WithTimeout(ctx, ChallengeValidationTimeout)
	defer cancel()

	resolver := &net.Resolver{}
	txts, err := resolver.LookupTXT(reqCtx, "_acme-challenge."+domain)
	if err != nil {
		return fmt.Errorf("查询 TXT 记录失败: %w", err)
	}
	if len(txts) == 0 {
		return fmt.Errorf("未找到 _acme-challenge.%s 的 TXT 记录", domain)
	}
	if expected == "" {
		return nil
	}
	for _, t := range txts {
		if strings.TrimSpace(t) == expected {
			return nil
		}
	}
	return fmt.Errorf("TXT 记录值与期望不匹配")
}

// ValidateChallengeReal 根据挑战类型执行真实的外部验证，并更新状态。
// domain 从挑战关联的 Authorization.identifier 中解析（调用方提供）。
// keyAuth 是调用方传入的 keyAuthorization（HTTP-01）或 TXT 期望值（DNS-01）；可为空。
func (s *Service) ValidateChallengeReal(ctx context.Context, chUUID, domain, keyAuthOrTXT string) error {
	ch, err := s.GetChallenge(ctx, chUUID)
	if err != nil {
		return err
	}
	if ch.Status == "valid" {
		return nil
	}

	var verr error
	switch ch.Type {
	case "http-01":
		verr = s.ValidateHTTP01(ctx, domain, ch.Token, keyAuthOrTXT)
	case "dns-01":
		verr = s.ValidateDNS01(ctx, domain, keyAuthOrTXT)
	case "tls-alpn-01":
		verr = s.ValidateTLSALPN01(ctx, domain, keyAuthOrTXT)
	default:
		verr = fmt.Errorf("不支持的挑战类型: %s", ch.Type)
	}

	now := time.Now()
	if verr != nil {
		// 更新挑战为 invalid，附带错误信息
		errJSON, _ := json.Marshal(map[string]string{
			"type":   "urn:ietf:params:acme:error:unauthorized",
			"detail": verr.Error(),
		})
		_, _ = s.db.ExecContext(ctx,
			`UPDATE acme_challenges SET status = 'invalid', error = ?, validated_at = ? WHERE uuid = ?`,
			string(errJSON), now, chUUID,
		)
		// 同时把对应授权置 invalid
		_, _ = s.db.ExecContext(ctx,
			`UPDATE acme_authorizations SET status = 'invalid' WHERE uuid = ?`,
			ch.AuthzUUID,
		)
		return verr
	}

	// 成功：挑战和授权一起置 valid
	_, _ = s.db.ExecContext(ctx,
		`UPDATE acme_challenges SET status = 'valid', validated_at = ? WHERE uuid = ?`,
		now, chUUID,
	)
	_, _ = s.db.ExecContext(ctx,
		`UPDATE acme_authorizations SET status = 'valid' WHERE uuid = ?`,
		ch.AuthzUUID,
	)
	// 若该订单下所有 authz 都 valid，则订单转为 ready
	var orderUUID string
	if err := s.db.QueryRowContext(ctx,
		`SELECT order_uuid FROM acme_authorizations WHERE uuid = ?`, ch.AuthzUUID,
	).Scan(&orderUUID); err == nil {
		s.refreshOrderReady(ctx, orderUUID) //nolint:errcheck
	}
	return nil
}

// refreshOrderReady 若订单所有授权均 valid，则订单状态转为 ready。
func (s *Service) refreshOrderReady(ctx context.Context, orderUUID string) error {
	var pendingCount int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM acme_authorizations WHERE order_uuid = ? AND status != 'valid'`,
		orderUUID,
	).Scan(&pendingCount)
	if err != nil {
		return err
	}
	if pendingCount == 0 {
		_, err = s.db.ExecContext(ctx,
			`UPDATE acme_orders SET status = 'ready' WHERE uuid = ? AND status = 'pending'`,
			orderUUID,
		)
		return err
	}
	return nil
}

// ---- ACME 订单 Finalize（签发证书）----

// FinalizeResult 是 FinalizeOrder 的返回结果。
type FinalizeResult struct {
	OrderUUID string
	CertPEM   string // 完整叶子证书 PEM（不含链）
	CertUUID  string // 对应 Certificate 记录 UUID（由 ca 侧写入时返回）
}

// FinalizeOrder 完成订单：校验所有授权已 valid，解析 CSR，调用 caSvc.IssueCert 签发证书。
//
//	订单状态跳转：ready → processing → valid；cert_url 字段写入 Certificate UUID。
//
// csrDER 是 PKCS#10 CertificateRequest 的 DER 编码（RFC 8555 §7.4 的 "csr" 字段 base64url 解码后）。
func (s *Service) FinalizeOrder(ctx context.Context, orderUUID string, csrDER []byte) (*FinalizeResult, error) {
	if s.caSvc == nil {
		return nil, fmt.Errorf("ACME 服务未注入 CA 签发依赖")
	}
	order, err := s.GetOrder(ctx, orderUUID)
	if err != nil {
		return nil, err
	}
	if order.Status != "ready" && order.Status != "processing" {
		return nil, fmt.Errorf("订单状态不允许 finalize: %s", order.Status)
	}

	// 解析 CSR
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名校验失败: %w", err)
	}

	// 从订单标识符提取待签域名，校验 CSR 中的 SAN/CN 至少覆盖这些域名
	var idents []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(order.Identifiers), &idents); err != nil {
		return nil, fmt.Errorf("解析订单 identifiers 失败: %w", err)
	}
	csrNames := map[string]bool{}
	if csr.Subject.CommonName != "" {
		csrNames[strings.ToLower(csr.Subject.CommonName)] = true
	}
	for _, n := range csr.DNSNames {
		csrNames[strings.ToLower(n)] = true
	}
	for _, id := range idents {
		if id.Type != "dns" {
			continue
		}
		if !csrNames[strings.ToLower(id.Value)] {
			return nil, fmt.Errorf("CSR 未包含订单标识符 %s", id.Value)
		}
	}

	// 订单转 processing
	_, _ = s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = 'processing' WHERE uuid = ?`, orderUUID,
	)

	// 通过账户 → 配置反向查找 CA 和颁发模板
	var caUUID, issuanceTmplUUID string
	err = s.db.QueryRowContext(ctx,
		`SELECT c.ca_uuid, c.issuance_tmpl_uuid
		 FROM acme_accounts a
		 JOIN acme_configs c ON a.config_id = c.uuid
		 WHERE a.uuid = ?`, order.AccountUUID,
	).Scan(&caUUID, &issuanceTmplUUID)
	if err != nil {
		return nil, fmt.Errorf("查询 ACME 配置失败: %w", err)
	}
	if caUUID == "" {
		return nil, fmt.Errorf("ACME 配置未指定 CA")
	}

	// 构造签发请求：主体取 CSR 的 Subject，若为空则使用第一个 identifier 作为 CN
	subject := csr.Subject
	if subject.CommonName == "" && len(idents) > 0 {
		subject = pkix.Name{CommonName: idents[0].Value}
	}

	issueReq := &ca.IssueRequest{
		CAUUID:           caUUID,
		Subject:          subject,
		KeyType:          "", // 从 CSR 中的公钥推断，ca.IssueCert 不使用 KeyType 时跳过生成
		ValidDays:        90, // ACME 默认 90 天（Let's Encrypt 对齐）
		IsCA:             false,
		DNSNames:         csr.DNSNames,
		IPAddresses:      csr.IPAddresses,
		EmailAddrs:       csr.EmailAddresses,
		IssuanceTmplUUID: issuanceTmplUUID,
		CSRPublicKey:     csr.PublicKey, // 使用 CSR 中的公钥，不生成新密钥
	}

	resp, err := s.caSvc.IssueCert(ctx, issueReq)
	if err != nil {
		_, _ = s.db.ExecContext(ctx,
			`UPDATE acme_orders SET status = 'invalid' WHERE uuid = ?`, orderUUID,
		)
		return nil, fmt.Errorf("签发失败: %w", err)
	}

	// 订单 valid，cert_url 存证书序列号作为索引（下载时用）
	_, _ = s.db.ExecContext(ctx,
		`UPDATE acme_orders SET status = 'valid', cert_url = ? WHERE uuid = ?`,
		resp.SerialNumber, orderUUID,
	)

	return &FinalizeResult{
		OrderUUID: orderUUID,
		CertPEM:   resp.CertPEM,
		CertUUID:  resp.SerialNumber,
	}, nil
}

// GetCertificateForOrder 根据订单 UUID 返回证书 PEM。
// 通过订单的 cert_url（序列号）在 certificates 表中查询对应证书。
func (s *Service) GetCertificateForOrder(ctx context.Context, orderUUID string) (string, error) {
	order, err := s.GetOrder(ctx, orderUUID)
	if err != nil {
		return "", err
	}
	if order.Status != "valid" || order.CertURL == "" {
		return "", fmt.Errorf("订单尚未签发完成")
	}
	var pemContent []byte
	err = s.db.QueryRowContext(ctx,
		`SELECT cert_content FROM certificates WHERE serial_number = ? LIMIT 1`, order.CertURL,
	).Scan(&pemContent)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("证书未找到")
	}
	if err != nil {
		return "", err
	}
	// 校验是否为合法 PEM 证书
	if block, _ := pem.Decode(pemContent); block == nil {
		return "", fmt.Errorf("证书内容不是合法的 PEM 格式")
	}
	return string(pemContent), nil
}
