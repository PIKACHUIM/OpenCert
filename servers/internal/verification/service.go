// Package verification 管理用户提交的主体信息与扩展信息（域名/邮箱/IP）及其验证流程。
//
// 验证方式由模板决定：
//   - 主体模板的每个字段可设为 人工审核 / 自动接口（实名认证回调）/ 免验证；
//   - 扩展信息模板按类型设置 人工审核 / 自动验证（DNS/HTTP/TLS/邮箱验证码）/ 免验证；
//   - 验证通过后按模板有效期（1d/7d/30d…）过期，过期需重新自助验证或人工审核。
package verification

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/mailer"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

const (
	emailCodeTTL        = 15 * time.Minute
	emailCodeMaxAttempt = 5
)

// Service 是验证服务。
type Service struct {
	db           *storage.DB
	mailer       mailer.Mailer   // 系统 SMTP（未指定邮件接口时使用）
	providers    *identity.Store // 认证接口（可选）
	tlsValidator func(ctx context.Context, domain, keyAuth string) error
	httpClient   *http.Client
}

// NewService 创建验证服务。
func NewService(db *storage.DB) *Service {
	return &Service{db: db, httpClient: &http.Client{
		Timeout: 10 * time.Second,
		// 所有权验证不跟随跨主机跳转，避免把验证导向第三方地址
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Hostname() != via[0].URL.Hostname() {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}}
}

// SetMailer 注入系统邮件发送器。
func (s *Service) SetMailer(m mailer.Mailer) { s.mailer = m }

// SetProviders 注入认证接口存储（邮件接口选择、实名认证）。
func (s *Service) SetProviders(p *identity.Store) { s.providers = p }

// SetTLSValidator 注入 TLS 验证实现（复用 ACME TLS-ALPN-01 校验）。
func (s *Service) SetTLSValidator(fn func(ctx context.Context, domain, keyAuth string) error) {
	s.tlsValidator = fn
}

// ---- 模板读取 ----

type subjectTemplate struct {
	Fields       []identity.SubjectField
	ProviderUUID string
	Validity     string
}

func (s *Service) loadSubjectTemplate(ctx context.Context, tmplUUID string) (*subjectTemplate, error) {
	var raw, provider, validity string
	err := s.db.QueryRowContext(ctx,
		`SELECT fields, verify_provider_uuid, verify_validity FROM subject_templates WHERE uuid = ?`, tmplUUID,
	).Scan(&raw, &provider, &validity)
	if err != nil {
		return nil, err
	}
	fields, err := identity.ParseSubjectFields(raw)
	if err != nil {
		return nil, err
	}
	return &subjectTemplate{Fields: fields, ProviderUUID: provider, Validity: validity}, nil
}

// extensionPolicy 读取扩展模板策略；无模板时返回缺省策略。
func (s *Service) extensionPolicy(ctx context.Context, tmplUUID string) identity.ExtensionPolicy {
	if tmplUUID == "" {
		return identity.DefaultExtensionPolicy()
	}
	var raw string
	var legacyDays int
	if err := s.db.QueryRowContext(ctx,
		`SELECT verify_policy, verify_expires_days FROM extension_templates WHERE uuid = ?`, tmplUUID,
	).Scan(&raw, &legacyDays); err != nil {
		return identity.DefaultExtensionPolicy()
	}
	p, err := identity.ParseExtensionPolicy(raw)
	if err != nil {
		return identity.DefaultExtensionPolicy()
	}
	// 历史模板未配置新策略时沿用旧的有效期天数
	if (raw == "" || raw == "{}") && legacyDays > 0 {
		v := fmt.Sprintf("%dd", legacyDays)
		p.Domain.Validity, p.Email.Validity, p.IP.Validity = v, v, v
	}
	return p
}

// ---- 主体信息 ----

const subjectInfoColumns = `uuid, user_uuid, subject_tmpl_uuid, field_values, status, verify_mode, reject_reason,
	reviewed_by, reviewed_at, expires_at, created_at, updated_at`

func scanSubjectInfo(scan func(dest ...interface{}) error) (*storage.SubjectInfo, error) {
	info := &storage.SubjectInfo{}
	var reviewedBy sql.NullString
	var reviewedAt, expiresAt sql.NullTime
	if err := scan(&info.UUID, &info.UserUUID, &info.SubjectTmplUUID, &info.FieldValues, &info.Status,
		&info.VerifyMode, &info.RejectReason, &reviewedBy, &reviewedAt, &expiresAt, &info.CreatedAt, &info.UpdatedAt); err != nil {
		return nil, err
	}
	info.ReviewedBy = reviewedBy.String
	if reviewedAt.Valid {
		info.ReviewedAt = &reviewedAt.Time
	}
	if expiresAt.Valid {
		info.ExpiresAt = &expiresAt.Time
	}
	return info, nil
}

// prepareSubject 按模板校验字段并确定初始状态。
func (s *Service) prepareSubject(ctx context.Context, info *storage.SubjectInfo) error {
	info.Status, info.VerifyMode = "pending", identity.VerifyManual
	info.ExpiresAt = nil
	if info.SubjectTmplUUID == "" {
		return nil // 未关联模板：一律人工审核
	}
	tmpl, err := s.loadSubjectTemplate(ctx, info.SubjectTmplUUID)
	if err != nil {
		return fmt.Errorf("主体模板不存在或配置错误")
	}
	values := map[string]string{}
	if info.FieldValues != "" {
		if err := json.Unmarshal([]byte(info.FieldValues), &values); err != nil {
			return fmt.Errorf("主体字段格式错误")
		}
	}
	clean, err := identity.ValidateSubjectValues(tmpl.Fields, values)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(clean)
	info.FieldValues = string(raw)

	info.VerifyMode = identity.SubjectVerifyMode(tmpl.Fields)
	switch info.VerifyMode {
	case identity.VerifyNone:
		now := time.Now()
		info.Status = "approved"
		info.ReviewedBy = "system"
		info.ReviewedAt = &now
		info.ExpiresAt = identity.ExpiryFrom(now, tmpl.Validity)
	case identity.VerifyAuto:
		if tmpl.ProviderUUID == "" {
			// 模板要求自动认证却未配置接口：降级为人工审核，避免用户卡死
			info.VerifyMode = identity.VerifyManual
		} else {
			info.Status = "verifying"
		}
	}
	return nil
}

// CreateSubjectInfo 创建主体信息：按模板校验字段，并按验证方式进入 待审核/待实名/已通过。
func (s *Service) CreateSubjectInfo(ctx context.Context, info *storage.SubjectInfo) error {
	if err := s.prepareSubject(ctx, info); err != nil {
		return err
	}
	info.UUID = uuid.New().String()
	info.CreatedAt = time.Now()
	info.UpdatedAt = info.CreatedAt
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO subject_infos (uuid, user_uuid, subject_tmpl_uuid, field_values, status, verify_mode,
		 reviewed_by, reviewed_at, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		info.UUID, info.UserUUID, info.SubjectTmplUUID, info.FieldValues, info.Status, info.VerifyMode,
		nullString(info.ReviewedBy), info.ReviewedAt, info.ExpiresAt, info.CreatedAt, info.UpdatedAt,
	)
	return err
}

// ResubmitSubjectInfo 修改并重新提交主体信息（被驳回、已过期或需要更正时），重新进入验证流程。
func (s *Service) ResubmitSubjectInfo(ctx context.Context, infoUUID, userUUID, fieldValues string) (*storage.SubjectInfo, error) {
	info, err := s.GetSubjectInfo(ctx, infoUUID)
	if err != nil {
		return nil, err
	}
	if info.UserUUID != userUUID {
		return nil, fmt.Errorf("无权修改此主体信息")
	}
	if fieldValues != "" {
		info.FieldValues = fieldValues
	}
	if err := s.prepareSubject(ctx, info); err != nil {
		return nil, err
	}
	info.RejectReason = ""
	_, err = s.db.ExecContext(ctx,
		`UPDATE subject_infos SET field_values = ?, status = ?, verify_mode = ?, reject_reason = '',
		 reviewed_by = ?, reviewed_at = ?, expires_at = ?, updated_at = ? WHERE uuid = ?`,
		info.FieldValues, info.Status, info.VerifyMode, nullString(info.ReviewedBy), info.ReviewedAt,
		info.ExpiresAt, time.Now(), infoUUID)
	return info, err
}

// GetSubjectInfo 按 UUID 查询主体信息。
func (s *Service) GetSubjectInfo(ctx context.Context, infoUUID string) (*storage.SubjectInfo, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+subjectInfoColumns+` FROM subject_infos WHERE uuid = ?`, infoUUID)
	info, err := scanSubjectInfo(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("主体信息不存在")
	}
	return info, err
}

func (s *Service) querySubjects(ctx context.Context, where string, args ...interface{}) ([]*storage.SubjectInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+subjectInfoColumns+` FROM subject_infos`+where+` ORDER BY created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	infos := []*storage.SubjectInfo{}
	for rows.Next() {
		info, err := scanSubjectInfo(rows.Scan)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, rows.Err()
}

// ListAllSubjectInfos 查询全部用户的主体信息（管理员审核队列），status 为空表示不过滤。
func (s *Service) ListAllSubjectInfos(ctx context.Context, status string) ([]*storage.SubjectInfo, error) {
	if status == "" {
		return s.querySubjects(ctx, "")
	}
	return s.querySubjects(ctx, ` WHERE status = ?`, status)
}

// ListSubjectInfos 查询用户的主体信息列表。
func (s *Service) ListSubjectInfos(ctx context.Context, userUUID string) ([]*storage.SubjectInfo, error) {
	return s.querySubjects(ctx, ` WHERE user_uuid = ?`, userUUID)
}

// subjectValidity 返回主体信息对应模板的有效期（无模板默认 1 年）。
func (s *Service) subjectValidity(ctx context.Context, tmplUUID string) string {
	if tmplUUID == "" {
		return "365d"
	}
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT verify_validity FROM subject_templates WHERE uuid = ?`, tmplUUID).Scan(&v); err != nil || v == "" {
		return "365d"
	}
	return v
}

func (s *Service) approveSubject(ctx context.Context, infoUUID, reviewer string, fromStatus ...string) error {
	info, err := s.GetSubjectInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	allowed := false
	for _, st := range fromStatus {
		if info.Status == st {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("当前状态（%s）不能审核通过", info.Status)
	}
	now := time.Now()
	exp := identity.ExpiryFrom(now, s.subjectValidity(ctx, info.SubjectTmplUUID))
	_, err = s.db.ExecContext(ctx,
		`UPDATE subject_infos SET status = 'approved', reject_reason = '', reviewed_by = ?, reviewed_at = ?, expires_at = ?, updated_at = ?
		 WHERE uuid = ? AND status = ?`,
		reviewer, now, exp, now, infoUUID, info.Status)
	return err
}

// ApproveSubjectInfo 人工审核通过主体信息（待审核或待实名均可由管理员人工放行）。
func (s *Service) ApproveSubjectInfo(ctx context.Context, infoUUID, adminUUID string) error {
	return s.approveSubject(ctx, infoUUID, adminUUID, "pending", "verifying")
}

// MarkSubjectIdentityPassed 实名认证回调通过后放行主体信息。
func (s *Service) MarkSubjectIdentityPassed(ctx context.Context, infoUUID, providerUUID string) error {
	return s.approveSubject(ctx, infoUUID, "identity:"+providerUUID, "verifying")
}

// RejectSubjectInfo 审核拒绝主体信息。
func (s *Service) RejectSubjectInfo(ctx context.Context, infoUUID, adminUUID string) error {
	return s.RejectSubjectInfoWithReason(ctx, infoUUID, adminUUID, "")
}

// RejectSubjectInfoWithReason 审核拒绝主体信息并记录原因（用户可修改后重新提交）。
func (s *Service) RejectSubjectInfoWithReason(ctx context.Context, infoUUID, adminUUID, reason string) error {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE subject_infos SET status = 'rejected', reject_reason = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
		 WHERE uuid = ? AND status IN ('pending', 'verifying')`,
		reason, adminUUID, now, now, infoUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("主体信息不存在或不在待审核状态")
	}
	return nil
}

// SubjectIdentityProvider 返回主体信息需要使用的实名认证接口。
func (s *Service) SubjectIdentityProvider(ctx context.Context, info *storage.SubjectInfo) (string, error) {
	if info.Status != "verifying" {
		return "", fmt.Errorf("该主体信息无需实名认证")
	}
	tmpl, err := s.loadSubjectTemplate(ctx, info.SubjectTmplUUID)
	if err != nil || tmpl.ProviderUUID == "" {
		return "", fmt.Errorf("未配置实名认证接口，请等待人工审核")
	}
	return tmpl.ProviderUUID, nil
}

// DeleteSubjectInfo 删除主体信息。
func (s *Service) DeleteSubjectInfo(ctx context.Context, infoUUID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM subject_infos WHERE uuid = ?`, infoUUID)
	return err
}

// ---- 扩展信息 ----

// methodFromPolicy 把策略中的方式名映射为存储值（dns → txt）。
func methodFromPolicy(m string) string {
	if m == "dns" {
		return "txt"
	}
	return m
}

// CreateExtensionInfo 创建扩展信息并按模板策略进入验证流程：
//   - none   → 直接通过；
//   - manual → 进入人工审核（reviewing）；
//   - auto   → 待自助验证（pending），邮箱会立即发送 6 位验证码。
func (s *Service) CreateExtensionInfo(ctx context.Context, info *storage.ExtensionInfo) error {
	info.InfoType = strings.ToLower(strings.TrimSpace(info.InfoType))
	info.Value = strings.TrimSpace(info.Value)
	if err := validateExtensionValue(info.InfoType, info.Value); err != nil {
		return err
	}
	if info.InfoType == "domain" {
		info.Value = strings.ToLower(info.Value)
	}

	policy := s.extensionPolicy(ctx, info.TmplUUID).For(info.InfoType)
	if info.TmplUUID != "" && !policy.Enabled {
		return fmt.Errorf("当前证书类型不支持此类扩展信息")
	}

	info.UUID = uuid.New().String()
	info.CreatedAt = time.Now()
	info.UpdatedAt = info.CreatedAt
	code, err := s.resetVerification(info, policy)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO extension_infos (uuid, user_uuid, tmpl_uuid, info_type, value, verify_method, verify_token, verify_code_hash,
		 verify_status, verified_at, expires_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		info.UUID, info.UserUUID, info.TmplUUID, info.InfoType, info.Value, info.VerifyMethod,
		info.VerifyToken, info.VerifyCodeHash, info.VerifyStatus, info.VerifiedAt, info.ExpiresAt, info.CreatedAt, info.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return fmt.Errorf("%s 已存在，可在列表中直接使用或重新验证", info.Value)
		}
		return err
	}
	if code != "" {
		s.sendEmailCode(policy.ProviderUUID, info.Value, code)
	}
	return nil
}

// resetVerification 按策略重置验证状态、令牌与验证码；返回需要发送的邮箱验证码。
func (s *Service) resetVerification(info *storage.ExtensionInfo, policy identity.TypePolicy) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("生成验证 token 失败: %w", err)
	}
	info.VerifyToken = hex.EncodeToString(tokenBytes)
	info.VerifyCodeHash = ""
	info.VerifiedAt, info.ExpiresAt = nil, nil
	info.RejectReason = ""

	// 验证方式：用户指定且被策略允许时采用，否则取策略第一个
	method := methodFromPolicy(policy.Methods[0])
	for _, m := range policy.Methods {
		if methodFromPolicy(m) == info.VerifyMethod {
			method = info.VerifyMethod
		}
	}
	info.VerifyMethod = method

	switch policy.Mode {
	case identity.VerifyNone:
		now := time.Now()
		info.VerifyStatus = "verified"
		info.VerifiedAt = &now
		info.ExpiresAt = identity.ExpiryFrom(now, policy.Validity)
		return "", nil
	case identity.VerifyManual:
		info.VerifyStatus = "reviewing"
		return "", nil
	}

	info.VerifyStatus = "pending"
	if info.InfoType != "email" {
		return "", nil
	}
	code, err := randomNumeric(6)
	if err != nil {
		return "", fmt.Errorf("生成验证码失败: %w", err)
	}
	sum := sha256.Sum256([]byte(code))
	info.VerifyCodeHash = hex.EncodeToString(sum[:])
	return code, nil
}

// ExtensionPolicy 返回扩展模板的验证策略（无模板时为缺省策略）。
func (s *Service) ExtensionPolicy(ctx context.Context, tmplUUID string) identity.ExtensionPolicy {
	return s.extensionPolicy(ctx, tmplUUID)
}

// RenewExtensionInfo 重新发起验证（验证过期、被驳回、需要更换验证方式，或需按新证书类型的要求重新验证）。
// tmplUUID 非空时改按该扩展模板的策略验证。
func (s *Service) RenewExtensionInfo(ctx context.Context, infoUUID, method string, tmplUUID ...string) (*storage.ExtensionInfo, error) {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return nil, err
	}
	if len(tmplUUID) > 0 && tmplUUID[0] != "" && tmplUUID[0] != info.TmplUUID {
		info.TmplUUID = tmplUUID[0]
		if _, err := s.db.ExecContext(ctx, `UPDATE extension_infos SET tmpl_uuid = ? WHERE uuid = ?`, info.TmplUUID, infoUUID); err != nil {
			return nil, err
		}
	}
	policy := s.extensionPolicy(ctx, info.TmplUUID).For(info.InfoType)
	if method != "" {
		info.VerifyMethod = methodFromPolicy(method)
	}
	code, err := s.resetVerification(info, policy)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE extension_infos SET verify_method = ?, verify_token = ?, verify_code_hash = ?, verify_status = ?,
		 verified_at = ?, expires_at = ?, reject_reason = '', verify_attempts = 0, updated_at = ? WHERE uuid = ?`,
		info.VerifyMethod, info.VerifyToken, info.VerifyCodeHash, info.VerifyStatus,
		info.VerifiedAt, info.ExpiresAt, time.Now(), infoUUID); err != nil {
		return nil, err
	}
	if code != "" {
		s.sendEmailCode(policy.ProviderUUID, info.Value, code)
	}
	return info, nil
}

// sendEmailCode 异步发送验证码邮件（优先使用策略指定的邮件接口）。
func (s *Service) sendEmailCode(providerUUID, to, code string) {
	subject := "OpenCert 邮箱验证码"
	body := fmt.Sprintf("您正在验证邮箱 %s\n\n验证码：%s\n\n有效期：15 分钟。\n如非本人操作请忽略此邮件。", to, code)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if s.providers != nil && providerUUID != "" {
			if err := s.providers.SendMail(ctx, providerUUID, to, subject, body); err == nil {
				return
			}
		}
		if s.mailer != nil {
			_ = s.mailer.Send(to, subject, body)
		}
	}()
}

// validateExtensionValue 校验扩展信息值格式。
func validateExtensionValue(infoType, v string) error {
	switch infoType {
	case "domain":
		d := strings.TrimPrefix(strings.ToLower(v), "*.")
		if len(d) > 253 || !strings.Contains(d, ".") || net.ParseIP(d) != nil {
			return fmt.Errorf("域名格式错误: %s", v)
		}
		for _, label := range strings.Split(d, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("域名格式错误: %s", v)
			}
		}
	case "email":
		at := strings.LastIndex(v, "@")
		if at <= 0 || at == len(v)-1 || strings.ContainsAny(v, " \t\r\n") {
			return fmt.Errorf("邮箱格式错误: %s", v)
		}
	case "ip":
		if net.ParseIP(v) == nil {
			return fmt.Errorf("IP 地址格式错误: %s", v)
		}
	default:
		return fmt.Errorf("不支持的扩展信息类型: %s", infoType)
	}
	return nil
}

// randomNumeric 生成 n 位纯数字验证码（安全随机）。
func randomNumeric(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("长度必须为正")
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		out[i] = byte('0' + idx.Int64())
	}
	return string(out), nil
}

const extensionInfoColumns = `uuid, user_uuid, tmpl_uuid, info_type, value, verify_method, verify_token, verify_code_hash,
	verify_status, reject_reason, verified_at, expires_at, created_at, updated_at`

func scanExtensionInfo(scan func(dest ...interface{}) error) (*storage.ExtensionInfo, error) {
	info := &storage.ExtensionInfo{}
	var verifiedAt, expiresAt sql.NullTime
	if err := scan(&info.UUID, &info.UserUUID, &info.TmplUUID, &info.InfoType, &info.Value, &info.VerifyMethod,
		&info.VerifyToken, &info.VerifyCodeHash, &info.VerifyStatus, &info.RejectReason, &verifiedAt, &expiresAt,
		&info.CreatedAt, &info.UpdatedAt); err != nil {
		return nil, err
	}
	if verifiedAt.Valid {
		info.VerifiedAt = &verifiedAt.Time
	}
	if expiresAt.Valid {
		info.ExpiresAt = &expiresAt.Time
	}
	return info, nil
}

func (s *Service) queryExtensions(ctx context.Context, where string, args ...interface{}) ([]*storage.ExtensionInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+extensionInfoColumns+` FROM extension_infos`+where+` ORDER BY created_at DESC LIMIT 1000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	infos := []*storage.ExtensionInfo{}
	for rows.Next() {
		info, err := scanExtensionInfo(rows.Scan)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, rows.Err()
}

// ListExtensionInfos 查询用户的扩展信息列表。
func (s *Service) ListExtensionInfos(ctx context.Context, userUUID string) ([]*storage.ExtensionInfo, error) {
	return s.queryExtensions(ctx, ` WHERE user_uuid = ?`, userUUID)
}

// ListAllExtensionInfos 查询全部扩展信息（管理员审核队列）。
func (s *Service) ListAllExtensionInfos(ctx context.Context, status string) ([]*storage.ExtensionInfo, error) {
	if status == "" {
		return s.queryExtensions(ctx, "")
	}
	return s.queryExtensions(ctx, ` WHERE verify_status = ?`, status)
}

func (s *Service) requirePending(info *storage.ExtensionInfo, method string) error {
	if info.VerifyStatus == "verified" && info.Usable(time.Now()) {
		return fmt.Errorf("已验证通过")
	}
	if info.VerifyStatus != "pending" {
		return fmt.Errorf("当前状态（%s）不能自助验证，请重新发起验证", info.VerifyStatus)
	}
	if method != "" && info.VerifyMethod != method {
		return fmt.Errorf("当前验证方式为 %s，请按提示完成验证或切换验证方式", info.VerifyMethod)
	}
	return nil
}

// VerifyDNSTXT 验证域名 DNS TXT 记录：_opencert.<domain> TXT "opencert-verify=<token>"。
func (s *Service) VerifyDNSTXT(ctx context.Context, infoUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.InfoType != "domain" {
		return fmt.Errorf("此验证项不支持 DNS TXT 验证")
	}
	if err := s.requirePending(info, "txt"); err != nil {
		return err
	}
	expected := fmt.Sprintf("opencert-verify=%s", info.VerifyToken)
	host := "_opencert." + strings.TrimPrefix(info.Value, "*.")
	txts, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		return fmt.Errorf("DNS 查询 %s 失败: %w", host, err)
	}
	for _, txt := range txts {
		if strings.TrimSpace(txt) == expected {
			return s.markVerified(ctx, infoUUID)
		}
	}
	return fmt.Errorf("未找到匹配的 DNS TXT 记录，期望 %s = %s", host, expected)
}

// VerifyHTTP 验证 http://<value>/.well-known/pki-validation/<token> 的内容包含 token。
func (s *Service) VerifyHTTP(ctx context.Context, infoUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.InfoType != "domain" && info.InfoType != "ip" {
		return fmt.Errorf("此验证项不支持 HTTP 验证")
	}
	if strings.HasPrefix(info.Value, "*.") {
		return fmt.Errorf("通配符域名请使用 DNS 验证")
	}
	if err := s.requirePending(info, "http"); err != nil {
		return err
	}
	host := info.Value
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	u := fmt.Sprintf("http://%s/.well-known/pki-validation/%s", host, info.VerifyToken)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP 验证请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("验证文件不存在（%s 返回 %d）", u, resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if !strings.Contains(string(body), info.VerifyToken) {
		return fmt.Errorf("验证文件内容不匹配")
	}
	return s.markVerified(ctx, infoUUID)
}

// VerifyTLS 按 TLS-ALPN-01（RFC 8737）方式验证：域名 443 端口以 acme-tls/1 返回含 SHA-256(token) 的证书。
func (s *Service) VerifyTLS(ctx context.Context, infoUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.InfoType != "domain" || strings.HasPrefix(info.Value, "*.") {
		return fmt.Errorf("仅非通配符域名支持 TLS 验证")
	}
	if err := s.requirePending(info, "tls"); err != nil {
		return err
	}
	if s.tlsValidator == nil {
		return fmt.Errorf("TLS 验证未启用")
	}
	if err := s.tlsValidator(ctx, info.Value, info.VerifyToken); err != nil {
		return fmt.Errorf("TLS 验证失败: %w", err)
	}
	return s.markVerified(ctx, infoUUID)
}

// VerifyEmailCode 验证邮箱验证码：15 分钟内有效，连续错误 5 次需重新发送。
func (s *Service) VerifyEmailCode(ctx context.Context, infoUUID, code string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.InfoType != "email" {
		return fmt.Errorf("此验证项不支持邮箱验证")
	}
	if err := s.requirePending(info, "email"); err != nil {
		return err
	}
	if info.VerifyCodeHash == "" {
		return fmt.Errorf("验证码未初始化，请重新发送")
	}
	var attempts int
	var sentAt time.Time
	s.db.QueryRowContext(ctx, //nolint:errcheck
		`SELECT verify_attempts, updated_at FROM extension_infos WHERE uuid = ?`, infoUUID).Scan(&attempts, &sentAt)
	if attempts >= emailCodeMaxAttempt {
		return fmt.Errorf("验证码错误次数过多，请重新发送")
	}
	if time.Since(sentAt) > emailCodeTTL {
		return fmt.Errorf("验证码已过期，请重新发送")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	if hex.EncodeToString(sum[:]) != info.VerifyCodeHash {
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE extension_infos SET verify_attempts = verify_attempts + 1 WHERE uuid = ?`, infoUUID)
		return fmt.Errorf("验证码错误")
	}
	return s.markVerified(ctx, infoUUID)
}

// ApproveExtensionInfo 人工审核通过扩展信息。
func (s *Service) ApproveExtensionInfo(ctx context.Context, infoUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.VerifyStatus != "reviewing" && info.VerifyStatus != "pending" {
		return fmt.Errorf("当前状态（%s）不能审核通过", info.VerifyStatus)
	}
	return s.markVerified(ctx, infoUUID)
}

// RejectExtensionInfo 人工驳回扩展信息。
func (s *Service) RejectExtensionInfo(ctx context.Context, infoUUID, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE extension_infos SET verify_status = 'rejected', reject_reason = ?, updated_at = ?
		 WHERE uuid = ? AND verify_status IN ('reviewing', 'pending')`, reason, time.Now(), infoUUID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("扩展信息不存在或不在待审核状态")
	}
	return nil
}

// DeleteExtensionInfo 删除扩展信息。
func (s *Service) DeleteExtensionInfo(ctx context.Context, infoUUID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM extension_infos WHERE uuid = ?`, infoUUID)
	return err
}

// GetExtensionInfo 按 UUID 查询扩展信息（公开方法）。
func (s *Service) GetExtensionInfo(ctx context.Context, infoUUID string) (*storage.ExtensionInfo, error) {
	return s.getExtensionInfo(ctx, infoUUID)
}

// MarkVerified 标记扩展信息验证通过（公开方法）。
func (s *Service) MarkVerified(ctx context.Context, infoUUID string) error {
	return s.markVerified(ctx, infoUUID)
}

func (s *Service) getExtensionInfo(ctx context.Context, infoUUID string) (*storage.ExtensionInfo, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+extensionInfoColumns+` FROM extension_infos WHERE uuid = ?`, infoUUID)
	info, err := scanExtensionInfo(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("验证项不存在: %s", infoUUID)
	}
	return info, err
}

// markVerified 标记验证通过，有效期取扩展模板策略（缺省 30 天）。
func (s *Service) markVerified(ctx context.Context, infoUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	now := time.Now()
	exp := identity.ExpiryFrom(now, s.extensionPolicy(ctx, info.TmplUUID).For(info.InfoType).Validity)
	_, err = s.db.ExecContext(ctx,
		`UPDATE extension_infos SET verify_status = 'verified', verify_code_hash = '', reject_reason = '',
		 verified_at = ?, expires_at = ?, updated_at = ? WHERE uuid = ?`,
		now, exp, now, infoUUID)
	return err
}

func nullString(v string) interface{} {
	if v == "" {
		return nil
	}
	return v
}
