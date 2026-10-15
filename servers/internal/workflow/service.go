// Package workflow 提供证书订单和申请审批工作流。
package workflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/issuance"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Service 是工作流服务。
type Service struct {
	db          *storage.DB
	caSvc       *ca.Service       // 可选；为 nil 时审批不自动签发
	issuanceSvc *issuance.Service // 可选；用于读取颁发模板参数
}

// NewService 创建工作流服务。
// caSvc 和 issuanceSvc 可为 nil（兼容旧用法和测试），为 nil 时审批通过后不会自动签发证书。
func NewService(db *storage.DB, caSvc *ca.Service, issuanceSvc *issuance.Service) *Service {
	return &Service{db: db, caSvc: caSvc, issuanceSvc: issuanceSvc}
}

// CreateOrder 创建证书订单。
//
// 服务端为权威定价方：金额优先沿用调用方（同样由服务端）计算出的结果，
// 未提供金额时按证书申请模板定价回填；订单状态一律由服务端设置为待支付，
// 不接受调用方构造"已支付"订单。
//
// 下单只做库存/模板等业务校验，不预扣余额、不冻结金额；
// 余额或在线支付在收银台阶段由支付流程完成。
func (s *Service) CreateOrder(ctx context.Context, o *storage.CertOrder) error {
	if o.UserUUID == "" {
		return fmt.Errorf("订单缺少归属用户")
	}
	o.UUID = uuid.New().String()
	o.CreatedAt = time.Now()
	o.UpdatedAt = time.Now()
	o.Status = storage.CertOrderPendingPayment
	o.FrozenCents = 0
	if o.OrderNo == "" {
		o.OrderNo = storage.GenerateOrderNo()
	}
	if o.AmountCents < 0 {
		o.AmountCents = 0
	}
	if o.SpecJSON == "" {
		o.SpecJSON = "{}"
	}

	// 解析权威定价与模板关联
	if err := s.resolveOrderPricing(ctx, o); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cert_orders
		 (uuid, order_no, user_uuid, product_code, sku_code, spec_json, applicant_email,
		  issuance_tmpl_uuid, cert_apply_tmpl_uuid, key_storage_tmpl_uuid,
		  amount_cents, frozen_cents, subscription_uuid, coupon_code, discount_cents, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.UUID, o.OrderNo, o.UserUUID, o.ProductCode, o.SKUCode, o.SpecJSON, o.ApplicantEmail,
		o.IssuanceTmplUUID, o.CertApplyTmplUUID, o.KeyStorageTmplUUID,
		o.AmountCents, o.FrozenCents, o.SubscriptionUUID, o.CouponCode, o.DiscountCents, o.Status, o.CreatedAt, o.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建订单失败: %w", err)
	}
	return nil
}

// resolveOrderPricing 解析并校验订单的权威定价与模板关联。
//
// 定价来源优先级：已有服务端定价 > 证书申请模板定价 > 颁发模板定价。
// 调用方（HTTP 层）已过滤客户端传入的金额，因此此处不会采纳用户输入的价格。
func (s *Service) resolveOrderPricing(ctx context.Context, o *storage.CertOrder) error {
	if o.CertApplyTmplUUID != "" {
		tmpl, err := s.loadApplyTemplate(ctx, o.CertApplyTmplUUID)
		if err != nil {
			return err
		}
		if !tmpl.Enabled {
			return fmt.Errorf("所选商品已下架，请重新选择")
		}
		if o.IssuanceTmplUUID == "" {
			o.IssuanceTmplUUID = tmpl.IssuanceTmplUUID
		}
		// 门户/自助订单已由服务端按规格定价（含免费规格），不能再回填模板价格
		if o.AmountCents == 0 && o.SKUCode == "" {
			o.AmountCents = tmpl.PriceCents
		}
		return nil
	}

	// 未指定申请模板时，退化为按颁发模板定价（兼容控制台直接下单）
	if o.IssuanceTmplUUID != "" && o.AmountCents == 0 && s.issuanceSvc != nil {
		tmpl, err := s.issuanceSvc.GetIssuanceTemplate(ctx, o.IssuanceTmplUUID)
		if err != nil {
			return err
		}
		if !tmpl.Enabled {
			return fmt.Errorf("所选颁发模板已停用，请重新选择")
		}
		o.AmountCents = tmpl.PriceCents
	}
	return nil
}

// LoadApplyTemplate 是 loadApplyTemplate 的导出版本（申请向导使用）。
func (s *Service) LoadApplyTemplate(ctx context.Context, tmplUUID string) (*storage.CertApplyTemplate, error) {
	return s.loadApplyTemplate(ctx, tmplUUID)
}

// loadApplyTemplate 读取证书申请模板（面向用户的产品化配置）。
func (s *Service) loadApplyTemplate(ctx context.Context, tmplUUID string) (*storage.CertApplyTemplate, error) {
	if tmplUUID == "" {
		return nil, fmt.Errorf("缺少证书申请模板")
	}
	t := &storage.CertApplyTemplate{}
	var enabled, requireApproval, allowRenewal int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, issuance_tmpl_uuid, valid_days, ca_uuid, enabled, require_approval,
		        allow_renewal, allowed_key_types, price_cents, description, subject_tmpl_uuid, extension_tmpl_uuid,
		        created_at, updated_at
		 FROM cert_apply_templates WHERE uuid = ?`, tmplUUID,
	).Scan(&t.UUID, &t.Name, &t.IssuanceTmplUUID, &t.ValidDays, &t.CAUUID, &enabled,
		&requireApproval, &allowRenewal, &t.AllowedKeyTypes, &t.PriceCents, &t.Description,
		&t.SubjectTmplUUID, &t.ExtensionTmplUUID, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("证书申请模板不存在: %s", tmplUUID)
	}
	if err != nil {
		return nil, fmt.Errorf("查询证书申请模板失败: %w", err)
	}
	t.Enabled = enabled == 1
	t.RequireApproval = requireApproval == 1
	t.AllowRenewal = allowRenewal == 1
	return t, nil
}

// certOrderColumns 是 cert_orders 的查询列，保证读写的字段集合一致。
const certOrderColumns = `uuid, order_no, user_uuid, product_code, sku_code, spec_json, applicant_email,
	issuance_tmpl_uuid, cert_apply_tmpl_uuid, key_storage_tmpl_uuid,
	amount_cents, frozen_cents, subscription_uuid, coupon_code, discount_cents, status, paid_at, created_at, updated_at`

func scanCertOrder(scan func(dest ...interface{}) error) (*storage.CertOrder, error) {
	o := &storage.CertOrder{}
	var paidAt sql.NullTime
	if err := scan(&o.UUID, &o.OrderNo, &o.UserUUID, &o.ProductCode, &o.SKUCode, &o.SpecJSON,
		&o.ApplicantEmail, &o.IssuanceTmplUUID, &o.CertApplyTmplUUID, &o.KeyStorageTmplUUID,
		&o.AmountCents, &o.FrozenCents, &o.SubscriptionUUID, &o.CouponCode, &o.DiscountCents,
		&o.Status, &paidAt, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return nil, err
	}
	if paidAt.Valid {
		o.PaidAt = &paidAt.Time
	}
	return o, nil
}

// GetOrder 按 UUID 查询订单。
func (s *Service) GetOrder(ctx context.Context, orderUUID string) (*storage.CertOrder, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certOrderColumns+` FROM cert_orders WHERE uuid = ?`, orderUUID)
	o, err := scanCertOrder(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订单不存在: %s", orderUUID)
	}
	return o, err
}

// GetOrderByNo 按对外订单号查询订单。
func (s *Service) GetOrderByNo(ctx context.Context, orderNo string) (*storage.CertOrder, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certOrderColumns+` FROM cert_orders WHERE order_no = ?`, orderNo)
	o, err := scanCertOrder(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("订单不存在: %s", orderNo)
	}
	return o, err
}

// ListOrders 查询用户的订单列表。
func (s *Service) ListOrders(ctx context.Context, userUUID string, page, pageSize int) ([]*storage.CertOrder, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	var total int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cert_orders WHERE user_uuid = ?`, userUUID,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certOrderColumns+` FROM cert_orders WHERE user_uuid = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		userUUID, pageSize, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	orders := []*storage.CertOrder{}
	for rows.Next() {
		o, err := scanCertOrder(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		orders = append(orders, o)
	}
	return orders, total, rows.Err()
}

// ListAllOrders 查询全部订单（管理员视图），支持按状态与订单号/邮箱关键字筛选。
func (s *Service) ListAllOrders(ctx context.Context, status, keyword string, page, pageSize int) ([]*storage.CertOrder, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	where := ` WHERE 1=1`
	args := []interface{}{}
	if status != "" {
		where += ` AND status = ?`
		args = append(args, status)
	}
	if kw := strings.TrimSpace(keyword); kw != "" {
		where += ` AND (order_no LIKE ? OR applicant_email LIKE ? OR product_code LIKE ?)`
		like := "%" + kw + "%"
		args = append(args, like, like, like)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cert_orders`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+certOrderColumns+` FROM cert_orders`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	orders := []*storage.CertOrder{}
	for rows.Next() {
		o, err := scanCertOrder(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		orders = append(orders, o)
	}
	return orders, total, rows.Err()
}

// CreateApplication 提交证书申请。
//
// 早期实现只做插入，不检查订单归属、支付状态与模板约束，
// 导致未支付的用户也能直接提交申请。此处补齐前置校验：
//  1. 订单必须存在且归属于该用户；
//  2. 订单必须已支付（含已完成/申请中等允许续办的状态）；
//  3. 关联的证书申请模板必须启用，且申请的密钥算法在允许范围内；
//  4. 若携带 CSR，必须能解析且自签名有效。
func (s *Service) CreateApplication(ctx context.Context, app *storage.CertApplication) error {
	if app.UserUUID == "" {
		return fmt.Errorf("申请缺少归属用户")
	}

	if err := s.validateApplication(ctx, app); err != nil {
		return err
	}

	app.UUID = uuid.New().String()
	app.Status = "pending"
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cert_applications
		 (uuid, order_uuid, user_uuid, subject_json, san_json, key_type, csr_pem, applicant_email, card_uuid, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		app.UUID, app.OrderUUID, app.UserUUID, app.SubjectJSON, app.SANJSON, app.KeyType,
		app.CSRPEM, app.ApplicantEmail, app.CardUUID, app.Status, app.CreatedAt, app.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("创建申请失败: %w", err)
	}

	// 订单进入申请阶段；未关联订单的自由申请保持原状态
	if app.OrderUUID != "" {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE cert_orders SET status = ?, updated_at = ? WHERE uuid = ? AND status = ?`,
			storage.CertOrderApplying, time.Now(), app.OrderUUID, storage.CertOrderPaid); err != nil {
			return fmt.Errorf("更新订单状态失败: %w", err)
		}
	}
	return nil
}

// validateApplication 校验申请的前置条件（订单归属、支付状态、数量、模板、目标卡与 CSR）。
func (s *Service) validateApplication(ctx context.Context, app *storage.CertApplication) error {
	// 目标卡片必须归属申请人
	if app.CardUUID != "" {
		var owner string
		if err := s.db.QueryRowContext(ctx,
			`SELECT user_uuid FROM cards WHERE uuid = ?`, app.CardUUID).Scan(&owner); err != nil || owner != app.UserUUID {
			return fmt.Errorf("目标智能卡不存在或不属于当前用户")
		}
	}

	if app.OrderUUID == "" {
		// 签发必须依托订单（销售或自助模式均会生成订单），不接受无订单申请
		return fmt.Errorf("申请缺少关联订单")
	}

	var (
		orderUser     string
		orderStatus   string
		applyTmplUUID string
		specJSON      string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT user_uuid, status, cert_apply_tmpl_uuid, spec_json FROM cert_orders WHERE uuid = ?`, app.OrderUUID,
	).Scan(&orderUser, &orderStatus, &applyTmplUUID, &specJSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("订单不存在")
	}
	if err != nil {
		return fmt.Errorf("查询订单失败: %w", err)
	}
	if orderUser != app.UserUUID {
		return fmt.Errorf("订单不属于当前用户")
	}

	switch storage.CertOrderStatus(orderStatus) {
	case storage.CertOrderPaid, storage.CertOrderApplying, storage.CertOrderReviewing, storage.CertOrderIssuing:
		// 允许提交或继续补交
	case storage.CertOrderPendingPayment:
		return fmt.Errorf("订单尚未支付，请先完成支付")
	case storage.CertOrderCompleted:
		return fmt.Errorf("订单已完成签发，如需续期请重新下单")
	default:
		return fmt.Errorf("订单状态不允许提交申请: %s", orderStatus)
	}

	// 数量约束：一个订单可签发的证书数不超过购买份数（被拒绝的申请不占额度）
	switch specKind(specJSON) {
	case storage.OrderKindCert:
	case storage.OrderKindCard:
		return fmt.Errorf("云端智能卡订单不能用于申请证书，请在「智能卡片管理」中开卡")
	default:
		return fmt.Errorf("该订单不是证书订单，不能用于申请证书")
	}
	var used int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM cert_applications WHERE order_uuid = ? AND status <> 'rejected'`, app.OrderUUID,
	).Scan(&used); err != nil {
		return fmt.Errorf("查询订单申请数失败: %w", err)
	}
	if qty := SpecQuantity(specJSON); used >= qty {
		return fmt.Errorf("该订单可申请 %d 张证书，已全部提交", qty)
	}

	// 模板约束：启用状态 + 允许的密钥算法
	if applyTmplUUID != "" {
		tmpl, err := s.loadApplyTemplate(ctx, applyTmplUUID)
		if err != nil {
			return err
		}
		if !tmpl.Enabled {
			return fmt.Errorf("所选商品已下架，无法提交申请")
		}
		if app.KeyType != "" && tmpl.AllowedKeyTypes != "" {
			var allowed []string
			if err := json.Unmarshal([]byte(tmpl.AllowedKeyTypes), &allowed); err == nil && len(allowed) > 0 {
				ok := false
				for _, k := range allowed {
					if k == app.KeyType {
						ok = true
						break
					}
				}
				if !ok {
					return fmt.Errorf("该商品不支持所选密钥算法: %s", app.KeyType)
				}
			}
		}
	}

	return validateCSRPEM(app.CSRPEM)
}

// validateCSRPEM 校验用户提交的 CSR：可解析、自签名有效，并回填密钥算法。
func validateCSRPEM(csrPEM string) error {
	if strings.TrimSpace(csrPEM) == "" {
		return nil
	}
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("CSR 签名校验失败: %w", err)
	}
	return nil
}

// ParseCSR 解析并校验 CSR（格式 + 自签名），供 API 层做名称所有权校验。
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	csr, err := parseCSRPEM(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR 签名校验失败: %w", err)
	}
	return csr, nil
}

// parseCSRPEM 解析 PEM 编码的 CSR。
func parseCSRPEM(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("CSR 格式错误：不是有效的 PEM 数据")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR 格式错误：PEM 类型为 %s", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	return csr, nil
}

// keyTypeFromPublicKey 根据 CSR 中的公钥推断密钥算法标识。
func keyTypeFromPublicKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ec%d", k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "ed25519"
	default:
		return ""
	}
}

// certApplicationColumns 是 cert_applications 的查询列，保证读写字段一致。
const certApplicationColumns = `uuid, order_uuid, user_uuid, subject_json, san_json, key_type,
	csr_pem, applicant_email, card_uuid, status, approved_by, approved_at, reject_reason, cert_uuid, created_at, updated_at`

func scanCertApplication(scan func(dest ...interface{}) error) (*storage.CertApplication, error) {
	a := &storage.CertApplication{}
	var approvedBy sql.NullString
	var approvedAt sql.NullTime
	if err := scan(&a.UUID, &a.OrderUUID, &a.UserUUID, &a.SubjectJSON, &a.SANJSON, &a.KeyType,
		&a.CSRPEM, &a.ApplicantEmail, &a.CardUUID, &a.Status, &approvedBy, &approvedAt, &a.RejectReason,
		&a.CertUUID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	if approvedBy.Valid {
		a.ApprovedBy = approvedBy.String
	}
	if approvedAt.Valid {
		a.ApprovedAt = &approvedAt.Time
	}
	return a, nil
}

// GetApplication 通过 UUID 查询单个证书申请。
func (s *Service) GetApplication(ctx context.Context, appUUID string) (*storage.CertApplication, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+certApplicationColumns+` FROM cert_applications WHERE uuid = ?`, appUUID)
	app, err := scanCertApplication(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("查询申请失败: %w", err)
	}
	return app, nil
}

func (s *Service) ListApplications(ctx context.Context, userUUID string, statusFilter string, page, pageSize int) ([]*storage.CertApplication, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `SELECT COUNT(*) FROM cert_applications WHERE 1=1`
	countArgs := []interface{}{}
	if userUUID != "" {
		query += ` AND user_uuid = ?`
		countArgs = append(countArgs, userUUID)
	}
	if statusFilter != "" {
		query += ` AND status = ?`
		countArgs = append(countArgs, statusFilter)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, query, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	selectQuery := `SELECT ` + certApplicationColumns + ` FROM cert_applications WHERE 1=1`
	selectArgs := []interface{}{}
	if userUUID != "" {
		selectQuery += ` AND user_uuid = ?`
		selectArgs = append(selectArgs, userUUID)
	}
	if statusFilter != "" {
		selectQuery += ` AND status = ?`
		selectArgs = append(selectArgs, statusFilter)
	}
	selectQuery += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	selectArgs = append(selectArgs, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	apps := []*storage.CertApplication{}
	for rows.Next() {
		a, err := scanCertApplication(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		apps = append(apps, a)
	}
	return apps, total, rows.Err()
}

// ApproveApplication 审批通过证书申请。
// 审批通过后：
//  1. 若已注入 caSvc/issuanceSvc，则自动调用签发引擎生成证书，创建 Certificate 记录，
//     并将申请状态置为 approved，订单状态置为 completed，冻结金额转为消费记录；
//  2. 若未注入相关依赖（旧用法或测试场景），则仅更新状态（兼容旧逻辑）。
func (s *Service) ApproveApplication(ctx context.Context, appUUID, adminUUID string) error {
	now := time.Now()

	// 查询申请信息
	app := &storage.CertApplication{}
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, order_uuid, user_uuid, subject_json, san_json, key_type, csr_pem, card_uuid, status
		 FROM cert_applications WHERE uuid = ?`, appUUID,
	).Scan(&app.UUID, &app.OrderUUID, &app.UserUUID, &app.SubjectJSON, &app.SANJSON, &app.KeyType,
		&app.CSRPEM, &app.CardUUID, &app.Status)
	if err != nil {
		return fmt.Errorf("查询申请失败: %w", err)
	}

	if app.Status != "pending" {
		return fmt.Errorf("只能审批待处理的申请，当前状态: %s", app.Status)
	}

	// 尝试自动签发证书
	var certUUID string
	if s.caSvc != nil && s.issuanceSvc != nil {
		certUUID, err = s.issueCertForApplication(ctx, app)
		if err != nil {
			return fmt.Errorf("自动签发证书失败: %w", err)
		}
	}

	// 更新申请状态为 approved，并回填 cert_uuid
	_, err = s.db.ExecContext(ctx,
		`UPDATE cert_applications SET status = 'approved', approved_by = ?, approved_at = ?, cert_uuid = ?, updated_at = ? WHERE uuid = ?`,
		adminUUID, now, certUUID, now, appUUID,
	)
	if err != nil {
		return fmt.Errorf("更新申请状态失败: %w", err)
	}

	// 更新关联订单状态：全部份数签发完成后订单才算完成
	if app.OrderUUID != "" {
		var specJSON string
		s.db.QueryRowContext(ctx, //nolint:errcheck
			`SELECT spec_json FROM cert_orders WHERE uuid = ?`, app.OrderUUID).Scan(&specJSON)
		var approved int
		s.db.QueryRowContext(ctx, //nolint:errcheck
			`SELECT COUNT(*) FROM cert_applications WHERE order_uuid = ? AND status = 'approved'`, app.OrderUUID).Scan(&approved)

		orderStatus := string(storage.CertOrderCompleted)
		if approved < SpecQuantity(specJSON) {
			orderStatus = string(storage.CertOrderApplying) // 仍有份数可继续申请
		}
		_, err = s.db.ExecContext(ctx,
			`UPDATE cert_orders SET status = ?, updated_at = ? WHERE uuid = ?`,
			orderStatus, now, app.OrderUUID,
		)
		if err != nil {
			return fmt.Errorf("更新订单状态失败: %w", err)
		}

		// 账户结算与签发解耦：
		//   - 历史订单（下单时冻结余额）在此把冻结金额转为消费；
		//   - 门户订单不预冻结，消费流水与扣款由支付流程负责，此处不再重复记账，
		//     避免出现 frozen_cents 变为负数或重复计入消费。
		var orderAmount, frozenAmount int64
		var orderUserUUID string
		var orderStatusDB string
		err = s.db.QueryRowContext(ctx,
			`SELECT user_uuid, amount_cents, frozen_cents, status FROM cert_orders WHERE uuid = ?`, app.OrderUUID,
		).Scan(&orderUserUUID, &orderAmount, &frozenAmount, &orderStatusDB)
		if err == nil && orderAmount > 0 && frozenAmount > 0 {
			// 条件更新确保不会把冻结金额扣成负数
			s.db.ExecContext(ctx, //nolint:errcheck
				`UPDATE user_balances SET frozen_cents = frozen_cents - ?, total_consume = total_consume + ?
				 WHERE user_uuid = ? AND frozen_cents >= ?`,
				frozenAmount, frozenAmount, orderUserUUID, frozenAmount,
			)
			// 写入消费记录
			consumeUUID := uuid.New().String()
			s.db.ExecContext(ctx, //nolint:errcheck
				`INSERT INTO consume_records (uuid, user_uuid, order_no, consume_type, amount_cents, remark, created_at)
				 VALUES (?, ?, ?, 'cert_purchase', ?, '证书签发消费', ?)`,
				consumeUUID, orderUserUUID, app.OrderUUID, frozenAmount, now,
			)
		}
	}

	return nil
}

// issueCertForApplication 根据申请信息自动签发证书。
// 从订单中取出 IssuanceTmplUUID/CertApplyTmplUUID，读取模板参数，调用 caSvc.IssueCert 并创建 Certificate 记录。
// 返回签发后的证书 UUID。
func (s *Service) issueCertForApplication(ctx context.Context, app *storage.CertApplication) (string, error) {
	if app.OrderUUID == "" {
		return "", fmt.Errorf("申请未关联订单，无法签发")
	}

	// 读取订单：issuance_tmpl_uuid / cert_apply_tmpl_uuid / 对外单号 / 规格快照
	var issuanceTmplUUID, certApplyTmplUUID, orderNo, orderSpec string
	err := s.db.QueryRowContext(ctx,
		`SELECT issuance_tmpl_uuid, cert_apply_tmpl_uuid, order_no, spec_json FROM cert_orders WHERE uuid = ?`, app.OrderUUID,
	).Scan(&issuanceTmplUUID, &certApplyTmplUUID, &orderNo, &orderSpec)
	if err != nil {
		return "", fmt.Errorf("读取订单失败: %w", err)
	}

	// 读取申请模板（若有）：取 CA、有效期。
	// 模板缺失或已下架时直接失败，避免在配置不完整的情况下静默按兜底参数签发。
	var caUUID string
	var validDays int
	if certApplyTmplUUID != "" {
		applyTmpl, tmplErr := s.loadApplyTemplate(ctx, certApplyTmplUUID)
		if tmplErr != nil {
			return "", tmplErr
		}
		if !applyTmpl.Enabled {
			return "", fmt.Errorf("所选商品已下架，无法签发")
		}
		caUUID = applyTmpl.CAUUID
		validDays = applyTmpl.ValidDays
		if issuanceTmplUUID == "" {
			issuanceTmplUUID = applyTmpl.IssuanceTmplUUID
		}
	}

	// 读取颁发模板（若有）：回填 CA、有效期缺省值
	if issuanceTmplUUID != "" {
		tmpl, err := s.issuanceSvc.GetIssuanceTemplate(ctx, issuanceTmplUUID)
		if err == nil {
			if caUUID == "" {
				caUUID = firstAllowedCA(tmpl.AllowedCAUUIDs)
			}
			if validDays == 0 {
				validDays = firstValidDays(tmpl.ValidDays)
			}
		}
	}

	// 订阅套餐可覆盖单张证书的有效期
	if d := SpecValidDays(orderSpec); d > 0 {
		validDays = d
	}

	if caUUID == "" {
		return "", fmt.Errorf("无法确定签发 CA（订单/申请模板/颁发模板均未指定）")
	}
	if validDays <= 0 {
		validDays = 365
	}

	// 解析主体 JSON → pkix.Name
	subject, err := parseSubjectJSON(app.SubjectJSON)
	if err != nil {
		return "", fmt.Errorf("解析主体 JSON 失败: %w", err)
	}

	// 解析 SAN JSON
	dnsNames, ips, emails, uris, err := parseSANJSON(app.SANJSON)
	if err != nil {
		return "", fmt.Errorf("解析 SAN JSON 失败: %w", err)
	}

	// 解析申请人自带 CSR（若有）：私钥留在申请者一侧，服务端只用其公钥签发
	var csrPubKey crypto.PublicKey
	if strings.TrimSpace(app.CSRPEM) != "" {
		csr, csrErr := parseCSRPEM(app.CSRPEM)
		if csrErr != nil {
			return "", csrErr
		}
		if csrErr := csr.CheckSignature(); csrErr != nil {
			return "", fmt.Errorf("CSR 签名校验失败: %w", csrErr)
		}
		csrPubKey = csr.PublicKey
		// 申请未显式提供 SAN 时，采用 CSR 中的名称，避免签出与 CSR 不一致的证书
		if len(dnsNames) == 0 {
			dnsNames = csr.DNSNames
		}
		if len(ips) == 0 {
			ips = csr.IPAddresses
		}
		if len(emails) == 0 {
			emails = csr.EmailAddresses
		}
		if len(uris) == 0 {
			// CSR 中的 URI SAN 为 *url.URL，签发请求使用字符串形式
			for _, u := range csr.URIs {
				if u != nil {
					uris = append(uris, u.String())
				}
			}
		}
		if subject.CommonName == "" {
			subject.CommonName = csr.Subject.CommonName
		}
	}

	// 密钥类型：优先申请指定；其次由 CSR 公钥推断；最后回退默认值
	keyType := app.KeyType
	if keyType == "" && csrPubKey != nil {
		keyType = keyTypeFromPublicKey(csrPubKey)
	}
	if keyType == "" {
		keyType = "ec256"
	}

	// 构造签发请求
	// 若指定了颁发模板，KU/EKU 交由签发引擎按 KeyUsageTemplate 回填；否则使用业务默认值。
	var defaultKU x509.KeyUsage
	var defaultEKU []x509.ExtKeyUsage
	if issuanceTmplUUID == "" {
		defaultKU = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		defaultEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	issueReq := &ca.IssueRequest{
		CAUUID:           caUUID,
		Subject:          subject,
		KeyType:          keyType,
		ValidDays:        validDays,
		IsCA:             false,
		KeyUsage:         defaultKU,
		ExtKeyUsage:      defaultEKU,
		DNSNames:         dnsNames,
		IPAddresses:      ips,
		EmailAddrs:       emails,
		URIs:             uris,
		IssuanceTmplUUID: issuanceTmplUUID,
		CSRPublicKey:     csrPubKey, // 非 nil 时不生成服务端私钥
	}

	// 调用签发引擎
	resp, err := s.caSvc.IssueCert(ctx, issueReq)
	if err != nil {
		return "", err
	}

	// 确定存放卡片：
	//   - 申请指定了用户智能卡 → 签入该卡（可远程签名/解密）；
	//   - 未指定 → 签入用户的系统托管容器（供下载，不支持远程密码运算）。
	// 证书表要求 card_uuid 引用有效卡片，不能写空值，否则会被外键拒绝。
	cardRepo := storage.NewCardRepo(s.db)
	targetCard := app.CardUUID
	if targetCard != "" {
		c, cErr := cardRepo.GetByUUID(ctx, targetCard)
		if cErr != nil || c.UserUUID != app.UserUUID {
			return "", fmt.Errorf("目标智能卡不存在或不属于申请人")
		}
	} else {
		hosting, hErr := cardRepo.GetOrCreateHostingCard(ctx, app.UserUUID)
		if hErr != nil {
			return "", hErr
		}
		targetCard = hosting.UUID
	}

	// 存入证书表
	ipStrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	cert := &storage.Certificate{
		CardUUID:         targetCard,
		OrderNo:          orderNo,
		UserUUID:         app.UserUUID,
		CertType:         "x509",
		KeyType:          keyType,
		CertContent:      []byte(resp.CertPEM),
		PrivateData:      resp.PrivateEnc,
		CAUUID:           caUUID,
		SerialNumber:     resp.SerialNumber,
		SerialHex:        resp.SerialNumber,
		SubjectDN:        resp.SubjectDN,
		IssuerDN:         resp.IssuerDN,
		NotBefore:        &resp.NotBefore,
		NotAfter:         &resp.NotAfter,
		SANDNS:           marshalJSONArray(dnsNames),
		SANIP:            marshalJSONArray(ipStrs),
		SANEmail:         marshalJSONArray(emails),
		SANURI:           marshalJSONArray(uris),
		IssuanceTmplUUID: issuanceTmplUUID,
		RevocationStatus: "active",
	}
	certRepo := storage.NewCertRepo(s.db)
	if err := certRepo.Create(ctx, cert); err != nil {
		return "", fmt.Errorf("保存签发证书失败: %w", err)
	}
	return cert.UUID, nil
}

// parseSubjectJSON 将 {"CN":"...", "O":"...", "C":"..."} 解析为 pkix.Name。
// 未识别的键会被忽略，空字符串不写入。
func parseSubjectJSON(s string) (pkix.Name, error) {
	name := pkix.Name{}
	if s == "" {
		return name, nil
	}
	fields := map[string]string{}
	if err := json.Unmarshal([]byte(s), &fields); err != nil {
		return name, err
	}
	for k, v := range fields {
		if v == "" {
			continue
		}
		switch k {
		case "CN", "commonName":
			name.CommonName = v
		case "C", "country":
			name.Country = []string{v}
		case "ST", "province":
			name.Province = []string{v}
		case "L", "locality":
			name.Locality = []string{v}
		case "O", "organization":
			name.Organization = []string{v}
		case "OU", "organizationalUnit":
			name.OrganizationalUnit = []string{v}
		case "serialNumber":
			name.SerialNumber = v
		}
	}
	return name, nil
}

// parseSANJSON 解析 SAN JSON：{"dns":["a.com"],"ip":["1.1.1.1"],"email":["a@b.com"],"uri":["https://a.com"]}。
func parseSANJSON(s string) (dns []string, ips []net.IP, emails []string, uris []string, err error) {
	if s == "" {
		return nil, nil, nil, nil, nil
	}
	var raw struct {
		DNS   []string `json:"dns"`
		IP    []string `json:"ip"`
		Email []string `json:"email"`
		URI   []string `json:"uri"`
	}
	if err = json.Unmarshal([]byte(s), &raw); err != nil {
		return nil, nil, nil, nil, err
	}
	dns = raw.DNS
	emails = raw.Email
	uris = raw.URI
	for _, ipStr := range raw.IP {
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return dns, ips, emails, uris, nil
}

// firstAllowedCA 从 JSON 数组字符串中提取第一个 CA UUID。
func firstAllowedCA(j string) string {
	if j == "" || j == "[]" {
		return ""
	}
	var arr []string
	if err := json.Unmarshal([]byte(j), &arr); err != nil || len(arr) == 0 {
		return ""
	}
	return arr[0]
}

// firstValidDays 从 JSON 数组字符串中提取第一个有效期。
func firstValidDays(j string) int {
	if j == "" || j == "[]" {
		return 0
	}
	var arr []int
	if err := json.Unmarshal([]byte(j), &arr); err != nil || len(arr) == 0 {
		return 0
	}
	return arr[0]
}

// RejectApplication 拒绝证书申请（解冻冻结金额）。
func (s *Service) RejectApplication(ctx context.Context, appUUID, adminUUID, reason string) error {
	now := time.Now()

	// 查询申请信息
	var orderUUID, userUUID, status string
	err := s.db.QueryRowContext(ctx,
		`SELECT order_uuid, user_uuid, status FROM cert_applications WHERE uuid = ?`, appUUID,
	).Scan(&orderUUID, &userUUID, &status)
	if err != nil {
		return fmt.Errorf("查询申请失败: %w", err)
	}

	if status != "pending" {
		return fmt.Errorf("只能拒绝待处理的申请，当前状态: %s", status)
	}

	// 更新申请状态为 rejected
	_, err = s.db.ExecContext(ctx,
		`UPDATE cert_applications SET status = 'rejected', approved_by = ?, approved_at = ?, reject_reason = ?, updated_at = ? WHERE uuid = ? AND status = 'pending'`,
		adminUUID, now, reason, now, appUUID,
	)
	if err != nil {
		return fmt.Errorf("更新申请状态失败: %w", err)
	}

	// 订单处理：
	//   - 仅历史订单存在冻结金额，按实际冻结额原路解冻（不能按订单金额"解冻"，否则会凭空给用户加余额）；
	//   - 订单回到"已支付"，用户修正资料后可重新提交申请；如不再需要可自助申请退款。
	if orderUUID != "" {
		var frozen int64
		if err := s.db.QueryRowContext(ctx,
			`SELECT frozen_cents FROM cert_orders WHERE uuid = ?`, orderUUID).Scan(&frozen); err == nil && frozen > 0 {
			res, _ := s.db.ExecContext(ctx,
				`UPDATE user_balances SET available_cents = available_cents + ?, frozen_cents = frozen_cents - ?
				 WHERE user_uuid = ? AND frozen_cents >= ?`,
				frozen, frozen, userUUID, frozen)
			if n, _ := res.RowsAffected(); n > 0 {
				s.db.ExecContext(ctx, //nolint:errcheck
					`UPDATE cert_orders SET frozen_cents = 0 WHERE uuid = ?`, orderUUID)
			}
		}
		// 没有其它进行中的申请时，订单回到已支付
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE cert_orders SET status = ?, updated_at = ?
			 WHERE uuid = ? AND status IN (?, ?)
			   AND NOT EXISTS (SELECT 1 FROM cert_applications WHERE order_uuid = ? AND status = 'pending')`,
			storage.CertOrderPaid, now, orderUUID, storage.CertOrderApplying, storage.CertOrderReviewing, orderUUID)
	}

	return nil
}

// SubmitApplication 提交证书申请；当申请模板无需人工审批时立即自动签发。
//
// 返回 autoIssued=true 表示已自动签发；自动签发失败时申请保持待审批，
// 并通过 issueErr 返回原因（不影响申请本身已提交成功）。
func (s *Service) SubmitApplication(ctx context.Context, app *storage.CertApplication) (autoIssued bool, issueErr error, err error) {
	if err := s.CreateApplication(ctx, app); err != nil {
		return false, nil, err
	}

	requireApproval := true
	var applyTmplUUID string
	if e := s.db.QueryRowContext(ctx,
		`SELECT cert_apply_tmpl_uuid FROM cert_orders WHERE uuid = ?`, app.OrderUUID).Scan(&applyTmplUUID); e == nil && applyTmplUUID != "" {
		if tmpl, e := s.loadApplyTemplate(ctx, applyTmplUUID); e == nil {
			requireApproval = tmpl.RequireApproval
		}
	}

	if requireApproval {
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE cert_orders SET status = ?, updated_at = ? WHERE uuid = ? AND status = ?`,
			storage.CertOrderReviewing, time.Now(), app.OrderUUID, storage.CertOrderApplying)
		return false, nil, nil
	}

	if e := s.ApproveApplication(ctx, app.UUID, SystemApprover); e != nil {
		return false, e, nil
	}
	// 回读申请，使返回值带上 cert_uuid（前端据此跳转证书详情）
	if refreshed, e := s.GetApplication(ctx, app.UUID); e == nil {
		*app = *refreshed
	} else {
		app.Status = "approved"
	}
	return true, nil, nil
}

// SystemApprover 是自动审批时记录的审批人标识。
const SystemApprover = "system"

// CreateSelfServiceOrder 为自助模式创建零金额订单（直接置为已支付）。
//
// 自助模式下用户无需购买即可申请，但签发链路仍依托订单记录，
// 以保留审计、数量约束与模板关联的一致性。
func (s *Service) CreateSelfServiceOrder(ctx context.Context, userUUID, applyTmplUUID, email string) (*storage.CertOrder, error) {
	if applyTmplUUID == "" {
		return nil, fmt.Errorf("请选择要申请的证书类型")
	}
	tmpl, err := s.loadApplyTemplate(ctx, applyTmplUUID)
	if err != nil {
		return nil, err
	}
	if !tmpl.Enabled {
		return nil, fmt.Errorf("该证书类型暂不开放申请")
	}

	spec, _ := json.Marshal(map[string]interface{}{
		"mode":          "self_service",
		"kind":          storage.OrderKindCert,
		"product_name":  tmpl.Name,
		"sku_name":      tmpl.Name,
		"quantity":      1,
		"delivery_mode": string(storage.DeliveryDownload),
	})
	order := &storage.CertOrder{
		UserUUID:          userUUID,
		CertApplyTmplUUID: applyTmplUUID,
		SpecJSON:          string(spec),
		ApplicantEmail:    email,
		SKUCode:           "self-service", // 标记为已定价，避免回填模板价格
	}
	if err := s.CreateOrder(ctx, order); err != nil {
		return nil, err
	}
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, paid_at = ?, updated_at = ? WHERE uuid = ?`,
		storage.CertOrderPaid, now, now, order.UUID); err != nil {
		return nil, fmt.Errorf("更新自助订单状态失败: %w", err)
	}
	order.Status = storage.CertOrderPaid
	order.PaidAt = &now
	return order, nil
}

// ListStalePendingOrders 列出早于 before 创建且仍待支付的门户订单号。
func (s *Service) ListStalePendingOrders(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT order_no FROM cert_orders WHERE status = ? AND order_no <> '' AND created_at < ? LIMIT 500`,
		storage.CertOrderPendingPayment, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var no string
		if rows.Scan(&no) == nil {
			out = append(out, no)
		}
	}
	return out, rows.Err()
}

// CreateSubscriptionOrder 使用订阅额度生成零金额订单（直接已支付）。
// validDays>0 时覆盖开通模板的证书有效期；sanPolicy 为该订单的 SAN 限制快照。
func (s *Service) CreateSubscriptionOrder(ctx context.Context, userUUID, subUUID, applyTmplUUID, email string,
	validDays int, sanPolicy string) (*storage.CertOrder, error) {
	tmpl, err := s.loadApplyTemplate(ctx, applyTmplUUID)
	if err != nil {
		return nil, err
	}
	if !tmpl.Enabled {
		return nil, fmt.Errorf("该证书类型暂不开放申请")
	}
	if sanPolicy == "" {
		sanPolicy = "{}"
	}
	spec, _ := json.Marshal(map[string]interface{}{
		"mode": "subscription", "kind": storage.OrderKindCert, "product_name": tmpl.Name, "sku_name": tmpl.Name,
		"quantity": 1, "delivery_mode": string(storage.DeliveryDownload), "valid_days": validDays,
		"san_policy": json.RawMessage(sanPolicy),
	})
	order := &storage.CertOrder{
		UserUUID: userUUID, CertApplyTmplUUID: applyTmplUUID, SpecJSON: string(spec), ApplicantEmail: email,
		SKUCode: "subscription", SubscriptionUUID: subUUID,
	}
	if err := s.CreateOrder(ctx, order); err != nil {
		return nil, err
	}
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, paid_at = ?, updated_at = ? WHERE uuid = ?`,
		storage.CertOrderPaid, now, now, order.UUID); err != nil {
		return nil, err
	}
	order.Status, order.PaidAt = storage.CertOrderPaid, &now
	return order, nil
}

// SpecValidDays 读取规格快照中的证书有效期覆盖值（订阅套餐设置）。
func SpecValidDays(specJSON string) int {
	var spec struct {
		ValidDays int `json:"valid_days"`
	}
	json.Unmarshal([]byte(specJSON), &spec) //nolint:errcheck
	return spec.ValidDays
}

// SpecSANPolicy 读取规格快照中的 SAN 限制（原样 JSON）。
func SpecSANPolicy(specJSON string) (string, int) {
	var spec struct {
		SANPolicy   json.RawMessage `json:"san_policy"`
		SANIncluded int             `json:"san_included"`
	}
	json.Unmarshal([]byte(specJSON), &spec) //nolint:errcheck
	return string(spec.SANPolicy), spec.SANIncluded
}

// CancelOrder 取消待支付订单。
//
// 已支付订单涉及资金，必须走退款流程，不能通过"取消"绕过；
// operatorUUID 为空时按订单归属校验（用户自助取消），非空时视为管理员操作。
func (s *Service) CancelOrder(ctx context.Context, orderUUID, userUUID string) error {
	order, err := s.GetOrder(ctx, orderUUID)
	if err != nil {
		return err
	}
	if userUUID != "" && order.UserUUID != userUUID {
		return fmt.Errorf("无权取消此订单")
	}
	if order.Status != storage.CertOrderPendingPayment {
		return fmt.Errorf("仅待支付订单可取消；已支付订单请申请退款（当前状态: %s）", order.Status)
	}

	res, err := s.db.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, updated_at = ? WHERE uuid = ? AND status = ?`,
		storage.CertOrderCancelled, time.Now(), orderUUID, storage.CertOrderPendingPayment)
	if err != nil {
		return fmt.Errorf("取消订单失败: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("订单状态已变化，请刷新后重试")
	}
	// 关闭未完成的支付尝试，防止取消后仍被渠道回调入账
	s.db.ExecContext(ctx, //nolint:errcheck
		`UPDATE payment_attempts SET status = 'closed' WHERE biz_uuid = ? AND status = 'pending'`, orderUUID)
	return nil
}

// ---- 订单规格快照工具 ----

// SpecQuantity 读取规格快照中的购买份数（缺省为 1）。
func SpecQuantity(specJSON string) int {
	var spec struct {
		Quantity int `json:"quantity"`
	}
	if json.Unmarshal([]byte(specJSON), &spec) != nil || spec.Quantity < 1 {
		return 1
	}
	return spec.Quantity
}

// specKind 读取规格快照中的订单类型（缺省为证书订单）。
func specKind(specJSON string) string {
	var spec struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(specJSON), &spec) != nil || spec.Kind == "" {
		return storage.OrderKindCert
	}
	return spec.Kind
}

// SpecKind 是 specKind 的导出版本，供其它模块判定订单类型。
func SpecKind(specJSON string) string { return specKind(specJSON) }

// SpecDeliveryMode 读取规格快照中的交付方式。
func SpecDeliveryMode(specJSON string) string {
	var spec struct {
		DeliveryMode string `json:"delivery_mode"`
	}
	if json.Unmarshal([]byte(specJSON), &spec) != nil {
		return ""
	}
	return spec.DeliveryMode
}

// CompleteOrder 完成订单（签发成功后调用）。
func (s *Service) CompleteOrder(ctx context.Context, orderUUID, certUUID string) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE cert_orders SET status = ?, updated_at = ? WHERE uuid = ?`,
		string(storage.CertOrderCompleted), now, orderUUID,
	)
	if err != nil {
		return fmt.Errorf("完成订单失败: %w", err)
	}
	if certUUID != "" {
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE cert_applications SET cert_uuid = ?, status = 'approved', updated_at = ? WHERE order_uuid = ?`,
			certUUID, now, orderUUID,
		)
	}
	return nil
}

// marshalJSONArray 将字符串切片编码为 JSON 数组字符串，空值返回 "[]"。
// 用于填充 Certificate 记录中的 SAN 与证书策略 JSON 列（NOT NULL 约束）。
func marshalJSONArray(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	b, err := json.Marshal(ss)
	if err != nil {
		return "[]"
	}
	return string(b)
}
