package issuance

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/globaltrusts/server-card/internal/meta"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/globaltrusts/server-card/internal/template"
)

// ---- 统一策略解析 ----
//
// 取值层级：颁发模板（定范围和默认值）→ 商品规格 / 订阅（在范围内收窄）→ 用户选择。
// 申请向导、提交、工作流签发、ACME、代办申请、商品保存校验全部只调用
// ResolvePolicy / ValidateNarrowing，避免多处各自取值、互相冲突。

// Narrowing 是在颁发模板允许范围内的收窄条件，零值表示"不收窄"。
type Narrowing struct {
	ValidDays    int      // 商品规格 / 订阅指定的有效期（0=用默认值）
	KeyTypes     []string // 商品规格允许的密钥算法（空=不收窄）
	DeliveryMode string   // 商品规格指定的交付方式（空=不收窄）
}

// EffectivePolicy 是解析后的生效策略。
type EffectivePolicy struct {
	ApplyTmpl    *storage.CertApplyTemplate // 可为空（直接按颁发模板解析时）
	IssuanceTmpl *storage.IssuanceTemplate
	KeyStorage   *storage.KeyStorageTemplate // 未关联密钥存储模板时为空

	CAUUIDs          []string // 候选 CA
	DefaultCA        string   // 默认 CA
	ValidDays        []int    // 可选有效期（空=不限制，1~3650 天）
	DefaultValidDays int
	KeyTypes         []string // 允许的用户密钥算法
	IsCA             bool
	PathLen          int

	DeliveryModes   []string // 允许的交付方式：download / cloud_card / csr
	DownloadFormats []string // 文件下载允许的格式：pem / pkcs12

	SubjectTmpl   string // 主体模板
	ExtensionTmpl string // 扩展信息模板

	RequireApproval bool
	AllowRenewal    bool
	ApplyModes      []string
}

// policyCache 是单次请求内的模板读取缓存，避免同一请求内重复查询。
type policyCache struct {
	issuance   map[string]*storage.IssuanceTemplate
	keyStorage map[string]*storage.KeyStorageTemplate
}

type policyCacheKey struct{}

// WithPolicyCache 返回带请求级缓存的 context。仅应在单次请求/任务内使用：
// 缓存不会感知模板的后续修改。
func WithPolicyCache(ctx context.Context) context.Context {
	if _, ok := ctx.Value(policyCacheKey{}).(*policyCache); ok {
		return ctx
	}
	return context.WithValue(ctx, policyCacheKey{}, &policyCache{
		issuance:   map[string]*storage.IssuanceTemplate{},
		keyStorage: map[string]*storage.KeyStorageTemplate{},
	})
}

func cacheFrom(ctx context.Context) *policyCache {
	c, _ := ctx.Value(policyCacheKey{}).(*policyCache)
	return c
}

func (s *Service) loadIssuance(ctx context.Context, id string) (*storage.IssuanceTemplate, error) {
	if c := cacheFrom(ctx); c != nil {
		if t, ok := c.issuance[id]; ok {
			return t, nil
		}
	}
	t, err := s.GetIssuanceTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	if c := cacheFrom(ctx); c != nil {
		c.issuance[id] = t
	}
	return t, nil
}

func (s *Service) loadKeyStorage(ctx context.Context, id string) (*storage.KeyStorageTemplate, error) {
	if c := cacheFrom(ctx); c != nil {
		if t, ok := c.keyStorage[id]; ok {
			return t, nil
		}
	}
	t, err := template.NewService(s.db).GetByUUID(ctx, id)
	if err != nil {
		return nil, err
	}
	if c := cacheFrom(ctx); c != nil {
		c.keyStorage[id] = t
	}
	return t, nil
}

func (s *Service) loadApplyTmpl(ctx context.Context, id string) (*storage.CertApplyTemplate, error) {
	t := &storage.CertApplyTemplate{}
	var enabled, requireApproval, allowRenewal int
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, name, issuance_tmpl_uuid, enabled, require_approval, allow_renewal, apply_modes, description,
		        created_at, updated_at
		 FROM cert_apply_templates WHERE uuid = ?`, id,
	).Scan(&t.UUID, &t.Name, &t.IssuanceTmplUUID, &enabled, &requireApproval, &allowRenewal, &t.ApplyModes,
		&t.Description, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("证书开通模板不存在: %s", id)
	}
	t.Enabled = enabled == 1
	t.RequireApproval = requireApproval == 1
	t.AllowRenewal = allowRenewal == 1
	return t, nil
}

// ResolvePolicy 解析生效策略。
//
// applyTmplUUID 为开通模板 UUID；为空时必须通过 issuanceTmplUUID 直接指定颁发模板
// （ACME、内部签发等没有开通模板的场景）。narrow 只做收窄并校验，不会放宽颁发模板范围。
func (s *Service) ResolvePolicy(ctx context.Context, applyTmplUUID, issuanceTmplUUID string, narrow *Narrowing) (*EffectivePolicy, error) {
	p := &EffectivePolicy{
		RequireApproval: false,
		AllowRenewal:    true,
		ApplyModes:      []string{"order", "self", "subscription"},
	}

	if applyTmplUUID != "" {
		at, err := s.loadApplyTmpl(ctx, applyTmplUUID)
		if err != nil {
			return nil, err
		}
		p.ApplyTmpl = at
		p.RequireApproval = at.RequireApproval
		p.AllowRenewal = at.AllowRenewal
		if modes := parseJSONStrArr(at.ApplyModes); len(modes) > 0 {
			p.ApplyModes = modes
		}
		if issuanceTmplUUID == "" {
			issuanceTmplUUID = at.IssuanceTmplUUID
		}
	}
	if issuanceTmplUUID == "" {
		return nil, fmt.Errorf("缺少颁发模板，无法确定签发策略")
	}

	it, err := s.loadIssuance(ctx, issuanceTmplUUID)
	if err != nil {
		return nil, err
	}
	p.IssuanceTmpl = it

	p.CAUUIDs = parseJSONStrArr(it.AllowedCAUUIDs)
	p.DefaultCA = it.DefaultCAUUID
	if p.DefaultCA == "" && len(p.CAUUIDs) > 0 {
		p.DefaultCA = p.CAUUIDs[0]
	}
	p.ValidDays = parseJSONIntArr(it.ValidDays)
	p.DefaultValidDays = it.DefaultValidDays
	if p.DefaultValidDays == 0 && len(p.ValidDays) > 0 {
		p.DefaultValidDays = p.ValidDays[0]
	}
	p.KeyTypes = parseJSONStrArr(it.AllowedKeyTypes)
	p.IsCA = it.IsCA
	p.PathLen = it.PathLen
	p.SubjectTmpl = it.SubjectTmplUUID
	p.ExtensionTmpl = it.ExtensionTmplUUID

	// 交付方式与下载格式取决于密钥存储模板；未关联时不限制。
	p.DeliveryModes = []string{string(storage.DeliveryDownload), string(storage.DeliveryCloudCard), string(storage.DeliveryCSR)}
	p.DownloadFormats = []string{"pem", "pkcs12"}
	if it.KeyStorageTmplUUID != "" {
		ks, err := s.loadKeyStorage(ctx, it.KeyStorageTmplUUID)
		if err != nil {
			return nil, fmt.Errorf("颁发模板关联的密钥存储模板不存在")
		}
		p.KeyStorage = ks
		p.DeliveryModes = deliveryModesOf(ks)
		p.DownloadFormats = parseJSONStrArr(ks.DownloadFormats)
	}

	// 收窄：只能取颁发模板范围的子集
	if narrow != nil {
		if err := p.ValidateNarrowing(narrow); err != nil {
			return nil, err
		}
		if narrow.ValidDays > 0 {
			p.ValidDays = []int{narrow.ValidDays}
			p.DefaultValidDays = narrow.ValidDays
		}
		if len(narrow.KeyTypes) > 0 {
			p.KeyTypes = narrow.KeyTypes
		}
		if narrow.DeliveryMode != "" {
			p.DeliveryModes = []string{narrow.DeliveryMode}
		}
	}
	return p, nil
}

// ValidateNarrowing 校验收窄条件是否落在颁发模板范围内（商品保存与下单时调用）。
func (p *EffectivePolicy) ValidateNarrowing(n *Narrowing) error {
	if n == nil {
		return nil
	}
	if n.ValidDays < 0 || n.ValidDays > 3650 {
		return fmt.Errorf("证书有效期需在 1-3650 天之间")
	}
	if n.ValidDays > 0 && len(p.ValidDays) > 0 && !containsInt(p.ValidDays, n.ValidDays) {
		return fmt.Errorf("证书有效期 %d 天不在颁发模板允许的范围内 %v", n.ValidDays, p.ValidDays)
	}
	for _, kt := range n.KeyTypes {
		if len(p.KeyTypes) > 0 && !containsStr(p.KeyTypes, kt) {
			return fmt.Errorf("密钥算法 %s 不在颁发模板允许的范围内", kt)
		}
	}
	if n.DeliveryMode != "" && !containsStr(p.DeliveryModes, n.DeliveryMode) {
		return fmt.Errorf("交付方式 %s 不在颁发模板允许的范围内", n.DeliveryMode)
	}
	return nil
}

// SigAlgsForCA 返回由指定算法的 CA 签发时可用的签名算法。
//
// X.509 的签名算法由签发者（CA）私钥的类型决定，与被签发证书自身的密钥算法无关
// （例如 EC CA 可以给 RSA 用户证书签名，只能用 ECDSA 系列）；
// 因此这里按 CA 的密钥族取兼容的签名算法，再与颁发模板的 allowed_sig_algs 求交集。
func (p *EffectivePolicy) SigAlgsForCA(caKeyType string) []string {
	fam := keyFamily(caKeyType)
	if fam == "" {
		return nil
	}
	allowed := parseJSONStrArr(p.IssuanceTmpl.AllowedSigAlgs)
	var out []string
	for _, info := range meta.SignatureAlgorithms {
		if sigFamily(info.Name) != fam {
			continue
		}
		if len(allowed) > 0 && !containsStr(allowed, info.Name) {
			continue
		}
		out = append(out, info.Name)
	}
	sort.Strings(out)
	return out
}

// ValidateSelection 校验用户最终选择（签发前调用）：CA、密钥算法、签名算法、有效期。
// 空值表示使用默认值，由调用方在调用本函数后通过 Default* 取用。
// sigAlg 非空时 caKeyType 必须给出（签名算法由 CA 密钥类型决定）。
func (p *EffectivePolicy) ValidateSelection(caUUID, keyType, sigAlg string, validDays int) error {
	return p.ValidateSelectionWithCA(caUUID, "", keyType, sigAlg, validDays)
}

// ValidateSelectionWithCA 与 ValidateSelection 相同，额外按 CA 密钥算法校验签名算法与 SM2 混用。
func (p *EffectivePolicy) ValidateSelectionWithCA(caUUID, caKeyType, keyType, sigAlg string, validDays int) error {
	if caUUID != "" && len(p.CAUUIDs) > 0 && !containsStr(p.CAUUIDs, caUUID) {
		return fmt.Errorf("所选 CA 不在该证书类型允许的范围内")
	}
	if keyType != "" && len(p.KeyTypes) > 0 && !containsStr(p.KeyTypes, keyType) {
		return fmt.Errorf("密钥算法 %s 不在该证书类型允许的范围内", keyType)
	}
	if caKeyType != "" && keyType != "" && (keyFamily(caKeyType) == "sm2") != (keyFamily(keyType) == "sm2") {
		return fmt.Errorf("国密 SM2 证书必须由 SM2 CA 签发，且 SM2 CA 只能签发 SM2 证书")
	}
	if sigAlg != "" {
		if caKeyType == "" {
			return fmt.Errorf("指定签名算法时需要先确定签发 CA")
		}
		if !containsStr(p.SigAlgsForCA(caKeyType), sigAlg) {
			return fmt.Errorf("签名算法 %s 不适用于 %s 算法的 CA", sigAlg, caKeyType)
		}
	}
	if validDays > 0 {
		if validDays > 3650 {
			return fmt.Errorf("证书有效期不能超过 3650 天")
		}
		if len(p.ValidDays) > 0 && !containsInt(p.ValidDays, validDays) {
			return fmt.Errorf("证书有效期 %d 天不在允许的范围内 %v", validDays, p.ValidDays)
		}
	}
	return nil
}

// AllowsPKCS12 判断指定密钥算法是否可以提供 PKCS#12 下载：SM2 证书不提供 PKCS#12，
// 其余算法需要下载格式中包含 pkcs12。
func (p *EffectivePolicy) AllowsPKCS12(keyType string) bool {
	if keyFamily(keyType) == "sm2" {
		return false
	}
	return containsStr(p.DownloadFormats, "pkcs12")
}

// ---- 内部工具 ----

// deliveryModesOf 由密钥存储模板推导可用的交付方式。
func deliveryModesOf(ks *storage.KeyStorageTemplate) []string {
	var modes []string
	if ks.KeyGenLocation == storage.KeyGenCSR {
		return []string{string(storage.DeliveryCSR)}
	}
	if ks.HasMethod(storage.StorageFileDownload) {
		modes = append(modes, string(storage.DeliveryDownload))
	}
	if ks.HasMethod(storage.StorageCloudCard) {
		modes = append(modes, string(storage.DeliveryCloudCard))
	}
	return modes
}

// keyFamily 返回密钥算法所属族：rsa / ec / ed25519 / sm2。
func keyFamily(keyType string) string {
	kt := strings.ToLower(keyType)
	switch {
	case strings.HasPrefix(kt, "rsa"):
		return "rsa"
	case strings.HasPrefix(kt, "ec"):
		return "ec"
	case strings.HasPrefix(kt, "ed25519"):
		return "ed25519"
	case strings.HasPrefix(kt, "sm2"):
		return "sm2"
	}
	return ""
}

// sigFamily 返回签名算法所属的密钥族。
func sigFamily(sigName string) string {
	n := strings.ToUpper(sigName)
	switch {
	case strings.HasPrefix(n, "SM2"):
		return "sm2"
	case strings.Contains(n, "ECDSA"):
		return "ec"
	case strings.Contains(n, "ED25519"):
		return "ed25519"
	case strings.Contains(n, "RSA"):
		return "rsa"
	}
	return ""
}

// ValidateIssuanceTemplateDeep 在基础校验之外，结合关联对象做完整校验（保存颁发模板时调用）：
//   - 候选 CA 必须存在且处于启用状态；
//   - CA 算法与允许的密钥算法必须匹配（SM2 CA 只能签 SM2 证书，反之亦然）；
//   - is_ca 时必须关联 CA 类密钥用途模板（含 CertSign）；
//   - 允许的签名算法必须与允许的密钥算法同族。
func (s *Service) ValidateIssuanceTemplateDeep(ctx context.Context, t *storage.IssuanceTemplate) error {
	if err := ValidateIssuanceTemplate(t); err != nil {
		return err
	}
	keyTypes := parseJSONStrArr(t.AllowedKeyTypes)

	for _, caUUID := range parseJSONStrArr(t.AllowedCAUUIDs) {
		var status, caKeyType string
		err := s.db.QueryRowContext(ctx,
			`SELECT status, key_type FROM cas WHERE uuid = ?`, caUUID).Scan(&status, &caKeyType)
		if err != nil {
			return fmt.Errorf("候选 CA 不存在: %s", caUUID)
		}
		if status != "active" {
			return fmt.Errorf("候选 CA 已停用，不能作为颁发模板的签发 CA")
		}
		if caKeyType == "" {
			continue // 旧数据尚未回填算法，读取兼容阶段再补
		}
		caFam := keyFamily(caKeyType)
		for _, kt := range keyTypes {
			// SM2 与其它算法不能混用：SM2 CA 只签 SM2 证书；非 SM2 CA 不签 SM2 证书
			if (caFam == "sm2") != (keyFamily(kt) == "sm2") {
				return fmt.Errorf("CA 算法 %s 与允许的密钥算法 %s 不匹配（国密 SM2 与其它算法不能混用）", caKeyType, kt)
			}
		}
	}

	if sigs := parseJSONStrArr(t.AllowedSigAlgs); len(sigs) > 0 {
		families := map[string]bool{}
		for _, kt := range keyTypes {
			families[keyFamily(kt)] = true
		}
		for _, sg := range sigs {
			if len(families) > 0 && !families[sigFamily(sg)] {
				return fmt.Errorf("签名算法 %s 与允许的密钥算法不匹配", sg)
			}
		}
	}

	if t.IsCA {
		if t.KeyUsageTmplUUID == "" {
			return fmt.Errorf("CA 证书必须关联带「证书签名」用途的密钥用途模板")
		}
		var ku int
		if err := s.db.QueryRowContext(ctx,
			`SELECT key_usage FROM key_usage_templates WHERE uuid = ?`, t.KeyUsageTmplUUID).Scan(&ku); err != nil {
			return fmt.Errorf("密钥用途模板不存在")
		}
		const keyUsageCertSign = 1 << 5 // x509.KeyUsageCertSign
		if ku&keyUsageCertSign == 0 {
			return fmt.Errorf("CA 证书的密钥用途模板必须包含「证书签名」")
		}
	}
	return nil
}

// MarshalStrings 将字符串数组编码为 JSON，供 handler 层统一使用。
func MarshalStrings(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}
