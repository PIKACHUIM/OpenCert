// Package identity 提供身份认证体系的规则层：主体模板字段、扩展信息验证策略、
// 商品规格 SAN 限制、认证有效期，以及邮件/实名认证接口（见 provider.go）。
//
// 规则层只做纯计算与校验，不直接访问数据库，便于单元测试与多处复用
// （创建主体信息、申请向导预览、提交申请时的最终校验）。
package identity

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---- 验证方式 ----

const (
	VerifyManual = "manual" // 人工审核
	VerifyAuto   = "auto"   // 自动接口（实名认证回调 / 域名 DNS-HTTP-TLS / 邮箱验证码）
	VerifyNone   = "none"   // 免验证
)

// 派生规则：主体字段由扩展信息推导，派生字段无需用户填写与单独审核。
const (
	DeriveNone        = ""
	DeriveFirstDomain = "first_domain"
	DeriveFirstEmail  = "first_email"
	DeriveFirstIP     = "first_ip"
)

// SubjectFieldKeys 是支持的主体字段（X.500 属性简称）。
var SubjectFieldKeys = []struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}{
	{"CN", "通用名称 (CN)"},
	{"O", "组织 (O)"},
	{"OU", "部门 (OU)"},
	{"C", "国家代码 (C)"},
	{"ST", "省/州 (ST)"},
	{"L", "城市 (L)"},
	{"STREET", "街道地址 (STREET)"},
	{"POSTALCODE", "邮政编码 (PostalCode)"},
	{"SERIALNUMBER", "序列号/证件号 (SerialNumber)"},
	{"E", "邮箱地址 (E)"},
	{"UID", "用户 ID (UID)"},
	{"TITLE", "职务 (Title)"},
	{"GIVENNAME", "名 (GivenName)"},
	{"SURNAME", "姓 (Surname)"},
	{"BUSINESSCATEGORY", "业务类别 (BusinessCategory)"},
	{"JURISDICTIONC", "注册地国家 (jurisdictionC)"},
	{"ORGID", "组织标识 (organizationIdentifier)"},
}

var subjectKeySet = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range SubjectFieldKeys {
		m[k.Key] = true
	}
	return m
}()

// 预置格式校验。
var formatPatterns = map[string]*regexp.Regexp{
	"country": regexp.MustCompile(`^[A-Z]{2}$`),
	"email":   regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`),
	"domain":  regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`),
	"digits":  regexp.MustCompile(`^[0-9]+$`),
	"uscc":    regexp.MustCompile(`^[0-9A-HJ-NPQRTUWXY]{2}\d{6}[0-9A-HJ-NPQRTUWXY]{10}$`), // 统一社会信用代码
}

// SubjectField 是主体模板中的单个字段定义。
type SubjectField struct {
	Key      string `json:"key"`      // CN/O/OU/C...
	Label    string `json:"label"`    // 展示名（缺省用预置名称）
	Required bool   `json:"required"` // 是否必填
	MinLen   int    `json:"min_len"`
	MaxLen   int    `json:"max_len"`
	Format   string `json:"format"`  // 预置格式：country/email/domain/digits/uscc，或留空
	Pattern  string `json:"pattern"` // 自定义正则（与 Format 同时存在时两者都需满足）
	Verify   string `json:"verify"`  // manual/auto/none
	Derive   string `json:"derive"`  // 派生规则，非空时字段值由扩展信息推导
	Default  string `json:"default"`
	Help     string `json:"help"`
}

// ParseSubjectFields 解析并校验主体模板字段定义。
func ParseSubjectFields(raw string) ([]SubjectField, error) {
	fields := []SubjectField{}
	if strings.TrimSpace(raw) == "" {
		return fields, nil
	}
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return nil, fmt.Errorf("主体字段定义格式错误: %w", err)
	}
	seen := map[string]bool{}
	for i := range fields {
		f := &fields[i]
		f.Key = strings.ToUpper(strings.TrimSpace(f.Key))
		if !subjectKeySet[f.Key] {
			return nil, fmt.Errorf("不支持的主体字段: %s", f.Key)
		}
		if seen[f.Key] {
			return nil, fmt.Errorf("主体字段重复: %s", f.Key)
		}
		seen[f.Key] = true
		switch f.Verify {
		case "":
			f.Verify = VerifyManual
		case VerifyManual, VerifyAuto, VerifyNone:
		default:
			return nil, fmt.Errorf("字段 %s 的验证方式无效: %s", f.Key, f.Verify)
		}
		switch f.Derive {
		case DeriveNone, DeriveFirstDomain, DeriveFirstEmail, DeriveFirstIP:
		default:
			return nil, fmt.Errorf("字段 %s 的派生规则无效: %s", f.Key, f.Derive)
		}
		if f.Derive != DeriveNone {
			// 派生值来自已验证的扩展信息，本身无需再审核
			f.Verify = VerifyNone
		}
		if f.MinLen < 0 || f.MaxLen < 0 || (f.MaxLen > 0 && f.MinLen > f.MaxLen) {
			return nil, fmt.Errorf("字段 %s 的长度范围无效", f.Key)
		}
		if f.Format != "" && formatPatterns[f.Format] == nil {
			return nil, fmt.Errorf("字段 %s 的格式无效: %s", f.Key, f.Format)
		}
		if f.Pattern != "" {
			if _, err := regexp.Compile(f.Pattern); err != nil {
				return nil, fmt.Errorf("字段 %s 的正则表达式无效: %w", f.Key, err)
			}
		}
		if f.Label == "" {
			for _, k := range SubjectFieldKeys {
				if k.Key == f.Key {
					f.Label = k.Label
				}
			}
		}
	}
	return fields, nil
}

// NeedsSubjectInfo 判断模板是否需要用户单独提交主体信息（存在非派生字段）。
func NeedsSubjectInfo(fields []SubjectField) bool {
	for _, f := range fields {
		if f.Derive == DeriveNone {
			return true
		}
	}
	return false
}

// SubjectVerifyMode 汇总主体信息所需的验证方式：任一字段人工 → 人工；否则任一自动 → 自动；否则免验证。
func SubjectVerifyMode(fields []SubjectField) string {
	mode := VerifyNone
	for _, f := range fields {
		if f.Derive != DeriveNone {
			continue
		}
		switch f.Verify {
		case VerifyManual:
			return VerifyManual
		case VerifyAuto:
			mode = VerifyAuto
		}
	}
	return mode
}

// ValidateSubjectValues 按模板校验用户填写的主体字段（派生字段忽略，由申请时推导）。
// 返回清洗后的值（去除首尾空白、补默认值、剔除模板未定义的字段）。
func ValidateSubjectValues(fields []SubjectField, values map[string]string) (map[string]string, error) {
	clean := map[string]string{}
	for _, f := range fields {
		if f.Derive != DeriveNone {
			continue
		}
		v := strings.TrimSpace(values[f.Key])
		if v == "" {
			v = strings.TrimSpace(f.Default)
		}
		if v == "" {
			if f.Required {
				return nil, fmt.Errorf("%s 为必填项", f.Label)
			}
			continue
		}
		n := utf8.RuneCountInString(v)
		if f.MinLen > 0 && n < f.MinLen {
			return nil, fmt.Errorf("%s 长度不能少于 %d 个字符", f.Label, f.MinLen)
		}
		max := f.MaxLen
		if max == 0 {
			max = 128 // X.520 ub-name 常见上限
		}
		if n > max {
			return nil, fmt.Errorf("%s 长度不能超过 %d 个字符", f.Label, max)
		}
		if f.Format != "" && !formatPatterns[f.Format].MatchString(v) {
			return nil, fmt.Errorf("%s 格式不正确", f.Label)
		}
		if f.Pattern != "" && !regexp.MustCompile(f.Pattern).MatchString(v) {
			return nil, fmt.Errorf("%s 格式不符合要求", f.Label)
		}
		clean[f.Key] = v
	}
	return clean, nil
}

// ApplyDerivedFields 用已验证的 SAN 填充派生字段，并校验必填派生字段是否有来源。
func ApplyDerivedFields(fields []SubjectField, subject map[string]string, san map[string][]string) error {
	for _, f := range fields {
		var src []string
		switch f.Derive {
		case DeriveNone:
			continue
		case DeriveFirstDomain:
			src = san["dns"]
		case DeriveFirstEmail:
			src = san["email"]
		case DeriveFirstIP:
			src = san["ip"]
		}
		if len(src) == 0 {
			if f.Required {
				return fmt.Errorf("%s 需由扩展信息派生，请至少添加一个对应的%s", f.Label, deriveLabel(f.Derive))
			}
			continue
		}
		subject[f.Key] = src[0]
	}
	return nil
}

func deriveLabel(d string) string {
	switch d {
	case DeriveFirstEmail:
		return "邮箱"
	case DeriveFirstIP:
		return "IP 地址"
	default:
		return "域名"
	}
}

// ---- 扩展信息验证策略 ----

// TypePolicy 是某一类扩展信息（域名/邮箱/IP）的验证策略。
type TypePolicy struct {
	Enabled bool     `json:"enabled"` // 是否允许此类扩展信息
	Mode    string   `json:"mode"`    // manual/auto/none
	Methods []string `json:"methods"` // 域名：dns/http/tls；IP：http；邮箱：email
	// ProviderUUIDs 是所选验证接口（按顺序优先使用；为空使用系统默认接口）。
	// 域名对应「域名验证接口」，邮箱对应「邮件接口」。
	ProviderUUIDs []string `json:"provider_uuids,omitempty"`
	// ProviderUUID 是历史字段（单个接口），读取时并入 ProviderUUIDs。
	ProviderUUID string `json:"provider_uuid,omitempty"`
	Validity     string `json:"validity"` // 验证有效期：1d/7d/30d...
}

// Providers 返回生效的接口 UUID 列表（兼容历史单值字段，去重且去空）。
func (tp *TypePolicy) Providers() []string {
	if tp == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range append([]string{tp.ProviderUUID}, tp.ProviderUUIDs...) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// PrimaryProvider 返回首选接口 UUID（无配置时为空，表示使用系统默认接口）。
func (tp *TypePolicy) PrimaryProvider() string {
	if ids := tp.Providers(); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// ExtensionPolicy 是扩展信息模板的验证策略集合。
type ExtensionPolicy struct {
	Domain TypePolicy `json:"domain"`
	Email  TypePolicy `json:"email"`
	IP     TypePolicy `json:"ip"`
}

// DefaultExtensionPolicy 返回缺省策略：域名 DNS/HTTP 自动验证、邮箱验证码、IP HTTP 验证，有效期 30 天。
func DefaultExtensionPolicy() ExtensionPolicy {
	return ExtensionPolicy{
		Domain: TypePolicy{Enabled: true, Mode: VerifyAuto, Methods: []string{"dns", "http"}, Validity: "30d"},
		Email:  TypePolicy{Enabled: true, Mode: VerifyAuto, Methods: []string{"email"}, Validity: "30d"},
		IP:     TypePolicy{Enabled: true, Mode: VerifyAuto, Methods: []string{"http"}, Validity: "30d"},
	}
}

// ParseExtensionPolicy 解析扩展策略；空值返回缺省策略。
func ParseExtensionPolicy(raw string) (ExtensionPolicy, error) {
	p := DefaultExtensionPolicy()
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return p, nil
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, fmt.Errorf("扩展信息验证策略格式错误: %w", err)
	}
	for name, tp := range map[string]*TypePolicy{"domain": &p.Domain, "email": &p.Email, "ip": &p.IP} {
		if tp.Mode == "" {
			tp.Mode = VerifyAuto
		}
		if tp.Mode != VerifyManual && tp.Mode != VerifyAuto && tp.Mode != VerifyNone {
			return p, fmt.Errorf("%s 的验证方式无效: %s", name, tp.Mode)
		}
		allowed := map[string][]string{"domain": {"dns", "http", "tls"}, "email": {"email"}, "ip": {"http"}}[name]
		clean := []string{}
		for _, m := range tp.Methods {
			if contains(allowed, m) {
				clean = append(clean, m)
			}
		}
		if len(clean) == 0 {
			clean = allowed[:1]
		}
		tp.Methods = clean
		if tp.Validity == "" {
			tp.Validity = "30d"
		}
		if _, err := ParseValidity(tp.Validity); err != nil {
			return p, fmt.Errorf("%s 的有效期无效: %w", name, err)
		}
	}
	return p, nil
}

// For 返回指定类型的策略。
func (p ExtensionPolicy) For(infoType string) TypePolicy {
	switch infoType {
	case "email":
		return p.Email
	case "ip":
		return p.IP
	default:
		return p.Domain
	}
}

// ---- 商品规格 SAN 限制 ----

// SANPolicy 是单张证书允许的 SAN 数量与格式限制（配置在商品规格上）。
type SANPolicy struct {
	MaxDNS        int      `json:"max_dns"`        // 域名数量上限（0 = 不允许）
	MaxEmail      int      `json:"max_email"`      // 邮箱数量上限
	MaxIP         int      `json:"max_ip"`         // IP 数量上限
	AllowWildcard bool     `json:"allow_wildcard"` // 是否允许通配符域名
	IPVersions    []string `json:"ip_versions"`    // 允许的 IP 版本：v4 / v6
	EmailSuffixes []string `json:"email_suffixes"` // 允许的邮箱后缀（空 = 不限）
	DNSSuffixes   []string `json:"dns_suffixes"`   // 允许的域名后缀（空 = 不限）
}

// ParseSANPolicy 解析 SAN 限制；空值时按 fallbackDNS（历史 san_included 字段）生成仅域名的限制。
func ParseSANPolicy(raw string, fallbackDNS int) SANPolicy {
	p := SANPolicy{MaxDNS: fallbackDNS, IPVersions: []string{"v4", "v6"}}
	raw = strings.TrimSpace(raw)
	if raw != "" && raw != "{}" {
		json.Unmarshal([]byte(raw), &p) //nolint:errcheck
	}
	if len(p.IPVersions) == 0 {
		p.IPVersions = []string{"v4", "v6"}
	}
	return p
}

// Check 校验一组 SAN 是否满足限制。
func (p SANPolicy) Check(san map[string][]string) error {
	if n := len(san["dns"]); n > p.MaxDNS {
		if p.MaxDNS == 0 {
			return fmt.Errorf("该证书不支持域名")
		}
		return fmt.Errorf("该证书最多包含 %d 个域名，当前 %d 个", p.MaxDNS, n)
	}
	if n := len(san["email"]); n > p.MaxEmail {
		if p.MaxEmail == 0 {
			return fmt.Errorf("该证书不支持邮箱地址")
		}
		return fmt.Errorf("该证书最多包含 %d 个邮箱，当前 %d 个", p.MaxEmail, n)
	}
	if n := len(san["ip"]); n > p.MaxIP {
		if p.MaxIP == 0 {
			return fmt.Errorf("该证书不支持 IP 地址")
		}
		return fmt.Errorf("该证书最多包含 %d 个 IP，当前 %d 个", p.MaxIP, n)
	}
	for _, d := range san["dns"] {
		if err := p.CheckValue("domain", d); err != nil {
			return err
		}
	}
	for _, e := range san["email"] {
		if err := p.CheckValue("email", e); err != nil {
			return err
		}
	}
	for _, ip := range san["ip"] {
		if err := p.CheckValue("ip", ip); err != nil {
			return err
		}
	}
	return nil
}

// CheckValue 校验单个扩展信息值是否符合格式限制（申请向导添加时即时提示）。
func (p SANPolicy) CheckValue(infoType, v string) error {
	switch infoType {
	case "domain":
		d := strings.ToLower(v)
		if strings.HasPrefix(d, "*.") && !p.AllowWildcard {
			return fmt.Errorf("该证书不支持通配符域名: %s", v)
		}
		if len(p.DNSSuffixes) > 0 && !hasSuffix(strings.TrimPrefix(d, "*."), p.DNSSuffixes) {
			return fmt.Errorf("域名 %s 不在允许的后缀范围内", v)
		}
	case "email":
		if len(p.EmailSuffixes) > 0 {
			at := strings.LastIndex(v, "@")
			if at < 0 || !hasSuffix(strings.ToLower(v[at+1:]), p.EmailSuffixes) {
				return fmt.Errorf("邮箱 %s 不在允许的后缀范围内", v)
			}
		}
	case "ip":
		ip := net.ParseIP(v)
		if ip == nil {
			return fmt.Errorf("IP 地址格式错误: %s", v)
		}
		ver := "v6"
		if ip.To4() != nil {
			ver = "v4"
		}
		if !contains(p.IPVersions, ver) {
			return fmt.Errorf("该证书不支持 IP%s 地址: %s", strings.ToUpper(ver[1:]), v)
		}
	}
	return nil
}

func hasSuffix(v string, suffixes []string) bool {
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "@"))
		s = strings.TrimPrefix(s, ".")
		if s != "" && (v == s || strings.HasSuffix(v, "."+s)) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- 有效期 ----

// ParseValidity 解析有效期表达式：Nh / Nd / Nw / Nm(30 天) / Ny(365 天)；"0" 或 "never" 表示长期有效。
func ParseValidity(v string) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "0" || v == "never" {
		return 0, nil
	}
	if len(v) < 2 {
		return 0, fmt.Errorf("有效期格式错误: %s（示例 1d/7d/30d/1y）", v)
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("有效期格式错误: %s（示例 1d/7d/30d/1y）", v)
	}
	unit := map[byte]time.Duration{'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour,
		'm': 30 * 24 * time.Hour, 'y': 365 * 24 * time.Hour}[v[len(v)-1]]
	if unit == 0 {
		return 0, fmt.Errorf("有效期单位无效: %s（支持 h/d/w/m/y）", v)
	}
	return time.Duration(n) * unit, nil
}

// ExpiryFrom 计算从 now 起的过期时间；长期有效返回 nil。
func ExpiryFrom(now time.Time, validity string) *time.Time {
	d, err := ParseValidity(validity)
	if err != nil || d == 0 {
		return nil
	}
	t := now.Add(d)
	return &t
}
