package identity

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---- 域名验证接口配置 ----
//
// 域名的验证方式（DNS TXT / HTTP 文件 / TLS-ALPN）由扩展信息模板引用的接口决定，
// 每个接口可以各自配置解析服务器、记录前缀、端口与超时。

// 域名验证方式标识（与模板中的 methods 取值一致）。
const (
	DomainMethodDNS     = "dns"
	DomainMethodHTTP    = "http"
	DomainMethodTLSALPN = "tls-alpn"
)

// DomainConfig 是一份域名验证接口的生效配置。
type DomainConfig struct {
	ProviderUUID string
	Name         string
	Driver       string // dns_txt / http_file / tls_alpn
	Method       string // dns / http / tls-alpn
	RecordPrefix string
	Resolver     string
	PathPrefix   string
	Port         int
	Timeout      time.Duration
}

// MethodOfDriver 把域名驱动映射为验证方式标识。
func MethodOfDriver(driver string) string {
	switch NormalizeDriver(driver) {
	case "dns_txt":
		return DomainMethodDNS
	case "http_file":
		return DomainMethodHTTP
	case "tls_alpn":
		return DomainMethodTLSALPN
	}
	return ""
}

// DriverOfMethod 把验证方式标识映射为驱动名。
func DriverOfMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case DomainMethodDNS, "dns_txt":
		return "dns_txt"
	case DomainMethodHTTP, "http_file", "http-01":
		return "http_file"
	case DomainMethodTLSALPN, "tls_alpn", "tls-alpn-01":
		return "tls_alpn"
	}
	return ""
}

// DomainConfigOf 把接口记录解析成域名验证配置。
func DomainConfigOf(p *Provider) *DomainConfig {
	if p == nil {
		return nil
	}
	cfg := &DomainConfig{
		ProviderUUID: p.UUID,
		Name:         p.Name,
		Driver:       NormalizeDriver(p.Driver),
		Method:       MethodOfDriver(p.Driver),
		RecordPrefix: strings.TrimSpace(p.Config["record_prefix"]),
		Resolver:     strings.TrimSpace(p.Config["resolver"]),
		PathPrefix:   strings.TrimSpace(p.Config["path_prefix"]),
	}
	// 默认值与平台既有的验证说明保持一致，避免升级后已提交的验证指引失效
	if cfg.RecordPrefix == "" {
		cfg.RecordPrefix = "_opencert"
	}
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/.well-known/pki-validation/"
	}
	if !strings.HasPrefix(cfg.PathPrefix, "/") {
		cfg.PathPrefix = "/" + cfg.PathPrefix
	}
	if !strings.HasSuffix(cfg.PathPrefix, "/") {
		cfg.PathPrefix += "/"
	}
	if v, err := strconv.Atoi(strings.TrimSpace(p.Config["port"])); err == nil && v > 0 {
		cfg.Port = v
	}
	if cfg.Port == 0 {
		switch cfg.Method {
		case DomainMethodTLSALPN:
			cfg.Port = 443
		default:
			cfg.Port = 80
		}
	}
	cfg.Timeout = 15 * time.Second
	if v, err := strconv.Atoi(strings.TrimSpace(p.Config["timeout"])); err == nil && v > 0 {
		cfg.Timeout = time.Duration(v) * time.Second
	}
	return cfg
}

// DomainConfigForProvider 读取指定域名接口的配置；为空时使用默认接口。
func (s *Store) DomainConfigForProvider(ctx context.Context, providerUUID string) (*DomainConfig, error) {
	if s == nil {
		return nil, fmt.Errorf("域名验证接口未启用")
	}
	var p *Provider
	var err error
	if strings.TrimSpace(providerUUID) == "" {
		p, err = s.DefaultProvider(ctx, KindDomain)
	} else {
		p, err = s.Get(ctx, providerUUID)
	}
	if err != nil {
		return nil, err
	}
	if p.Kind != KindDomain || !p.Enabled {
		return nil, fmt.Errorf("域名验证接口「%s」不可用", p.Name)
	}
	cfg := DomainConfigOf(p)
	if cfg.Method == "" {
		return nil, fmt.Errorf("域名验证接口「%s」的验证方式无法识别", p.Name)
	}
	return cfg, nil
}
