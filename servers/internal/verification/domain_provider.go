package verification

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/identity"
)

// ---- 按所选域名接口执行验证 ----
//
// 域名验证不再是"写死的三种方式"，而是由扩展信息模板引用的接口决定：
// 记录前缀、解析服务器、文件路径、端口、超时都取自接口配置。

// resolverFor 返回按配置构造的解析器（未配置时使用系统默认）。
func resolverFor(cfg *identity.DomainConfig) *net.Resolver {
	if cfg == nil || strings.TrimSpace(cfg.Resolver) == "" {
		return net.DefaultResolver
	}
	addr := cfg.Resolver
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.Timeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// TestDomainProvider 按接口配置做一次连通性检查（不校验具体令牌）。
//
// 用于管理端"测试"按钮：确认解析服务器可达 / 目标端口可连，
// 这样配置错误在保存后就能发现，而不是等用户提交验证才暴露。
func (s *Service) TestDomainProvider(ctx context.Context, cfg *identity.DomainConfig, domain string) error {
	if cfg == nil {
		return fmt.Errorf("域名验证接口未配置")
	}
	domain = strings.TrimPrefix(strings.TrimSpace(domain), "*.")
	if domain == "" {
		return fmt.Errorf("请填写测试域名")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	switch cfg.Method {
	case identity.DomainMethodDNS:
		host := strings.TrimSuffix(cfg.RecordPrefix, ".") + "." + domain
		_, err := resolverFor(cfg).LookupTXT(ctx, host)
		if err != nil && !isNotFound(err) {
			return fmt.Errorf("DNS 查询 %s 失败: %w", host, err)
		}
		return nil

	case identity.DomainMethodHTTP, identity.DomainMethodTLSALPN:
		addr := net.JoinHostPort(domain, fmt.Sprintf("%d", cfg.Port))
		d := net.Dialer{Timeout: cfg.Timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("无法连接 %s: %w", addr, err)
		}
		return conn.Close()

	default:
		return fmt.Errorf("不支持的验证方式: %s", cfg.Method)
	}
}

// isNotFound 判断 DNS 查询结果是否为"记录不存在"（对连通性测试而言属于正常返回）。
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "not found") ||
		strings.Contains(msg, "nxdomain") || strings.Contains(msg, "timeout")
}

// VerifyDomainTicket 按接口配置校验收到的令牌内容。
//
// 供扩展信息验证调用：HTTP 方式请求 {path_prefix}{token}，DNS 方式查询 {prefix}.{domain}。
func (s *Service) VerifyDomainTicket(ctx context.Context, cfg *identity.DomainConfig, domain, token string) error {
	if cfg == nil {
		return fmt.Errorf("域名验证接口未配置")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	switch cfg.Method {
	case identity.DomainMethodDNS:
		host := strings.TrimSuffix(cfg.RecordPrefix, ".") + "." + strings.TrimPrefix(domain, "*.")
		txts, err := resolverFor(cfg).LookupTXT(ctx, host)
		if err != nil {
			return fmt.Errorf("DNS 查询 %s 失败: %w", host, err)
		}
		for _, txt := range txts {
			if strings.Contains(txt, token) {
				return nil
			}
		}
		return fmt.Errorf("未在 %s 找到包含该验证码的 TXT 记录", host)

	case identity.DomainMethodHTTP:
		host := domain
		if cfg.Port != 0 && cfg.Port != 80 {
			host = net.JoinHostPort(domain, fmt.Sprintf("%d", cfg.Port))
		}
		u := fmt.Sprintf("http://%s%s%s", host, cfg.PathPrefix, token)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return fmt.Errorf("验证地址无效: %w", err)
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("读取验证文件失败: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("验证文件不可访问（%s 返回 %d）", u, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return fmt.Errorf("读取验证文件失败: %w", err)
		}
		if !strings.Contains(string(body), token) {
			return fmt.Errorf("验证文件内容不匹配")
		}
		return nil

	case identity.DomainMethodTLSALPN:
		if s.tlsValidator == nil {
			return fmt.Errorf("TLS 验证未启用")
		}
		if strings.HasPrefix(domain, "*.") {
			return fmt.Errorf("通配符域名请使用 DNS 验证")
		}
		return s.tlsValidator(ctx, domain, token)
	}
	return fmt.Errorf("不支持的验证方式: %s", cfg.Method)
}

// TimeoutOf 返回接口配置的超时（未配置时 15 秒），供调用方设置整体预算。
func TimeoutOf(cfg *identity.DomainConfig) time.Duration {
	if cfg != nil && cfg.Timeout > 0 {
		return cfg.Timeout
	}
	return 15 * time.Second
}

// domainConfig 读取指定（或默认）域名接口配置。未配置任何接口时返回 nil，调用方回退到历史默认行为。
func (s *Service) domainConfig(ctx context.Context, providerUUID string) (*identity.DomainConfig, error) {
	if s.providers == nil {
		return nil, nil
	}
	cfg, err := s.providers.DomainConfigForProvider(ctx, providerUUID)
	if err != nil {
		if providerUUID != "" {
			return nil, err
		}
		// 没有默认接口：保持旧行为（写死的记录前缀与文件路径）
		return nil, nil
	}
	return cfg, nil
}

// VerifyDomainByProvider 按指定（或默认）域名接口执行验证并标记通过。
func (s *Service) VerifyDomainByProvider(ctx context.Context, infoUUID, providerUUID string) error {
	info, err := s.getExtensionInfo(ctx, infoUUID)
	if err != nil {
		return err
	}
	if info.InfoType != "domain" && info.InfoType != "ip" {
		return fmt.Errorf("此验证项不支持域名验证")
	}
	cfg, err := s.domainConfig(ctx, providerUUID)
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("尚未配置域名验证接口")
	}
	method := map[string]string{
		identity.DomainMethodDNS:     "txt",
		identity.DomainMethodHTTP:    "http",
		identity.DomainMethodTLSALPN: "tls",
	}[cfg.Method]
	if method == "" {
		return fmt.Errorf("不支持的验证方式: %s", cfg.Method)
	}
	if err := s.requirePending(info, method); err != nil {
		return err
	}
	if err := s.VerifyDomainTicket(ctx, cfg, info.Value, info.VerifyToken); err != nil {
		return err
	}
	return s.markVerified(ctx, infoUUID)
}
