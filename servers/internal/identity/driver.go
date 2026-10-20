package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ---- 实名认证驱动接口 ----
//
// 每个实名方式实现 Start（生成跳转地址）/ Callback（处理第三方回调）/ Query（主动查询结果），
// 三者必须至少实现其一，未实现的返回 ErrDriverNotSupported，便于前端给出可读提示。
//
// 新增实名方式时：在 provider.go 的 Drivers 里登记字段，再在 init() 中注册实现。

// ErrDriverNotSupported 表示该驱动不支持某项操作。
type ErrDriverNotSupported struct{ Op string }

func (e *ErrDriverNotSupported) Error() string {
	return fmt.Sprintf("该实名认证方式不支持%s操作", e.Op)
}

// StartInput 是发起实名认证时的上下文。
type StartInput struct {
	BaseURL   string            // 平台对外地址（用于拼回调地址）
	ReturnURL string            // 认证完成后回到的前端页面
	Fields    map[string]string // 主体信息字段（证件号、姓名等），用于预填
}

// IdentityDriver 是实名认证驱动。Store 由调用方注入，驱动只负责协议细节，
// 会话落库与状态流转统一由 Store 完成。
type IdentityDriver interface {
	// Start 返回用户需要跳转的地址。
	Start(ctx context.Context, s *Store, p *Provider, sess *Session, in StartInput) (string, error)
	// Callback 处理第三方异步回调：校验来源，返回解析结果与要回给第三方的响应体。
	Callback(ctx context.Context, s *Store, p *Provider, r *http.Request, body []byte) (*CallbackResult, []byte, error)
	// Query 主动查询认证结果（回调不可达或需要补偿时使用）。
	Query(ctx context.Context, s *Store, p *Provider, sess *Session) (*CallbackResult, error)
}

var identityDrivers = map[string]IdentityDriver{}

// RegisterIdentityDriver 注册实名驱动实现。
func RegisterIdentityDriver(name string, d IdentityDriver) {
	identityDrivers[strings.ToLower(strings.TrimSpace(name))] = d
}

func identityDriverOf(name string) (IdentityDriver, error) {
	d, ok := identityDrivers[NormalizeDriver(name)]
	if !ok {
		return nil, fmt.Errorf("不支持的实名认证方式: %s", name)
	}
	return d, nil
}

// NormalizeDriver 处理历史驱动名与别名：webhook 是「三方回调认证」的旧名字，
// wechat 是「微信慧眼」的旧名字。
func NormalizeDriver(driver string) string {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "webhook":
		return "callback"
	case "wechat":
		return "wechat_faceid"
	}
	return strings.ToLower(strings.TrimSpace(driver))
}

// migrateLegacyConfig 兼容旧配置的字段名（webhook → callback）。
func migrateLegacyConfig(driver string, cfg map[string]string) map[string]string {
	if strings.EqualFold(strings.TrimSpace(driver), "webhook") {
		if cfg["request_url"] == "" {
			cfg["request_url"] = cfg["redirect_url"]
		}
		if cfg["request_method"] == "" {
			cfg["request_method"] = http.MethodGet
		}
		if cfg["verify_mode"] == "" {
			cfg["verify_mode"] = "hmac"
		}
		if cfg["callback_format"] == "" {
			cfg["callback_format"] = "json"
		}
	}
	return cfg
}

// providerFieldMapping 解析主体字段映射（实名参数 → 主体字段键）。
func providerFieldMapping(cfg map[string]string) map[string]string {
	out := map[string]string{}
	raw := strings.TrimSpace(cfg["field_mapping"])
	if raw == "" {
		return out
	}
	json.Unmarshal([]byte(raw), &out) //nolint:errcheck
	return out
}
