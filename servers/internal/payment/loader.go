// Package payment - 支付渠道 Loader：从数据库 PaymentPlugin 表加载启用的渠道并注入 Registry。
//
// 工作流程：
//  1. 查询 payment_plugins 表中 enabled=1 的所有插件
//  2. 用 decryptFn 解密 ConfigEnc 字段（与 handler_payment.go 写入路径对称）
//  3. 按 plugin_type 路由到对应 NewXxxProvider 构造函数
//  4. 注册到 Registry，覆盖同 type 的旧 provider（支持热更新）
//
// 调用时机：
//   - main.go 启动时一次性加载（首次注入）
//   - 管理员通过 API 创建/更新/删除插件后可再次调用 Reload 热更新
package payment

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// DecryptFn 是解密函数签名，用 cardSvc.DecryptData 实例化。
type DecryptFn func(cipher []byte) ([]byte, error)

// Loader 负责从数据库加载支付渠道到 Registry。
type Loader struct {
	db        DBExecutor
	registry  *Registry
	decryptFn DecryptFn
}

// DBExecutor 是 Loader 需要的最小数据库接口（便于测试桩）。
type DBExecutor interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// NewLoader 创建 Loader。
func NewLoader(db DBExecutor, registry *Registry, decryptFn DecryptFn) *Loader {
	return &Loader{db: db, registry: registry, decryptFn: decryptFn}
}

// Reload 重新加载启用的支付插件到 Registry。
// 加载失败的单个插件会被跳过并打印日志，不影响其它插件加载。
// 返回成功加载的插件类型列表。
func (l *Loader) Reload(ctx context.Context) ([]string, error) {
	rows, err := l.db.QueryContext(ctx,
		`SELECT uuid, name, plugin_type, config_enc
		 FROM payment_plugins
		 WHERE enabled = 1
		 ORDER BY sort_weight DESC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询支付插件失败: %w", err)
	}
	defer rows.Close()

	// 先构建完整的新注册表再整体替换：停用/删除的插件会立即下线。
	// 同一类型存在多个启用插件时，按 sort_weight 降序取第一个生效。
	next := map[string]PaymentProvider{}
	defer func() { l.registry.Replace(next) }()

	var loaded []string
	for rows.Next() {
		var uuidStr, name, pluginType string
		var configEnc []byte
		if err := rows.Scan(&uuidStr, &name, &pluginType, &configEnc); err != nil {
			slog.Error("扫描支付插件行失败", "error", err)
			continue
		}

		// 解密配置
		var rawConfig []byte
		if len(configEnc) > 0 {
			rawConfig, err = l.decryptFn(configEnc)
			if err != nil {
				slog.Error("解密支付插件配置失败，已跳过",
					"uuid", uuidStr, "type", pluginType, "error", err)
				continue
			}
		}

		// 按类型路由到对应 provider
		provider, err := buildProvider(pluginType, rawConfig)
		if err != nil {
			slog.Error("构造支付渠道失败，已跳过",
				"uuid", uuidStr, "type", pluginType, "name", name, "error", err)
			continue
		}
		if _, exists := next[pluginType]; exists {
			slog.Warn("同类型支付插件已启用，按排序权重仅保留优先级最高的一个",
				"type", pluginType, "skipped", name)
			continue
		}
		next[pluginType] = provider
		loaded = append(loaded, pluginType)
		slog.Info("已注册支付渠道", "type", pluginType, "name", name)
	}
	return loaded, rows.Err()
}

// ValidateProviderConfig 校验插件类型与配置是否可用（管理端保存前调用）。
func ValidateProviderConfig(pluginType string, rawConfig []byte) error {
	_, err := buildProvider(pluginType, rawConfig)
	return err
}

// buildProvider 按 pluginType 调度到具体的 NewXxxProvider 构造函数。
// 优先使用 RegisterFactory 注册的扩展插件，便于新增渠道而不修改本文件。
func buildProvider(pluginType string, rawConfig []byte) (PaymentProvider, error) {
	if f, ok := lookupFactory(pluginType); ok {
		return f(rawConfig)
	}
	switch pluginType {
	case "alipay":
		return NewAlipayProvider(rawConfig)
	case "wechat":
		return NewWeChatProvider(rawConfig)
	case "stripe":
		return NewStripeProvider(rawConfig)
	case "paypal":
		return NewPayPalProvider(rawConfig)
	default:
		return nil, fmt.Errorf("未知支付渠道类型: %s", pluginType)
	}
}
