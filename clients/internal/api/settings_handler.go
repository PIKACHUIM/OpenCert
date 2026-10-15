// Package api：Settings 配置的读取与持久化接口。
// GET  /api/settings → 返回当前运行时 ClientConfig
// PUT  /api/settings → 把请求体写入 config.yaml，并热更新进程内 cfg 指针
package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"

	config "github.com/globaltrusts/client-card/configs"
)

// fullConfigHolder 持有一份完整的 Config（包括 ClientConfig + 其它段），
// 用于在 PUT /api/settings 时把新配置写回 YAML 而不丢失其它段。
// 进程启动时由 NewServer 负责调用 BindFullConfig 注入完整 Config 引用。
var (
	fullCfgMu  sync.RWMutex
	fullCfg    *config.Config
	configPath string
)

// BindFullConfig 由 main() 在启动阶段调用，把完整配置 + 配置文件路径
// 注入给 api 包，使 settings handler 可以读写 YAML。
func BindFullConfig(cfg *config.Config, path string) {
	fullCfgMu.Lock()
	defer fullCfgMu.Unlock()
	fullCfg = cfg
	configPath = path
}

// handleGetSettings GET /api/settings
// 返回当前 ClientConfig 的快照（JSON 格式）。
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	fullCfgMu.RLock()
	defer fullCfgMu.RUnlock()
	if fullCfg == nil {
		// 未绑定：返回默认 ClientConfig（通常发生在单测或 main 未调 BindFullConfig 时）
		writeOK(w, config.DefaultConfig().Client)
		return
	}
	writeOK(w, fullCfg.Client)
}

// handlePutSettings PUT /api/settings
// 接收 ClientConfig 的完整或部分字段，更新进程内配置并落盘到 config.yaml。
func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var incoming config.ClientConfig
	if err := decodeJSON(r, &incoming); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// 基本校验
	if incoming.SyncIntervalMinutes < 0 {
		writeError(w, http.StatusBadRequest, "sync_interval_minutes 不能为负数")
		return
	}
	if incoming.SessionExpiresMinutes < 0 {
		writeError(w, http.StatusBadRequest, "session_expires_minutes 不能为负数")
		return
	}

	fullCfgMu.Lock()
	defer fullCfgMu.Unlock()

	if fullCfg == nil {
		// 未绑定：接受配置但不落盘（例如在单测中调用）
		c := config.DefaultConfig()
		c.Client = incoming
		writeOK(w, c.Client)
		return
	}

	// 更新进程内配置
	fullCfg.Client = incoming

	// 落盘：把完整 Config 序列化为 YAML 覆盖写入
	if configPath != "" {
		if err := writeConfigYAML(configPath, fullCfg); err != nil {
			writeError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
			return
		}
	}

	writeOK(w, fullCfg.Client)
}

// writeConfigYAML 把 Config 序列化为 YAML 并原子写入目标路径。
func writeConfigYAML(path string, cfg *config.Config) error {
	if path == "" {
		return fmt.Errorf("配置文件路径为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("yaml 序列化失败: %w", err)
	}
	// 原子写：先写 .tmp 再 rename，避免半截写入导致下次启动失败
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
