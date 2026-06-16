// Package config 提供应用配置的加载和保存功能。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Config 应用配置
type Config struct {
	BackendURL  string `json:"backend_url"`  // 后端服务地址
	Language    string `json:"language"`     // 界面语言：zh-CN / en-US
	HideExpired bool   `json:"hide_expired"` // 隐藏过期证书
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		BackendURL: "http://localhost:1026",
		Language:   "zh-CN",
	}
}

var (
	instance *Config
	mu       sync.RWMutex
	cfgPath  string
)

// Init 初始化配置，加载配置文件
func Init() error {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("获取配置目录失败: %w", err)
	}
	cfgPath = filepath.Join(configDir, "globaltrusts", "natives-client", "config.json")

	instance = DefaultConfig()
	return instance.load()
}

// Get 获取当前配置
func Get() *Config {
	mu.RLock()
	defer mu.RUnlock()
	return instance
}

// Save 保存配置修改
func Save(cfg *Config) error {
	mu.Lock()
	defer mu.Unlock()
	instance = cfg
	return instance.save()
}

// load 从文件加载配置
func (c *Config) load() error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 配置文件不存在则使用默认值
		}
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	return json.Unmarshal(data, c)
}

// save 保存配置到文件
func (c *Config) save() error {
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	return os.WriteFile(cfgPath, data, 0644)
}
