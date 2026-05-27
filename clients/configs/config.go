// Package config 负责加载和管理应用配置。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Config 是应用的顶层配置结构。
type Config struct {
	IPC      IPCConfig      `yaml:"ipc"`
	API      APIConfig      `yaml:"api"`
	Database DatabaseConfig `yaml:"database"`
	Log      LogConfig      `yaml:"log"`
	Tray     TrayConfig     `yaml:"tray"`
	Client   ClientConfig   `yaml:"client"`
}

// IPCConfig 是与 pkcs11-mock 通信的 IPC 配置。
type IPCConfig struct {
	PipeName string `yaml:"pipe_name"`
	Timeout  int    `yaml:"timeout"`
}

// APIConfig 是 REST API 服务配置。
type APIConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	TLSEnabled     bool   `yaml:"tls_enabled"`
	TLSCert        string `yaml:"tls_cert"`
	TLSKey         string `yaml:"tls_key"`
	JWTSecret      string `yaml:"jwt_secret"`
	JWTExpireHours int    `yaml:"jwt_expire_hours"`
	DataDir        string `yaml:"data_dir"` // 数据目录，用于存储认证 Token 等
}

// DatabaseConfig 是 SQLite 数据库配置。
type DatabaseConfig struct {
	Path         string `yaml:"path"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
}

// LogConfig 是日志配置。
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// TrayConfig 是系统托盘配置。
type TrayConfig struct {
	Enabled bool   `yaml:"enabled"`
	Icon    string `yaml:"icon"`
}

// ClientConfig 是前端/Electron/集成相关的可运行时修改的配置项。
// 这些字段通过 GET/PUT /api/settings 暴露给 UI 进行动态调整，修改后写回 config.yaml。
type ClientConfig struct {
	// 通用
	Language       string `yaml:"language"`         // zh-CN / en-US
	Theme          string `yaml:"theme"`            // light / dark / system
	CloseToTray    bool   `yaml:"close_to_tray"`    // 关闭窗口时最小化到托盘
	// 云端
	DefaultCloudURL      string `yaml:"default_cloud_url"`       // 新增云端账号时默认填充
	AllowInsecureCloud   bool   `yaml:"allow_insecure_cloud"`    // 是否允许 http://
	AutoSync             bool   `yaml:"auto_sync"`               // 是否自动同步
	SyncIntervalMinutes  int    `yaml:"sync_interval_minutes"`   // 自动同步间隔（分钟），默认 5
	// 集成
	RegisterPKCS11Mock bool `yaml:"register_pkcs11_mock"` // 是否让 Electron 主进程把 pkcs11-mock 注册到系统
	// 安全
	SessionExpiresMinutes int  `yaml:"session_expires_minutes"` // 会话过期（分钟），默认 1440
	DetailedRequestLog    bool `yaml:"detailed_request_log"`    // 是否记录详细请求日志
}

// DefaultConfig 返回默认配置。
func DefaultConfig() *Config {
	return &Config{
		IPC: IPCConfig{
			PipeName: "clients",
			Timeout:  30,
		},
		API: APIConfig{
			Host:           "127.0.0.1",
			Port:           1026,
			TLSEnabled:     false,
			JWTExpireHours: 24,
			DataDir:        userDataDir(),
		},
		Database: DatabaseConfig{
			Path:         defaultDBPath(),
			MaxOpenConns: 5,
			MaxIdleConns: 2,
		},
		Log: LogConfig{
			Level: "info",
		},
		Tray: TrayConfig{
			Enabled: true,
		},
		Client: ClientConfig{
			Language:              "zh-CN",
			Theme:                 "system",
			CloseToTray:           true,
			DefaultCloudURL:       "",
			AllowInsecureCloud:    false,
			AutoSync:              false,
			SyncIntervalMinutes:   5,
			RegisterPKCS11Mock:    false,
			SessionExpiresMinutes: 1440,
			DetailedRequestLog:    false,
		},
	}
}

// Load 从指定路径加载配置文件，若文件不存在则使用默认配置。
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = defaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 配置文件不存在，使用默认配置
			return cfg, nil
		}
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 补全空值
	if cfg.Database.Path == "" {
		cfg.Database.Path = defaultDBPath()
	}

	return cfg, nil
}

// Addr 返回 API 监听地址字符串。
func (c *APIConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// IPCPath 返回平台对应的 IPC 路径。
func (c *IPCConfig) IPCPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\` + c.PipeName
	}
	return filepath.Join(os.TempDir(), c.PipeName+".sock")
}

// defaultConfigPath 返回默认配置文件路径。
func defaultConfigPath() string {
	return filepath.Join(userDataDir(), "config.yaml")
}

// ResolveConfigPath 返回当前默认使用的配置文件路径（导出给其它包使用，
// 例如 api 包在 Settings 写回 YAML 时需要定位目标文件）。
func ResolveConfigPath() string {
	return defaultConfigPath()
}

// defaultDBPath 返回默认数据库文件路径（可执行文件所在目录的 data 子目录）。
func defaultDBPath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("data", "clients.db")
	}
	return filepath.Join(filepath.Dir(exe), "data", "clients.db")
}

// userDataDir 返回用户数据目录。
func userDataDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("APPDATA"); dir != "" {
			return filepath.Join(dir, "clients")
		}
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "Library", "Application Support", "clients")
		}
	default:
		if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
			return filepath.Join(dir, "clients")
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".local", "share", "clients")
		}
	}
	return "."
}
