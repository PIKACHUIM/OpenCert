package keybackend

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// 配置项类型（前端据此渲染表单）。
const (
	FieldText     = "text"
	FieldPassword = "password"
	FieldNumber   = "number"
	FieldSelect   = "select"
	FieldBool     = "bool"
	FieldFile     = "file"
)

// Field 描述驱动的一个配置项。
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Default  string   `json:"default,omitempty"`
	Hint     string   `json:"hint,omitempty"`
	Options  []string `json:"options,omitempty"`
	Secret   bool     `json:"secret,omitempty"` // Secret=true 的字段在列表接口中不回显
}

// Preset 是针对某类设备的预置参数（例如 eToken 5110 的 PKCS#11 库路径）。
type Preset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Kind        Kind              `json:"kind,omitempty"`
	Driver      string            `json:"driver,omitempty"`
	Params      map[string]string `json:"params"`
	// SearchPaths 是需要自动探测存在的库路径（用于「扫描本机」）。
	SearchPaths []string `json:"search_paths,omitempty"`
}

// Params 是驱动配置参数（字符串键值，便于入库与前端表单）。
type Params map[string]string

// Get 读取参数（去空白）。
func (p Params) Get(key string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p[key])
}

// GetDefault 读取参数，为空时返回默认值。
func (p Params) GetDefault(key, def string) string {
	if v := p.Get(key); v != "" {
		return v
	}
	return def
}

// Int 读取整数参数。
func (p Params) Int(key string, def int) int {
	v := p.Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// Bool 读取布尔参数（true/1/yes 视为真）。
func (p Params) Bool(key string) bool {
	switch strings.ToLower(p.Get(key)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// Has 判断参数是否被显式配置（即使值为空字符串）。
func (p Params) Has(key string) bool {
	_, ok := p[key]
	return ok
}

// ExpandPath 展开路径中的环境变量与占位符：
//   - 支持 ${SYSTEM32}（Windows 系统目录 System32，等价于 %SystemRoot%\System32）；
//   - 支持 $VAR / ${VAR} 形式的环境变量；
//   - 支持开头的 ~ 表示用户主目录。
func ExpandPath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, "${SYSTEM32}", system32Dir())
	s = strings.ReplaceAll(s, "%SystemRoot%", os.Getenv("SystemRoot"))
	s = strings.ReplaceAll(s, "%WINDIR%", os.Getenv("SystemRoot"))
	if strings.HasPrefix(s, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			s = home + s[1:]
		}
	}
	return os.ExpandEnv(s)
}

// system32Dir 返回 Windows 系统目录（非 Windows 返回空串）。
func system32Dir() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32")
}

// Redact 返回抹去敏感字段后的副本（用于列表接口回显）。
func (p Params) Redact(secretKeys []string) Params {
	out := make(Params, len(p))
	for k, v := range p {
		out[k] = v
	}
	for _, k := range secretKeys {
		if _, ok := out[k]; ok {
			out[k] = ""
		}
	}
	return out
}

// Config 是打开一个私钥后端所需的全部信息。
type Config struct {
	// Driver 是驱动 ID（database / tpm2 / pkcs11 ...）。
	Driver string
	// Kind 是后端大类。
	Kind Kind
	// Params 是驱动参数（库路径、令牌、PIN 等）。
	Params Params
	// MasterKey 是服务端主密钥（本地后端使用）。
	MasterKey []byte
	// Label 是存储区域名称，用于设备对象命名。
	Label string
	// CacheKey 是 Provider 缓存的键（通常是存储区域 UUID）。
	CacheKey string
}

// Factory 按配置创建一个 Provider。
type Factory func(ctx context.Context, cfg Config) (Provider, error)

// Descriptor 描述一个已注册的驱动。
type Descriptor struct {
	Driver          string       `json:"driver"`
	Kind            Kind         `json:"kind"`
	Name            string       `json:"name"`
	Description     string       `json:"description"`
	Fields          []Field      `json:"fields"`
	Presets         []Preset     `json:"presets,omitempty"`
	Capabilities    Capabilities `json:"capabilities"`
	Available       bool         `json:"available"`
	AvailableDetail string       `json:"available_detail,omitempty"`

	// Factory 由驱动实现提供，用于按配置创建 Provider（不参与序列化）。
	Factory Factory `json:"-"`
}

// SecretKeys 返回需要在列表接口中抹除的配置项。
func (d Descriptor) SecretKeys() []string {
	var keys []string
	for _, f := range d.Fields {
		if f.Secret {
			keys = append(keys, f.Key)
		}
	}
	return keys
}

var (
	registryMu sync.RWMutex
	registry   = map[string]Descriptor{}
)

// Register 注册一个驱动（通常在包 init 中调用）。
func Register(d Descriptor) {
	if d.Driver == "" || d.Factory == nil {
		panic("keybackend: 注册驱动必须提供 Driver 与 Factory")
	}
	if d.Kind == "" {
		d.Kind = KindDatabase
	}
	d.Capabilities.KeyTypes = sortedKeyTypes(d.Capabilities.KeyTypes)
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[d.Driver]; dup {
		panic("keybackend: 驱动重复注册: " + d.Driver)
	}
	registry[d.Driver] = d
}

// RegisterPresets 为已注册的驱动追加预设（供外部插件清单调用）。
func RegisterPresets(driver string, presets ...Preset) {
	registryMu.Lock()
	defer registryMu.Unlock()
	d, ok := registry[driver]
	if !ok {
		return
	}
	d.Presets = append(d.Presets, presets...)
	registry[driver] = d
}

// Descriptors 返回全部驱动描述（按大类与驱动 ID 稳定排序）。
func Descriptors() []Descriptor {
	registryMu.RLock()
	out := make([]Descriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	registryMu.RUnlock()
	order := map[Kind]int{KindDatabase: 0, KindTPM: 1, KindHSM: 2}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			oi, oj := order[out[i].Kind], order[out[j].Kind]
			if oi > oj || (oi == oj && out[i].Driver > out[j].Driver) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Lookup 按驱动 ID 查找驱动描述。
func Lookup(driver string) (Descriptor, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := registry[driver]
	return d, ok
}

// Open 按配置打开一个后端实例。调用方负责 Close。
func Open(ctx context.Context, cfg Config) (Provider, error) {
	if cfg.Driver == "" {
		cfg.Driver = DriverDatabase
	}
	d, ok := Lookup(cfg.Driver)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrDriverNotFound, cfg.Driver)
	}
	if cfg.Kind == "" {
		cfg.Kind = d.Kind
	}
	return d.Factory(ctx, cfg)
}

// Manager 缓存已打开的 Provider（按存储区域），避免每次密码运算都重新登录设备。
type Manager struct {
	mu        sync.Mutex
	providers map[string]Provider
}

// NewManager 创建 Provider 缓存管理器。
func NewManager() *Manager {
	return &Manager{providers: map[string]Provider{}}
}

// Open 打开（或复用）某个存储区域对应的 Provider。
func (m *Manager) Open(ctx context.Context, cfg Config) (Provider, error) {
	key := cfg.CacheKey
	if key == "" {
		key = cfg.Driver + "|" + cfg.Label + "|" + cfg.Params.Get("library") + "|" + cfg.Params.Get("token")
	}

	m.mu.Lock()
	if p, ok := m.providers[key]; ok {
		m.mu.Unlock()
		return p, nil
	}
	m.mu.Unlock()

	p, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	if exist, ok := m.providers[key]; ok {
		// 并发打开时保留先到者，关闭后到者
		m.mu.Unlock()
		_ = p.Close()
		return exist, nil
	}
	m.providers[key] = p
	m.mu.Unlock()
	return p, nil
}

// Invalidate 丢弃某个存储区域的缓存（配置变更或删除时调用）。
func (m *Manager) Invalidate(cacheKey string) {
	m.mu.Lock()
	p, ok := m.providers[cacheKey]
	delete(m.providers, cacheKey)
	m.mu.Unlock()
	if ok {
		_ = p.Close()
	}
}

// InvalidateAll 丢弃全部缓存。
func (m *Manager) InvalidateAll() {
	m.mu.Lock()
	all := m.providers
	m.providers = map[string]Provider{}
	m.mu.Unlock()
	for _, p := range all {
		_ = p.Close()
	}
}

// Close 释放全部后端资源。
func (m *Manager) Close() error {
	m.InvalidateAll()
	return nil
}

// ---- 外部驱动清单（插件化扩展） ----

// pluginFile 是外部驱动清单文件的结构。
type pluginFile struct {
	Presets []Preset `json:"presets"`
}

// LoadPresetFile 从 JSON 清单加载额外的驱动预设（无需改代码即可接入新厂商的 PKCS#11 模块）。
//
// 清单格式：
//
//	{
//	  "presets": [
//	    {"id":"mytoken","name":"MyToken","driver":"pkcs11",
//	     "params":{"library":"C:\\\\Vendor\\\\mytoken.dll"},
//	     "search_paths":["C:\\\\Vendor\\\\mytoken.dll"]}
//	  ]
//	}
func LoadPresetFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取私钥后端清单失败: %w", err)
	}
	var pf pluginFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return fmt.Errorf("解析私钥后端清单失败: %w", err)
	}
	grouped := map[string][]Preset{}
	for _, p := range pf.Presets {
		driver := p.Driver
		if driver == "" {
			driver = DriverPKCS11
		}
		if p.Kind == "" && driver == DriverPKCS11 {
			p.Kind = KindHSM
		}
		grouped[driver] = append(grouped[driver], p)
	}
	for driver, presets := range grouped {
		RegisterPresets(driver, presets...)
	}
	slog.Info("已加载私钥后端预设清单", "path", path, "count", len(pf.Presets))
	return nil
}
