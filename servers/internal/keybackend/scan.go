package keybackend

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DiscoveredLibrary 是「扫描本机」发现的候选动态库。
type DiscoveredLibrary struct {
	Preset      string            `json:"preset"`                 // 预设 ID
	PresetName  string            `json:"preset_name"`            // 预设显示名
	Driver      string            `json:"driver"`                 // 驱动 ID
	Kind        Kind              `json:"kind"`                   // 后端大类
	Path        string            `json:"path"`                   // 展开后的绝对/原始路径
	Exists      bool              `json:"exists"`                 // 文件是否存在
	Verified    bool              `json:"verified"`               // 是否已确认为合法 PKCS#11 模块
	LibraryName string            `json:"library_name,omitempty"` // 模块自报名称（验证通过时）
	Error       string            `json:"error,omitempty"`
	Params      map[string]string `json:"params"` // 可直接用于创建存储区域的参数
}

// moduleProbe 由具体驱动注册（PKCS#11 驱动负责），用于验证动态库是否可用。
var (
	probeMu     sync.RWMutex
	moduleProbe func(path string) (string, error)
)

// RegisterModuleProbe 注册模块校验函数（由 pkcs11 驱动在 init 中调用）。
func RegisterModuleProbe(fn func(path string) (string, error)) {
	probeMu.Lock()
	defer probeMu.Unlock()
	moduleProbe = fn
}

// ProbeModule 校验一个动态库是否是可用的 PKCS#11 模块，返回模块自报名称。
func ProbeModule(path string) (string, error) {
	probeMu.RLock()
	fn := moduleProbe
	probeMu.RUnlock()
	if fn == nil {
		return "", fmt.Errorf("当前构建未启用 PKCS#11 模块校验")
	}
	return fn(path)
}

// ScanPresets 扫描所有已注册预设中声明的库路径，返回本机实际存在的候选模块。
//
// 该能力对应「查找是否有通用接口 / 接入多种驱动」：新厂商设备只需在
// configs/keybackends.json 里增加一条预设，即可被扫描与一键创建存储区域。
func ScanPresets() []DiscoveredLibrary {
	var out []DiscoveredLibrary
	seen := map[string]bool{}

	for _, d := range Descriptors() {
		for _, p := range d.Presets {
			paths := p.SearchPaths
			if len(paths) == 0 {
				if lib := p.Params["library"]; lib != "" {
					paths = []string{lib}
				}
			}
			for _, raw := range paths {
				full := ExpandPath(raw)
				key := strings.ToLower(full)
				if seen[key] {
					continue
				}
				seen[key] = true

				item := DiscoveredLibrary{
					Preset:     p.ID,
					PresetName: p.Name,
					Driver:     d.Driver,
					Kind:       d.Kind,
					Path:       full,
					Params:     map[string]string{},
				}
				for k, v := range p.Params {
					item.Params[k] = v
				}
				if filepath.IsAbs(full) {
					item.Params["library"] = full
				}

				info, err := os.Stat(full)
				if err != nil {
					item.Exists = false
					item.Error = "未找到文件"
				} else if info.IsDir() {
					item.Exists = false
					item.Error = "路径是目录"
				} else {
					item.Exists = true
					if d.Kind == KindHSM {
						if name, perr := ProbeModule(full); perr != nil {
							item.Error = perr.Error()
						} else {
							item.Verified = true
							item.LibraryName = name
						}
					} else {
						item.Verified = true
					}
				}
				out = append(out, item)
			}
		}
	}
	return out
}
