package pkcs11

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/globaltrusts/server-card/internal/keybackend"
)

func init() {
	keybackend.RegisterModuleProbe(ProbeLibrary)
}

// ProbeLibrary 尝试加载指定动态库并读取其自报信息，用于「扫描本机模块」校验。
func ProbeLibrary(path string) (string, error) {
	m, err := LoadModule(path)
	if err != nil {
		return "", err
	}
	defer ReleaseModule(path)

	info, err := m.LibraryInfo()
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(info.Description)
	if name == "" {
		name = filepath.Base(path)
	}
	version := fmt.Sprintf("%d.%d", info.LibraryMajor, info.LibraryMinor)
	return fmt.Sprintf("%s（Cryptoki v%d.%d / 模块 v%s）",
		name, info.CryptokiMajor, info.CryptokiMinor, version), nil
}
