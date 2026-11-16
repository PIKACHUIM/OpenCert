//go:build windows

package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RestoreFiles 把 .tsb 中的 store / pcp / registry 写回本机。
//
// 仅支持“卡片未被删除、同一系统”的恢复场景：包内 DPAPI 密文必须能被本机解开。
// 重装系统后的还原还需要 DPAPI 明文重加密，当前尚未实现。
func RestoreFiles(ctx context.Context, files map[string][]byte) error {
	if len(files) == 0 {
		return fmt.Errorf("备份内容为空")
	}
	for name, data := range files {
		if strings.HasPrefix(name, "dpapi/") {
			continue // 明文在 store 写回后处理，避免被密文覆盖
		}
		switch {
		case strings.HasPrefix(name, "store/"):
			rel := strings.TrimPrefix(name, "store/")
			target, err := safeJoin(vscStoreRoot, rel)
			if err != nil {
				return err
			}
			if err := writeFile(target, data); err != nil {
				return err
			}
		case strings.HasPrefix(name, "pcp/"):
			rel := strings.TrimPrefix(name, "pcp/")
			index, rest, ok := strings.Cut(rel, "/")
			if !ok {
				return fmt.Errorf("PCPKEY 路径无效: %s", name)
			}
			idx := -1
			if _, err := fmt.Sscanf(index, "%d", &idx); err != nil || idx < 0 || idx >= len(pcpKeyDirs) {
				return fmt.Errorf("PCPKEY 目录索引无效: %s", index)
			}
			target, err := safeJoin(pcpKeyDirs[idx], rest)
			if err != nil {
				return err
			}
			// 同名文件不覆盖，避免破坏本机其它 TPM 密钥。
			if _, err := os.Stat(target); err == nil {
				continue
			}
			if err := writeFile(target, data); err != nil {
				return err
			}
		case strings.HasPrefix(name, "dpapi/"):
			rel := strings.TrimPrefix(name, "dpapi/")
			target, err := safeJoin(vscStoreRoot, rel)
			if err != nil {
				return err
			}
			encrypted, err := protectDPAPI(data)
			if err != nil {
				return fmt.Errorf("重新加密 %s 失败: %w", rel, err)
			}
			if _, err := unprotectDPAPI(encrypted); err != nil {
				return fmt.Errorf("重新加密 %s 回验失败: %w", rel, err)
			}
			if err := writeFile(target, encrypted); err != nil {
				return err
			}
		case strings.HasPrefix(name, "registry/"):
			if err := RestoreRegistry(ctx, data); err != nil {
				return err
			}
		default:
			return fmt.Errorf("未知的备份部件: %s", name)
		}
	}
	return nil
}

// safeJoin 拒绝绝对路径与目录穿越，确保只能写在预期根目录内。
func safeJoin(root, rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("备份路径非法: %s", rel)
	}
	target := filepath.Join(root, clean)
	rootClean := filepath.Clean(root)
	if target != rootClean && !strings.HasPrefix(target, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("备份路径越界: %s", rel)
	}
	return target, nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建目录 %s 失败: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入 %s 失败（需要管理员权限）: %w", path, err)
	}
	return nil
}
