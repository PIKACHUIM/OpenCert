//go:build windows

package backup

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 本文件实现 .tsb 的设备侧采集（注册表 + 卡片 store + PCPKEY 密钥索引）。
//
// 注意：DPAPI 明文（keymaps/pinmaps/pinpolicy/blobs）尚未采集，
// 因此当前包只能用于“卡片未被删除、同一系统”的恢复场景；
// 重装系统后的完整还原需要下一步的 DPAPI 解密与 SYSTEM 令牌借用。

const (
	vscStoreRoot = `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Windows\SmartCard\Tpm`
	vscRegistry  = `HKLM\SYSTEM\CurrentControlSet\Enum\ROOT\SMARTCARDREADER`
)

var pcpKeyDirs = []string{
	`C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Crypto\PCPKSP`,
	`C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Crypto\PCPKSP`,
	`C:\ProgramData\Microsoft\Crypto\PCPKSP`,
}

// CollectCard 收集本机 VSC 相关数据。storeGUID 为空时收集全部卡片 store。
//
// 需要管理员权限；失败时返回具体路径与原因，不静默跳过。
func CollectCard(ctx context.Context, storeGUID string) (map[string][]byte, *Manifest, error) {
	files := make(map[string][]byte)

	stores, err := collectStores(storeGUID)
	if err != nil {
		return nil, nil, err
	}
	for name, data := range stores {
		files["store/"+name] = data
	}

	pcp, err := collectPCPKeys()
	if err != nil {
		return nil, nil, err
	}
	for name, data := range pcp {
		files["pcp/"+name] = data
	}

	regData, err := exportRegistry(ctx, vscRegistry)
	if err != nil {
		return nil, nil, err
	}
	files["registry/smartcardreader.reg"] = regData

	dpapi, err := collectDPAPIPlain(stores)
	if err != nil {
		return nil, nil, err
	}
	for name, data := range dpapi {
		files["dpapi/"+name] = data
	}

	manifest := &Manifest{
		CardID:        storeGUID,
		IncludesDPAPI: len(dpapi) > 0,
	}
	return files, manifest, nil
}

// collectDPAPIPlain 在 SYSTEM 身份下解开卡片数据中的 DPAPI blob。
// 解不开任何一个文件就整体失败，避免产出“看起来完整、实际还原不了”的包。
func collectDPAPIPlain(stores map[string][]byte) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := withSystemToken(func() error {
		for name, data := range stores {
			base := strings.ToLower(filepath.Base(name))
			isBlob := strings.HasPrefix(strings.ToLower(name), "blobs/")
			if base != "keymaps" && base != "pinmaps" && base != "pinpolicy" && !isBlob {
				continue
			}
			plain, err := unprotectDPAPI(data)
			if err != nil {
				return fmt.Errorf("解密 %s 失败: %w", name, err)
			}
			out[name] = plain
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func collectStores(storeGUID string) (map[string][]byte, error) {
	out := make(map[string][]byte)
	root := vscStoreRoot
	if storeGUID != "" {
		root = filepath.Join(vscStoreRoot, storeGUID)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("读取 VSC 卡片数据目录失败（需要管理员权限）: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("VSC 卡片数据路径不是目录: %s", root)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(vscStoreRoot, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取卡片数据文件 %s 失败: %w", path, err)
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("遍历卡片数据目录失败: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("卡片数据目录为空: %s", root)
	}
	return out, nil
}

func collectPCPKeys() (map[string][]byte, error) {
	out := make(map[string][]byte)
	found := 0
	for i, dir := range pcpKeyDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) || os.IsPermission(err) {
				continue
			}
			return nil, fmt.Errorf("读取 PCPKSP 目录 %s 失败: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PCPKEY") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("读取 PCPKEY %s 失败: %w", entry.Name(), err)
			}
			out[fmt.Sprintf("%d/%s", i, entry.Name())] = data
			found++
		}
	}
	if found == 0 {
		return nil, fmt.Errorf("没有找到任何 *.PCPKEY；请确认卡片已创建且以管理员身份运行")
	}
	return out, nil
}

func exportRegistry(ctx context.Context, key string) ([]byte, error) {
	tmp, err := os.CreateTemp("", "opencert-reg-*.reg")
	if err != nil {
		return nil, fmt.Errorf("创建临时注册表文件失败: %w", err)
	}
	path := tmp.Name()
	tmp.Close()
	defer os.Remove(path)

	cmd := exec.CommandContext(ctx, "reg.exe", "export", key, path, "/y")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("导出注册表 %s 失败（需要管理员权限）: %s", key, strings.TrimSpace(string(output)))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取注册表导出结果失败: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("注册表导出结果为空: %s", key)
	}
	return data, nil
}

// RestoreRegistry 通过 reg import 写回设备节点注册表。
func RestoreRegistry(ctx context.Context, regData []byte) error {
	tmp, err := os.CreateTemp("", "opencert-vsc-*.reg")
	if err != nil {
		return fmt.Errorf("创建临时注册表文件失败: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)
	if _, err := tmp.Write(regData); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "reg.exe", "import", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("导入注册表失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}
