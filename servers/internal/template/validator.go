// Package template - 模板配置合法性校验。
package template

import (
	"encoding/json"
	"fmt"

	"github.com/globaltrusts/server-card/internal/storage"
)

// validDownloadFormats 是文件下载允许的格式。
var validDownloadFormats = map[string]bool{"pem": true, "pkcs12": true}

// Validate 校验密钥存储类型模板配置的合法性。
// zoneNonExportable 为 true 表示模板绑定的存储区域是硬件区域（私钥不可导出）。
func Validate(t *storage.KeyStorageTemplate, zoneNonExportable bool) error {
	// 至少勾选一种存储方式
	if t.StorageMethods == 0 {
		return fmt.Errorf("至少需要选择一种存储方式")
	}

	if t.Name == "" {
		return fmt.Errorf("模板名称不能为空")
	}

	hasFileDownload := t.HasMethod(storage.StorageFileDownload)
	hasVirtualCard := t.HasMethod(storage.StorageVirtualCard)
	hasCloudCard := t.HasMethod(storage.StorageCloudCard)
	hasPhysicalCard := t.HasMethod(storage.StoragePhysicalCard)

	// 密钥生成位置
	switch t.KeyGenLocation {
	case "":
		t.KeyGenLocation = storage.KeyGenServer
	case storage.KeyGenServer, storage.KeyGenCSR, storage.KeyGenCard:
	default:
		return fmt.Errorf("密钥生成位置不合法: %s", t.KeyGenLocation)
	}
	if t.KeyGenLocation == storage.KeyGenCard && !(hasCloudCard || hasPhysicalCard || hasVirtualCard) {
		return fmt.Errorf("在智能卡上生成密钥时，至少需要选择一种智能卡下发方式")
	}
	if t.KeyGenLocation == storage.KeyGenCSR && hasFileDownload {
		return fmt.Errorf("使用自带 CSR 时私钥不经过服务端，不能提供私钥文件下载")
	}

	// 下载格式
	if t.DownloadFormats == "" {
		t.DownloadFormats = `["pem","pkcs12"]`
	}
	var formats []string
	if err := json.Unmarshal([]byte(t.DownloadFormats), &formats); err != nil {
		return fmt.Errorf("下载格式配置错误")
	}
	if hasFileDownload && len(formats) == 0 {
		return fmt.Errorf("提供文件下载时至少选择一种下载格式")
	}
	for _, f := range formats {
		if !validDownloadFormats[f] {
			return fmt.Errorf("不支持的下载格式: %s", f)
		}
	}

	// 不可导出的存储区域：私钥无法下载，也无法备份
	if zoneNonExportable {
		if hasFileDownload {
			return fmt.Errorf("所选存储区域中的私钥不可导出，不能提供文件下载")
		}
		if t.CloudBackup {
			return fmt.Errorf("所选存储区域中的私钥不可导出，不能启用云端备份")
		}
	}

	// 虚拟智能卡必须选择安全等级
	if hasVirtualCard {
		switch t.SecurityLevel {
		case storage.SecurityHigh, storage.SecurityMedium, storage.SecurityLow:
			// 合法
		default:
			return fmt.Errorf("勾选虚拟智能卡时必须选择安全等级（high/medium/low）")
		}
	}

	// 高安全性规则：不可导出、不可备份、不可重新导入
	if hasVirtualCard && t.SecurityLevel == storage.SecurityHigh {
		if t.CloudBackup {
			return fmt.Errorf("高安全性模式下不允许云端备份（TPM 内密钥不可导出）")
		}
		if t.AllowReimport {
			return fmt.Errorf("高安全性模式下不允许重新导入（密钥不可导出）")
		}
	}

	// 文件下载自动启用云端备份，且不限次数、无需"重新导入"
	if hasFileDownload {
		t.CloudBackup = true
		t.AllowReissue = true
		t.MaxReissueCount = -1
		t.AllowReimport = false
	}

	// 云端备份是重新下发的前提
	if t.AllowReissue && !t.CloudBackup {
		return fmt.Errorf("启用重新下发需要先启用云端私钥备份")
	}

	// 下发次数校验（-1 表示不限）
	if t.AllowReissue && !hasFileDownload {
		if t.MaxReissueCount == 0 {
			return fmt.Errorf("启用重新下发时，最大下发次数不能为 0（填 -1 表示不限）")
		}
		if t.MaxReissueCount < -1 {
			return fmt.Errorf("最大下发次数不合法: %d", t.MaxReissueCount)
		}
	}

	return nil
}
