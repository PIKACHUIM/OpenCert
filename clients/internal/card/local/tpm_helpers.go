// Package local - 与 TPM Provider 协作的辅助函数。
//
// 设计要点：
//   - 所有 NV / wrapped key 的 authValue 都从 masterKey 派生（HMAC-SHA256 + 不同 label），
//     用户 PIN 解锁主密钥后即可使用 medium/high 卡片，无需另外输入 AdminKey。
//   - AdminKey 仍保留为"应急副本"加密 KEK，丢失主密钥时可恢复 TPM 证书密钥。
//   - magic / version 标记写到 cert.TPMPlatform 上，使 slot 解密路径可以辨别加密版本。
package local

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/globaltrusts/client-card/internal/tpm"
)

// 以下 magic 写入 cert.TPMPlatform，区分加密结构版本。
const (
	tpmPlatformMediumV2 = "medium-v2" // medium：master 加密 → TPM 证书密钥再加密
	tpmPlatformHighV1   = "high-v1"   // high：tpm.WrappedKey，私钥永不出 TPM
)

// deriveTPMCertKeyAuth 从主密钥派生"medium 模式 NV 授权值"。
func deriveTPMCertKeyAuth(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("tpm-cert-key/auth/v1"))
	return mac.Sum(nil)
}

// deriveTPMHighKeyAuth 从主密钥派生"high 模式 wrapped key 授权值"。
// 加 certUUID 是为了让同一张卡上的不同 high 证书各自拥有独立 authValue。
func deriveTPMHighKeyAuth(masterKey []byte, certUUID string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("tpm-high-key/auth/v1"))
	mac.Write([]byte(certUUID))
	return mac.Sum(nil)
}

// marshalWrappedKey 将 tpm.WrappedKey 序列化为 JSON，存到 cert.TPMWrappedBlob。
func marshalWrappedKey(w *tpm.WrappedKey) ([]byte, error) {
	if w == nil {
		return nil, fmt.Errorf("wrapped key 为空")
	}
	return json.Marshal(w)
}

// unmarshalWrappedKey 从 cert.TPMWrappedBlob 还原 tpm.WrappedKey。
func unmarshalWrappedKey(blob []byte) (*tpm.WrappedKey, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("wrapped key blob 为空")
	}
	var w tpm.WrappedKey
	if err := json.Unmarshal(blob, &w); err != nil {
		return nil, fmt.Errorf("反序列化 wrapped key 失败: %w", err)
	}
	return &w, nil
}

// keyTypeToTPMAlg 把 KeyGenRequest.KeyType 转换为 tpm.KeyAlg。
func keyTypeToTPMAlg(keyType string) (tpm.KeyAlg, error) {
	switch keyType {
	case "rsa2048":
		return tpm.KeyAlgRSA2048, nil
	case "rsa3072":
		return tpm.KeyAlgRSA3072, nil
	case "rsa4096":
		return tpm.KeyAlgRSA4096, nil
	case "ec256":
		return tpm.KeyAlgECP256, nil
	case "ec384":
		return tpm.KeyAlgECP384, nil
	case "ec521":
		return tpm.KeyAlgECP521, nil
	default:
		return "", fmt.Errorf("high 安全等级不支持密钥类型 %q（支持 rsa2048/rsa3072/rsa4096/ec256/ec384/ec521）", keyType)
	}
}
