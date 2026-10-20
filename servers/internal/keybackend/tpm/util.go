package tpm

import (
	"crypto/rand"
	"encoding/hex"
)

// randSuffix 生成 4 字节随机十六进制后缀，避免密钥容器名冲突。
func randSuffix() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "0000"
	}
	return hex.EncodeToString(buf)
}
