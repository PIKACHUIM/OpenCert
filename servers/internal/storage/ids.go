// Package storage - 对外标识生成。
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateOrderNo 生成对外订单号：CO + 时间戳 + 随机后缀。
// 前缀 CO 便于与充值订单（RC）区分，具体账务归属仍以持久化记录为准。
func GenerateOrderNo() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		// 随机源不可用时退化为纳秒时间戳，仍保证唯一性概率
		return fmt.Sprintf("CO%s%06d", time.Now().Format("20060102150405"), time.Now().UnixNano()%1e6)
	}
	return fmt.Sprintf("CO%s%s", time.Now().Format("20060102150405"), hex.EncodeToString(buf))
}
