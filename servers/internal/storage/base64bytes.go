package storage

import (
	"database/sql/driver"
	"encoding/base64"
	"fmt"
)

// Base64Bytes 是一个 []byte 包装类型，存入数据库时自动 base64 编码为 TEXT，
// 从数据库读取时自动 base64 解码为 []byte。
// 业务层使用时与 []byte 完全一致。
type Base64Bytes []byte

// Value 实现 driver.Valuer 接口，写入数据库时将 []byte 编码为 base64 字符串。
func (b Base64Bytes) Value() (driver.Value, error) {
	if b == nil {
		return nil, nil
	}
	if len(b) == 0 {
		return "", nil
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Scan 实现 sql.Scanner 接口，从数据库读取时将 base64 字符串解码为 []byte。
func (b *Base64Bytes) Scan(src interface{}) error {
	if src == nil {
		*b = nil
		return nil
	}

	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		// 兼容旧数据：如果数据库中仍然是 BLOB 格式（迁移过渡期），直接使用原始字节
		// 尝试 base64 解码，如果失败则认为是原始二进制数据
		decoded, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			// 不是有效的 base64，直接使用原始字节（兼容旧 BLOB 数据）
			*b = v
			return nil
		}
		*b = decoded
		return nil
	default:
		return fmt.Errorf("Base64Bytes.Scan: 不支持的类型 %T", src)
	}

	if s == "" {
		*b = []byte{}
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// 不是有效的 base64，可能是纯文本（兼容旧数据）
		*b = []byte(s)
		return nil
	}
	*b = decoded
	return nil
}

// Bytes 返回底层 []byte 切片。
func (b Base64Bytes) Bytes() []byte {
	return []byte(b)
}
