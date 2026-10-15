// Package totp 实现 RFC 6238 TOTP 和 RFC 4226 HOTP 算法。
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithm 是 TOTP/HOTP 使用的哈希算法。
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// Type 是 OTP 类型。
type Type string

const (
	TypeTOTP Type = "totp"
	TypeHOTP Type = "hotp"
)

// Entry 是一个 TOTP/HOTP 条目。
type Entry struct {
	UUID      string    `json:"uuid"`
	CardUUID  string    `json:"card_uuid"`
	OTPType   Type      `json:"otp_type"`  // totp 或 hotp
	Issuer    string    `json:"issuer"`    // 发行者
	Account   string    `json:"account"`   // 账户名
	Algorithm Algorithm `json:"algorithm"` // SHA1/SHA256/SHA512
	Digits    int       `json:"digits"`    // 6 或 8
	Period    int       `json:"period"`    // TOTP 周期（秒），默认 30
	Counter   uint64    `json:"counter"`   // HOTP 计数器
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GenerateTOTP 根据密钥和当前时间生成 TOTP 验证码。
func GenerateTOTP(secret []byte, t time.Time, period int, digits int, algo Algorithm) (string, error) {
	if period <= 0 {
		period = 30
	}
	counter := uint64(t.Unix()) / uint64(period)
	return GenerateHOTP(secret, counter, digits, algo)
}

// GenerateHOTP 根据密钥和计数器生成 HOTP 验证码（RFC 4226）。
func GenerateHOTP(secret []byte, counter uint64, digits int, algo Algorithm) (string, error) {
	if digits < 6 || digits > 8 {
		digits = 6
	}

	// 将计数器转为 8 字节大端序
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	// 选择哈希函数
	var h func() hash.Hash
	switch algo {
	case AlgorithmSHA256:
		h = sha256.New
	case AlgorithmSHA512:
		h = sha512.New
	default:
		h = sha1.New
	}

	// HMAC 计算
	mac := hmac.New(h, secret)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// 动态截断（Dynamic Truncation）
	offset := sum[len(sum)-1] & 0x0F
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF

	// 取模得到指定位数
	mod := uint32(math.Pow10(digits))
	otp := code % mod

	// 格式化为固定位数字符串
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, otp), nil
}

// RemainingSeconds 返回当前 TOTP 周期的剩余秒数。
func RemainingSeconds(period int) int {
	if period <= 0 {
		period = 30
	}
	elapsed := int(time.Now().Unix()) % period
	return period - elapsed
}

// DecodeSecret 解码 Base32 编码的密钥。
func DecodeSecret(secret string) ([]byte, error) {
	// 去除空格，转大写，补齐 padding
	secret = strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(secret, " ", "")))
	if m := len(secret) % 8; m != 0 {
		secret += strings.Repeat("=", 8-m)
	}
	return base32.StdEncoding.DecodeString(secret)
}

// ParseOTPAuthURI 解析 otpauth:// URI 格式。
// 格式：otpauth://totp/Issuer:Account?secret=XXX&issuer=XXX&algorithm=SHA1&digits=6&period=30
func ParseOTPAuthURI(uri string) (*Entry, string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, "", fmt.Errorf("解析 URI 失败: %w", err)
	}

	if u.Scheme != "otpauth" {
		return nil, "", fmt.Errorf("无效的 scheme: %s（期望 otpauth）", u.Scheme)
	}

	entry := &Entry{
		Algorithm: AlgorithmSHA1,
		Digits:    6,
		Period:    30,
	}

	// 类型
	switch u.Host {
	case "totp":
		entry.OTPType = TypeTOTP
	case "hotp":
		entry.OTPType = TypeHOTP
	default:
		return nil, "", fmt.Errorf("不支持的 OTP 类型: %s", u.Host)
	}

	// 标签（Issuer:Account 或 Account）
	label := strings.TrimPrefix(u.Path, "/")
	if idx := strings.Index(label, ":"); idx >= 0 {
		entry.Issuer = label[:idx]
		entry.Account = label[idx+1:]
	} else {
		entry.Account = label
	}

	// 查询参数
	q := u.Query()

	secret := q.Get("secret")
	if secret == "" {
		return nil, "", fmt.Errorf("缺少 secret 参数")
	}

	if issuer := q.Get("issuer"); issuer != "" {
		entry.Issuer = issuer
	}

	if algo := q.Get("algorithm"); algo != "" {
		switch strings.ToUpper(algo) {
		case "SHA256":
			entry.Algorithm = AlgorithmSHA256
		case "SHA512":
			entry.Algorithm = AlgorithmSHA512
		default:
			entry.Algorithm = AlgorithmSHA1
		}
	}

	if d := q.Get("digits"); d != "" {
		if n, err := strconv.Atoi(d); err == nil && (n == 6 || n == 8) {
			entry.Digits = n
		}
	}

	if p := q.Get("period"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			entry.Period = n
		}
	}

	if c := q.Get("counter"); c != "" {
		if n, err := strconv.ParseUint(c, 10, 64); err == nil {
			entry.Counter = n
		}
	}

	return entry, secret, nil
}

// ZeroBytes 安全清零字节切片。
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
