package fido

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
)

// PINState 保存本机认证器的 PIN 校验值与重试计数。
// 持久化由平台实现（Windows 用 DPAPI），这里只定义状态与比对逻辑。
type PINState struct {
	mu       sync.Mutex
	hash     []byte
	retries  int
	persist  func(hash []byte, retries int) error
	restored bool
}

// NewPINState 创建内存状态，persist 为 nil 表示不落盘（测试用）。
func NewPINState(persist func([]byte, int) error) *PINState {
	return &PINState{persist: persist, retries: PINRetries}
}

// Restore 恢复已保存的 PIN 校验值。
func (p *PINState) Restore(hash []byte, retries int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hash = append([]byte(nil), hash...)
	if retries <= 0 || retries > PINRetries {
		retries = PINRetries
	}
	p.retries = retries
}

// Retries 返回剩余尝试次数。
func (p *PINState) Retries() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.retries
}

// IsSet 表示是否已设置 PIN。
func (p *PINState) IsSet() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.hash) > 0
}

// SetPIN 设置或修改 PIN。
func (p *PINState) SetPIN(pin []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	sum := sha256.Sum256(pin)
	p.hash = sum[:]
	p.retries = PINRetries
	if p.persist != nil {
		return p.persist(p.hash, p.retries)
	}
	return nil
}

// VerifyHash 直接校验 SHA-256(PIN) 的值（CTAP2 pinHashEnc 路径）。
func (p *PINState) VerifyHash(hash []byte) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.hash) == 0 || p.retries <= 0 || len(hash) != len(p.hash) {
		return false, nil
	}
	if subtle.ConstantTimeCompare(hash, p.hash) == 1 {
		p.retries = PINRetries
		if p.persist != nil {
			_ = p.persist(p.hash, p.retries)
		}
		return true, nil
	}
	p.retries--
	if p.persist != nil {
		_ = p.persist(p.hash, p.retries)
	}
	return false, nil
}

// Verify 校验 PIN，错误会消耗一次重试；次数用尽后返回错误且不再比对。
func (p *PINState) Verify(pin []byte) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.hash) == 0 {
		return false, nil
	}
	if p.retries <= 0 {
		return false, nil
	}
	sum := sha256.Sum256(pin)
	if subtle.ConstantTimeCompare(sum[:], p.hash) == 1 {
		p.retries = PINRetries
		if p.persist != nil {
			_ = p.persist(p.hash, p.retries)
		}
		return true, nil
	}
	p.retries--
	if p.persist != nil {
		_ = p.persist(p.hash, p.retries)
	}
	return false, nil
}
