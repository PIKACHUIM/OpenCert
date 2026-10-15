// Package card - PIN 会话令牌管理。
//
// 设计说明：
//
//	PIN 验证通过后签发短时令牌，后续敏感操作（签名/解密/密钥生成/证书增删）需携带此令牌。
//	令牌以进程内内存 Map 存储，单实例部署足够；如需多实例部署请改用 Redis。
//	默认有效期 15 分钟，支持提前撤销（DELETE）。
package card

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// DefaultPINSessionTTL 是 PIN 会话默认有效期。
const DefaultPINSessionTTL = 15 * time.Minute

// PINSession 描述一次 PIN 验证通过后的会话信息。
type PINSession struct {
	Token     string    // 会话令牌（32 字节随机 Base64）
	CardUUID  string    // 关联的卡片 UUID
	UserUUID  string    // 关联的用户 UUID（避免令牌被其他用户使用）
	ExpiresAt time.Time // 过期时间（UTC）
}

// PINSessionStore 是 PIN 会话存储（进程内）。
type PINSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*PINSession // token → session
	ttl      time.Duration
}

// NewPINSessionStore 创建会话存储。
func NewPINSessionStore(ttl time.Duration) *PINSessionStore {
	if ttl <= 0 {
		ttl = DefaultPINSessionTTL
	}
	s := &PINSessionStore{
		sessions: make(map[string]*PINSession),
		ttl:      ttl,
	}
	// 启动后台清理 goroutine，每分钟扫描一次过期会话
	go s.cleanupLoop()
	return s
}

// Create 创建新会话并返回令牌。
func (s *PINSessionStore) Create(cardUUID, userUUID string) (*PINSession, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("生成 PIN 会话令牌失败: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	session := &PINSession{
		Token:     token,
		CardUUID:  cardUUID,
		UserUUID:  userUUID,
		ExpiresAt: time.Now().Add(s.ttl),
	}

	s.mu.Lock()
	s.sessions[token] = session
	s.mu.Unlock()
	return session, nil
}

// Verify 校验令牌并返回会话。
// 返回错误时表示令牌不存在、已过期、或与 cardUUID/userUUID 不匹配。
func (s *PINSessionStore) Verify(token, cardUUID, userUUID string) (*PINSession, error) {
	if token == "" {
		return nil, fmt.Errorf("缺少 PIN 会话令牌")
	}
	s.mu.RLock()
	session, ok := s.sessions[token]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("PIN 会话令牌无效")
	}
	if time.Now().After(session.ExpiresAt) {
		// 立即移除过期会话
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return nil, fmt.Errorf("PIN 会话已过期，请重新验证 PIN")
	}
	if session.CardUUID != cardUUID {
		return nil, fmt.Errorf("PIN 会话与卡片不匹配")
	}
	if session.UserUUID != userUUID {
		return nil, fmt.Errorf("PIN 会话与用户不匹配")
	}
	return session, nil
}

// Revoke 显式撤销令牌。
func (s *PINSessionStore) Revoke(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// RevokeByCard 撤销指定卡片的所有会话（如 PIN 变更后调用）。
func (s *PINSessionStore) RevokeByCard(cardUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if session.CardUUID == cardUUID {
			delete(s.sessions, token)
		}
	}
}

// TTL 返回会话默认有效期（秒）。
func (s *PINSessionStore) TTL() time.Duration {
	return s.ttl
}

// cleanupLoop 每分钟清理一次过期会话，避免内存泄漏。
func (s *PINSessionStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.cleanup()
	}
}

// cleanup 清理所有过期会话。
func (s *PINSessionStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}
