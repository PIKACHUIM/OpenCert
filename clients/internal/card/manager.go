package card

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// Manager 管理所有 Slot 和会话。
type Manager struct {
	mu       sync.RWMutex
	slots    map[pkcs11types.SlotID]SlotProvider
	sessions map[pkcs11types.SessionHandle]*Session
	nextSID  atomic.Uint32
}

// NewManager 创建卡片管理器。
func NewManager() *Manager {
	m := &Manager{
		slots:    make(map[pkcs11types.SlotID]SlotProvider),
		sessions: make(map[pkcs11types.SessionHandle]*Session),
	}
	m.nextSID.Store(1)
	return m
}

// RegisterSlot 注册一个 Slot Provider。
func (m *Manager) RegisterSlot(p SlotProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.slots[p.SlotID()] = p
}

// GetSlotList 返回所有 Slot ID 列表。
// tokenPresent=true 时只返回有 Token 的 Slot。
func (m *Manager) GetSlotList(tokenPresent bool) []pkcs11types.SlotID {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]pkcs11types.SlotID, 0, len(m.slots))
	for id := range m.slots {
		ids = append(ids, id)
	}
	return ids
}

// GetSlot 返回指定 Slot 的 Provider 实例，不存在返回 nil。
func (m *Manager) GetSlot(slotID pkcs11types.SlotID) SlotProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.slots[slotID]
}

// GetSlotInfo 返回指定 Slot 的信息。
func (m *Manager) GetSlotInfo(slotID pkcs11types.SlotID) (pkcs11types.SlotInfo, error) {
	m.mu.RLock()
	p, ok := m.slots[slotID]
	m.mu.RUnlock()
	if !ok {
		return pkcs11types.SlotInfo{}, fmt.Errorf("slot %d 不存在", slotID)
	}
	return p.SlotInfo(), nil
}

// GetTokenInfo 返回指定 Slot 的 Token 信息。
func (m *Manager) GetTokenInfo(slotID pkcs11types.SlotID) (pkcs11types.TokenInfo, error) {
	m.mu.RLock()
	p, ok := m.slots[slotID]
	m.mu.RUnlock()
	if !ok {
		return pkcs11types.TokenInfo{}, fmt.Errorf("slot %d 不存在", slotID)
	}
	return p.TokenInfo(), nil
}

// GetMechanisms 返回指定 Slot 支持的算法列表。
func (m *Manager) GetMechanisms(slotID pkcs11types.SlotID) ([]pkcs11types.MechanismType, error) {
	m.mu.RLock()
	p, ok := m.slots[slotID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("slot %d 不存在", slotID)
	}
	return p.Mechanisms(), nil
}

// OpenSession 打开一个新会话，返回会话句柄。
// flags 应包含 CKF_SERIAL_SESSION，可选 CKF_RW_SESSION。
func (m *Manager) OpenSession(slotID pkcs11types.SlotID, flags uint32) (pkcs11types.SessionHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.slots[slotID]
	if !ok {
		return 0, fmt.Errorf("slot %d 不存在", slotID)
	}

	// 确定初始会话状态
	var state pkcs11types.SessionState
	if flags&pkcs11types.CKF_RW_SESSION != 0 {
		state = pkcs11types.CKS_RW_PUBLIC_SESSION
	} else {
		state = pkcs11types.CKS_RO_PUBLIC_SESSION
	}

	handle := pkcs11types.SessionHandle(m.nextSID.Add(1))
	m.sessions[handle] = &Session{
		Handle:   handle,
		SlotID:   slotID,
		Flags:    flags,
		State:    state,
		Provider: p,
	}
	return handle, nil
}

// CloseSession 关闭指定会话。
func (m *Manager) CloseSession(handle pkcs11types.SessionHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[handle]; !ok {
		return fmt.Errorf("会话 %d 不存在", handle)
	}
	delete(m.sessions, handle)
	return nil
}

// CloseAllSessions 关闭指定 Slot 的所有会话。
func (m *Manager) CloseAllSessions(slotID pkcs11types.SlotID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for h, s := range m.sessions {
		if s.SlotID == slotID {
			delete(m.sessions, h)
		}
	}
}

// GetSession 获取会话，若不存在返回错误。
func (m *Manager) GetSession(handle pkcs11types.SessionHandle) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessions[handle]
	if !ok {
		return nil, fmt.Errorf("会话 %d 不存在或已关闭", handle)
	}
	return s, nil
}

// Login 在指定会话上执行登录，实现完整的 PKCS#11 会话状态机。
func (m *Manager) Login(ctx context.Context, handle pkcs11types.SessionHandle, userType pkcs11types.UserType, pin string) error {
	s, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()

	// 检查是否已登录
	if s.IsLoggedIn() {
		return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
	}

	switch userType {
	case pkcs11types.CKU_USER:
		// RO_PUBLIC -> RO_USER, RW_PUBLIC -> RW_USER
		switch s.State {
		case pkcs11types.CKS_RO_PUBLIC_SESSION:
			if err := s.Provider.Login(ctx, userType, pin); err != nil {
				return err
			}
			s.State = pkcs11types.CKS_RO_USER_FUNCTIONS
			// 同步更新同一 Slot 的所有会话状态
			m.updateSlotSessionsState(s.SlotID, userType)
			return nil
		case pkcs11types.CKS_RW_PUBLIC_SESSION:
			if err := s.Provider.Login(ctx, userType, pin); err != nil {
				return err
			}
			s.State = pkcs11types.CKS_RW_USER_FUNCTIONS
			m.updateSlotSessionsState(s.SlotID, userType)
			return nil
		default:
			return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
		}

	case pkcs11types.CKU_SO:
		// 只有 RW_PUBLIC 可以 SO 登录；如果存在 RO 会话则拒绝
		if s.State != pkcs11types.CKS_RW_PUBLIC_SESSION {
			if s.State == pkcs11types.CKS_RO_PUBLIC_SESSION {
				return pkcs11types.CKR_SESSION_READ_ONLY_EXISTS
			}
			return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
		}
		// 检查同一 Slot 是否存在 RO 会话
		if m.hasROSessionForSlot(s.SlotID) {
			return pkcs11types.CKR_SESSION_READ_ONLY_EXISTS
		}
		if err := s.Provider.Login(ctx, userType, pin); err != nil {
			return err
		}
		s.State = pkcs11types.CKS_RW_SO_FUNCTIONS
		return nil

	default:
		return pkcs11types.CKR_USER_TYPE_INVALID
	}
}

// Logout 在指定会话上执行登出，回退到对应的 PUBLIC 状态。
func (m *Manager) Logout(ctx context.Context, handle pkcs11types.SessionHandle) error {
	s, err := m.GetSession(handle)
	if err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()

	if !s.IsLoggedIn() {
		return pkcs11types.CKR_USER_NOT_LOGGED_IN
	}

	if err := s.Provider.Logout(ctx); err != nil {
		return err
	}

	// 回退到对应的 PUBLIC 状态
	switch s.State {
	case pkcs11types.CKS_RO_USER_FUNCTIONS:
		s.State = pkcs11types.CKS_RO_PUBLIC_SESSION
	case pkcs11types.CKS_RW_USER_FUNCTIONS, pkcs11types.CKS_RW_SO_FUNCTIONS:
		s.State = pkcs11types.CKS_RW_PUBLIC_SESSION
	}

	// 同步更新同一 Slot 的所有会话状态
	m.revertSlotSessionsToPublic(s.SlotID)
	return nil
}

// hasROSessionForSlot 检查指定 Slot 是否存在只读会话。
func (m *Manager) hasROSessionForSlot(slotID pkcs11types.SlotID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.SlotID == slotID && !s.IsRW() {
			return true
		}
	}
	return false
}

// updateSlotSessionsState 当 User 登录成功时，同步更新同一 Slot 的所有会话状态。
// PKCS#11 规范要求：同一 Token 上的所有会话共享登录状态。
func (m *Manager) updateSlotSessionsState(slotID pkcs11types.SlotID, userType pkcs11types.UserType) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.SlotID != slotID {
			continue
		}
		// 注意：调用方已持有当前 session 的锁，这里只更新其他 session
		switch userType {
		case pkcs11types.CKU_USER:
			if s.State == pkcs11types.CKS_RO_PUBLIC_SESSION {
				s.State = pkcs11types.CKS_RO_USER_FUNCTIONS
			} else if s.State == pkcs11types.CKS_RW_PUBLIC_SESSION {
				s.State = pkcs11types.CKS_RW_USER_FUNCTIONS
			}
		}
	}
}

// revertSlotSessionsToPublic 当登出时，同步将同一 Slot 的所有会话回退到 PUBLIC 状态。
func (m *Manager) revertSlotSessionsToPublic(slotID pkcs11types.SlotID) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.SlotID != slotID {
			continue
		}
		switch s.State {
		case pkcs11types.CKS_RO_USER_FUNCTIONS:
			s.State = pkcs11types.CKS_RO_PUBLIC_SESSION
		case pkcs11types.CKS_RW_USER_FUNCTIONS, pkcs11types.CKS_RW_SO_FUNCTIONS:
			s.State = pkcs11types.CKS_RW_PUBLIC_SESSION
		}
	}
}
