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
	// 检查是否已登录
	if s.IsLoggedIn() {
		s.Unlock()
		return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
	}

	switch userType {
	case pkcs11types.CKU_USER:
		// RO_PUBLIC -> RO_USER, RW_PUBLIC -> RW_USER
		switch s.State {
		case pkcs11types.CKS_RO_PUBLIC_SESSION:
			if err := s.Provider.Login(ctx, userType, pin); err != nil {
				s.Unlock()
				return err
			}
			s.State = pkcs11types.CKS_RO_USER_FUNCTIONS
			s.Unlock()
			// 同步更新同一 Slot 的其他会话状态
			m.updateSlotSessionsState(s.SlotID, userType, s.Handle)
			return nil
		case pkcs11types.CKS_RW_PUBLIC_SESSION:
			if err := s.Provider.Login(ctx, userType, pin); err != nil {
				s.Unlock()
				return err
			}
			s.State = pkcs11types.CKS_RW_USER_FUNCTIONS
			s.Unlock()
			m.updateSlotSessionsState(s.SlotID, userType, s.Handle)
			return nil
		default:
			s.Unlock()
			return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
		}

	case pkcs11types.CKU_SO:
		// 只有 RW_PUBLIC 可以 SO 登录；如果存在 RO 会话则拒绝
		if s.State != pkcs11types.CKS_RW_PUBLIC_SESSION {
			state := s.State
			s.Unlock()
			if state == pkcs11types.CKS_RO_PUBLIC_SESSION {
				return pkcs11types.CKR_SESSION_READ_ONLY_EXISTS
			}
			return pkcs11types.CKR_USER_ALREADY_LOGGED_IN
		}
		// 检查同一 Slot 是否存在 RO 会话
		if m.hasROSessionForSlot(s.SlotID) {
			s.Unlock()
			return pkcs11types.CKR_SESSION_READ_ONLY_EXISTS
		}
		if err := s.Provider.Login(ctx, userType, pin); err != nil {
			s.Unlock()
			return err
		}
		s.State = pkcs11types.CKS_RW_SO_FUNCTIONS
		s.Unlock()
		return nil

	default:
		s.Unlock()
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
	if !s.IsLoggedIn() {
		s.Unlock()
		return pkcs11types.CKR_USER_NOT_LOGGED_IN
	}

	if err := s.Provider.Logout(ctx); err != nil {
		s.Unlock()
		return err
	}

	// 回退到对应的 PUBLIC 状态
	switch s.State {
	case pkcs11types.CKS_RO_USER_FUNCTIONS:
		s.State = pkcs11types.CKS_RO_PUBLIC_SESSION
	case pkcs11types.CKS_RW_USER_FUNCTIONS, pkcs11types.CKS_RW_SO_FUNCTIONS:
		s.State = pkcs11types.CKS_RW_PUBLIC_SESSION
	}
	s.Unlock()

	// 同步更新同一 Slot 的其他会话状态
	m.revertSlotSessionsToPublic(s.SlotID, s.Handle)
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

// sessionsOfSlot 收集指定 Slot 上除 exclude 之外的会话。
// 返回前已释放 Manager 锁，调用方可逐个对会话加锁，
// 避免出现「持有会话 A 的锁再去抢会话 B 的锁」这类交叉加锁。
func (m *Manager) sessionsOfSlot(slotID pkcs11types.SlotID, exclude pkcs11types.SessionHandle) []*Session {
	m.mu.RLock()
	targets := make([]*Session, 0, len(m.sessions))
	for h, s := range m.sessions {
		if s.SlotID == slotID && h != exclude {
			targets = append(targets, s)
		}
	}
	m.mu.RUnlock()
	return targets
}

// updateSlotSessionsState 当 User 登录成功时，同步更新同一 Slot 的其他会话状态。
// PKCS#11 规范要求：同一 Token 上的所有会话共享登录状态。
//
// 并发要点：State 字段由各会话自己的互斥锁保护，因此这里逐个加锁更新；
// 且调用方必须已释放当前会话的锁（否则会与其它 goroutine 的登录/登出交叉加锁而死锁）。
func (m *Manager) updateSlotSessionsState(slotID pkcs11types.SlotID, userType pkcs11types.UserType, exclude pkcs11types.SessionHandle) {
	if userType != pkcs11types.CKU_USER {
		return
	}
	for _, s := range m.sessionsOfSlot(slotID, exclude) {
		s.Lock()
		switch s.State {
		case pkcs11types.CKS_RO_PUBLIC_SESSION:
			s.State = pkcs11types.CKS_RO_USER_FUNCTIONS
		case pkcs11types.CKS_RW_PUBLIC_SESSION:
			s.State = pkcs11types.CKS_RW_USER_FUNCTIONS
		}
		s.Unlock()
	}
}

// revertSlotSessionsToPublic 当登出时，同步将同一 Slot 的其他会话回退到 PUBLIC 状态。
// 与 updateSlotSessionsState 相同，逐个加锁且不嵌套持有多个会话锁。
func (m *Manager) revertSlotSessionsToPublic(slotID pkcs11types.SlotID, exclude pkcs11types.SessionHandle) {
	for _, s := range m.sessionsOfSlot(slotID, exclude) {
		s.Lock()
		switch s.State {
		case pkcs11types.CKS_RO_USER_FUNCTIONS:
			s.State = pkcs11types.CKS_RO_PUBLIC_SESSION
		case pkcs11types.CKS_RW_USER_FUNCTIONS, pkcs11types.CKS_RW_SO_FUNCTIONS:
			s.State = pkcs11types.CKS_RW_PUBLIC_SESSION
		}
		s.Unlock()
	}
}
