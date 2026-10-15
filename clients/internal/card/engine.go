// Package card 定义虚拟智能卡的核心接口和引擎。
// 支持 local / tpm2 / cloud 三种 Slot 类型，可扩展。
package card

import (
	"context"
	"sync"

	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// SlotProvider 是虚拟智能卡 Slot 的核心接口。
// 每种卡片类型（local/tpm2/cloud）都需要实现此接口。
type SlotProvider interface {
	// SlotID 返回此 Slot 的唯一标识符。
	SlotID() pkcs11types.SlotID

	// SlotInfo 返回 Slot 信息。
	SlotInfo() pkcs11types.SlotInfo

	// TokenInfo 返回 Token 信息。
	TokenInfo() pkcs11types.TokenInfo

	// Mechanisms 返回支持的算法列表。
	Mechanisms() []pkcs11types.MechanismType

	// Login 验证 PIN/密码，建立已认证会话。
	Login(ctx context.Context, userType pkcs11types.UserType, pin string) error

	// Logout 注销当前会话。
	Logout(ctx context.Context) error

	// IsLoggedIn 返回当前是否已登录。
	IsLoggedIn() bool

	// FindObjects 根据属性模板查找对象句柄列表。
	FindObjects(ctx context.Context, template []pkcs11types.Attribute) ([]pkcs11types.ObjectHandle, error)

	// GetAttributes 获取对象的属性值。
	GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error)

	// Sign 使用私钥对数据进行签名。
	Sign(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, data []byte) ([]byte, error)

	// Decrypt 使用私钥解密数据。
	Decrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, ciphertext []byte) ([]byte, error)

	// Encrypt 使用公钥加密数据。
	Encrypt(ctx context.Context, handle pkcs11types.ObjectHandle, mechanism pkcs11types.Mechanism, plaintext []byte) ([]byte, error)
}

// Session 表示一个 PKCS#11 会话。
type Session struct {
	mu       sync.Mutex // 保护 Session 内部状态的互斥锁
	Handle   pkcs11types.SessionHandle
	SlotID   pkcs11types.SlotID
	Flags    uint32                   // CKF_RW_SESSION | CKF_SERIAL_SESSION 等
	State    pkcs11types.SessionState // 5 种会话状态
	Provider SlotProvider

	// 当前进行中的操作（查找/签名/加密/解密）
	FindTemplate []pkcs11types.Attribute
	FindResults  []pkcs11types.ObjectHandle
	FindPos      int
	FindActive   bool // FindObjectsInit 是否已调用

	SignHandle    pkcs11types.ObjectHandle
	SignMechanism pkcs11types.Mechanism
	SignActive    bool // SignInit 是否已调用

	DecryptHandle pkcs11types.ObjectHandle
	DecryptMech   pkcs11types.Mechanism
	DecryptActive bool // DecryptInit 是否已调用

	EncryptHandle pkcs11types.ObjectHandle
	EncryptMech   pkcs11types.Mechanism
	EncryptActive bool // EncryptInit 是否已调用
}

// Lock 获取 Session 互斥锁。
func (s *Session) Lock() {
	s.mu.Lock()
}

// Unlock 释放 Session 互斥锁。
func (s *Session) Unlock() {
	s.mu.Unlock()
}

// IsRW 返回会话是否为读写模式。
func (s *Session) IsRW() bool {
	return s.Flags&pkcs11types.CKF_RW_SESSION != 0
}

// IsLoggedIn 返回会话是否处于已登录状态。
func (s *Session) IsLoggedIn() bool {
	return s.State == pkcs11types.CKS_RO_USER_FUNCTIONS ||
		s.State == pkcs11types.CKS_RW_USER_FUNCTIONS ||
		s.State == pkcs11types.CKS_RW_SO_FUNCTIONS
}
