package card

import (
	"context"

	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// 本文件定义 SlotProvider 的**可选能力**接口。
//
// 背景：PKCS#11 中 C_InitPIN / C_SetPIN / C_CreateObject / C_DestroyObject /
// C_SetAttributeValue / C_GetObjectSize / C_GenerateKeyPair 属于可选功能。
// 早期 IPC 层对未实现的命令直接返回 CKR_OK 并给出句柄 0，属于"假装成功"：
// 调用方（浏览器 / ssh / pkcs11-tool）会认为密钥已生成、PIN 已修改，
// 之后的操作才以难以定位的方式失败。
//
// 现在的约定：
//   - 实现该能力的 Slot 实现对应接口，IPC 层通过类型断言调用；
//   - 未实现的 Slot 由 IPC 层返回 CKR_FUNCTION_NOT_SUPPORTED，让调用方立即得到明确结论。
//
// 当前实现情况：
//   - local.Slot（本地卡，含 TPM 卡）：PINManager + ObjectManager + KeyPairGenerator
//   - cloud.Slot：均不实现（PIN 与对象由云端服务端管理）

// PINManager 提供卡片 PIN 管理能力，对应 C_SetPIN / C_InitPIN。
type PINManager interface {
	// SetPIN 校验 oldPIN 后把用户 PIN 改为 newPIN（C_SetPIN 语义）。
	SetPIN(ctx context.Context, oldPIN, newPIN string) error
	// SetUserPIN 在已通过 SO/管理员凭据登录的会话中设置用户 PIN（C_InitPIN 语义）。
	SetUserPIN(ctx context.Context, newPIN string) error
}

// ObjectManager 提供卡片内对象管理能力，对应 C_CreateObject / C_DestroyObject /
// C_SetAttributeValue / C_GetObjectSize。
type ObjectManager interface {
	// CreateObject 依据 PKCS#11 属性模板创建对象，返回对象句柄。
	CreateObject(ctx context.Context, template []pkcs11types.Attribute) (pkcs11types.ObjectHandle, error)
	// DestroyObject 删除句柄对应的对象。
	DestroyObject(ctx context.Context, handle pkcs11types.ObjectHandle) error
	// SetAttributes 更新对象属性（当前支持 CKA_LABEL）。
	SetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.Attribute) error
	// ObjectSize 返回对象大小（字节）。
	ObjectSize(ctx context.Context, handle pkcs11types.ObjectHandle) (uint32, error)
}

// KeyPairGenerator 提供卡片内密钥对生成能力，对应 C_GenerateKeyPair。
type KeyPairGenerator interface {
	// GenerateKeyPair 按机制生成密钥对，返回（公钥句柄, 私钥句柄）。
	GenerateKeyPair(ctx context.Context, mechanism pkcs11types.MechanismType) (pub, priv pkcs11types.ObjectHandle, err error)
}
