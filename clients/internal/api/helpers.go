package api

import (
	"context"
	"fmt"
	"strings"

	cryptoutil "github.com/globaltrusts/client-card/internal/crypto"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/google/uuid"
)

// hashPassword 使用 bcrypt 哈希密码。
func hashPassword(password string) (string, error) {
	return cryptoutil.HashPassword(password)
}

// verifyPassword 验证密码与 bcrypt 哈希是否匹配。
func verifyPassword(password, hash string) bool {
	return cryptoutil.VerifyPassword(password, hash)
}

// createLocalCard 创建本地智能卡（保留作兼容封装；新代码推荐直接用 local.CreateCardWithCreds）。
func createLocalCard(ctx context.Context, cardRepo *storage.CardRepo, userUUID, cardName, pin, cardPassword, remark string) (*storage.Card, error) {
	return local.CreateCard(ctx, cardRepo, userUUID, cardName, pin, cardPassword, remark)
}

// newUUID 生成新 UUID。
func newUUID() string {
	return uuid.New().String()
}

// isNotFoundErr 判断错误是否为“记录不存在”类型。
func isNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "不存在") || strings.Contains(msg, "not found")
}

// validateSlotType 验证 SlotType 合法性。
func validateSlotType(t string) error {
	switch storage.SlotType(t) {
	case storage.SlotTypeLocal, storage.SlotTypeTPM2, storage.SlotTypeTPMSC, storage.SlotTypeCloud:
		return nil
	default:
		return fmt.Errorf("不支持的 slot_type: %s（支持 local/tpm2/tpmsc/cloud）", t)
	}
}
