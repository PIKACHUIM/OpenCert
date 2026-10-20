package verification

import (
	"context"
	"fmt"

	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 管理员代用户创建主体 / 扩展信息 ----
//
// 管理员代办申请时，资料可能由管理员直接录入并核定，不必再走用户自助验证流程。
// 这里复用用户侧创建的校验逻辑，最后按需直接置为已通过。

// AdminCreateSubjectInfo 管理员代用户创建主体信息。
//
// approve=true 时直接标记为审核通过（代办人写入 reviewed_by），
// approve=false 时与用户提交一致，进入待审核/待实名。
func (s *Service) AdminCreateSubjectInfo(ctx context.Context, info *storage.SubjectInfo, approve bool, reviewer string) error {
	if info.UserUUID == "" {
		return fmt.Errorf("缺少所属用户")
	}
	if err := s.CreateSubjectInfo(ctx, info); err != nil {
		return err
	}
	if !approve {
		return nil
	}
	if err := s.ApproveSubjectInfo(ctx, info.UUID, reviewer); err != nil {
		// 已自动通过（无需人工审核）时不算失败
		return fmt.Errorf("创建成功但自动审核失败: %w", err)
	}
	info.Status = "approved"
	info.ReviewedBy = reviewer
	return nil
}

// AdminCreateExtensionInfo 管理员代用户创建扩展信息。
//
// approve=true 时直接标记为已验证（等价于管理员已核对所有权），
// approve=false 时按模板策略进入待验证。
func (s *Service) AdminCreateExtensionInfo(ctx context.Context, info *storage.ExtensionInfo, approve bool) error {
	if info.UserUUID == "" {
		return fmt.Errorf("缺少所属用户")
	}
	if err := s.CreateExtensionInfo(ctx, info); err != nil {
		return err
	}
	if !approve {
		return nil
	}
	if err := s.markVerified(ctx, info.UUID); err != nil {
		return fmt.Errorf("创建成功但标记验证通过失败: %w", err)
	}
	info.VerifyStatus = "verified"
	return nil
}
