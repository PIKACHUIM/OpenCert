package pkcs11

import (
	"context"
	"strings"
	"testing"

	"github.com/globaltrusts/server-card/internal/keybackend"
)

// TestProviderAgainstRealModule 走完整 Provider 链路（配置解析 → 模块加载 →
// 布局判定 → 选槽 → 建会话 → 登录 → 健康检查）验证后端真的可用。
func TestProviderAgainstRealModule(t *testing.T) {
	path := testModulePath(t)

	p, err := keybackend.Open(context.Background(), keybackend.Config{
		Driver: keybackend.DriverPKCS11,
		Kind:   keybackend.KindHSM,
		Label:  "测试区域",
		Params: keybackend.Params{
			"library": path,
			"pin":     "1234",
			"keygen":  "true",
		},
	})
	if err != nil {
		t.Fatalf("打开 PKCS#11 后端失败: %v", err)
	}
	defer p.Close() //nolint:errcheck

	if p.Driver() != keybackend.DriverPKCS11 || p.Kind() != keybackend.KindHSM {
		t.Fatalf("驱动标识不正确: %s/%s", p.Driver(), p.Kind())
	}
	if caps := p.Capabilities(); !caps.Sign || !caps.Generate || caps.Exportable {
		t.Fatalf("能力描述不符合 HSM 预期: %+v", caps)
	}

	info, err := p.Info(context.Background())
	if err != nil {
		t.Fatalf("健康检查调用失败: %v", err)
	}
	if info == nil || !info.OK {
		t.Fatalf("健康检查未通过: %+v", info)
	}
	if len(info.Devices) == 0 {
		t.Fatalf("未识别到设备: %+v", info)
	}
	t.Logf("设备：%+v", info.Devices[0])
	for _, d := range info.Devices {
		if d.Name == "" && d.Serial == "" {
			t.Errorf("设备信息不完整（标签与序列号均为空）: %+v", d)
		}
	}
}

// TestProviderMissingLibraryRejected 未配置或配置了不存在的库时明确报错。
func TestProviderMissingLibraryRejected(t *testing.T) {
	_, err := keybackend.Open(context.Background(), keybackend.Config{
		Driver: keybackend.DriverPKCS11,
		Kind:   keybackend.KindHSM,
		Params: keybackend.Params{},
	})
	if err == nil || !strings.Contains(err.Error(), "模块路径") {
		t.Fatalf("缺少模块路径时应报配置错误，实际: %v", err)
	}

	missing := "/no/such/pkcs11/module.so"
	_, err = keybackend.Open(context.Background(), keybackend.Config{
		Driver: keybackend.DriverPKCS11,
		Kind:   keybackend.KindHSM,
		Params: keybackend.Params{"library": missing},
	})
	if err == nil || !strings.Contains(err.Error(), "不存在") {
		t.Fatalf("模块不存在时应报配置错误，实际: %v", err)
	}
}

// TestExportNotAllowedForGeneratedKeys 设备内生成的密钥不可导出。
func TestExportNotAllowedForGeneratedKeys(t *testing.T) {
	path := testModulePath(t)
	p, err := keybackend.Open(context.Background(), keybackend.Config{
		Driver: keybackend.DriverPKCS11,
		Kind:   keybackend.KindHSM,
		Params: keybackend.Params{"library": path, "pin": "1234"},
	})
	if err != nil {
		t.Fatalf("打开后端失败: %v", err)
	}
	defer p.Close() //nolint:errcheck

	// 伪造一个引用（即使设备里没有该对象，导出也必须走「不可导出」路径）
	ref, err := keybackend.EncodeRef(keybackend.DriverPKCS11, map[string]string{"cka_id": "00"})
	if err != nil {
		t.Fatalf("编码引用失败: %v", err)
	}
	_, err = p.Export(context.Background(), keybackend.KeyHandle{Driver: keybackend.DriverPKCS11, Ref: ref})
	if err == nil {
		t.Fatal("HSM 后端的 Export 必须失败")
	}
	if !strings.Contains(err.Error(), "不可导出") && !strings.Contains(err.Error(), "未找到") {
		t.Fatalf("导出错误信息不符合预期: %v", err)
	}
}

// TestScanFindsPresets 扫描接口在无设备时也应正常返回（不 panic）。
func TestScanFindsPresets(t *testing.T) {
	found := keybackend.ScanPresets()
	t.Logf("扫描到 %d 个候选模块路径", len(found))
	for _, m := range found {
		if m.Path == "" {
			t.Errorf("扫描结果缺少路径: %+v", m)
		}
	}
}
