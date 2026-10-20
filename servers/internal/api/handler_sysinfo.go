package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/keybackend"
)

// ---- 系统设置：系统信息 / 系统邮件 ----

// ServiceVersion 是构建版本号（启动时由 main 注入）。
var ServiceVersion = "dev"

// systemKeyDriver 是"系统信息"里展示的密钥驱动条目。
type systemKeyDriver struct {
	Driver      string   `json:"driver"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Available   bool     `json:"available"`
	Detail      string   `json:"detail,omitempty"`
	KeyTypes    []string `json:"key_types,omitempty"`
	Exportable  bool     `json:"exportable"`
	Description string   `json:"description,omitempty"`
}

// handleSystemInfo GET /api/system/info
//
// 只返回管理员需要知道的运行信息：版本、数据库类型、可用密钥驱动、国密支持。
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	drivers := []systemKeyDriver{}
	for _, d := range keybackend.Descriptors() {
		drivers = append(drivers, systemKeyDriver{
			Driver: d.Driver, Name: d.Name, Kind: string(d.Kind),
			Available: d.Available, Detail: d.AvailableDetail,
			KeyTypes: d.Capabilities.KeyTypes, Exportable: d.Capabilities.Exportable,
			Description: d.Description,
		})
	}
	sort.SliceStable(drivers, func(i, j int) bool { return drivers[i].Driver < drivers[j].Driver })

	// 存储区域统计：让管理员一眼看出当前有没有配置硬件区域
	zones := []map[string]interface{}{}
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT name, storage_type, status FROM storage_zones ORDER BY created_at`)
	if err == nil {
		for rows.Next() {
			var name, stype, status string
			if rows.Scan(&name, &stype, &status) == nil {
				zones = append(zones, map[string]interface{}{
					"name": name, "storage_type": stype, "status": status,
				})
			}
		}
		rows.Close()
	}

	smAvailable := ca.IsSM2Available()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":     ServiceVersion,
		"database":    map[string]string{"driver": string(s.db.Driver)},
		"key_drivers": drivers,
		"sm": map[string]bool{
			"sm2": smAvailable, "sm3": smAvailable, "sm4": smAvailable,
		},
		"storage_zones": zones,
	})
}

// systemMailView 是"系统邮件"页面的数据。
type systemMailView struct {
	DefaultProviderUUID string               `json:"default_provider_uuid"`
	Providers           []*identity.Provider `json:"providers"`
}

func (s *Server) handleGetSystemMail(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "认证接口服务未启用")
		return
	}
	providers, err := s.identityStore.List(r.Context(), identity.KindEmail)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	view := systemMailView{Providers: providers}
	for _, p := range providers {
		if p.IsDefault {
			view.DefaultProviderUUID = p.UUID
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleUpdateSystemMail PUT /api/system/mail
//
// 两种动作：
//   - {"default_provider_uuid":"..."}：把某个邮件接口设为系统默认发信通道（空串表示取消默认，回退到环境变量 SMTP）
//   - {"test_to":"a@b.com","provider_uuid":"..."}：用指定接口发一封测试邮件
func (s *Server) handleUpdateSystemMail(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "认证接口服务未启用")
		return
	}
	var req struct {
		DefaultProviderUUID string `json:"default_provider_uuid"`
		ProviderUUID        string `json:"provider_uuid"`
		TestTo              string `json:"test_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if strings.TrimSpace(req.TestTo) != "" {
		if !strings.Contains(req.TestTo, "@") {
			writeError(w, http.StatusBadRequest, "请填写有效的收件邮箱")
			return
		}
		providerUUID := strings.TrimSpace(req.ProviderUUID)
		if providerUUID == "" {
			providerUUID = strings.TrimSpace(req.DefaultProviderUUID)
		}
		if providerUUID == "" {
			writeError(w, http.StatusBadRequest, "请先选择邮件接口")
			return
		}
		if err := s.identityStore.SendVia(r.Context(), providerUUID, req.TestTo,
			"OpenCert 系统邮件测试", "这是一封测试邮件，说明系统邮件配置正确。"); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "测试邮件已发送"})
		return
	}

	if strings.TrimSpace(req.DefaultProviderUUID) == "" {
		// 取消默认：清空同类默认标记，此后回退到环境变量 SMTP
		if _, err := s.db.ExecContext(r.Context(),
			`UPDATE verify_providers SET is_default = 0 WHERE kind = ?`, identity.KindEmail); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "已取消默认邮件接口"})
		return
	}
	if err := s.identityStore.SetDefault(r.Context(), req.DefaultProviderUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已设为系统默认邮件接口"})
}
