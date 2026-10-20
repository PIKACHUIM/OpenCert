package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/keybackend"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 私钥存储区域（数据库 / TPM / HSM） ----

// storageZoneRequest 是存储区域创建/更新请求体。
type storageZoneRequest struct {
	Name        string            `json:"name"`
	StorageType string            `json:"storage_type"` // database/tpm/hsm
	HSMDriver   string            `json:"hsm_driver"`   // 驱动 ID：database/tpm2/pkcs11
	Params      map[string]string `json:"params"`       // 驱动参数（PIN 等敏感项会被加密保存）
	Status      string            `json:"status"`
}

// storageZoneView 是返回给管理端的存储区域视图。
type storageZoneView struct {
	UUID            string                  `json:"uuid"`
	Name            string                  `json:"name"`
	StorageType     string                  `json:"storage_type"`
	HSMDriver       string                  `json:"hsm_driver,omitempty"`
	DriverName      string                  `json:"driver_name,omitempty"`
	Kind            keybackend.Kind         `json:"kind"`
	Status          string                  `json:"status"`
	Params          map[string]string       `json:"params,omitempty"`
	Capabilities    keybackend.Capabilities `json:"capabilities"`
	Available       bool                    `json:"available"`
	AvailableDetail string                  `json:"available_detail,omitempty"`
	LastCheckAt     *time.Time              `json:"last_check_at,omitempty"`
	LastCheckError  string                  `json:"last_check_error,omitempty"`
	LastCheckDetail string                  `json:"last_check_detail,omitempty"`
	CardCount       int                     `json:"card_count"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
}

func (s *Server) storageZoneView(ctx context.Context, z *storage.StorageZone) storageZoneView {
	driver := z.DriverID()
	view := storageZoneView{
		UUID:            z.UUID,
		Name:            z.Name,
		StorageType:     z.StorageType,
		HSMDriver:       driver,
		Status:          z.Status,
		Params:          s.cardSvc.ParamsForView(z),
		Capabilities:    s.cardSvc.ZoneCapabilities(z),
		LastCheckAt:     z.LastCheckAt,
		LastCheckError:  z.LastCheckError,
		LastCheckDetail: z.LastCheckDetail,
		CreatedAt:       z.CreatedAt,
		UpdatedAt:       z.UpdatedAt,
	}
	if desc, ok := keybackend.Lookup(driver); ok {
		view.DriverName = desc.Name
		view.Available = desc.Available
		view.AvailableDetail = desc.AvailableDetail
		view.Kind = desc.Kind
	}
	if repo := s.cardSvc.StorageZones(); repo != nil && ctx != nil {
		if n, err := repo.CountCards(ctx, z.UUID); err == nil {
			view.CardCount = n
		}
	}
	return view
}

func (s *Server) handleListStorageZones(w http.ResponseWriter, r *http.Request) {
	repo := s.cardSvc.StorageZones()
	if repo == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"zones": []storageZoneView{}, "total": 0})
		return
	}
	zones, err := repo.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]storageZoneView, 0, len(zones))
	for _, z := range zones {
		views = append(views, s.storageZoneView(r.Context(), z))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"zones": views, "total": len(views)})
}

func (s *Server) handleCreateStorageZone(w http.ResponseWriter, r *http.Request) {
	repo := s.cardSvc.StorageZones()
	if repo == nil {
		writeError(w, http.StatusInternalServerError, "服务未启用存储区域")
		return
	}
	var req storageZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	zone, err := buildStorageZone(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enc, err := s.cardSvc.EncryptZoneParams(keybackend.Params(req.Params))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	zone.ParamsEnc = enc
	if caps, err := json.Marshal(s.cardSvc.ZoneCapabilities(zone)); err == nil {
		zone.Capabilities = string(caps)
	}
	if err := repo.Create(r.Context(), zone); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		Action: fmt.Sprintf("create_storage_zone:%s:%s", zone.UUID, zone.DriverID()),
		IPAddr: r.RemoteAddr,
	})
	writeJSON(w, http.StatusCreated, s.storageZoneView(r.Context(), zone))
}

func (s *Server) handleUpdateStorageZone(w http.ResponseWriter, r *http.Request) {
	repo := s.cardSvc.StorageZones()
	if repo == nil {
		writeError(w, http.StatusInternalServerError, "服务未启用存储区域")
		return
	}
	zoneUUID := r.PathValue("uuid")
	existing, err := repo.GetByUUID(r.Context(), zoneUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var req storageZoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = existing.Name
	}
	updated, err := buildStorageZone(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated.UUID = zoneUUID

	// 参数为「覆盖式更新」：未提交的旧参数保留（避免前端不回显 PIN 导致丢失）
	if len(req.Params) > 0 {
		enc, encErr := s.cardSvc.EncryptZoneParams(keybackend.Params(req.Params))
		if encErr != nil {
			writeError(w, http.StatusInternalServerError, encErr.Error())
			return
		}
		updated.ParamsEnc = enc
	} else {
		updated.ParamsEnc = existing.ParamsEnc
	}
	if caps, cerr := json.Marshal(s.cardSvc.ZoneCapabilities(updated)); cerr == nil {
		updated.Capabilities = string(caps)
	}
	if err := repo.Update(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.cardSvc.InvalidateZone(zoneUUID)
	s.logRepo.Create(r.Context(), &storage.Log{ //nolint:errcheck
		Action: fmt.Sprintf("update_storage_zone:%s:%s", zoneUUID, updated.DriverID()),
		IPAddr: r.RemoteAddr,
	})
	writeJSON(w, http.StatusOK, s.storageZoneView(r.Context(), updated))
}

func (s *Server) handleDeleteStorageZone(w http.ResponseWriter, r *http.Request) {
	repo := s.cardSvc.StorageZones()
	if repo == nil {
		writeError(w, http.StatusInternalServerError, "服务未启用存储区域")
		return
	}
	zoneUUID := r.PathValue("uuid")
	if n, err := repo.CountCards(r.Context(), zoneUUID); err == nil && n > 0 {
		writeError(w, http.StatusConflict,
			fmt.Sprintf("该存储区域仍被 %d 张卡片使用，请先迁移或删除这些卡片", n))
		return
	}
	if err := repo.Delete(r.Context(), zoneUUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.cardSvc.InvalidateZone(zoneUUID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "存储区域已删除"})
}

// handleListKeyDrivers 返回可用的私钥存储驱动清单（含配置字段与厂商预设）。
func (s *Server) handleListKeyDrivers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"drivers": keybackend.Descriptors()})
}

// handleScanKeyModules 扫描本机可用的 PKCS#11 模块（eToken/SoftHSM/YubiKey/...）。
func (s *Server) handleScanKeyModules(w http.ResponseWriter, r *http.Request) {
	found := keybackend.ScanPresets()
	writeJSON(w, http.StatusOK, map[string]interface{}{"modules": found, "total": len(found)})
}

// probeRequest 是用「未保存的配置」测试后端的请求体。
type probeRequest struct {
	StorageType string            `json:"storage_type"`
	HSMDriver   string            `json:"hsm_driver"`
	Params      map[string]string `json:"params"`
}

// handleProbeKeyBackend 使用给定配置尝试打开后端并返回设备信息（不落库）。
func (s *Server) handleProbeKeyBackend(w http.ResponseWriter, r *http.Request) {
	var req probeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	driver := normalizeDriver(req.StorageType, req.HSMDriver)
	desc, ok := keybackend.Lookup(driver)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("未注册的驱动: %s", driver))
		return
	}
	provider, err := s.cardSvc.ProbeZone(r.Context(), driver, keybackend.NormalizeKind(req.StorageType), keybackend.Params(req.Params))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      false,
			"driver":  driver,
			"name":    desc.Name,
			"error":   err.Error(),
			"checked": time.Now(),
		})
		return
	}
	defer provider.Close() //nolint:errcheck

	info, ierr := provider.Info(r.Context())
	resp := map[string]interface{}{
		"ok":         ierr == nil && info != nil && info.OK,
		"driver":     driver,
		"name":       desc.Name,
		"capability": provider.Capabilities(),
		"checked":    time.Now(),
	}
	if ierr != nil {
		resp["error"] = ierr.Error()
	} else if info != nil {
		resp["detail"] = info.Detail
		resp["devices"] = info.Devices
		if !info.OK {
			resp["ok"] = false
			resp["error"] = info.Detail
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleCheckStorageZone 对已保存的存储区域做健康检查并记录结果。
func (s *Server) handleCheckStorageZone(w http.ResponseWriter, r *http.Request) {
	zoneUUID := r.PathValue("uuid")
	provider, zone, err := s.cardSvc.OpenZone(r.Context(), zoneUUID)
	if err != nil {
		if zone != nil && s.cardSvc.StorageZones() != nil {
			s.cardSvc.StorageZones().SaveCheck(r.Context(), zoneUUID, "", err) //nolint:errcheck
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      false,
			"error":   err.Error(),
			"checked": time.Now(),
		})
		return
	}
	info, ierr := provider.Info(r.Context())
	if ierr == nil && info == nil {
		ierr = errors.New("后端未返回状态")
	}
	detail := ""
	if info != nil {
		detail = info.Detail
	}
	if s.cardSvc.StorageZones() != nil {
		s.cardSvc.StorageZones().SaveCheck(r.Context(), zoneUUID, detail, ierr) //nolint:errcheck
	}
	resp := map[string]interface{}{
		"ok":         ierr == nil && info != nil && info.OK,
		"detail":     detail,
		"devices":    deviceList(info),
		"capability": provider.Capabilities(),
		"checked":    time.Now(),
	}
	if ierr != nil {
		resp["error"] = ierr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func deviceList(info *keybackend.Info) []keybackend.DeviceInfo {
	if info == nil {
		return nil
	}
	return info.Devices
}

// buildStorageZone 由请求构造存储区域（不含加密参数）。
func buildStorageZone(req *storageZoneRequest) (*storage.StorageZone, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errors.New("区域名称不能为空")
	}
	driver := normalizeDriver(req.StorageType, req.HSMDriver)
	desc, ok := keybackend.Lookup(driver)
	if !ok {
		return nil, fmt.Errorf("未注册的私钥存储驱动: %s", driver)
	}
	stype := strings.ToLower(strings.TrimSpace(req.StorageType))
	switch desc.Kind {
	case keybackend.KindDatabase:
		stype = string(keybackend.KindDatabase)
	case keybackend.KindTPM:
		stype = string(keybackend.KindTPM)
	case keybackend.KindHSM:
		stype = string(keybackend.KindHSM)
	}
	if stype == "" {
		stype = string(keybackend.KindDatabase)
	}

	// 必填项校验（避免创建出无法使用的存储区域）
	for _, f := range desc.Fields {
		if !f.Required {
			continue
		}
		if strings.TrimSpace(req.Params[f.Key]) == "" {
			return nil, fmt.Errorf("驱动「%s」缺少必填配置项：%s", desc.Name, f.Label)
		}
	}

	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "active"
	}
	return &storage.StorageZone{
		Name:        name,
		StorageType: stype,
		HSMDriver:   driver,
		Status:      status,
	}, nil
}

// normalizeDriver 归一化驱动 ID。
func normalizeDriver(storageType, driver string) string {
	if d := strings.ToLower(strings.TrimSpace(driver)); d != "" {
		return d
	}
	switch strings.ToLower(strings.TrimSpace(storageType)) {
	case "hsm":
		return storage.DriverPKCS11
	case "tpm":
		return storage.DriverTPM
	default:
		return storage.DriverDatabase
	}
}
