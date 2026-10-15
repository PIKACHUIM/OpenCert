package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/identity"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 主体信息 ----

func (s *Server) handleListSubjectInfos(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	userUUID := claims.UserUUID
	if auth.IsOperatorOrAbove(claims.Role) {
		if r.URL.Query().Get("scope") == "all" {
			infos, err := s.verifySvc.ListAllSubjectInfos(r.Context(), r.URL.Query().Get("status"))
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"items": infos, "subject_infos": infos, "total": len(infos)})
			return
		}
		if q := r.URL.Query().Get("user_uuid"); q != "" {
			userUUID = q
		}
	}
	infos, err := s.verifySvc.ListSubjectInfos(r.Context(), userUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": infos, "subject_infos": infos, "total": len(infos)})
}

// subjectInfoRequest 兼容两种写法：field_values 为 JSON 字符串或对象。
type subjectInfoRequest struct {
	SubjectTmplUUID string          `json:"subject_tmpl_uuid"`
	FieldValues     json.RawMessage `json:"field_values"`
}

func (req subjectInfoRequest) values() (string, error) {
	raw := strings.TrimSpace(string(req.FieldValues))
	if raw == "" || raw == "null" {
		return "{}", nil
	}
	if strings.HasPrefix(raw, `"`) {
		var str string
		if err := json.Unmarshal(req.FieldValues, &str); err != nil {
			return "", err
		}
		return str, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal(req.FieldValues, &m); err != nil {
		return "", fmt.Errorf("主体字段格式错误")
	}
	b, _ := json.Marshal(m)
	return string(b), nil
}

func (s *Server) handleCreateSubjectInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req subjectInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	values, err := req.values()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info := &storage.SubjectInfo{UserUUID: claims.UserUUID, SubjectTmplUUID: req.SubjectTmplUUID, FieldValues: values}
	if err := s.verifySvc.CreateSubjectInfo(r.Context(), info); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// handleResubmitSubjectInfo PUT /api/subject-infos/{uuid}：修改后重新进入验证流程。
func (s *Server) handleResubmitSubjectInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req subjectInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	values, err := req.values()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if values == "{}" {
		values = ""
	}
	info, err := s.verifySvc.ResubmitSubjectInfo(r.Context(), r.PathValue("uuid"), claims.UserUUID, values)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleDeleteSubjectInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	info, err := s.verifySvc.GetSubjectInfo(r.Context(), r.PathValue("uuid"))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if info.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权删除此主体信息")
		return
	}
	if err := s.verifySvc.DeleteSubjectInfo(r.Context(), info.UUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "主体信息已删除"})
}

func (s *Server) handleApproveSubjectInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	infoUUID := r.PathValue("uuid")
	if err := s.verifySvc.ApproveSubjectInfo(r.Context(), infoUUID, claims.UserUUID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditIdentity(r, "approve_subject_info", infoUUID, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "主体信息已审核通过"})
}

func (s *Server) handleRejectSubjectInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	infoUUID := r.PathValue("uuid")
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if err := s.verifySvc.RejectSubjectInfoWithReason(r.Context(), infoUUID, claims.UserUUID, req.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditIdentity(r, "reject_subject_info", infoUUID, req.Reason)
	writeJSON(w, http.StatusOK, map[string]string{"message": "主体信息已驳回"})
}

// handleStartSubjectIdentity POST /api/subject-infos/{uuid}/identity：发起实名认证，返回跳转地址。
func (s *Server) handleStartSubjectIdentity(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "实名认证未启用")
		return
	}
	info, err := s.verifySvc.GetSubjectInfo(r.Context(), r.PathValue("uuid"))
	if err != nil || info.UserUUID != claims.UserUUID {
		writeError(w, http.StatusNotFound, "主体信息不存在")
		return
	}
	providerUUID, err := s.verifySvc.SubjectIdentityProvider(r.Context(), info)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req struct {
		ReturnURL string `json:"return_url"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	base := fmt.Sprintf("%s://%s", scheme(r), r.Host)
	// 回跳地址只允许本站，防止开放重定向
	ret := base + "/console/subject-infos"
	if strings.HasPrefix(req.ReturnURL, "/") && !strings.HasPrefix(req.ReturnURL, "//") {
		ret = base + req.ReturnURL
	}
	url, err := s.identityStore.StartIdentity(r.Context(), providerUUID, info.UUID, claims.UserUUID, base, ret)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": url})
}

// handleIdentityCallback POST /api/identity/callback/{provider}：第三方实名结果回调（HMAC 签名）。
func (s *Server) handleIdentityCallback(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "实名认证未启用")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取回调失败")
		return
	}
	providerUUID := r.PathValue("provider")
	res, err := s.identityStore.HandleCallback(r.Context(), providerUUID, body, r.Header.Get("X-Signature"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if res.Passed {
		if err := s.verifySvc.MarkSubjectIdentityPassed(r.Context(), res.SubjectInfoUUID, providerUUID); err != nil &&
			!strings.Contains(err.Error(), "不能审核通过") {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		reason := "实名认证未通过"
		if res.Message != "" {
			reason += "：" + res.Message
		}
		s.verifySvc.RejectSubjectInfoWithReason(r.Context(), res.SubjectInfoUUID, "identity:"+providerUUID, reason) //nolint:errcheck
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "ok"})
}

// ---- 扩展信息 ----

func (s *Server) handleListExtensionInfos(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	infos, err := s.verifySvc.ListExtensionInfos(r.Context(), claims.UserUUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": infos, "extension_infos": infos, "total": len(infos)})
}

func (s *Server) handleCreateExtensionInfo(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r.Context())
	var req struct {
		TmplUUID     string `json:"tmpl_uuid"`
		InfoType     string `json:"info_type"`
		Value        string `json:"value"`
		VerifyMethod string `json:"verify_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	info := &storage.ExtensionInfo{
		UserUUID: claims.UserUUID, TmplUUID: req.TmplUUID, InfoType: req.InfoType,
		Value: req.Value, VerifyMethod: req.VerifyMethod,
	}
	if info.VerifyMethod == "dns" {
		info.VerifyMethod = "txt"
	}
	if err := s.verifySvc.CreateExtensionInfo(r.Context(), info); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"extension_info": info,
		"verify_token":   info.VerifyToken,
		"instructions":   verifyInstructions(info),
	})
}

// verifyInstructions 生成面向用户的验证操作说明。
func verifyInstructions(info *storage.ExtensionInfo) string {
	switch info.VerifyStatus {
	case "verified":
		return "已通过验证"
	case "reviewing":
		return "已提交，等待管理员人工审核"
	}
	switch info.VerifyMethod {
	case "txt":
		return fmt.Sprintf("请添加 DNS TXT 记录：_opencert.%s  值：opencert-verify=%s",
			strings.TrimPrefix(info.Value, "*."), info.VerifyToken)
	case "http":
		return fmt.Sprintf("请在 http://%s/.well-known/pki-validation/%s 放置内容为 %s 的文件", info.Value, info.VerifyToken, info.VerifyToken)
	case "tls":
		return fmt.Sprintf("请在 %s:443 以 ALPN acme-tls/1 返回包含 SHA-256(%s) 的 acmeIdentifier 扩展证书（RFC 8737）", info.Value, info.VerifyToken)
	case "email":
		return fmt.Sprintf("验证码已发送至 %s，15 分钟内有效", info.Value)
	}
	return ""
}

// ownedExtensionInfo 校验扩展信息归属当前用户（管理员放行）。
func (s *Server) ownedExtensionInfo(w http.ResponseWriter, r *http.Request) (*storage.ExtensionInfo, bool) {
	claims := claimsFromCtx(r.Context())
	info, err := s.verifySvc.GetExtensionInfo(r.Context(), r.PathValue("uuid"))
	if err != nil {
		writeError(w, http.StatusNotFound, "扩展信息不存在")
		return nil, false
	}
	if info.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权操作此扩展信息")
		return nil, false
	}
	return info, true
}

func (s *Server) handleVerifyDNS(w http.ResponseWriter, r *http.Request) {
	if info, ok := s.ownedExtensionInfo(w, r); ok {
		s.respondVerify(w, s.verifySvc.VerifyDNSTXT(r.Context(), info.UUID), "DNS 验证通过")
	}
}

func (s *Server) handleVerifyHTTP(w http.ResponseWriter, r *http.Request) {
	if info, ok := s.ownedExtensionInfo(w, r); ok {
		s.respondVerify(w, s.verifySvc.VerifyHTTP(r.Context(), info.UUID), "HTTP 验证通过")
	}
}

func (s *Server) handleVerifyTLS(w http.ResponseWriter, r *http.Request) {
	if info, ok := s.ownedExtensionInfo(w, r); ok {
		s.respondVerify(w, s.verifySvc.VerifyTLS(r.Context(), info.UUID), "TLS 验证通过")
	}
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	info, ok := s.ownedExtensionInfo(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	s.respondVerify(w, s.verifySvc.VerifyEmailCode(r.Context(), info.UUID, req.Code), "邮箱验证通过")
}

func (s *Server) respondVerify(w http.ResponseWriter, err error, okMsg string) {
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": okMsg})
}

// handleRenewExtensionInfo POST /api/extension-infos/{uuid}/renew：重新发起验证（可切换方式）。
func (s *Server) handleRenewExtensionInfo(w http.ResponseWriter, r *http.Request) {
	info, ok := s.ownedExtensionInfo(w, r)
	if !ok {
		return
	}
	var req struct {
		Method   string `json:"method"`
		TmplUUID string `json:"tmpl_uuid"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	updated, err := s.verifySvc.RenewExtensionInfo(r.Context(), info.UUID, req.Method, req.TmplUUID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"extension_info": updated, "verify_token": updated.VerifyToken, "instructions": verifyInstructions(updated),
	})
}

func (s *Server) handleApproveExtensionInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	if err := s.verifySvc.ApproveExtensionInfo(r.Context(), id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditIdentity(r, "approve_extension_info", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"message": "已审核通过"})
}

func (s *Server) handleRejectExtensionInfo(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("uuid")
	var req struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if err := s.verifySvc.RejectExtensionInfo(r.Context(), id, req.Reason); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditIdentity(r, "reject_extension_info", id, req.Reason)
	writeJSON(w, http.StatusOK, map[string]string{"message": "已驳回"})
}

func (s *Server) handleDeleteExtensionInfo(w http.ResponseWriter, r *http.Request) {
	info, ok := s.ownedExtensionInfo(w, r)
	if !ok {
		return
	}
	if err := s.verifySvc.DeleteExtensionInfo(r.Context(), info.UUID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "扩展信息已删除"})
}

// ---- 身份认证审核（管理员） ----

// handleListIdentityReviews GET /api/admin/identity-reviews?kind=subject|extension&status=
func (s *Server) handleListIdentityReviews(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	status := r.URL.Query().Get("status")
	names := map[string]string{}
	username := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		if u, err := s.userRepo.GetByUUID(r.Context(), id); err == nil {
			names[id] = u.Username
		} else {
			names[id] = ""
		}
		return names[id]
	}

	if kind == "extension" {
		if status == "" {
			status = "reviewing"
		}
		infos, err := s.verifySvc.ListAllExtensionInfos(r.Context(), status)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		type view struct {
			*storage.ExtensionInfo
			Username string `json:"username"`
		}
		items := make([]view, 0, len(infos))
		for _, i := range infos {
			items = append(items, view{ExtensionInfo: i, Username: username(i.UserUUID)})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
		return
	}

	if status == "" {
		status = "pending"
	}
	infos, err := s.verifySvc.ListAllSubjectInfos(r.Context(), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmplNames := map[string]string{}
	type view struct {
		*storage.SubjectInfo
		Username     string `json:"username"`
		TemplateName string `json:"template_name"`
	}
	items := make([]view, 0, len(infos))
	for _, i := range infos {
		if _, ok := tmplNames[i.SubjectTmplUUID]; !ok && i.SubjectTmplUUID != "" {
			var n string
			s.db.QueryRowContext(r.Context(), `SELECT name FROM subject_templates WHERE uuid = ?`, i.SubjectTmplUUID).Scan(&n) //nolint:errcheck
			tmplNames[i.SubjectTmplUUID] = n
		}
		items = append(items, view{SubjectInfo: i, Username: username(i.UserUUID), TemplateName: tmplNames[i.SubjectTmplUUID]})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

func (s *Server) auditIdentity(r *http.Request, action, id, reason string) {
	claims := claimsFromCtx(r.Context())
	s.auditLogRepo.Create(r.Context(), &storage.AuditLog{ //nolint:errcheck
		UserUUID: claims.UserUUID, Action: action, ResourceType: "identity", ResourceUUID: id,
		Detail: fmt.Sprintf(`{"reason":%q}`, reason), IPAddress: r.RemoteAddr,
	})
}

// ---- 认证接口（自动审核）管理 ----

func (s *Server) handleListVerifyProviders(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"items": []interface{}{}, "drivers": identity.SortedDrivers()})
		return
	}
	list, err := s.identityStore.List(r.Context(), r.URL.Query().Get("kind"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": list, "drivers": identity.SortedDrivers()})
}

func (s *Server) handleSaveVerifyProvider(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "认证接口服务未启用")
		return
	}
	var p identity.Provider
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	p.UUID = r.PathValue("uuid") // POST 为空（创建），PUT 为更新
	if err := s.identityStore.Save(r.Context(), &p); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.auditIdentity(r, "save_verify_provider", p.UUID, p.Name)
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeleteVerifyProvider(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "认证接口服务未启用")
		return
	}
	if err := s.identityStore.Delete(r.Context(), r.PathValue("uuid")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "已删除"})
}

// handleTestVerifyProvider POST /api/verify-providers/{uuid}/test：邮件接口发送测试邮件。
func (s *Server) handleTestVerifyProvider(w http.ResponseWriter, r *http.Request) {
	if s.identityStore == nil {
		writeError(w, http.StatusServiceUnavailable, "认证接口服务未启用")
		return
	}
	var req struct {
		To string `json:"to"`
	}
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
	if !strings.Contains(req.To, "@") {
		writeError(w, http.StatusBadRequest, "请填写接收测试邮件的邮箱")
		return
	}
	if err := s.identityStore.SendMail(r.Context(), r.PathValue("uuid"), req.To,
		"OpenCert 邮件接口测试", "这是一封测试邮件，说明邮件接口配置正确。"); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "测试邮件已发送"})
}
