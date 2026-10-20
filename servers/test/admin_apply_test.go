// Package test - 管理员代用户提交证书申请测试。
//
// 覆盖：代办上下文、管理员录入资料并直接核定、跳过审批直接签发、
// 代办标记与申请人归属、普通用户越权拒绝、申请列表返回可读信息。
package test

import (
	"fmt"
	"net/http"
	"testing"
)

// buyerUUID 通过管理员用户列表接口取回测试用户的真实 UUID（用户创建时由服务端生成）。
func buyerUUID(t *testing.T, env *apiEnv, adminToken string) string {
	t.Helper()
	var resp struct {
		Users []struct {
			UUID     string `json:"uuid"`
			Username string `json:"username"`
		} `json:"users"`
	}
	env.mustCall(http.MethodGet, "/api/users?keyword=buyer&page=1&page_size=10", adminToken, nil, &resp)
	for _, u := range resp.Users {
		if u.Username == "buyer" {
			return u.UUID
		}
	}
	t.Fatal("未找到测试用户 buyer")
	return ""
}

func TestAdminProxyApplication(t *testing.T) {
	env := newAPIEnv(t)
	admin, buyer := env.tokens["admin"], env.tokens["buyer"]
	buyerID := buyerUUID(t, env, admin)

	// ---- 基础配置：CA + 颁发模板 + 主体/扩展模板 + 开通模板（允许自助方式）----
	var caResp struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/cas", admin, map[string]interface{}{
		"name": "代办测试 CA", "key_type": "ec256", "validity_years": 5, "common_name": "代办测试 CA",
	}, &caResp)

	var subjectTmpl struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/subject", admin, map[string]string{
		"name": "代办主体模板",
		"fields": `[{"key":"CN","required":true},{"key":"O","required":true,"min_len":2,"max_len":40,"verify":"manual"}]`,
		"verify_validity": "1d",
	}, &subjectTmpl)

	var extTmpl struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/extension", admin, map[string]string{
		"name": "代办扩展模板",
		"verify_policy": `{"domain":{"enabled":true,"mode":"none","methods":["dns"],"validity":"1d"},` +
			`"email":{"enabled":false},"ip":{"enabled":false}}`,
	}, &extTmpl)

	var issuance struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/issuance", admin, map[string]interface{}{
		"name": "代办颁发模板", "category": "ssl", "enabled": true, "valid_days": "[365]",
		"default_valid_days": 365, "allowed_key_types": `["ec256"]`,
		"allowed_ca_uuids": fmt.Sprintf(`["%s"]`, caResp.UUID), "default_ca_uuid": caResp.UUID,
		"subject_tmpl_uuid": subjectTmpl.UUID, "extension_tmpl_uuid": extTmpl.UUID,
	}, &issuance)

	var applyTmpl struct {
		UUID string `json:"uuid"`
	}
	env.mustCall(http.MethodPost, "/api/templates/cert-apply", admin, map[string]interface{}{
		"name": "代办开通模板", "issuance_tmpl_uuid": issuance.UUID, "enabled": true,
		"require_approval": false, "allow_renewal": true, "apply_modes": `["self"]`,
	}, &applyTmpl)

	// ---- 代办上下文：返回目标用户与可代办类型 ----
	var ctxResp struct {
		User struct {
			UUID     string `json:"uuid"`
			Username string `json:"username"`
		} `json:"user"`
		Templates []map[string]interface{} `json:"templates"`
	}
	env.mustCall(http.MethodGet, "/api/admin/apply-context?user_uuid="+buyerID, admin, nil, &ctxResp)
	if ctxResp.User.Username != "buyer" {
		t.Errorf("代办上下文应返回目标用户，实际 %+v", ctxResp.User)
	}
	found := false
	for _, tpl := range ctxResp.Templates {
		if tpl["uuid"] == applyTmpl.UUID {
			found = true
		}
	}
	if !found {
		t.Error("代办上下文应包含启用中的证书类型")
	}

	// 普通用户不能调用代办上下文
	env.mustFail(http.MethodGet, "/api/admin/apply-context?user_uuid="+buyerID, buyer, nil)
	// 不存在的客户应报错
	env.mustFail(http.MethodGet, "/api/admin/apply-context?user_uuid=no-such-user", admin, nil)

	// ---- 管理员录入资料 + 跳过审批，直接签发 ----
	var submit struct {
		Application map[string]interface{} `json:"application"`
		AutoIssued  bool                   `json:"auto_issued"`
		Message     string                 `json:"message"`
	}
	env.mustCall(http.MethodPost, "/api/admin/cert-applications", admin, map[string]interface{}{
		"user_uuid":            buyerID,
		"cert_apply_tmpl_uuid": applyTmpl.UUID,
		"subject":             map[string]string{"CN": "proxy.example.com", "O": "代办组织"},
		"extensions":          []map[string]string{{"info_type": "domain", "value": "proxy.example.com"}},
		"key_type":            "ec256",
		"skip_approval":       true,
	}, &submit)
	if !submit.AutoIssued {
		t.Fatalf("跳过审批应直接签发，实际: %+v", submit)
	}
	appUUID, _ := submit.Application["uuid"].(string)
	if appUUID == "" {
		t.Fatal("代办申请未返回申请 UUID")
	}
	// 申请归属目标用户，并带代办标记
	if got, _ := submit.Application["user_uuid"].(string); got != buyerID {
		t.Errorf("申请应归属目标用户，实际 %s", got)
	}

	// ---- 申请列表：返回可读信息，不再只有 UUID ----
	var list struct {
		Items []map[string]interface{} `json:"items"`
	}
	env.mustCall(http.MethodGet, "/api/cert-applications?status=approved&page=1&page_size=10", admin, nil, &list)
	if len(list.Items) == 0 {
		t.Fatal("申请列表为空")
	}
	first := list.Items[0]
	for _, key := range []string{"user_name", "template_name", "subject_summary"} {
		if v, _ := first[key].(string); v == "" {
			t.Errorf("列表应返回可读字段 %s，实际: %+v", key, first)
		}
	}
	if v, _ := first["on_behalf"].(bool); !v {
		t.Errorf("代办申请应带 on_behalf 标记，实际: %+v", first)
	}

	// ---- 引用已有资料再提交一份（不跳过审批时进入待审核）----
	var subjectInfo struct {
		UUID string `json:"uuid"`
	}
	// 用户自己先提交一份主体信息（人工字段 → 待审核）
	env.mustCall(http.MethodPost, "/api/subject-infos", buyer, map[string]interface{}{
		"subject_tmpl_uuid": subjectTmpl.UUID,
		"field_values":      map[string]string{"CN": "reuse.example.com", "O": "复用组织"},
	}, &subjectInfo)
	env.mustCall(http.MethodPost, "/api/subject-infos/"+subjectInfo.UUID+"/approve", admin, nil, nil)

	var extInfo struct {
		ExtensionInfo struct {
			UUID string `json:"uuid"`
		} `json:"extension_info"`
	}
	env.mustCall(http.MethodPost, "/api/extension-infos", buyer, map[string]interface{}{
		"tmpl_uuid": extTmpl.UUID, "info_type": "domain", "value": "reuse.example.com",
	}, &extInfo)

	var second struct {
		AutoIssued bool `json:"auto_issued"`
	}
	env.mustCall(http.MethodPost, "/api/admin/cert-applications", admin, map[string]interface{}{
		"user_uuid":            buyerID,
		"cert_apply_tmpl_uuid": applyTmpl.UUID,
		"subject_info_uuid":    subjectInfo.UUID,
		"extension_info_uuids": []string{extInfo.ExtensionInfo.UUID},
		"key_type":             "ec256",
		"skip_approval":        false,
	}, &second)
	if !second.AutoIssued {
		t.Errorf("开通模板无需审批时应自动签发")
	}

	// 非法算法应被拒绝（颁发模板只允许 ec256）
	env.mustFail(http.MethodPost, "/api/admin/cert-applications", admin, map[string]interface{}{
		"user_uuid":            buyerID,
		"cert_apply_tmpl_uuid": applyTmpl.UUID,
		"subject_info_uuid":    subjectInfo.UUID,
		"extension_info_uuids": []string{extInfo.ExtensionInfo.UUID},
		"key_type":             "rsa4096",
		"skip_approval":        true,
	})
}
