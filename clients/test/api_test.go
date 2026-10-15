package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	config "github.com/globaltrusts/client-card/configs"
	"github.com/globaltrusts/client-card/internal/api"
	"github.com/globaltrusts/client-card/internal/card"
	"github.com/globaltrusts/client-card/internal/storage"
)

// testAPIToken 保存最近一次 setupAPIServer 生成的本地 API Token。
// 认证中间件要求受保护的 /api/ 路由必须携带 Bearer Token，
// apiReq 会自动附加该 Token（代表本机系统调用方，角色为 system）。
var testAPIToken string

// setupAPIServer 创建测试用 API 服务器（内存 SQLite + 空 Manager）。
func setupAPIServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	f, err := os.CreateTemp("", "api-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	db, err := storage.Open(f.Name())
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}

	mgr := card.NewManager()
	// DataDir 指向临时目录：既保证认证 Token 初始化成功，也避免污染工作目录。
	cfg := &config.APIConfig{Host: "127.0.0.1", Port: 0, DataDir: t.TempDir()}
	srv, err := api.NewServer(cfg, mgr, db)
	if err != nil {
		db.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	testAPIToken = srv.AuthToken()

	ts := httptest.NewServer(srv.Handler())
	return ts, func() {
		ts.Close()
		db.Close()
		os.Remove(f.Name())
	}
}

// apiReq 发送 JSON 请求并返回响应。
func apiReq(t *testing.T, ts *httptest.Server, method, path string, body interface{}) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("序列化请求体失败: %v", err)
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, &buf)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if testAPIToken != "" {
		req.Header.Set("Authorization", "Bearer "+testAPIToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("发送请求失败: %v", err)
	}
	return resp
}

// decodeResp 解码 JSON 响应体。
func decodeResp(t *testing.T, resp *http.Response, out interface{}) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("解码响应失败: %v", err)
	}
}

// ---- 健康检查 ----

func TestAPIHealth(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	resp := apiReq(t, ts, http.MethodGet, "/api/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("健康检查状态码错误: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	decodeResp(t, resp, &result)
	if result["data"] == nil {
		t.Error("健康检查响应缺少 data 字段")
	}
}

// ---- 认证与公开路径 ----

// TestAPILogin 回归测试：认证之后的 RBAC 采用 fail-closed 策略，
// 但公开路径（登录/注册/健康检查/前端静态资源）必须仍然可达。
func TestAPILogin(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	resp := apiReq(t, ts, http.MethodPost, "/api/auth/login", map[string]interface{}{
		"username": "root",
		"password": "root",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("登录状态码错误: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
			Role  string `json:"role"`
		} `json:"data"`
	}
	decodeResp(t, resp, &result)
	if result.Data.Token == "" {
		t.Fatal("登录响应缺少 token")
	}
	if result.Data.Role != "admin" {
		t.Errorf("默认 root 用户角色应为 admin，实际 %q", result.Data.Role)
	}
}

// TestAPIPublicPathsNotBlockedByRBAC 验证公开路径不会因缺少用户角色被拒绝。
func TestAPIPublicPathsNotBlockedByRBAC(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	// 健康检查属于公开 API
	healthResp := apiReq(t, ts, http.MethodGet, "/api/health", nil)
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("健康检查状态码错误: got %d, want %d", healthResp.StatusCode, http.StatusOK)
	}
	healthResp.Body.Close()

	// 非 /api/ 路径是前端静态资源，不能返回 403
	spaResp := apiReq(t, ts, http.MethodGet, "/", nil)
	if spaResp.StatusCode == http.StatusForbidden {
		t.Error("前端静态资源被 RBAC 拒绝（403）")
	}
	spaResp.Body.Close()
}

// ---- 应用指标鉴权 ----

// TestAPIMetricsRequiresToken 验证 /metrics 位于 /api/ 前缀之外，
// 仍需本地 API Token 才能访问（否则指标对同机任意进程开放）。
func TestAPIMetricsRequiresToken(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	// 不带 Token → 401
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("无 Token 访问 /metrics 应返回 401，实际 %d", resp.StatusCode)
	}

	// 带本地 API Token → 200
	req2, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", "Bearer "+testAPIToken)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("带 Token 访问 /metrics 应返回 200，实际 %d", resp2.StatusCode)
	}
}

// ---- 用户 CRUD ----

func TestAPIUserCRUD(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	// 创建用户
	createResp := apiReq(t, ts, http.MethodPost, "/api/users", map[string]interface{}{
		"user_type":    "local",
		"display_name": "API 测试用户",
		"email":        "api@test.com",
		"password":     "testpass123",
	})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("创建用户状态码错误: got %d, want %d", createResp.StatusCode, http.StatusCreated)
	}

	var createResult struct {
		Code int                    `json:"code"`
		Data map[string]interface{} `json:"data"`
	}
	decodeResp(t, createResp, &createResult)
	userUUID, _ := createResult.Data["uuid"].(string)
	if userUUID == "" {
		t.Fatal("创建用户响应缺少 uuid")
	}

	// 查询用户
	getResp := apiReq(t, ts, http.MethodGet, "/api/users/"+userUUID, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Errorf("查询用户状态码错误: got %d, want %d", getResp.StatusCode, http.StatusOK)
	}
	getResp.Body.Close()

	// 列出用户
	listResp := apiReq(t, ts, http.MethodGet, "/api/users", nil)
	if listResp.StatusCode != http.StatusOK {
		t.Errorf("列出用户状态码错误: got %d, want %d", listResp.StatusCode, http.StatusOK)
	}
	var listResult struct {
		Data []interface{} `json:"data"`
	}
	decodeResp(t, listResp, &listResult)
	// 数据库初始化时会 seed 默认 root 用户，因此期望 2 个（root + 本次创建）
	if len(listResult.Data) != 2 {
		t.Errorf("用户数量错误: got %d, want 2", len(listResult.Data))
	}

	// 更新用户
	updateResp := apiReq(t, ts, http.MethodPut, "/api/users/"+userUUID, map[string]interface{}{
		"display_name": "更新后的名称",
	})
	if updateResp.StatusCode != http.StatusOK {
		t.Errorf("更新用户状态码错误: got %d, want %d", updateResp.StatusCode, http.StatusOK)
	}
	updateResp.Body.Close()

	// 删除用户
	deleteResp := apiReq(t, ts, http.MethodDelete, "/api/users/"+userUUID, nil)
	if deleteResp.StatusCode != http.StatusOK {
		t.Errorf("删除用户状态码错误: got %d, want %d", deleteResp.StatusCode, http.StatusOK)
	}
	deleteResp.Body.Close()

	// 查询已删除用户应返回 404
	notFoundResp := apiReq(t, ts, http.MethodGet, "/api/users/"+userUUID, nil)
	if notFoundResp.StatusCode != http.StatusNotFound {
		t.Errorf("查询已删除用户状态码错误: got %d, want %d", notFoundResp.StatusCode, http.StatusNotFound)
	}
	notFoundResp.Body.Close()
}

// ---- 卡片 CRUD ----

func TestAPICardCRUD(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	// 先创建用户
	createUserResp := apiReq(t, ts, http.MethodPost, "/api/users", map[string]interface{}{
		"user_type":    "local",
		"display_name": "卡片测试用户",
		"email":        "card-api@test.com",
		"password":     "cardpass123",
	})
	var userResult struct {
		Data map[string]interface{} `json:"data"`
	}
	decodeResp(t, createUserResp, &userResult)
	userUUID, _ := userResult.Data["uuid"].(string)

	// 创建卡片
	createCardResp := apiReq(t, ts, http.MethodPost, "/api/cards", map[string]interface{}{
		"slot_type":     "local",
		"card_name":     "API 测试卡片",
		"user_uuid":     userUUID,
		"user_password": "cardpass123",
		"pin":           "123456",
		"remark":        "测试",
	})
	if createCardResp.StatusCode != http.StatusCreated {
		t.Fatalf("创建卡片状态码错误: got %d, want %d", createCardResp.StatusCode, http.StatusCreated)
	}

	// 响应结构为 {data: {card: {...}, puk, admin_key, pin}}
	var cardResult struct {
		Data struct {
			Card map[string]interface{} `json:"card"`
		} `json:"data"`
	}
	decodeResp(t, createCardResp, &cardResult)
	cardUUID, _ := cardResult.Data.Card["uuid"].(string)
	if cardUUID == "" {
		t.Fatal("创建卡片响应缺少 uuid")
	}

	// 查询卡片
	getCardResp := apiReq(t, ts, http.MethodGet, "/api/cards/"+cardUUID, nil)
	if getCardResp.StatusCode != http.StatusOK {
		t.Errorf("查询卡片状态码错误: got %d, want %d", getCardResp.StatusCode, http.StatusOK)
	}
	getCardResp.Body.Close()

	// 列出卡片（按用户过滤）
	listCardResp := apiReq(t, ts, http.MethodGet, "/api/cards?user_uuid="+userUUID, nil)
	if listCardResp.StatusCode != http.StatusOK {
		t.Errorf("列出卡片状态码错误: got %d, want %d", listCardResp.StatusCode, http.StatusOK)
	}
	var listCardResult struct {
		Data []interface{} `json:"data"`
	}
	decodeResp(t, listCardResp, &listCardResult)
	if len(listCardResult.Data) != 1 {
		t.Errorf("卡片数量错误: got %d, want 1", len(listCardResult.Data))
	}

	// 更新卡片
	updateCardResp := apiReq(t, ts, http.MethodPut, "/api/cards/"+cardUUID, map[string]interface{}{
		"card_name": "更新后的卡片名",
	})
	if updateCardResp.StatusCode != http.StatusOK {
		t.Errorf("更新卡片状态码错误: got %d, want %d", updateCardResp.StatusCode, http.StatusOK)
	}
	updateCardResp.Body.Close()

	// 删除卡片（需要用户身份二次校验）
	deleteCardResp := apiReq(t, ts, http.MethodDelete, "/api/cards/"+cardUUID, map[string]interface{}{
		"user_uuid":     userUUID,
		"user_password": "cardpass123",
	})
	if deleteCardResp.StatusCode != http.StatusOK {
		t.Errorf("删除卡片状态码错误: got %d, want %d", deleteCardResp.StatusCode, http.StatusOK)
	}
	deleteCardResp.Body.Close()
}

// ---- 日志查询 ----

func TestAPILogs(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	resp := apiReq(t, ts, http.MethodGet, "/api/logs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("日志查询状态码错误: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()
}

// ---- Slot 状态 ----

func TestAPISlots(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	resp := apiReq(t, ts, http.MethodGet, "/api/slots", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Slot 状态查询状态码错误: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	resp.Body.Close()
}

// ---- 参数校验 ----

func TestAPIValidation(t *testing.T) {
	ts, cleanup := setupAPIServer(t)
	defer cleanup()

	// 创建用户缺少必填字段
	resp := apiReq(t, ts, http.MethodPost, "/api/users", map[string]interface{}{
		"email": "no-name@test.com",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("缺少 display_name 应返回 400: got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 查询不存在的用户
	resp2 := apiReq(t, ts, http.MethodGet, "/api/users/nonexistent-uuid", nil)
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("查询不存在用户应返回 404: got %d", resp2.StatusCode)
	}
	resp2.Body.Close()

	// 创建卡片密码错误
	createUserResp := apiReq(t, ts, http.MethodPost, "/api/users", map[string]interface{}{
		"user_type":    "local",
		"display_name": "验证测试用户",
		"email":        "valid@test.com",
		"password":     "validpass",
	})
	var userResult struct {
		Data map[string]interface{} `json:"data"`
	}
	decodeResp(t, createUserResp, &userResult)
	userUUID, _ := userResult.Data["uuid"].(string)

	resp3 := apiReq(t, ts, http.MethodPost, "/api/cards", map[string]interface{}{
		"card_name":     "测试卡",
		"user_uuid":     userUUID,
		"user_password": "wrongpassword",
		"pin":           "123456",
	})
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("密码错误应返回 403: got %d", resp3.StatusCode)
	}
	resp3.Body.Close()
}
