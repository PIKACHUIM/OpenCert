// Package storage_test - 云卡认证与授权契约测试。
//
// 覆盖 17 报告中的三项阻断：TOTP 登录分支、云卡 PIN 会话、证书下发接口契约。
package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card/cloud"
)

// mockCloudAuth 是一个覆盖认证/授权路径的 servers Mock。
type mockCloudAuth struct {
	token           string
	totpRequired    bool
	totpSession     string
	requirePIN      bool
	pinValue        string
	pinSessionToken string
	deliverAllowed  bool
	// 记录最近一次请求，便于断言请求头
	lastPINHeader string
	lastDeliver   map[string]interface{}
}

func (m *mockCloudAuth) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if m.totpRequired {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
				"require_totp":  true,
				"session_token": m.totpSession,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"token":      m.token,
			"user_uuid":  "user-001",
			"username":   "testuser",
			"expires_at": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST /api/auth/totp-verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SessionToken string `json:"session_token"`
			Code         string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.SessionToken != m.totpSession || req.Code != "123456" {
			http.Error(w, `{"error":"TOTP 验证码错误"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"token":      m.token,
			"user_uuid":  "user-001",
			"expires_at": time.Now().Add(2 * time.Hour).Format(time.RFC3339),
		})
	})

	mux.HandleFunc("POST /api/cards/{uuid}/verify-pin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PIN string `json:"pin"`
		}
		json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck
		if req.PIN != m.pinValue {
			http.Error(w, `{"error":"PIN 错误"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"success":           true,
			"pin_session_token": m.pinSessionToken,
			"expires_at":        time.Now().Add(15 * time.Minute).Format(time.RFC3339),
			"ttl_seconds":       900,
			"remaining":         3,
		})
	})

	mux.HandleFunc("POST /api/cards/{uuid}/sign", func(w http.ResponseWriter, r *http.Request) {
		m.lastPINHeader = r.Header.Get("X-PIN-Session")
		if m.requirePIN && m.lastPINHeader != m.pinSessionToken {
			w.Header().Set("X-PIN-Required", "true")
			http.Error(w, `{"error":"需要 PIN 会话"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]byte{"signature": []byte("sig")}) //nolint:errcheck
	})

	mux.HandleFunc("POST /api/certificates/{uuid}/download", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		m.lastDeliver = body

		if !m.deliverAllowed {
			http.Error(w, `{"error":"该证书的密钥存储策略不允许导出私钥"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"cert_pem":  "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
			"key_pem":   "-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----",
			"algorithm": "rsa2048",
		})
	})

	return mux
}

func newCloudAuthClient(t *testing.T, cfg *mockCloudAuth) *cloud.Client {
	t.Helper()
	srv := httptest.NewServer(cfg.handler())
	t.Cleanup(srv.Close)

	client, err := cloud.NewClient(srv.URL, true)
	if err != nil {
		t.Fatalf("创建云客户端失败: %v", err)
	}
	return client
}

func TestCloudLoginTOTPBranch(t *testing.T) {
	t.Parallel()
	mock := &mockCloudAuth{
		token:        "jwt-after-totp",
		totpRequired: true,
		totpSession:  "sess-001",
		pinValue:     "123456",
	}
	client := newCloudAuthClient(t, mock)
	ctx := context.Background()

	// 需要二次验证时必须返回可判定错误，而不是"登录成功但 Token 为空"
	_, err := client.Login(ctx, "testuser", "testpass")
	if !errors.Is(err, cloud.ErrTOTPRequired) {
		t.Fatalf("应返回 ErrTOTPRequired，实际: %v", err)
	}
	// 未完成验证前不得持有 Token
	if !client.IsTokenExpired() {
		t.Error("未完成二次验证时不应持有有效 Token")
	}

	// 错误的验证码应失败
	if _, err := client.VerifyTOTP(ctx, "sess-001", "000000"); err == nil {
		t.Error("错误验证码应被拒绝")
	}

	// 正确验证码后获得 Token
	if _, err := client.VerifyTOTP(ctx, "sess-001", "123456"); err != nil {
		t.Fatalf("二次验证失败: %v", err)
	}
	if client.IsTokenExpired() {
		t.Error("二次验证后应持有有效 Token")
	}
}

func TestCloudSignRequiresPINSession(t *testing.T) {
	t.Parallel()
	mock := &mockCloudAuth{
		token:           "jwt-ok",
		pinValue:        "123456",
		pinSessionToken: "pin-sess-001",
		requirePIN:      true,
	}
	client := newCloudAuthClient(t, mock)
	ctx := context.Background()

	if _, err := client.Login(ctx, "testuser", "testpass"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	// 无 PIN 会话：服务端返回 X-PIN-Required，客户端应给出可判定错误
	_, err := client.Sign(ctx, "card-1", "cert-1", "ECDSA_SHA256", []byte("data"))
	if !errors.Is(err, cloud.ErrPINRequired) {
		t.Fatalf("应返回 ErrPINRequired，实际: %v", err)
	}

	// 错误的 PIN 不应建立会话
	if _, err := client.VerifyPIN(ctx, "card-1", "000000"); err == nil {
		t.Error("错误 PIN 应被拒绝")
	}
	if client.HasPINSession("card-1") {
		t.Error("PIN 校验失败后不应存在会话")
	}

	// 正确 PIN 后签名应携带会话令牌
	if _, err := client.VerifyPIN(ctx, "card-1", "123456"); err != nil {
		t.Fatalf("PIN 校验失败: %v", err)
	}
	if !client.HasPINSession("card-1") {
		t.Fatal("PIN 校验成功后应存在会话")
	}
	if _, err := client.Sign(ctx, "card-1", "cert-1", "ECDSA_SHA256", []byte("data")); err != nil {
		t.Fatalf("带 PIN 会话的签名应成功: %v", err)
	}
	if mock.lastPINHeader != "pin-sess-001" {
		t.Errorf("签名请求应携带 X-PIN-Session，实际 %q", mock.lastPINHeader)
	}

	// 退出后会话必须被清除
	client.ClearPINSession("card-1")
	if client.HasPINSession("card-1") {
		t.Error("清除后不应再存在 PIN 会话")
	}
}

func TestCloudDeliveryContract(t *testing.T) {
	t.Parallel()
	mock := &mockCloudAuth{
		token:          "jwt-ok",
		pinValue:       "123456",
		deliverAllowed: false,
	}
	client := newCloudAuthClient(t, mock)
	ctx := context.Background()
	if _, err := client.Login(ctx, "testuser", "testpass"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}

	// 策略拒绝：应转换为可判定错误，而不是可重试的未知错误
	_, err := client.DownloadCertWithKey(ctx, "cert-1")
	if !errors.Is(err, cloud.ErrDeliveryDenied) {
		t.Fatalf("应返回 ErrDeliveryDenied，实际: %v", err)
	}
	// 请求体必须显式声明需要私钥
	if mock.lastDeliver["include_key"] != true {
		t.Errorf("下发请求应包含 include_key=true，实际 %v", mock.lastDeliver)
	}

	// 允许交付时返回证书与私钥
	mock.deliverAllowed = true
	delivered, err := client.DownloadCertWithKey(ctx, "cert-1")
	if err != nil {
		t.Fatalf("允许交付时不应失败: %v", err)
	}
	if !strings.Contains(delivered.KeyPEM, "PRIVATE KEY") {
		t.Errorf("应返回私钥 PEM，实际 %q", delivered.KeyPEM)
	}
	if delivered.Algorithm != "rsa2048" {
		t.Errorf("算法字段应被解析，实际 %q", delivered.Algorithm)
	}
}
