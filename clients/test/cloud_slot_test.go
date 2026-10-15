// Package storage_test - Cloud Slot 集成测试。
// 启动内嵌的 servers 服务，测试 Cloud Slot 的完整流程。
package storage_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/globaltrusts/client-card/internal/card/cloud"
	"github.com/globaltrusts/client-card/internal/storage"
	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// mockServerCard 是一个简单的 servers Mock 服务器，用于测试。
type mockServerCard struct {
	token string
	certs []*cloud.Cert
	signs map[string][]byte // certUUID -> 固定签名（测试用）
}

// newMockServerCard 创建 Mock servers。
func newMockServerCard() *mockServerCard {
	return &mockServerCard{
		token: "test-jwt-token",
		certs: []*cloud.Cert{
			{
				UUID:        "cert-001",
				CardUUID:    "cloud-card-001",
				CertType:    "x509",
				KeyType:     "ec256",
				CertContent: []byte("mock-public-key"),
				Remark:      "测试EC密钥",
				CreatedAt:   time.Now(),
			},
		},
		signs: make(map[string][]byte),
	}
}

// handler 返回 Mock 服务器的 HTTP Handler。
func (m *mockServerCard) handler() http.Handler {
	mux := http.NewServeMux()

	// 登录
	mux.HandleFunc("POST /api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Username == "testuser" && req.Password == "testpass" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"token":     m.token,
				"user_uuid": "user-001",
				"username":  req.Username,
			})
		} else {
			http.Error(w, `{"error":"用户名或密码错误"}`, http.StatusUnauthorized)
		}
	})

	// 证书列表
	mux.HandleFunc("GET /api/cards/{uuid}/certs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			http.Error(w, `{"error":"未授权"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"certs": m.certs,
			"total": len(m.certs),
		})
	})

	// 签名
	mux.HandleFunc("POST /api/cards/{uuid}/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			http.Error(w, `{"error":"未授权"}`, http.StatusUnauthorized)
			return
		}
		var req struct {
			CertUUID  string `json:"cert_uuid"`
			Mechanism string `json:"mechanism"`
			Data      []byte `json:"data"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		// 生成随机签名（模拟服务端签名）
		sig := make([]byte, 64)
		rand.Read(sig)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]byte{"signature": sig})
	})

	// 解密
	mux.HandleFunc("POST /api/cards/{uuid}/decrypt", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			http.Error(w, `{"error":"未授权"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]byte{"plaintext": []byte("decrypted-data")})
	})

	return mux
}

// TestCloudSlotLogin 测试 Cloud Slot 登录流程。
func TestCloudSlotLogin(t *testing.T) {
	// 启动 Mock servers
	mockSvr := newMockServerCard()
	ts := httptest.NewServer(mockSvr.handler())
	defer ts.Close()

	ctx := context.Background()

	// 创建 Cloud Slot
	card := &storage.Card{
		UUID:          "local-card-001",
		SlotType:      storage.SlotTypeCloud,
		CardName:      "测试云端卡片",
		UserUUID:      "user-001",
		CloudURL:      ts.URL,
		CloudCardUUID: "cloud-card-001",
	}

	// Mock 服务器使用 http://，测试场景显式允许非 HTTPS 连接
	slot, err := cloud.New(pkcs11types.SlotID(100), card, true)
	if err != nil {
		t.Fatalf("创建 Cloud Slot 失败: %v", err)
	}

	// 错误密码应该失败
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "testuser:wrongpass"); err == nil {
		t.Error("错误密码应该登录失败")
	}

	// PIN 格式错误应该失败
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "no-colon-pin"); err == nil {
		t.Error("PIN 格式错误应该失败")
	}

	// 正确密码应该成功
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "testuser:testpass"); err != nil {
		t.Fatalf("Cloud Slot 登录失败: %v", err)
	}

	if !slot.IsLoggedIn() {
		t.Error("登录后 IsLoggedIn 应为 true")
	}
	t.Log("Cloud Slot 登录成功")

	// 注销
	if err := slot.Logout(ctx); err != nil {
		t.Fatalf("注销失败: %v", err)
	}
	if slot.IsLoggedIn() {
		t.Error("注销后 IsLoggedIn 应为 false")
	}
}

// TestCloudSlotFindObjects 测试 Cloud Slot 查找证书对象。
func TestCloudSlotFindObjects(t *testing.T) {
	mockSvr := newMockServerCard()
	ts := httptest.NewServer(mockSvr.handler())
	defer ts.Close()

	ctx := context.Background()

	card := &storage.Card{
		UUID:          "local-card-002",
		SlotType:      storage.SlotTypeCloud,
		CardName:      "查找测试卡片",
		UserUUID:      "user-001",
		CloudURL:      ts.URL,
		CloudCardUUID: "cloud-card-001",
	}

	slot, err := cloud.New(pkcs11types.SlotID(101), card, true)
	if err != nil {
		t.Fatalf("创建 Cloud Slot 失败: %v", err)
	}
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "testuser:testpass"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer slot.Logout(ctx)

	// 查找所有私钥对象
	handles, err := slot.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))},
	})
	if err != nil {
		t.Fatalf("查找对象失败: %v", err)
	}
	if len(handles) == 0 {
		t.Fatal("应该找到至少一个私钥对象")
	}
	t.Logf("找到 %d 个私钥对象", len(handles))

	// 获取属性
	attrs, err := slot.GetAttributes(ctx, handles[0], []pkcs11types.AttributeType{
		pkcs11types.CKA_LABEL,
		pkcs11types.CKA_ID,
		pkcs11types.CKA_SIGN,
	})
	if err != nil {
		t.Fatalf("获取属性失败: %v", err)
	}
	t.Logf("属性数量: %d", len(attrs))
}

// TestCloudSlotSign 测试 Cloud Slot 签名。
func TestCloudSlotSign(t *testing.T) {
	mockSvr := newMockServerCard()
	ts := httptest.NewServer(mockSvr.handler())
	defer ts.Close()

	ctx := context.Background()

	card := &storage.Card{
		UUID:          "local-card-003",
		SlotType:      storage.SlotTypeCloud,
		CardName:      "签名测试卡片",
		UserUUID:      "user-001",
		CloudURL:      ts.URL,
		CloudCardUUID: "cloud-card-001",
	}

	slot, err := cloud.New(pkcs11types.SlotID(102), card, true)
	if err != nil {
		t.Fatalf("创建 Cloud Slot 失败: %v", err)
	}
	if err := slot.Login(ctx, pkcs11types.CKU_USER, "testuser:testpass"); err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	defer slot.Logout(ctx)

	// 查找私钥
	handles, err := slot.FindObjects(ctx, []pkcs11types.Attribute{
		{Type: pkcs11types.CKA_CLASS, Value: uint32BE(uint32(pkcs11types.CKO_PRIVATE_KEY))},
	})
	if err != nil || len(handles) == 0 {
		t.Fatalf("查找私钥失败: %v", err)
	}

	// 签名
	testData := []byte("Cloud Slot 签名测试数据")
	sig, err := slot.Sign(ctx, handles[0], pkcs11types.Mechanism{Type: pkcs11types.CKM_ECDSA_SHA256}, testData)
	if err != nil {
		t.Fatalf("云端签名失败: %v", err)
	}
	if len(sig) == 0 {
		t.Error("签名结果不应为空")
	}
	t.Logf("云端签名成功，签名长度: %d 字节", len(sig))
}

// TestCloudSlotTokenInfo 测试 Cloud Slot Token 信息。
func TestCloudSlotTokenInfo(t *testing.T) {
	card := &storage.Card{
		UUID:          "local-card-004",
		SlotType:      storage.SlotTypeCloud,
		CardName:      "Token信息测试",
		UserUUID:      "user-001",
		CloudURL:      "http://localhost:1027",
		CloudCardUUID: "cloud-card-001",
	}

	slot, err := cloud.New(pkcs11types.SlotID(103), card, true)
	if err != nil {
		t.Fatalf("创建 Cloud Slot 失败: %v", err)
	}

	info := slot.TokenInfo()
	if info.Label == "" {
		t.Error("TokenInfo.Label 不应为空")
	}
	if info.Model != "CloudCard-v1" {
		t.Errorf("期望 Model=CloudCard-v1，实际=%s", info.Model)
	}

	slotInfo := slot.SlotInfo()
	if slotInfo.SlotID != 103 {
		t.Errorf("期望 SlotID=103，实际=%d", slotInfo.SlotID)
	}
	t.Logf("SlotInfo: %+v", slotInfo)
	t.Logf("TokenInfo: Label=%s, Model=%s", info.Label, info.Model)
}
