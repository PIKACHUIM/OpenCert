package identity

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ---- 微信实名（腾讯云慧眼人脸核身）----
//
// 使用 TC3-HMAC-SHA256 签名调用 faceid.tencentcloudapi.com：
//   - DetectAuth：创建核身流程，返回跳转用的 Url/BizToken；
//   - GetDetectInfoEnhanced：查询核身结果（Text/IdCardData 中的结论）。
//
// 参考：腾讯云 API 3.0 签名方法 v3。

const (
	tcService       = "faceid"
	tcAPIVersion    = "2018-03-01"
	tcDefaultHost   = "faceid.tencentcloudapi.com"
	tcDefaultRegion = "ap-guangzhou"
)

type wechatFaceIDDriver struct {
	http *http.Client
}

func init() {
	RegisterIdentityDriver("wechat_faceid", &wechatFaceIDDriver{http: &http.Client{Timeout: 15 * time.Second}})
}

// tc3Sign 计算腾讯云 API 3.0 签名，返回 Authorization 头。
func tc3Sign(secretID, secretKey, host, action, payload, timestamp string) string {
	date := timestamp[:10]
	hashedPayload := sha256Hex(payload)
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := strings.Join([]string{
		http.MethodPost, "/", "",
		canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")
	credentialScope := date + "/" + tcService + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", timestamp, credentialScope, sha256Hex(canonicalRequest),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, tcService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	return fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		secretID, credentialScope, signedHeaders, signature)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// call 发起一次腾讯云 API 调用。
func (d *wechatFaceIDDriver) call(ctx context.Context, cfg map[string]string, action string, payload map[string]interface{}) (map[string]interface{}, error) {
	host := firstNonEmpty(cfg["endpoint"], tcDefaultHost)
	region := firstNonEmpty(cfg["region"], tcDefaultRegion)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	auth := tc3Sign(cfg["secret_id"], cfg["secret_key"], host, action, string(body), ts)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", tcAPIVersion)
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-TC-Region", region)
	req.Header.Set("Authorization", auth)

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求腾讯云慧眼失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Response map[string]interface{} `json:"Response"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("腾讯云返回内容无法解析: %s", strings.TrimSpace(string(raw)))
	}
	if out.Response == nil {
		return nil, fmt.Errorf("腾讯云未返回结果")
	}
	if e, ok := out.Response["Error"].(map[string]interface{}); ok {
		msg, _ := e["Message"].(string)
		code, _ := e["Code"].(string)
		return nil, fmt.Errorf("腾讯云返回 %s: %s", code, msg)
	}
	return out.Response, nil
}

func (d *wechatFaceIDDriver) Start(ctx context.Context, s *Store, p *Provider, sess *Session, in StartInput) (string, error) {
	name := firstNonEmpty(in.Fields["name"], in.Fields["real_name"], in.Fields["CN"])
	idNumber := firstNonEmpty(in.Fields["id_number"], in.Fields["cert_no"], in.Fields["id_card"])
	if name == "" || idNumber == "" {
		return "", fmt.Errorf("微信实名需要先填写姓名与身份证号")
	}
	payload := map[string]interface{}{
		"RuleId":    p.Config["rule_id"],
		"IdCard":    idNumber,
		"Name":      name,
		"Extra":     sess.UUID,
		"ImageType": "1",
	}
	resp, err := d.call(ctx, p.Config, "DetectAuth", payload)
	if err != nil {
		return "", err
	}
	bizToken, _ := resp["BizToken"].(string)
	target, _ := resp["Url"].(string)
	if target == "" {
		return "", fmt.Errorf("腾讯云未返回认证地址")
	}
	// 记录 BizToken，供查询使用（Extra 已带 session，BizToken 单独存会话 extra 更可靠）
	if bizToken != "" {
		s.db.ExecContext(ctx, //nolint:errcheck
			`UPDATE identity_sessions SET extra = ?, updated_at = ? WHERE uuid = ?`, bizToken, time.Now(), sess.UUID)
	}
	return target, nil
}

func (d *wechatFaceIDDriver) Callback(ctx context.Context, s *Store, p *Provider, r *http.Request, body []byte) (*CallbackResult, []byte, error) {
	// 慧眼通过 return_url 跳回，结果以查询为准
	sessionID := firstNonEmpty(r.URL.Query().Get("session"), r.URL.Query().Get("Extra"))
	if sessionID == "" {
		return nil, nil, fmt.Errorf("回调缺少 session")
	}
	res, err := s.QueryIdentity(ctx, p.UUID, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return res, []byte(`{"code":0,"message":"ok"}`), nil
}

func (d *wechatFaceIDDriver) Query(ctx context.Context, s *Store, p *Provider, sess *Session) (*CallbackResult, error) {
	var bizToken string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(extra, '') FROM identity_sessions WHERE uuid = ?`, sess.UUID).
		Scan(&bizToken); err != nil {
		return nil, err
	}
	if bizToken == "" {
		return nil, fmt.Errorf("该会话还没有完成核身，请先在微信中完成认证")
	}
	resp, err := d.call(ctx, p.Config, "GetDetectInfoEnhanced", map[string]interface{}{
		"BizToken": bizToken, "RuleId": p.Config["rule_id"], "InfoType": "10",
	})
	if err != nil {
		return nil, err
	}
	// InfoType=10 返回 Text，其中 ErrCode=0 表示核身通过
	passed := false
	message := ""
	if text, ok := resp["Text"].(map[string]interface{}); ok {
		if errCode, ok := text["ErrCode"]; ok {
			if n, ok := errCode.(float64); ok && n == 0 {
				passed = true
			}
		}
		message, _ = text["ErrMsg"].(string)
	}
	return s.applyCallbackResult(ctx, p, sess.UUID, passed, message)
}
