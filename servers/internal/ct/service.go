// Package ct 提供证书透明度（Certificate Transparency）功能。
//
// 实现 RFC 6962 add-chain 提交流程：
//  1. 构造 {"chain":["<base64-cert-der>", "<base64-ca-der>", ...]} 请求体
//  2. POST 到 <ct_server>/ct/v1/add-chain
//  3. 解析响应 SCT（Signed Certificate Timestamp）并 JSON 序列化存储
//  4. 失败时记录 status=failed，错误信息存入 sct_data 便于排查
package ct

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// DefaultSubmitTimeout 是 CT 提交 HTTP 调用的默认超时时间。
const DefaultSubmitTimeout = 30 * time.Second

// CTEntry 是 CT 提交记录模型。
type CTEntry struct {
	UUID        string     `json:"uuid"`
	CertUUID    string     `json:"cert_uuid"`
	CAUUID      string     `json:"ca_uuid"`
	CertHash    string     `json:"cert_hash"`    // 证书 SHA-256 指纹
	CTServer    string     `json:"ct_server"`    // CT 日志服务器地址
	SCTData     []byte     `json:"sct_data"`     // Signed Certificate Timestamp 数据
	Status      string     `json:"status"`       // pending/submitted/failed
	SubmittedBy string     `json:"submitted_by"` // 提交者用户 UUID
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// SCTResponse 描述 RFC 6962 add-chain 的响应体。
type SCTResponse struct {
	SCTVersion uint8  `json:"sct_version"`
	ID         string `json:"id"`         // Log ID（Base64）
	Timestamp  int64  `json:"timestamp"`  // 毫秒
	Extensions string `json:"extensions"` // Base64
	Signature  string `json:"signature"`  // Base64
}

// Service 是 CT 服务。
type Service struct {
	db         *storage.DB
	httpClient *http.Client
}

// NewService 创建 CT 服务。
func NewService(db *storage.DB) *Service {
	return &Service{
		db: db,
		httpClient: &http.Client{
			Timeout: DefaultSubmitTimeout,
		},
	}
}

// Submit 提交证书到 CT 日志（RFC 6962 add-chain）。
// chainDER 可选：CA 证书链 DER（叶子除外，顺序为签发 CA → 上级 CA → 根）。
// 即使 HTTP 调用失败，也会记录 status=failed 的 CT 条目，便于后续重试。
func (s *Service) Submit(ctx context.Context, certUUID, caUUID, ctServer, submittedBy string, certDER []byte, chainDER [][]byte) (*CTEntry, error) {
	if certUUID == "" || ctServer == "" {
		return nil, fmt.Errorf("证书 UUID 和 CT 服务器地址不能为空")
	}
	if len(certDER) == 0 {
		return nil, fmt.Errorf("证书 DER 数据不能为空")
	}

	// 计算证书哈希
	hash := sha256.Sum256(certDER)
	certHash := hex.EncodeToString(hash[:])

	entry := &CTEntry{
		UUID:        uuid.New().String(),
		CertUUID:    certUUID,
		CAUUID:      caUUID,
		CertHash:    certHash,
		CTServer:    ctServer,
		Status:      "pending",
		SubmittedBy: submittedBy,
		CreatedAt:   time.Now(),
	}

	// 调用 CT 日志服务器的 add-chain 接口
	sctResp, sctRaw, err := s.postAddChain(ctx, ctServer, certDER, chainDER)
	now := time.Now()
	entry.SubmittedAt = &now
	if err != nil {
		entry.Status = "failed"
		entry.SCTData = []byte(fmt.Sprintf(`{"error":%q}`, err.Error()))
	} else {
		entry.Status = "submitted"
		entry.SCTData = sctRaw
		_ = sctResp // 保留以便未来扩展 SCT 版本校验
	}

	_, dbErr := s.db.ExecContext(ctx,
		`INSERT INTO ct_entries (uuid, cert_uuid, ca_uuid, cert_hash, ct_server, sct_data, status, submitted_by, submitted_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.UUID, entry.CertUUID, entry.CAUUID, entry.CertHash, entry.CTServer,
		entry.SCTData, entry.Status, entry.SubmittedBy, entry.SubmittedAt, entry.CreatedAt,
	)
	if dbErr != nil {
		return nil, fmt.Errorf("保存 CT 记录失败: %w", dbErr)
	}
	// 提交失败也返回 entry 以便调用方感知（不返回 error，因已持久化 failed 状态）
	if err != nil {
		return entry, fmt.Errorf("CT 提交失败（记录已保存为 failed）: %w", err)
	}
	return entry, nil
}

// postAddChain 发起 RFC 6962 add-chain HTTP POST 请求。
// 返回解析后的 SCT 响应结构和原始响应 JSON 字节，用于存入数据库。
func (s *Service) postAddChain(ctx context.Context, ctServer string, certDER []byte, chainDER [][]byte) (*SCTResponse, []byte, error) {
	// 构造 {"chain":["<b64>", ...]}
	b64Chain := make([]string, 0, 1+len(chainDER))
	b64Chain = append(b64Chain, base64.StdEncoding.EncodeToString(certDER))
	for _, der := range chainDER {
		if len(der) > 0 {
			b64Chain = append(b64Chain, base64.StdEncoding.EncodeToString(der))
		}
	}
	body, err := json.Marshal(map[string][]string{"chain": b64Chain})
	if err != nil {
		return nil, nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	// 组装完整 URL（ctServer 可能带或不带路径后缀）
	endpoint := strings.TrimRight(ctServer, "/") + "/ct/v1/add-chain"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("构造 HTTP 请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("调用 CT 服务器失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("CT 服务器返回错误: HTTP %d, %s", resp.StatusCode, string(respBody))
	}

	var sct SCTResponse
	if err := json.Unmarshal(respBody, &sct); err != nil {
		return nil, nil, fmt.Errorf("解析 SCT 响应失败: %w", err)
	}
	if sct.ID == "" || sct.Signature == "" {
		return nil, nil, fmt.Errorf("SCT 响应缺少 id 或 signature 字段")
	}
	return &sct, respBody, nil
}

// List 查询 CT 提交记录列表。
func (s *Service) List(ctx context.Context, certUUID string, page, pageSize int) ([]*CTEntry, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	query := `SELECT COUNT(*) FROM ct_entries`
	countArgs := []interface{}{}
	if certUUID != "" {
		query += ` WHERE cert_uuid = ?`
		countArgs = append(countArgs, certUUID)
	}

	var total int
	if err := s.db.QueryRowContext(ctx, query, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	selectQuery := `SELECT uuid, cert_uuid, ca_uuid, cert_hash, ct_server, sct_data, status, submitted_by, submitted_at, created_at
		 FROM ct_entries`
	selectArgs := []interface{}{}
	if certUUID != "" {
		selectQuery += ` WHERE cert_uuid = ?`
		selectArgs = append(selectArgs, certUUID)
	}
	selectQuery += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	selectArgs = append(selectArgs, pageSize, offset)

	rows, err := s.db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*CTEntry
	for rows.Next() {
		e := &CTEntry{}
		var submittedAt sql.NullTime
		if err := rows.Scan(&e.UUID, &e.CertUUID, &e.CAUUID, &e.CertHash, &e.CTServer,
			&e.SCTData, &e.Status, &e.SubmittedBy, &submittedAt, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		if submittedAt.Valid {
			e.SubmittedAt = &submittedAt.Time
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

// GetByUUID 按 UUID 查询 CT 记录。
func (s *Service) GetByUUID(ctx context.Context, entryUUID string) (*CTEntry, error) {
	e := &CTEntry{}
	var submittedAt sql.NullTime
	err := s.db.QueryRowContext(ctx,
		`SELECT uuid, cert_uuid, ca_uuid, cert_hash, ct_server, sct_data, status, submitted_by, submitted_at, created_at
		 FROM ct_entries WHERE uuid = ?`, entryUUID,
	).Scan(&e.UUID, &e.CertUUID, &e.CAUUID, &e.CertHash, &e.CTServer,
		&e.SCTData, &e.Status, &e.SubmittedBy, &submittedAt, &e.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("CT 记录不存在: %s", entryUUID)
	}
	if submittedAt.Valid {
		e.SubmittedAt = &submittedAt.Time
	}
	return e, err
}

// Delete 删除 CT 记录。
func (s *Service) Delete(ctx context.Context, entryUUID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ct_entries WHERE uuid = ?`, entryUUID)
	return err
}

// QueryByCertHash 按证书哈希查询 CT 记录（供外部查询）。
func (s *Service) QueryByCertHash(ctx context.Context, certHash string) ([]*CTEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, cert_uuid, ca_uuid, cert_hash, ct_server, sct_data, status, submitted_by, submitted_at, created_at
		 FROM ct_entries WHERE cert_hash = ? AND status = 'submitted' ORDER BY created_at DESC`, certHash,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*CTEntry
	for rows.Next() {
		e := &CTEntry{}
		var submittedAt sql.NullTime
		if err := rows.Scan(&e.UUID, &e.CertUUID, &e.CAUUID, &e.CertHash, &e.CTServer,
			&e.SCTData, &e.Status, &e.SubmittedBy, &submittedAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		if submittedAt.Valid {
			e.SubmittedAt = &submittedAt.Time
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
