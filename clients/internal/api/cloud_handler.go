package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/globaltrusts/client-card/internal/card/cloud"
	"github.com/globaltrusts/client-card/internal/card/local"
	"github.com/globaltrusts/client-card/internal/storage"
)

// ---- 同步状态（进程内全局、线程安全）----

// syncStatus 表示一次云端同步的执行结果摘要。
type syncStatus struct {
	LastSync     *time.Time `json:"last_sync,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	SyncedCards  int        `json:"synced_cards"`
	SyncedCerts  int        `json:"synced_certs"`
	NewCards     int        `json:"new_cards"`
	NewCerts     int        `json:"new_certs"`
	DeletedCards int        `json:"deleted_cards"`
	DurationMS   int64      `json:"duration_ms"`
}

var (
	cloudSyncMu     sync.RWMutex
	cloudSyncStatus syncStatus
)

// readSyncStatus 安全读取最近一次同步状态快照。
func readSyncStatus() syncStatus {
	cloudSyncMu.RLock()
	defer cloudSyncMu.RUnlock()
	return cloudSyncStatus
}

// writeSyncStatus 原子写入同步状态。
func writeSyncStatus(s syncStatus) {
	cloudSyncMu.Lock()
	cloudSyncStatus = s
	cloudSyncMu.Unlock()
}

// ---- 自动定时同步 ----

// StartAutoSync 根据配置启动自动定时云端同步后台任务。
// 调用方需传入可取消的 context，用于在进程退出时优雅停止。
// 若 AutoSync 未启用或间隔 <= 0，则不启动。
func (s *Server) StartAutoSync(ctx context.Context) {
	fullCfgMu.RLock()
	cfg := fullCfg
	fullCfgMu.RUnlock()

	if cfg == nil || !cfg.Client.AutoSync {
		slog.Info("云端自动同步未启用")
		return
	}

	intervalMin := cfg.Client.SyncIntervalMinutes
	if intervalMin <= 0 {
		intervalMin = 5 // 默认 5 分钟
	}
	interval := time.Duration(intervalMin) * time.Minute

	slog.Info("云端自动同步已启动", "interval", interval)

	go func() {
		// 启动后立即执行一次同步
		stat := s.doCloudSync(ctx)
		slog.Info("自动同步完成（首次）",
			"synced_cards", stat.SyncedCards,
			"new_certs", stat.NewCerts,
			"duration_ms", stat.DurationMS,
		)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				slog.Info("云端自动同步已停止")
				return
			case <-ticker.C:
				// 每次执行前重新读取配置，支持热更新开关
				fullCfgMu.RLock()
				latestCfg := fullCfg
				fullCfgMu.RUnlock()
				if latestCfg != nil && !latestCfg.Client.AutoSync {
					slog.Debug("自动同步已被用户关闭，跳过本轮")
					continue
				}

				stat := s.doCloudSync(ctx)
				if stat.LastError != "" {
					slog.Warn("自动同步出现错误", "error", stat.LastError)
				} else {
					slog.Debug("自动同步完成",
						"synced_cards", stat.SyncedCards,
						"new_certs", stat.NewCerts,
						"duration_ms", stat.DurationMS,
					)
				}
			}
		}
	}()
}

// ---- 同步核心逻辑 ----

// doCloudSync 执行一次全量云端同步（不依赖 HTTP 请求）。
// 遍历所有 Cloud 类型卡片，拉取云端证书列表并增量落库。
func (s *Server) doCloudSync(ctx context.Context) syncStatus {
	start := time.Now()

	cards, err := s.cardRepo.ListAll(ctx)
	if err != nil {
		stat := syncStatus{LastError: "查询卡片失败: " + err.Error()}
		now := time.Now()
		stat.LastSync = &now
		stat.DurationMS = time.Since(start).Milliseconds()
		writeSyncStatus(stat)
		return stat
	}

	stat := syncStatus{}
	anyChange := false

	// 按 (cloud_url, user_uuid) 分组避免重复登录同一云端
	type ctxKey struct {
		URL      string
		UserUUID string
	}
	cache := make(map[ctxKey]*cloud.Client)

	for _, c := range cards {
		if c.SlotType != storage.SlotTypeCloud || c.CloudURL == "" {
			continue
		}

		user, err := s.userRepo.GetByUUID(ctx, c.UserUUID)
		if err != nil || user == nil || len(user.AuthToken) == 0 {
			stat.LastError = fmt.Sprintf("卡片 %s 对应用户缺少云端 token", c.CardName)
			continue
		}

		key := ctxKey{URL: c.CloudURL, UserUUID: c.UserUUID}
		client, ok := cache[key]
		if !ok {
			client, err = cloud.NewClient(c.CloudURL, true)
			if err != nil {
				stat.LastError = "创建云端客户端失败: " + err.Error()
				continue
			}
			client.SetToken(string(user.AuthToken))
			cache[key] = client
		}

		synced, added := s.syncOneCloudCard(ctx, client, c)
		stat.SyncedCerts += synced
		stat.NewCerts += added
		if added > 0 {
			anyChange = true
		}
		stat.SyncedCards++
	}

	now := time.Now()
	stat.LastSync = &now
	stat.DurationMS = time.Since(start).Milliseconds()
	writeSyncStatus(stat)

	if anyChange {
		s.notifySlotChanged("sync")
	}

	return stat
}

// ---- HTTP Handlers ----

// handleCloudSync POST /api/cloud/sync
// 触发一次全量云端同步：把每个本地 Cloud 卡片对应的云端卡片列表与证书列表
// 落库到 cards / certificates 表（公开部分），并广播 slot_changed 事件。
func (s *Server) handleCloudSync(w http.ResponseWriter, r *http.Request) {
	stat := s.doCloudSync(r.Context())
	if stat.LastError != "" {
		// 有部分错误但不完全失败，仍返回 200 + 错误信息
		slog.Warn("手动同步出现部分错误", "error", stat.LastError)
	}
	writeOK(w, stat)
}

// syncOneCloudCard 同步单张云端卡片的证书列表到本地 certificates 表。
// 返回 (拉取到的证书数, 新增的证书数)。
func (s *Server) syncOneCloudCard(ctx context.Context, client *cloud.Client, c *storage.Card) (int, int) {
	if c.CloudCardUUID == "" {
		return 0, 0
	}
	cloudCerts, err := client.ListCerts(ctx, c.CloudCardUUID)
	if err != nil {
		slog.Warn("拉取云端证书失败", "card", c.CardName, "error", err)
		return 0, 0
	}

	// 读取本地已有证书用于去重
	existing, err := s.certRepo.ListByCard(ctx, c.UUID)
	if err != nil {
		slog.Warn("读取本地证书失败", "error", err)
		return len(cloudCerts), 0
	}
	have := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		have[e.UUID] = struct{}{}
	}

	added := 0
	for _, cc := range cloudCerts {
		if _, ok := have[cc.UUID]; ok {
			continue // 已存在：跳过（后续可按需实现 Update）
		}
		cert := &storage.Certificate{
			UUID:        cc.UUID,
			SlotType:    storage.SlotTypeCloud,
			CardUUID:    c.UUID,
			CertType:    storage.CertType(nonEmpty(cc.CertType, string(storage.CertTypeX509))),
			KeyType:     cc.KeyType,
			CertContent: cc.CertContent,
			Remark:      cc.Remark,
		}
		if err := s.certRepo.Create(ctx, cert); err != nil {
			slog.Warn("证书落库失败", "cert_uuid", cc.UUID, "error", err)
			continue
		}
		added++
	}
	return len(cloudCerts), added
}

// handleCloudStatus GET /api/cloud/status
// 返回最近一次云端同步的状态。
func (s *Server) handleCloudStatus(w http.ResponseWriter, r *http.Request) {
	writeOK(w, readSyncStatus())
}

// nonEmpty 返回 a，若 a 为空则返回 b。
func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}

// ---- 云端证书下发 ----

// deliverRequest 是 /api/cloud/deliver 的请求体。
// Target：database 表示下发到本地 pki_certs 表；card 表示下发到本地/TPM2 智能卡。
type deliverRequest struct {
	CertUUID     string `json:"cert_uuid"`
	SourceCloud  string `json:"source_cloud_url,omitempty"`  // 可选，明确来源云端 URL；不填则从 CardUUID 推断
	SourceCard   string `json:"source_card_uuid,omitempty"`  // 可选，本地云卡 UUID（用于拿 AuthToken）
	Target       string `json:"target"`                      // "database" | "card"
	TargetCard   string `json:"target_card_uuid,omitempty"`  // Target=card 时必填（目的本地卡）
	CardPassword string `json:"card_password,omitempty"`     // Target=card 时必填
	Remark       string `json:"remark,omitempty"`
}

// deliverResponse 是下发成功的响应体。
type deliverResponse struct {
	Target     string `json:"target"`
	UUID       string `json:"uuid"`                // 下发后本地新记录的 UUID（pki_certs.uuid 或 certificates.uuid）
	CommonName string `json:"common_name,omitempty"`
	CardUUID   string `json:"card_uuid,omitempty"` // Target=card 时填
}

// handleCloudDeliver POST /api/cloud/deliver
// 从云端拉取证书+私钥，根据 target 存入本地数据库或导入到本地智能卡。
func (s *Server) handleCloudDeliver(w http.ResponseWriter, r *http.Request) {
	var req deliverRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if strings.TrimSpace(req.CertUUID) == "" {
		writeError(w, http.StatusBadRequest, "cert_uuid 不能为空")
		return
	}
	if req.Target != "database" && req.Target != "card" {
		writeError(w, http.StatusBadRequest, "target 必须为 database 或 card")
		return
	}

	// 1. 确认来源云端信息（cloud_url + auth_token）
	cloudURL, authToken, err := s.resolveCloudSource(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 2. 调用云端下载证书+私钥
	client, err := cloud.NewClient(cloudURL, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "创建云端客户端失败: "+err.Error())
		return
	}
	client.SetToken(authToken)

	delivered, err := client.DownloadCertWithKey(r.Context(), req.CertUUID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "拉取云端证书失败: "+err.Error())
		return
	}
	if delivered == nil || strings.TrimSpace(delivered.CertPEM) == "" || strings.TrimSpace(delivered.KeyPEM) == "" {
		writeError(w, http.StatusBadRequest, "云端未返回完整的证书与私钥")
		return
	}

	// 3. 按 target 分别处理
	var resp *deliverResponse
	switch req.Target {
	case "database":
		resp, err = s.deliverToDatabase(r.Context(), &req, delivered)
	case "card":
		if req.TargetCard == "" || req.CardPassword == "" {
			writeError(w, http.StatusBadRequest, "target=card 时 target_card_uuid 与 card_password 不能为空")
			return
		}
		resp, err = s.deliverToCard(r.Context(), &req, delivered)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 4. 审计日志（失败不阻断主流程）
	s.writeDeliverAudit(r.Context(), &req, resp)

	writeJSON(w, http.StatusCreated, Response{Code: 0, Message: "ok", Data: resp})
}

// resolveCloudSource 从请求体或数据库中推断云端 URL 与 AuthToken。
// 优先顺序：(SourceCloud + SourceCard 关联用户) > SourceCard 查本地 card 推断。
func (s *Server) resolveCloudSource(ctx context.Context, req *deliverRequest) (string, string, error) {
	// 如果显式提供了 SourceCard，从本地卡片记录取 CloudURL 与用户 Token
	if req.SourceCard != "" {
		card, err := s.cardRepo.GetByUUID(ctx, req.SourceCard)
		if err != nil {
			return "", "", fmt.Errorf("查询来源卡片失败: %w", err)
		}
		if card == nil {
			return "", "", fmt.Errorf("来源卡片不存在: %s", req.SourceCard)
		}
		user, err := s.userRepo.GetByUUID(ctx, card.UserUUID)
		if err != nil || user == nil {
			return "", "", fmt.Errorf("来源卡片对应用户缺失")
		}
		if len(user.AuthToken) == 0 {
			return "", "", fmt.Errorf("来源用户未登录云端")
		}
		cloudURL := req.SourceCloud
		if cloudURL == "" {
			cloudURL = card.CloudURL
		}
		if cloudURL == "" {
			cloudURL = user.CloudURL
		}
		if cloudURL == "" {
			return "", "", fmt.Errorf("缺少 cloud_url")
		}
		return cloudURL, string(user.AuthToken), nil
	}

	// 否则尝试用 SourceCloud 找匹配的云端账号
	if req.SourceCloud == "" {
		return "", "", fmt.Errorf("source_cloud_url 或 source_card_uuid 至少需提供一个")
	}
	users, err := s.userRepo.List(ctx)
	if err != nil {
		return "", "", fmt.Errorf("查询用户失败: %w", err)
	}
	for _, u := range users {
		if u.UserType == storage.UserTypeCloud && u.CloudURL == req.SourceCloud && len(u.AuthToken) > 0 {
			// List 方法未返回 AuthToken，需要再拉一次完整记录
			full, err := s.userRepo.GetByUUID(ctx, u.UUID)
			if err == nil && full != nil && len(full.AuthToken) > 0 {
				return req.SourceCloud, string(full.AuthToken), nil
			}
		}
	}
	// 兜底：直接遍历逐个查（因为 List 未返回 AuthToken 字段）
	for _, u := range users {
		if u.UserType != storage.UserTypeCloud || u.CloudURL != req.SourceCloud {
			continue
		}
		full, err := s.userRepo.GetByUUID(ctx, u.UUID)
		if err == nil && full != nil && len(full.AuthToken) > 0 {
			return req.SourceCloud, string(full.AuthToken), nil
		}
	}
	return "", "", fmt.Errorf("未找到与 %s 关联的已登录云端账号", req.SourceCloud)
}

// deliverToDatabase 下发云端证书到本地 pki_certs 表。
// 实现采用"私钥 PEM → AES-256-GCM 加密后直接存 private_key_enc"的简化策略，
// 加密密钥为 cfg.DataDir/.deliver.key（首次自动生成并 chmod 0600）。
func (s *Server) deliverToDatabase(ctx context.Context, req *deliverRequest, d *cloud.DeliveredCert) (*deliverResponse, error) {
	// 解析证书基础信息（CN/有效期/序列号）
	cn, sn, nb, na, err := parseCertBasics(d.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析云端证书失败: %w", err)
	}

	encKey, err := loadOrCreateDeliverKey(s.cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("加载证书加密密钥失败: %w", err)
	}
	encryptedKeyPEM, err := aesEncrypt(encKey, []byte(d.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("加密私钥失败: %w", err)
	}

	rec := &storage.PKICert{
		CommonName:    cn,
		SerialNumber:  sn,
		KeyType:       nonEmpty(d.Algorithm, "unknown"),
		KeyStorage:    storage.KeyStorageDatabase,
		CertPEM:       d.CertPEM,
		HasPrivateKey: true,
		PrivateKeyEnc: encryptedKeyPEM,
		NotBefore:     nb,
		NotAfter:      na,
		Remark:        nonEmpty(req.Remark, "云端下发"),
	}
	if err := s.pkiCertRepo.Create(ctx, rec); err != nil {
		return nil, fmt.Errorf("保存下发证书失败: %w", err)
	}
	return &deliverResponse{Target: "database", UUID: rec.UUID, CommonName: cn}, nil
}

// deliverToCard 下发云端证书到本地/TPM2 智能卡。
// 流程：解锁卡片主密钥 → 解析私钥 DER → 用 KeyManager.ImportPrivateKey 存入 → 同时 ImportCertificate 存公开证书。
func (s *Server) deliverToCard(ctx context.Context, req *deliverRequest, d *cloud.DeliveredCert) (*deliverResponse, error) {
	card, err := s.cardRepo.GetByUUID(ctx, req.TargetCard)
	if err != nil || card == nil {
		return nil, fmt.Errorf("目标卡片不存在: %s", req.TargetCard)
	}
	if card.SlotType == storage.SlotTypeCloud {
		return nil, fmt.Errorf("不能把云端证书下发到另一张云端卡片")
	}

	// 解锁卡片主密钥
	slot := local.New(0, card, s.certRepo)
	if err := slot.Login(ctx, 1, req.CardPassword); err != nil {
		return nil, fmt.Errorf("卡片密码错误")
	}
	defer slot.Logout(ctx)

	masterKey := slot.MasterKey()
	if masterKey == nil {
		return nil, fmt.Errorf("获取主密钥失败")
	}

	// 解析 PEM
	keyDER, keyType, err := parsePrivateKeyPEM(d.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %w", err)
	}
	pubDER, err := parseCertPublicKeyPEM(d.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书公钥失败: %w", err)
	}

	km := local.NewKeyManagerWithTPM(s.certRepo, s.cardRepo, s.tpmProvider)
	result, err := km.ImportPrivateKey(ctx, local.KeyGenRequest{
		CardUUID: card.UUID,
		CertType: storage.CertTypeX509,
		KeyType:  keyType,
		Remark:   nonEmpty(req.Remark, "云端下发"),
	}, masterKey, keyDER, pubDER)
	if err != nil {
		return nil, fmt.Errorf("导入私钥到卡片失败: %w", err)
	}

	// 追加公开证书（DER）
	certDER, err := certPEMToDER(d.CertPEM)
	if err == nil {
		_, _ = km.ImportCertificate(ctx, card.UUID, certDER, "云端下发证书")
	}

	cn, _, _, _, _ := parseCertBasics(d.CertPEM)
	return &deliverResponse{
		Target:     "card",
		UUID:       result.CertUUID,
		CommonName: cn,
		CardUUID:   card.UUID,
	}, nil
}

// writeDeliverAudit 写一条下发审计日志；失败仅记录 slog 不阻断业务。
func (s *Server) writeDeliverAudit(ctx context.Context, req *deliverRequest, resp *deliverResponse) {
	if s.auditRepo == nil || resp == nil {
		return
	}
	err := s.auditRepo.Write(ctx, &storage.AuditLog{
		LogType:  "operation",
		LogLevel: "info",
		SlotType: "cloud",
		CardUUID: resp.CardUUID,
		Title:    "云端证书已下发",
		Content:  fmt.Sprintf("target=%s cert_uuid=%s local_uuid=%s cn=%s", req.Target, req.CertUUID, resp.UUID, resp.CommonName),
	})
	if err != nil {
		slog.Warn("审计日志写入失败", "error", err)
	}
}