// Package revocation 提供证书吊销服务（CRL/OCSP/CAIssuer）。
package revocation

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
)

// ServiceConfig 是吊销服务配置模型。
type ServiceConfig struct {
	UUID        string `json:"uuid"`
	CAUUID      string `json:"ca_uuid"`
	ServiceType string `json:"service_type"` // crl/ocsp/caissuer
	Path        string `json:"path"`         // 服务路径
	Enabled     bool   `json:"enabled"`
	CRLInterval int    `json:"crl_interval"` // CRL 更新间隔（分钟）
}

// OCSPStatus 是 OCSP 查询结果。
type OCSPStatus struct {
	SerialNumber string     `json:"serial_number"`
	Status       string     `json:"status"` // good/revoked/unknown
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Reason       int        `json:"reason,omitempty"`
}

// crlScheduler 描述单个 CA 的 CRL 刷新调度器。
type crlScheduler struct {
	cancel   context.CancelFunc
	interval int // 当前调度间隔（分钟）
}

// Service 是吊销服务管理。
type Service struct {
	db           *storage.DB
	caSvc        *ca.Service
	crlCache     map[string][]byte // caUUID -> CRL DER
	crlCacheMu   sync.RWMutex
	schedulers   map[string]*crlScheduler // caUUID -> 独立调度器
	schedulersMu sync.Mutex
	signerLoader SignerLoader // OCSP 响应服务使用平台证书签名时的加载器
}

// parseCertPEM 解析 PEM 证书。
func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("证书 PEM 格式错误")
	}
	return x509.ParseCertificate(block.Bytes)
}

// NewService 创建吊销服务。
func NewService(db *storage.DB, caSvc *ca.Service) *Service {
	return &Service{
		db:         db,
		caSvc:      caSvc,
		crlCache:   make(map[string][]byte),
		schedulers: make(map[string]*crlScheduler),
	}
}

// CreateServiceConfig 创建吊销服务配置。
func (s *Service) CreateServiceConfig(ctx context.Context, cfg *ServiceConfig) error {
	if cfg.Path == "" {
		return fmt.Errorf("服务路径不能为空")
	}
	if cfg.CRLInterval <= 0 {
		cfg.CRLInterval = 60 // 默认 60 分钟
	}
	cfg.UUID = uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO revocation_services (uuid, ca_uuid, service_type, path, enabled, crl_interval)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		cfg.UUID, cfg.CAUUID, cfg.ServiceType, cfg.Path,
		boolToInt(cfg.Enabled), cfg.CRLInterval,
	)
	return err
}

// ListServiceConfigs 查询吊销服务配置列表。
func (s *Service) ListServiceConfigs(ctx context.Context, caUUID string) ([]*ServiceConfig, error) {
	query := `SELECT uuid, ca_uuid, service_type, path, enabled, crl_interval
		 FROM revocation_services`
	var args []interface{}
	if caUUID != "" {
		query += ` WHERE ca_uuid = ?`
		args = append(args, caUUID)
	}
	query += ` ORDER BY service_type`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*ServiceConfig
	for rows.Next() {
		c := &ServiceConfig{}
		var enabled int
		if err := rows.Scan(&c.UUID, &c.CAUUID, &c.ServiceType,
			&c.Path, &enabled, &c.CRLInterval); err != nil {
			return nil, err
		}
		c.Enabled = enabled == 1
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

// DeleteServiceConfig 删除吊销服务配置。
func (s *Service) DeleteServiceConfig(ctx context.Context, cfgUUID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM revocation_services WHERE uuid = ?`, cfgUUID,
	)
	return err
}

// GetCRL 获取 CA 的 CRL（优先从缓存获取）。
func (s *Service) GetCRL(ctx context.Context, caUUID string) ([]byte, error) {
	s.crlCacheMu.RLock()
	if crl, ok := s.crlCache[caUUID]; ok {
		s.crlCacheMu.RUnlock()
		return crl, nil
	}
	s.crlCacheMu.RUnlock()

	return s.RefreshCRL(ctx, caUUID)
}

// RefreshCRL 刷新 CA 的 CRL 缓存。
func (s *Service) RefreshCRL(ctx context.Context, caUUID string) ([]byte, error) {
	crl, err := s.caSvc.GenerateCRL(ctx, caUUID)
	if err != nil {
		return nil, err
	}

	s.crlCacheMu.Lock()
	s.crlCache[caUUID] = crl
	s.crlCacheMu.Unlock()

	return crl, nil
}

// QueryOCSPStatus 查询证书的 OCSP 状态。
func (s *Service) QueryOCSPStatus(ctx context.Context, caUUID, serialNumber string) (*OCSPStatus, error) {
	status := &OCSPStatus{
		SerialNumber: serialNumber,
		Status:       "good",
	}

	var revokedAt sql.NullTime
	var reason int
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at, reason FROM revoked_certs
		 WHERE ca_uuid = ? AND serial_number = ?`,
		caUUID, serialNumber,
	).Scan(&revokedAt, &reason)

	if err == sql.ErrNoRows {
		return status, nil // 未吊销
	}
	if err != nil {
		return nil, fmt.Errorf("查询吊销状态失败: %w", err)
	}

	status.Status = "revoked"
	if revokedAt.Valid {
		status.RevokedAt = &revokedAt.Time
	}
	status.Reason = reason
	return status, nil
}

// GetCAIssuerCert 获取 CA 证书 PEM（用于 AIA CAIssuer）。
func (s *Service) GetCAIssuerCert(ctx context.Context, caUUID string) (string, error) {
	caObj, err := s.caSvc.GetByUUID(ctx, caUUID)
	if err != nil {
		return "", err
	}
	return caObj.CertPEM, nil
}

// StartCRLRefreshLoop 启动 CRL 调度管理器。
// 架构：
//  1. 主循环每 60 秒扫描 revocation_services 表，同步各 CA 的独立调度器；
//  2. 每个启用的 CRL 配置对应一个独立 goroutine，按自身 CRLInterval（分钟）刷新；
//  3. 配置新增/删除/间隔变更时，对应调度器会被启动/停止/重建；
//  4. 主 ctx 取消时，所有子调度器级联退出。
func (s *Service) StartCRLRefreshLoop(ctx context.Context) {
	go func() {
		// 启动立即同步一次
		s.syncSchedulers(ctx)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.stopAllSchedulers()
				return
			case <-ticker.C:
				s.syncSchedulers(ctx)
			}
		}
	}()
}

// syncSchedulers 按 revocation_services 表状态同步各 CA 的独立调度器。
// - 配置新增：启动调度器
// - 配置禁用/删除：停止调度器
// - CRLInterval 变更：停止旧调度器、重建新调度器
func (s *Service) syncSchedulers(ctx context.Context) {
	configs, err := s.ListServiceConfigs(ctx, "")
	if err != nil {
		slog.Error("加载吊销服务配置失败", "error", err)
		return
	}

	// 1. 收集当前启用的 CRL 配置（caUUID -> 最小间隔）
	// 若同一 CA 有多条 CRL 配置，取最小间隔作为调度周期，保证按最频繁的配置刷新
	desired := make(map[string]int)
	for _, cfg := range configs {
		if cfg.ServiceType != "crl" || !cfg.Enabled {
			continue
		}
		interval := cfg.CRLInterval
		if interval <= 0 {
			interval = 60
		}
		if prev, ok := desired[cfg.CAUUID]; !ok || interval < prev {
			desired[cfg.CAUUID] = interval
		}
	}

	s.schedulersMu.Lock()
	defer s.schedulersMu.Unlock()

	// 2. 停止已不存在或间隔变更的调度器
	for caUUID, sched := range s.schedulers {
		newInterval, keep := desired[caUUID]
		if !keep || sched.interval != newInterval {
			sched.cancel()
			delete(s.schedulers, caUUID)
			slog.Info("CRL 调度器已停止", "ca_uuid", caUUID, "reason", ternary(!keep, "配置已移除", "间隔变更"))
		}
	}

	// 3. 启动新的调度器
	for caUUID, interval := range desired {
		if _, exists := s.schedulers[caUUID]; exists {
			continue
		}
		schedCtx, cancel := context.WithCancel(ctx)
		s.schedulers[caUUID] = &crlScheduler{
			cancel:   cancel,
			interval: interval,
		}
		go s.runCRLScheduler(schedCtx, caUUID, interval)
		slog.Info("CRL 调度器已启动", "ca_uuid", caUUID, "interval_min", interval)
	}
}

// runCRLScheduler 单个 CA 的 CRL 刷新调度器 goroutine。
// 启动后立即刷新一次，随后按 intervalMinutes 分钟周期刷新，直至 ctx 被取消。
func (s *Service) runCRLScheduler(ctx context.Context, caUUID string, intervalMinutes int) {
	// 立即刷新一次
	if _, err := s.RefreshCRL(ctx, caUUID); err != nil {
		slog.Error("CRL 初始刷新失败", "ca_uuid", caUUID, "error", err)
	} else {
		slog.Debug("CRL 已刷新", "ca_uuid", caUUID)
	}

	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.RefreshCRL(ctx, caUUID); err != nil {
				slog.Error("CRL 定时刷新失败", "ca_uuid", caUUID, "error", err)
				continue
			}
			slog.Debug("CRL 已刷新", "ca_uuid", caUUID)
		}
	}
}

// stopAllSchedulers 停止所有子调度器（主 loop 退出时调用）。
func (s *Service) stopAllSchedulers() {
	s.schedulersMu.Lock()
	defer s.schedulersMu.Unlock()
	for caUUID, sched := range s.schedulers {
		sched.cancel()
		delete(s.schedulers, caUUID)
	}
}

// ternary 简易三元运算（仅用于日志）。
func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateOCSPResponseDER 接收 RFC 6960 OCSP 请求 DER，查询状态并生成已签名的 OCSP 响应 DER。
// 适配 POST application/ocsp-request 和 GET base64 两种传输方式。
// 若请求包含多个 SingleRequest，仅响应第一个（符合 RFC 6960 多数实现惯例）。
func (s *Service) CreateOCSPResponseDER(ctx context.Context, caUUID string, reqDER []byte) ([]byte, error) {
	ocspReq, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("解析 OCSP 请求失败: %w", err)
	}

	// 获取 CA 证书和私钥（用于签名响应）
	caCert, caSigner, err := s.caSvc.GetCAKeypair(ctx, caUUID)
	if err != nil {
		return nil, fmt.Errorf("获取 CA 密钥对失败: %w", err)
	}

	// 按十六进制序列号查询吊销状态（与 revoked_certs 表存储格式一致）
	serialHex := strings.ToUpper(hex.EncodeToString(ocspReq.SerialNumber.Bytes()))
	// 兼容短前导零：先尝试十进制再试十六进制
	serialDec := ocspReq.SerialNumber.String()

	now := time.Now()
	resp := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: new(big.Int).Set(ocspReq.SerialNumber),
		ThisUpdate:   now,
		NextUpdate:   now.Add(1 * time.Hour),
	}

	// revoked_certs 只有 serial_number 列（无 serial_hex），按十六进制与
	// 十进制两种历史写入格式分别匹配。
	var revokedAt sql.NullTime
	var reason int
	err = s.db.QueryRowContext(ctx,
		`SELECT revoked_at, reason FROM revoked_certs
		 WHERE ca_uuid = ? AND (serial_number = ? OR serial_number = ?)`,
		caUUID, serialHex, serialDec,
	).Scan(&revokedAt, &reason)

	switch {
	case err == sql.ErrNoRows:
		resp.Status = ocsp.Good
	case err != nil:
		return nil, fmt.Errorf("查询吊销状态失败: %w", err)
	default:
		resp.Status = ocsp.Revoked
		if revokedAt.Valid {
			resp.RevokedAt = revokedAt.Time
		} else {
			resp.RevokedAt = now
		}
		resp.RevocationReason = reason
	}

	// CreateResponse(issuer, responder, template, signer)
	// responder 使用 CA 证书本身（Responder ID = CA），符合 RFC 6960 B 模式。
	// SM2 CA 的公钥标准库不认识，需要走国密专用编码（见 ocsp_gm.go）。
	var der []byte
	if isSM2PubKey(caCert) {
		der, err = CreateOCSPResponseSM2(caCert, caCert, resp, caSigner.(crypto.Signer))
	} else {
		der, err = ocsp.CreateResponse(caCert, caCert, resp, caSigner.(crypto.Signer))
	}
	if err != nil {
		return nil, fmt.Errorf("签名 OCSP 响应失败: %w", err)
	}
	return der, nil
}
