// Package cps 管理证书策略（CP）/ 证书实践声明（CPS）等公开策略页面。
//
// 每个策略是一个独立接口：GET /policy/{path}，按 content_type 以 Markdown 或 HTML 返回。
// 颁发模板的证书扩展（CertificatePolicies / CPS URI）可引用这些地址。
package cps

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/internal/storage"
	"github.com/google/uuid"
)

// Policy 是一份策略文档。
type Policy struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`         // 公开地址 /policy/{path}
	ContentType string    `json:"content_type"` // markdown / html
	Content     string    `json:"content,omitempty"`
	Version     string    `json:"version"`
	Enabled     bool      `json:"enabled"`
	IsPublic    bool      `json:"is_public"` // 是否在官网「信任中心」列出
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Service 是策略页面服务。
type Service struct{ db *storage.DB }

// NewService 创建策略页面服务。
func NewService(db *storage.DB) *Service { return &Service{db: db} }

var pathRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,94}$`)

const columns = `uuid, name, path, content_type, content, version, enabled, is_public, created_at, updated_at`

func scan(scan func(dest ...interface{}) error) (*Policy, error) {
	p := &Policy{}
	var enabled, public int
	if err := scan(&p.UUID, &p.Name, &p.Path, &p.ContentType, &p.Content, &p.Version, &enabled, &public,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	p.Enabled, p.IsPublic = enabled == 1, public == 1
	return p, nil
}

// List 查询策略；withContent=false 时不返回正文（列表视图）。
func (s *Service) List(ctx context.Context, publicOnly, withContent bool) ([]*Policy, error) {
	q := `SELECT ` + columns + ` FROM cert_policies`
	if publicOnly {
		q += ` WHERE enabled = 1 AND is_public = 1`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Policy{}
	for rows.Next() {
		p, err := scan(rows.Scan)
		if err != nil {
			return nil, err
		}
		if !withContent {
			p.Content = ""
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// Get 按 UUID 查询。
func (s *Service) Get(ctx context.Context, id string) (*Policy, error) {
	p, err := scan(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM cert_policies WHERE uuid = ?`, id).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("策略不存在")
	}
	return p, err
}

// GetByPath 按公开路径查询（仅启用的策略）。
func (s *Service) GetByPath(ctx context.Context, path string) (*Policy, error) {
	p, err := scan(s.db.QueryRowContext(ctx,
		`SELECT `+columns+` FROM cert_policies WHERE path = ? AND enabled = 1`, strings.ToLower(path)).Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("策略不存在")
	}
	return p, err
}

// Save 创建或更新策略。
func (s *Service) Save(ctx context.Context, p *Policy) error {
	p.Name = strings.TrimSpace(p.Name)
	p.Path = strings.ToLower(strings.TrimSpace(p.Path))
	if p.Name == "" {
		return fmt.Errorf("请填写策略名称")
	}
	if !pathRe.MatchString(p.Path) {
		return fmt.Errorf("路径只能包含小写字母、数字、点、下划线和短横线")
	}
	if p.ContentType != "html" {
		p.ContentType = "markdown"
	}
	if len(p.Content) > 2<<20 {
		return fmt.Errorf("正文不能超过 2MB")
	}
	now := time.Now()
	var err error
	if p.UUID == "" {
		p.UUID = uuid.New().String()
		p.CreatedAt = now
		_, err = s.db.ExecContext(ctx, `INSERT INTO cert_policies (`+columns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			p.UUID, p.Name, p.Path, p.ContentType, p.Content, p.Version,
			storage.BoolToInt(p.Enabled), storage.BoolToInt(p.IsPublic), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE cert_policies SET name = ?, path = ?, content_type = ?, content = ?, version = ?, enabled = ?, is_public = ?, updated_at = ?
			 WHERE uuid = ?`,
			p.Name, p.Path, p.ContentType, p.Content, p.Version,
			storage.BoolToInt(p.Enabled), storage.BoolToInt(p.IsPublic), now, p.UUID)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("路径 %s 已被占用", p.Path)
	}
	p.UpdatedAt = now
	return err
}

// Delete 删除策略。
func (s *Service) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cert_policies WHERE uuid = ?`, id)
	return err
}
