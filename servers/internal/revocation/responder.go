package revocation

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
)

// Responder 是独立的 OCSP 响应服务配置。
//
// 一个响应服务使用唯一的签名证书，可同时响应多个 CA 签发证书的状态查询：
//   - signer_type=ca   使用某个 CA 自身签名（该 CA 以外的证书查询属于"受信任响应者"模式）；
//   - signer_type=cert 使用平台内一张证书（建议为各 CA 签发的 id-kp-OCSPSigning 委托证书，
//     或由依赖方显式信任的独立响应者证书），响应中会附带该证书。
type Responder struct {
	UUID              string    `json:"uuid"`
	Name              string    `json:"name"`
	Path              string    `json:"path"`        // 公开地址 /ocsp/r/{path}
	SignerType        string    `json:"signer_type"` // ca / cert
	SignerRef         string    `json:"signer_ref"`  // CA UUID 或证书 UUID
	CAUUIDs           []string  `json:"ca_uuids"`    // 负责响应的 CA 列表
	NextUpdateMinutes int       `json:"next_update_minutes"`
	UnknownPolicy     string    `json:"unknown_policy"` // unknown / good
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// SignerLoader 按证书 UUID 加载签名证书与私钥（由证书服务实现）。
type SignerLoader func(ctx context.Context, certUUID string) (*x509.Certificate, crypto.Signer, error)

var responderPathRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// SetSignerLoader 注入证书签名者加载器。
func (s *Service) SetSignerLoader(fn SignerLoader) { s.signerLoader = fn }

const responderColumns = `uuid, name, path, signer_type, signer_ref, ca_uuids, next_update_minutes, unknown_policy,
	enabled, created_at, updated_at`

func scanResponder(scan func(dest ...interface{}) error) (*Responder, error) {
	r := &Responder{}
	var cas string
	var enabled int
	if err := scan(&r.UUID, &r.Name, &r.Path, &r.SignerType, &r.SignerRef, &cas, &r.NextUpdateMinutes,
		&r.UnknownPolicy, &enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	r.Enabled = enabled == 1
	r.CAUUIDs = []string{}
	json.Unmarshal([]byte(cas), &r.CAUUIDs) //nolint:errcheck
	return r, nil
}

// ListResponders 查询全部 OCSP 响应服务。
func (s *Service) ListResponders(ctx context.Context) ([]*Responder, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+responderColumns+` FROM ocsp_responders ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []*Responder{}
	for rows.Next() {
		r, err := scanResponder(rows.Scan)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

// GetResponderByPath 按公开路径查询响应服务。
func (s *Service) GetResponderByPath(ctx context.Context, path string) (*Responder, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+responderColumns+` FROM ocsp_responders WHERE path = ?`, path)
	r, err := scanResponder(row.Scan)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("OCSP 服务不存在")
	}
	return r, err
}

// SaveResponder 创建或更新 OCSP 响应服务，并校验签名者可用。
func (s *Service) SaveResponder(ctx context.Context, r *Responder) error {
	r.Name = strings.TrimSpace(r.Name)
	r.Path = strings.ToLower(strings.TrimSpace(r.Path))
	if r.Name == "" {
		return fmt.Errorf("请填写服务名称")
	}
	if !responderPathRe.MatchString(r.Path) {
		return fmt.Errorf("路径只能包含小写字母、数字和短横线（1-63 位）")
	}
	if len(r.CAUUIDs) == 0 {
		return fmt.Errorf("请至少选择一个需要响应的 CA")
	}
	for _, id := range r.CAUUIDs {
		if _, err := s.caSvc.GetByUUID(ctx, id); err != nil {
			return fmt.Errorf("CA 不存在: %s", id)
		}
	}
	if r.SignerType != "ca" && r.SignerType != "cert" {
		return fmt.Errorf("签名者类型只能为 ca 或 cert")
	}
	if r.UnknownPolicy != "good" {
		r.UnknownPolicy = "unknown"
	}
	if r.NextUpdateMinutes <= 0 || r.NextUpdateMinutes > 7*24*60 {
		r.NextUpdateMinutes = 60
	}
	if _, _, err := s.loadResponderSigner(ctx, r); err != nil {
		return fmt.Errorf("签名证书不可用: %w", err)
	}

	cas, _ := json.Marshal(r.CAUUIDs)
	now := time.Now()
	var err error
	if r.UUID == "" {
		r.UUID = uuid.New().String()
		r.CreatedAt = now
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO ocsp_responders (`+responderColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.UUID, r.Name, r.Path, r.SignerType, r.SignerRef, string(cas), r.NextUpdateMinutes, r.UnknownPolicy,
			boolToInt(r.Enabled), now, now)
	} else {
		_, err = s.db.ExecContext(ctx,
			`UPDATE ocsp_responders SET name = ?, path = ?, signer_type = ?, signer_ref = ?, ca_uuids = ?,
			 next_update_minutes = ?, unknown_policy = ?, enabled = ?, updated_at = ? WHERE uuid = ?`,
			r.Name, r.Path, r.SignerType, r.SignerRef, string(cas), r.NextUpdateMinutes, r.UnknownPolicy,
			boolToInt(r.Enabled), now, r.UUID)
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("路径 %s 已被占用", r.Path)
	}
	r.UpdatedAt = now
	return err
}

// DeleteResponder 删除 OCSP 响应服务。
func (s *Service) DeleteResponder(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ocsp_responders WHERE uuid = ?`, id)
	return err
}

func (s *Service) loadResponderSigner(ctx context.Context, r *Responder) (*x509.Certificate, crypto.Signer, error) {
	switch r.SignerType {
	case "ca":
		return s.caSvc.GetCAKeypair(ctx, r.SignerRef)
	case "cert":
		if s.signerLoader == nil {
			return nil, nil, fmt.Errorf("证书签名者未启用")
		}
		cert, signer, err := s.signerLoader(ctx, r.SignerRef)
		if err != nil {
			return nil, nil, err
		}
		if time.Now().After(cert.NotAfter) {
			return nil, nil, fmt.Errorf("签名证书已过期")
		}
		return cert, signer, nil
	}
	return nil, nil, fmt.Errorf("未知签名者类型")
}

// issuerKeyHash 计算证书公钥（subjectPublicKey BIT STRING）的摘要，用于匹配 OCSP CertID。
func issuerKeyHash(cert *x509.Certificate, h crypto.Hash) ([]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	if !h.Available() {
		return nil, fmt.Errorf("不支持的摘要算法")
	}
	hh := h.New()
	hh.Write(spki.PublicKey.RightAlign())
	return hh.Sum(nil), nil
}

// Respond 处理一条 OCSP 请求并返回 DER 响应。
//
// 请求的颁发者不在本服务负责的 CA 列表中时返回 unauthorized（RFC 6960 §2.3），
// 而不是用错误的密钥签出一份依赖方无法验证的响应。
func (s *Service) Respond(ctx context.Context, r *Responder, reqDER []byte) ([]byte, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return ocsp.MalformedRequestErrorResponse, nil
	}
	if !r.Enabled {
		return ocsp.InternalErrorErrorResponse, nil
	}

	var issuer *x509.Certificate
	var caUUID string
	for _, id := range r.CAUUIDs {
		caObj, err := s.caSvc.GetByUUID(ctx, id)
		if err != nil {
			continue
		}
		cert, err := parseCertPEM(caObj.CertPEM)
		if err != nil {
			continue
		}
		kh, err := issuerKeyHash(cert, req.HashAlgorithm)
		if err == nil && hex.EncodeToString(kh) == hex.EncodeToString(req.IssuerKeyHash) {
			issuer, caUUID = cert, id
			break
		}
	}
	if issuer == nil {
		return ocsp.UnauthorizedErrorResponse, nil
	}

	signerCert, signer, err := s.loadResponderSigner(ctx, r)
	if err != nil {
		return ocsp.InternalErrorErrorResponse, nil
	}

	now := time.Now().UTC().Truncate(time.Second)
	tmpl := ocsp.Response{
		SerialNumber: new(big.Int).Set(req.SerialNumber),
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Duration(r.NextUpdateMinutes) * time.Minute),
	}
	status, revokedAt, reason, err := s.lookupStatus(ctx, caUUID, req.SerialNumber)
	if err != nil {
		return ocsp.InternalErrorErrorResponse, nil
	}
	switch status {
	case ocsp.Revoked:
		tmpl.Status, tmpl.RevokedAt, tmpl.RevocationReason = ocsp.Revoked, revokedAt, reason
	case ocsp.Unknown:
		tmpl.Status = ocsp.Unknown
		if r.UnknownPolicy == "good" {
			tmpl.Status = ocsp.Good
		}
	default:
		tmpl.Status = ocsp.Good
	}
	// 响应者不是颁发者本身时附带签名证书，供依赖方校验委托关系
	if !signerCert.Equal(issuer) {
		tmpl.Certificate = signerCert
	}
	// SM2 CA/签名证书标准库不认识，需要走国密专用编码（见 ocsp_gm.go）。
	if isSM2PubKey(issuer) || isSM2PubKey(signerCert) {
		return CreateOCSPResponseSM2(issuer, signerCert, tmpl, signer)
	}
	return ocsp.CreateResponse(issuer, signerCert, tmpl, signer)
}

// lookupStatus 查询序列号状态：已吊销 → revoked；平台内有签发记录 → good；否则 unknown。
func (s *Service) lookupStatus(ctx context.Context, caUUID string, serial *big.Int) (int, time.Time, int, error) {
	hexSerial := strings.ToUpper(hex.EncodeToString(serial.Bytes()))
	dec := serial.String()

	// revoked_certs 仅存 serial_number（历史数据可能是十进制或十六进制），两种形式都匹配
	var revokedAt sql.NullTime
	var reason int
	err := s.db.QueryRowContext(ctx,
		`SELECT revoked_at, reason FROM revoked_certs
		 WHERE ca_uuid = ? AND (serial_number = ? OR serial_number = ? OR UPPER(serial_number) = ?)`,
		caUUID, hexSerial, dec, hexSerial).Scan(&revokedAt, &reason)
	switch {
	case err == nil:
		t := time.Now()
		if revokedAt.Valid {
			t = revokedAt.Time
		}
		return ocsp.Revoked, t, reason, nil
	case err != sql.ErrNoRows:
		return 0, time.Time{}, 0, err
	}

	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM certificates
		 WHERE ca_uuid = ? AND (serial_number = ? OR serial_number = ? OR UPPER(serial_hex) = ?)`,
		caUUID, dec, hexSerial, hexSerial).Scan(&n); err != nil {
		return 0, time.Time{}, 0, err
	}
	if n > 0 {
		return ocsp.Good, time.Time{}, 0, nil
	}
	return ocsp.Unknown, time.Time{}, 0, nil
}
