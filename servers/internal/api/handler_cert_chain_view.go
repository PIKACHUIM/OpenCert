package api

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strings"

	"github.com/globaltrusts/server-card/internal/auth"
	"github.com/globaltrusts/server-card/internal/storage"
)

// ---- 证书链结构化视图（T24）----
//
// 与 /api/certs/{uuid}/chain（返回 PEM 拼接链）不同，此处提供结构化 JSON 视图：
// 每个节点包含 uuid/subject/issuer/serial_hex/not_before/not_after/is_ca/is_root/is_self_signed/status，
// 便于前端用树形或时间线控件展示证书链。

// CertChainNode 是证书链中单个节点的结构化描述。
type CertChainNode struct {
	Level        int    `json:"level"`         // 0=叶子；1、2 … 依次向上到根
	UUID         string `json:"uuid,omitempty"` // 本系统内部 UUID（外部 CA 可能为空）
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialHex    string `json:"serial_hex"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	IsCA         bool   `json:"is_ca"`
	IsRoot       bool   `json:"is_root"`
	IsSelfSigned bool   `json:"is_self_signed"`
	Status       string `json:"status,omitempty"` // active/revoked/expired，仅本系统内证书/CA 有效
	CAUUID       string `json:"ca_uuid,omitempty"` // 签发 CA 的 UUID（若已知）
}

// handleGetCertChainView 返回指定证书的结构化证书链视图。
// GET /api/certs/{uuid}/chain-view
func (s *Server) handleGetCertChainView(w http.ResponseWriter, r *http.Request) {
	certUUID := r.PathValue("uuid")
	certRepo := storage.NewCertRepo(s.db)
	cert, err := certRepo.GetByUUID(r.Context(), certUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "证书不存在")
		return
	}

	claims := claimsFromCtx(r.Context())
	if cert.UserUUID != claims.UserUUID && !auth.IsAdmin(claims.Role) {
		writeError(w, http.StatusForbidden, "无权查看此证书")
		return
	}

	nodes := make([]CertChainNode, 0, 4)

	// 叶子节点
	leafNode := CertChainNode{
		Level:     0,
		UUID:      cert.UUID,
		SerialHex: cert.SerialHex,
		Subject:   cert.SubjectDN,
		Issuer:    cert.IssuerDN,
		Status:    cert.RevocationStatus,
		CAUUID:    cert.CAUUID,
	}
	if cert.NotBefore != nil {
		leafNode.NotBefore = cert.NotBefore.Format("2006-01-02T15:04:05Z07:00")
	}
	if cert.NotAfter != nil {
		leafNode.NotAfter = cert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
	}
	// 从 PEM 内容解析 IsCA 标志与自签名状态
	if leaf := parseFirstCertFromPEM(cert.CertContent); leaf != nil {
		leafNode.IsCA = leaf.IsCA
		leafNode.IsSelfSigned = isSelfSigned(leaf)
		if leafNode.SerialHex == "" && leaf.SerialNumber != nil {
			leafNode.SerialHex = strings.ToUpper(hex.EncodeToString(leaf.SerialNumber.Bytes()))
		}
	}
	nodes = append(nodes, leafNode)

	// 沿 CA 链向上递归（最多 16 层，防止循环）
	level := 1
	currentCAUUID := cert.CAUUID
	visited := map[string]bool{}
	for i := 0; i < 16 && currentCAUUID != ""; i++ {
		if visited[currentCAUUID] {
			break
		}
		visited[currentCAUUID] = true

		ca, err := s.caSvc.GetByUUID(r.Context(), currentCAUUID)
		if err != nil {
			break
		}

		node := CertChainNode{
			Level:  level,
			UUID:   ca.UUID,
			Status: ca.Status,
		}
		if caCert := parseFirstCertFromPEM([]byte(ca.CertPEM)); caCert != nil {
			node.Subject = caCert.Subject.String()
			node.Issuer = caCert.Issuer.String()
			node.NotBefore = caCert.NotBefore.Format("2006-01-02T15:04:05Z07:00")
			node.NotAfter = caCert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
			node.IsCA = caCert.IsCA
			node.IsSelfSigned = isSelfSigned(caCert)
			if caCert.SerialNumber != nil {
				node.SerialHex = strings.ToUpper(hex.EncodeToString(caCert.SerialNumber.Bytes()))
			}
		}
		// 判定根：无父 CA 且自签名
		node.IsRoot = ca.ParentUUID == "" && node.IsSelfSigned

		nodes = append(nodes, node)

		if ca.ParentUUID == "" {
			break
		}
		currentCAUUID = ca.ParentUUID
		level++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cert_uuid": certUUID,
		"chain":     nodes,
		"total":     len(nodes),
	})
}

// handleGetCAChainView 返回指定 CA 及其所有父 CA 的结构化链视图。
// GET /api/cas/{uuid}/chain-view
func (s *Server) handleGetCAChainView(w http.ResponseWriter, r *http.Request) {
	caUUID := r.PathValue("uuid")

	nodes := make([]CertChainNode, 0, 4)
	level := 0
	currentCAUUID := caUUID
	visited := map[string]bool{}
	for i := 0; i < 16 && currentCAUUID != ""; i++ {
		if visited[currentCAUUID] {
			break
		}
		visited[currentCAUUID] = true

		ca, err := s.caSvc.GetByUUID(r.Context(), currentCAUUID)
		if err != nil {
			if level == 0 {
				writeError(w, http.StatusNotFound, "CA 不存在")
				return
			}
			break
		}
		node := CertChainNode{
			Level:  level,
			UUID:   ca.UUID,
			Status: ca.Status,
		}
		if caCert := parseFirstCertFromPEM([]byte(ca.CertPEM)); caCert != nil {
			node.Subject = caCert.Subject.String()
			node.Issuer = caCert.Issuer.String()
			node.NotBefore = caCert.NotBefore.Format("2006-01-02T15:04:05Z07:00")
			node.NotAfter = caCert.NotAfter.Format("2006-01-02T15:04:05Z07:00")
			node.IsCA = caCert.IsCA
			node.IsSelfSigned = isSelfSigned(caCert)
			if caCert.SerialNumber != nil {
				node.SerialHex = strings.ToUpper(hex.EncodeToString(caCert.SerialNumber.Bytes()))
			}
		}
		node.IsRoot = ca.ParentUUID == "" && node.IsSelfSigned
		nodes = append(nodes, node)

		if ca.ParentUUID == "" {
			break
		}
		currentCAUUID = ca.ParentUUID
		level++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ca_uuid": caUUID,
		"chain":   nodes,
		"total":   len(nodes),
	})
}

// parseFirstCertFromPEM 从 PEM 字节数据中解析第一张 X.509 证书。
func parseFirstCertFromPEM(pemData []byte) *x509.Certificate {
	rest := pemData
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return c
			}
		}
		rest = r
		if len(rest) == 0 {
			return nil
		}
	}
}

// isSelfSigned 判断证书是否自签名（Subject == Issuer 且签名由自身公钥验证通过）。
func isSelfSigned(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	if c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}
