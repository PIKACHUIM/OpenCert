package api

import (
	"net/http"

	"github.com/globaltrusts/server-card/internal/ca"
	"github.com/globaltrusts/server-card/internal/meta"
)

// ---- 元数据处理器（静态预置数据）----

// handleGetSubjectFields 返回预置的主体 DN 字段列表（基于 XCA dn.txt）。
// GET /api/meta/subject-fields
func (s *Server) handleGetSubjectFields(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"fields": meta.GetSubjectFields(),
	})
}

// handleGetPredefinedOIDs 返回预置的 OID 库（按分类）。
// GET /api/meta/predefined-oids?category=ssl
// 未指定 category 时返回全部分类。
func (s *Server) handleGetPredefinedOIDs(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	data := meta.GetPredefinedOIDs(category)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": data,
	})
}

// handleListOIDCategories 返回所有 OID 分类名。
// GET /api/meta/predefined-oids/categories
func (s *Server) handleListOIDCategories(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"categories": meta.GetPredefinedOIDCategories(),
	})
}

// handleGetAlgorithms 返回所有密码学算法清单（含 SM2/SM3/SM4/RSA 全范围/Ed25519 等），
// 以及签名算法清单和"密钥算法 → 允许的签名哈希"映射，供前端联动渲染
// 算法选择表单（选择 SM2 时只能选 SM3，不再各页面写死）。
// GET /api/meta/algorithms
func (s *Server) handleGetAlgorithms(w http.ResponseWriter, r *http.Request) {
	overrides := map[string]bool{
		"sm2": ca.IsSM2Available(),
		"sm3": ca.IsSM2Available(), // SM3 与 SM2 同属 gmsm 库
		"sm4": ca.IsSM2Available(),
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"algorithms":      meta.GetSupportedAlgorithms(overrides),
		"signature_algos": meta.SignatureAlgorithms,
		"key_sig_map":     meta.KeyTypeToSigHashes,
	})
}
