package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/globaltrusts/client-card/internal/backup"
)

// handleBackupTSB POST /api/cards/{uuid}/tsb/backup
// 采集 store + PCPKEY + 设备注册表，打包为 .tsb（可口令加密），直接返回文件内容。
func (s *Server) handleBackupTSB(w http.ResponseWriter, r *http.Request) {
	card, ok := s.loadTPMSCCard(w, r, "整卡备份")
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	files, manifest, err := backup.CollectCard(r.Context(), "")
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	manifest.CardName = card.CardName
	manifest.CardID = card.UUID

	tmp, err := tempTSBPath()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := backup.Write(tmp, manifest, files, req.Password); err != nil {
		writeError(w, http.StatusInternalServerError, "生成备份包失败: "+err.Error())
		return
	}
	data, err := readAndRemove(tmp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]any{
		"filename":       fmt.Sprintf("%s-%s.tsb", safeFileName(card.CardName), time.Now().Format("20060102-150405")),
		"data_b64":       base64.StdEncoding.EncodeToString(data),
		"protection":     manifest.Protection,
		"parts":          len(manifest.Parts),
		"includes_dpapi": manifest.IncludesDPAPI,
		"warning":        "当前备份不含 DPAPI 明文，只适用于卡片未删除且同一系统的恢复",
	})
}

// handleRestoreTSB POST /api/cards/{uuid}/tsb/restore
// 请求体：{data_b64, password}。写回 store / PCPKEY / 设备注册表。
func (s *Server) handleRestoreTSB(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.loadTPMSCCard(w, r, "整卡还原"); !ok {
		return
	}
	var req struct {
		DataB64  string `json:"data_b64"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if req.DataB64 == "" {
		writeError(w, http.StatusBadRequest, "data_b64 不能为空")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil || len(data) == 0 || len(data) > 64<<20 {
		writeError(w, http.StatusBadRequest, "备份文件内容无效或超过 64MB")
		return
	}
	tmp, err := tempTSBPath()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := writeTemp(tmp, data); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	manifest, files, err := backup.Open(tmp, req.Password)
	removeFile(tmp)
	if err != nil {
		writeError(w, http.StatusBadRequest, "读取备份包失败: "+err.Error())
		return
	}
	if err := backup.RestoreFiles(r.Context(), files); err != nil {
		writeError(w, http.StatusInternalServerError, "还原失败: "+err.Error())
		return
	}
	writeOK(w, map[string]any{
		"status":         "restored",
		"card_name":      manifest.CardName,
		"parts":          len(manifest.Parts),
		"includes_dpapi": manifest.IncludesDPAPI,
		"note":           "如读卡器未出现，请重启系统或重新插拔后再刷新",
	})
}

func safeFileName(name string) string {
	replacer := strings.NewReplacer("\\", "_", "/", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	name = strings.TrimSpace(replacer.Replace(name))
	if name == "" {
		return "vsc"
	}
	return name
}

func tempTSBPath() (string, error) {
	dir, err := os.MkdirTemp("", "opencert-tsb-")
	if err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}
	return filepath.Join(dir, "backup.tsb"), nil
}

func readAndRemove(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	os.RemoveAll(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("读取备份包失败: %w", err)
	}
	return data, nil
}

func writeTemp(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		os.RemoveAll(filepath.Dir(path))
		return fmt.Errorf("写入临时备份文件失败: %w", err)
	}
	return nil
}

func removeFile(path string) {
	os.RemoveAll(filepath.Dir(path))
}
