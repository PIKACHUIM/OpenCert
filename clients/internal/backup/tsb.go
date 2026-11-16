// Package backup 实现 .tsb v2 备份容器：ZIP + manifest + 可选口令加密。
//
// 文件布局：
//   - 未加密：标准 ZIP，含 manifest.json 与各部件。
//   - 加密：magic "TSBENC2\n" + salt(16) + nonce(12) + AES-256-GCM(zip 明文)。
// 口令经 PBKDF2-HMAC-SHA256（120000 次）派生 32 字节密钥。
package backup

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// FormatV2 是当前备份格式标识。
	FormatV2 = "tsb/2"
	// ManifestName 是 ZIP 内清单文件名。
	ManifestName = "manifest.json"
	// ProtectionNone / ProtectionPassphrase 表示容器的加密方式。
	ProtectionNone       = "none"
	ProtectionPassphrase = "passphrase"

	encryptedMagic = "TSBENC2\n"
	keyIterations  = 120000
	saltLen        = 16
)

// ErrWrongPassphrase 表示口令错误或文件被篡改（GCM 校验失败）。
var ErrWrongPassphrase = errors.New("备份口令错误或文件已损坏")

// Part 描述备份中的一个部件。
type Part struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest 是 .tsb 包的清单。
type Manifest struct {
	Format        string    `json:"format"`
	Version       int       `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	CardName      string    `json:"card_name,omitempty"`
	CardID        string    `json:"card_id,omitempty"`
	Protection    string    `json:"protection"`
	IncludesDPAPI bool      `json:"includes_dpapi_plaintext"`
	Parts         []Part    `json:"parts"`
}

// Write 生成备份包。files 的键是包内路径，值是内容。
func Write(path string, manifest *Manifest, files map[string][]byte, passphrase string) error {
	if manifest == nil {
		return errors.New("manifest 不能为空")
	}
	if len(files) == 0 {
		return errors.New("备份内容为空")
	}
	manifest.Format = FormatV2
	manifest.Version = 2
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = time.Now()
	}
	manifest.Parts = make([]Part, 0, len(files))
	if passphrase == "" {
		manifest.Protection = ProtectionNone
	} else {
		manifest.Protection = ProtectionPassphrase
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		sum := sha256.Sum256(data)
		manifest.Parts = append(manifest.Parts, Part{
			Name:   name,
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(sum[:]),
		})
		w, err := zw.Create(name)
		if err != nil {
			return fmt.Errorf("写入备份部件 %s 失败: %w", name, err)
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("写入备份部件 %s 失败: %w", name, err)
		}
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("编码 manifest 失败: %w", err)
	}
	w, err := zw.Create(ManifestName)
	if err != nil {
		return fmt.Errorf("写入 manifest 失败: %w", err)
	}
	if _, err := w.Write(manifestJSON); err != nil {
		return fmt.Errorf("写入 manifest 失败: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("完成 ZIP 失败: %w", err)
	}

	payload := buf.Bytes()
	if passphrase != "" {
		payload, err = encrypt(payload, passphrase)
		if err != nil {
			return err
		}
	}
	return atomicWrite(path, payload)
}

// Open 读取并校验备份包，返回清单与部件内容。
func Open(path, passphrase string) (*Manifest, map[string][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("读取备份文件失败: %w", err)
	}
	if bytes.HasPrefix(raw, []byte(encryptedMagic)) {
		if passphrase == "" {
			return nil, nil, errors.New("该备份已加密，需要口令")
		}
		raw, err = decrypt(raw, passphrase)
		if err != nil {
			return nil, nil, err
		}
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, nil, fmt.Errorf("备份不是有效的 ZIP/TSB: %w", err)
	}
	files := make(map[string][]byte, len(zr.File))
	var manifest *Manifest
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("读取备份部件 %s 失败: %w", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("读取备份部件 %s 失败: %w", f.Name, err)
		}
		if f.Name == ManifestName {
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, nil, fmt.Errorf("manifest 解析失败: %w", err)
			}
			manifest = &m
			continue
		}
		files[f.Name] = data
	}
	if manifest == nil {
		return nil, nil, errors.New("备份缺少 manifest.json")
	}
	if manifest.Format != FormatV2 {
		return nil, nil, fmt.Errorf("不支持的备份格式: %s", manifest.Format)
	}
	for _, part := range manifest.Parts {
		data, ok := files[part.Name]
		if !ok {
			return nil, nil, fmt.Errorf("备份缺少部件 %s", part.Name)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != part.SHA256 {
			return nil, nil, fmt.Errorf("备份部件 %s 校验失败", part.Name)
		}
	}
	return manifest, files, nil
}

func encrypt(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("生成备份 salt 失败: %w", err)
	}
	key := pbkdf2.Key([]byte(passphrase), salt, keyIterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("生成备份 nonce 失败: %w", err)
	}
	out := make([]byte, 0, len(encryptedMagic)+len(salt)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, encryptedMagic...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, nil)
	return out, nil
}

func decrypt(raw []byte, passphrase string) ([]byte, error) {
	prefix := len(encryptedMagic)
	if len(raw) < prefix+saltLen+12 {
		return nil, ErrWrongPassphrase
	}
	body := raw[prefix:]
	salt := body[:saltLen]
	body = body[saltLen:]
	key := pbkdf2.Key([]byte(passphrase), salt, keyIterations, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(body) < gcm.NonceSize() {
		return nil, ErrWrongPassphrase
	}
	nonce := body[:gcm.NonceSize()]
	ciphertext := body[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plain, nil
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建备份目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tsb-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时备份文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入备份文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("原子替换备份文件失败: %w", err)
	}
	return nil
}
