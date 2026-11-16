//go:build windows

package fido

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type pinRecord struct {
	Hash    []byte `json:"hash"`
	Retries int    `json:"retries"`
}

// DefaultPINStatePath 返回 PIN 状态文件位置。
func DefaultPINStatePath() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "OpenCertManager", "fido", "pin.bin")
}

// NewPersistentPINState 用 DPAPI 加密保存 PIN 哈希与重试计数。
func NewPersistentPINState(path string) *PINState {
	if path == "" {
		path = DefaultPINStatePath()
	}
	state := NewPINState(func(hash []byte, retries int) error {
		data, err := json.Marshal(pinRecord{Hash: hash, Retries: retries})
		if err != nil {
			return err
		}
		blob, err := dpapiProtect(data)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, blob, 0o600)
	})
	if raw, err := os.ReadFile(path); err == nil {
		if plain, err := dpapiUnprotect(raw); err == nil {
			var rec pinRecord
			if json.Unmarshal(plain, &rec) == nil {
				state.Restore(rec.Hash, rec.Retries)
			}
		}
	}
	return state
}
