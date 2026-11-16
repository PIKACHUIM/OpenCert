//go:build windows

package fido

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32DLL             = windows.NewLazySystemDLL("crypt32.dll")
	kernel32DLL            = windows.NewLazySystemDLL("kernel32.dll")
	procCryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32DLL.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func dpapiProtect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("内容为空")
	}
	in := dataBlob{cbData: uint32(len(plain)), pbData: &plain[0]}
	var out dataBlob
	if r, _, _ := procCryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0x1, uintptr(unsafe.Pointer(&out))); r == 0 {
		return nil, fmt.Errorf("DPAPI 加密失败")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	data := make([]byte, out.cbData)
	copy(data, unsafe.Slice(out.pbData, out.cbData))
	return data, nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("内容为空")
	}
	in := dataBlob{cbData: uint32(len(blob)), pbData: &blob[0]}
	var out dataBlob
	if r, _, _ := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0x1, uintptr(unsafe.Pointer(&out))); r == 0 {
		return nil, fmt.Errorf("DPAPI 解密失败")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	data := make([]byte, out.cbData)
	copy(data, unsafe.Slice(out.pbData, out.cbData))
	return data, nil
}

// StoredCredential 是 WebAuthn 凭据，私钥由 DPAPI 保护，不依赖卡片 PIN。
type StoredCredential struct {
	ID          []byte    `json:"id"`
	RPID        string    `json:"rp_id"`
	UserHandle  []byte    `json:"user_handle,omitempty"`
	UserName    string    `json:"user_name,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	PrivateKey  []byte    `json:"private_key"`
	Counter     uint32    `json:"counter"`
	CreatedAt   time.Time `json:"created_at"`
}

// KeyStore 是当前用户的 FIDO 凭据文件。
type KeyStore struct {
	path string
	mu   sync.Mutex
}

// DefaultKeyStorePath 返回 %APPDATA%\OpenCertManager\fido\credentials.bin。
func DefaultKeyStorePath() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "OpenCertManager", "fido", "credentials.bin")
}

// NewKeyStore 创建凭据存储；path 为空时使用默认位置。
func NewKeyStore(path string) *KeyStore {
	if path == "" {
		path = DefaultKeyStorePath()
	}
	return &KeyStore{path: path}
}

func (k *KeyStore) load() ([]StoredCredential, error) {
	raw, err := os.ReadFile(k.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 FIDO 凭据失败: %w", err)
	}
	plain, err := dpapiUnprotect(raw)
	if err != nil {
		return nil, err
	}
	var creds []StoredCredential
	if err := json.Unmarshal(plain, &creds); err != nil {
		return nil, fmt.Errorf("FIDO 凭据文件损坏: %w", err)
	}
	return creds, nil
}

func (k *KeyStore) save(creds []StoredCredential) error {
	plain, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	blob, err := dpapiProtect(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(k.path, blob, 0o600)
}

// Put 新增或覆盖同 ID 的凭据。
func (k *KeyStore) Put(c StoredCredential) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	creds, err := k.load()
	if err != nil {
		return err
	}
	for i := range creds {
		if string(creds[i].ID) == string(c.ID) {
			creds[i] = c
			return k.save(creds)
		}
	}
	return k.save(append(creds, c))
}

// Find 按凭据 ID 查找。
func (k *KeyStore) Find(id []byte) (*StoredCredential, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	creds, err := k.load()
	if err != nil {
		return nil, err
	}
	for i := range creds {
		if string(creds[i].ID) == string(id) {
			c := creds[i]
			return &c, nil
		}
	}
	return nil, nil
}

// Increment 增加签名计数器并返回新值。
func (k *KeyStore) Increment(id []byte) (uint32, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	creds, err := k.load()
	if err != nil {
		return 0, err
	}
	for i := range creds {
		if string(creds[i].ID) == string(id) {
			creds[i].Counter++
			if err := k.save(creds); err != nil {
				return 0, err
			}
			return creds[i].Counter, nil
		}
	}
	return 0, fmt.Errorf("凭据不存在")
}
