//go:build !windows

package fido

import (
	"errors"
	"time"
)

// StoredCredential 是 WebAuthn 凭据。
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

// KeyStore 在非 Windows 平台不可用。
type KeyStore struct{ path string }

// NewKeyStore 创建不可用存储。
func NewKeyStore(path string) *KeyStore { return &KeyStore{path: path} }

var errKeyStoreUnsupported = errors.New("当前平台未实现 FIDO 凭据存储")

func (k *KeyStore) Put(StoredCredential) error             { return errKeyStoreUnsupported }
func (k *KeyStore) Find([]byte) (*StoredCredential, error) { return nil, errKeyStoreUnsupported }
func (k *KeyStore) Increment([]byte) (uint32, error)       { return 0, errKeyStoreUnsupported }

// FindByRP 在非 Windows 平台不可用。
func (k *KeyStore) FindByRP(string) (*StoredCredential, error) { return nil, errKeyStoreUnsupported }

// ListByRP 在非 Windows 平台不可用。
func (k *KeyStore) ListByRP(string) ([]StoredCredential, error) { return nil, errKeyStoreUnsupported }
