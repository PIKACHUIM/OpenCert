//go:build !windows

package sshagent

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// KSPBackend 在非 Windows 平台不可用。
type KSPBackend struct {
	Readers  func() ([]string, error)
	Provider any
}

var errUnsupported = errors.New("当前平台未实现卡上 SSH 签名")

func (b *KSPBackend) Identities() ([]Identity, error) { return nil, errUnsupported }

func (b *KSPBackend) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errUnsupported
}
