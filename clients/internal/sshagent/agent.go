// Package sshagent 提供只读的 SSH agent：用卡片上的私钥签名，但拒绝导入任何私钥。
//
// 协议由 golang.org/x/crypto/ssh/agent 处理，本包只负责身份列表与签名回调。
package sshagent

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Identity 是 agent 对外暴露的一个公钥身份。
type Identity struct {
	PublicKey ssh.PublicKey
	Comment   string
}

// Backend 由平台层实现：列出身份，并用对应私钥签名。
//
// Sign 的返回值必须是完整的 SSH 签名格式（rsa-sha2-256 或 ecdsa-sha2-*），
// 不能返回裸签名。
type Backend interface {
	Identities() ([]Identity, error)
	Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error)
}

// ErrReadOnly 表示请求会向 agent 写入私钥，已被拒绝。
var ErrReadOnly = errors.New("SSH agent 为只读：拒绝导入私钥")

// Serve 在连接上处理 SSH agent 协议，直到对端关闭。
func Serve(conn io.ReadWriteCloser, backend Backend) error {
	return agent.ServeAgent(&server{backend: backend}, conn)
}

type server struct {
	backend Backend
}

func (s *server) List() ([]*agent.Key, error) {
	identities, err := s.backend.Identities()
	if err != nil {
		return nil, err
	}
	keys := make([]*agent.Key, 0, len(identities))
	for _, id := range identities {
		keys = append(keys, &agent.Key{
			Format:  id.PublicKey.Type(),
			Blob:    id.PublicKey.Marshal(),
			Comment: id.Comment,
		})
	}
	return keys, nil
}

func (s *server) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.backend.Sign(key, data)
}

func (s *server) Add(agent.AddedKey) error       { return ErrReadOnly }
func (s *server) Remove(ssh.PublicKey) error     { return ErrReadOnly }
func (s *server) RemoveAll() error               { return ErrReadOnly }
func (s *server) Lock([]byte) error              { return ErrReadOnly }
func (s *server) Unlock([]byte) error            { return ErrReadOnly }
func (s *server) Signers() ([]ssh.Signer, error) { return nil, fmt.Errorf("Signers 未实现") }

// FindIdentity 按公钥字节匹配身份，供平台层签名时定位容器。
func FindIdentity(identities []Identity, key ssh.PublicKey) (Identity, bool) {
	want := key.Marshal()
	for _, id := range identities {
		if string(id.PublicKey.Marshal()) == string(want) {
			return id, true
		}
	}
	return Identity{}, false
}
