// Package pki - sshkey.go：OpenSSH 公钥与 SubjectPublicKeyInfo 互转，及指纹计算。
//
// 用于 PKCS#11 对象层把 cert_type=ssh 的公钥按标准属性暴露给 OpenSSH/sshd 等。
//   - SubjectPublicKeyInfo (PKIX/DER) <-> OpenSSH wire format
//   - SHA256 指纹（OpenSSH 风格："SHA256:" + base64(sha256(blob))）
package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SSHPublicKeyFromPKIX 将 SubjectPublicKeyInfo DER 转换为 OpenSSH 单行格式（"ssh-rsa AAAA..."）。
func SSHPublicKeyFromPKIX(spkiDER []byte, comment string) ([]byte, error) {
	pub, err := parsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("转换为 SSH 公钥失败: %w", err)
	}
	line := ssh.MarshalAuthorizedKey(sshPub)
	if comment != "" {
		// MarshalAuthorizedKey 末尾带换行，去掉换行再附 comment
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		line = append(line, ' ')
		line = append(line, []byte(comment)...)
		line = append(line, '\n')
	}
	return line, nil
}

// SSHPublicKeyToPKIX 将 OpenSSH authorized_keys 格式或 wire blob 转为 SubjectPublicKeyInfo DER。
// 接受两种输入：
//  1. authorized_keys 行（含算法前缀）
//  2. wire 格式 blob
func SSHPublicKeyToPKIX(input []byte) ([]byte, error) {
	// 优先按 authorized_keys 解析
	pub, _, _, _, err := ssh.ParseAuthorizedKey(input)
	if err == nil {
		return cryptoPubFromSSH(pub)
	}
	// 退而求其次：wire blob
	pub, err = ssh.ParsePublicKey(input)
	if err != nil {
		return nil, fmt.Errorf("解析 SSH 公钥失败: %w", err)
	}
	return cryptoPubFromSSH(pub)
}

// SSHFingerprintSHA256 返回 OpenSSH 风格的 SHA256 指纹（如 "SHA256:abc..."）。
// 输入接受 authorized_keys 行或 wire blob；用于填充 PKCS#11 的 CKA_ID。
func SSHFingerprintSHA256(input []byte) (string, []byte, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(input)
	if err != nil {
		// 试 wire blob
		p, err2 := ssh.ParsePublicKey(input)
		if err2 != nil {
			return "", nil, fmt.Errorf("解析 SSH 公钥失败: %v / %v", err, err2)
		}
		pub = p
	}
	sum := sha256.Sum256(pub.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), sum[:], nil
}

// cryptoPubFromSSH 将 ssh.PublicKey（必为 CryptoPublicKey）转为 PKIX DER。
func cryptoPubFromSSH(pub ssh.PublicKey) ([]byte, error) {
	cp, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("不支持的 SSH 公钥类型: %s", pub.Type())
	}
	return marshalPKIXPublicKey(cp.CryptoPublicKey())
}

// parsePKIXPublicKey 解析 SubjectPublicKeyInfo DER。
func parsePKIXPublicKey(der []byte) (interface{}, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("解析 PKIX 公钥失败: %w", err)
	}
	return pub, nil
}

// marshalPKIXPublicKey 编码 SubjectPublicKeyInfo DER。
func marshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("编码 PKIX 公钥失败: %w", err)
	}
	return der, nil
}
