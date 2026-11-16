package fido

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// CTAP2 clientPIN 子命令。
const (
	PINSubGetRetries      = 0x01
	PINSubGetKeyAgreement = 0x02
	PINSubSetPIN          = 0x03
	PINSubChangePIN       = 0x04
	PINSubGetPINToken     = 0x05
)

// PINRetries 是允许的连续错误次数。
const PINRetries = 8

// pinCrypto 封装 clientPIN 用到的 ECDH + AES-256-CBC + HMAC-SHA256。
type pinCrypto struct {
	key *ecdh.PrivateKey
}

func newPinCrypto() (*pinCrypto, error) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &pinCrypto{key: key}, nil
}

// cosePublicKey 返回 keyAgreement 的 COSE_Key（EC2 / P-256）。
func (p *pinCrypto) cosePublicKey() []byte {
	pub := p.key.PublicKey().Bytes() // 0x04 || X || Y
	out := []byte{0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20}
	out = append(out, pub[1:33]...)
	out = append(out, 0x22, 0x58, 0x20)
	out = append(out, pub[33:]...)
	return out
}

// deriveKey 计算 ECDH 共享密钥并取 SHA-256 作为 AES/HMAC 密钥。
func (p *pinCrypto) deriveKey(peerCOSE []byte) ([]byte, error) {
	x, y, err := parseCOSEEC2(peerCOSE)
	if err != nil {
		return nil, err
	}
	peerPub, err := ecdh.P256().NewPublicKey(append([]byte{0x04}, append(x, y...)...))
	if err != nil {
		return nil, fmt.Errorf("平台公钥无效: %w", err)
	}
	secret, err := p.key.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(secret)
	return sum[:], nil
}

func aesCBCEncrypt(key, iv, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(plain)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("明文长度必须是 16 的倍数")
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度必须是 16 的倍数")
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// parseCOSEEC2 从 COSE_Key 的 CBOR 中解析 X/Y 坐标。
func parseCOSEEC2(cose []byte) ([]byte, []byte, error) {
	// 简化解析：COSE EC2 结构固定为 a5 01 02 03 38 18 20 01 21 58 20 <x32> 22 58 20 <y32>
	if len(cose) < 77 || cose[0] != 0xA5 {
		return nil, nil, fmt.Errorf("不支持的 COSE 公钥格式")
	}
	for i := 0; i+2 < len(cose); i++ {
		if cose[i] == 0x21 && cose[i+1] == 0x58 && cose[i+2] == 0x20 && i+35 <= len(cose) {
			x := cose[i+3 : i+35]
			if i+37 < len(cose) && cose[i+35] == 0x22 && cose[i+36] == 0x58 && cose[i+37] == 0x20 && i+70 <= len(cose) {
				return x, cose[i+38 : i+70], nil
			}
			return nil, nil, fmt.Errorf("COSE 公钥缺少 Y 坐标")
		}
	}
	return nil, nil, fmt.Errorf("COSE 公钥缺少 X 坐标")
}

// u32 辅助，便于测试。
func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
