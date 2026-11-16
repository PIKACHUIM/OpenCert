package fido

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// PINService 处理 CTAP2 clientPIN 子命令，并保存本次会话的 pinUvAuthToken。
type PINService struct {
	State      *PINState
	key        *pinCrypto
	token      []byte
	Authorized bool
}

// NewPINService 生成临时 keyAgreement 密钥。
func NewPINService(state *PINState) (*PINService, error) {
	key, err := newPinCrypto()
	if err != nil {
		return nil, err
	}
	return &PINService{State: state, key: key}, nil
}

// Handle 处理 clientPIN 请求，返回 base64 的 cbor_resp 包装。
func (s *PINService) Handle(body map[string]any) map[string]any {
	raw, _ := body["cbor_req"].(string)
	req, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(req) == 0 {
		return map[string]any{"rv": 1}
	}
	resp, err := s.handle(req)
	if err != nil {
		return map[string]any{"rv": 1, "data": map[string]string{"error": err.Error()}}
	}
	return map[string]any{"rv": 0, "data": map[string]string{
		"cbor_resp": base64.StdEncoding.EncodeToString(resp),
	}}
}

func (s *PINService) handle(req []byte) ([]byte, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(req, &m); err != nil {
		return nil, fmt.Errorf("解析 clientPIN 请求失败: %w", err)
	}
	var sub uint8
	if err := cbor.Unmarshal(m[2], &sub); err != nil {
		return nil, fmt.Errorf("缺少 subCommand")
	}
	switch sub {
	case PINSubGetRetries:
		return cbor.Marshal(map[int]any{3: s.State.Retries()})
	case PINSubGetKeyAgreement:
		return cbor.Marshal(map[int]any{1: s.key.cosePublicKey()})
	case PINSubSetPIN:
		if s.State.IsSet() {
			return nil, fmt.Errorf("PIN 已设置，请使用 changePIN")
		}
		pin, err := s.decryptPin(m[3], m[5], 64)
		if err != nil {
			return nil, err
		}
		if err := s.State.SetPIN(pin); err != nil {
			return nil, err
		}
		return cbor.Marshal(map[int]any{})
	case PINSubChangePIN:
		old, err := s.decryptHash(m[3], m[6])
		if err != nil {
			return nil, err
		}
		ok, _ := s.State.VerifyHash(old)
		if !ok {
			return nil, fmt.Errorf("当前 PIN 不正确")
		}
		pin, err := s.decryptPin(m[3], m[5], 64)
		if err != nil {
			return nil, err
		}
		if err := s.State.SetPIN(pin); err != nil {
			return nil, err
		}
		return cbor.Marshal(map[int]any{})
	case PINSubGetPINToken, PINSubGetTokenPerm:
		pin, err := s.decryptHash(m[3], m[6])
		if err != nil {
			return nil, err
		}
		ok, _ := s.State.VerifyHash(pin)
		if !ok {
			return nil, fmt.Errorf("PIN 不正确，剩余 %d 次", s.State.Retries())
		}
		token := make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return nil, err
		}
		s.token = token
		s.Authorized = true
		return cbor.Marshal(map[int]any{2: token})
	default:
		return nil, fmt.Errorf("不支持的 clientPIN 子命令 0x%02X", sub)
	}
}

// VerifyAuth 校验 pinUvAuthParam = HMAC-SHA256(pinToken, clientDataHash)。
func (s *PINService) VerifyAuth(clientDataHash, param []byte) bool {
	if len(s.token) == 0 || len(param) == 0 {
		return false
	}
	mac := hmacSHA256(s.token, clientDataHash)
	return subtle.ConstantTimeCompare(mac[:16], param) == 1
}

func (s *PINService) sessionKey(peer cbor.RawMessage) ([]byte, error) {
	var cose []byte
	if err := cbor.Unmarshal(peer, &cose); err != nil {
		return nil, fmt.Errorf("缺少 keyAgreement")
	}
	return s.key.deriveKey(cose)
}

// decryptPin 解密 newPinEnc：前 16 字节 IV，其余为 AES-CBC 密文。
func (s *PINService) decryptPin(peer cbor.RawMessage, enc cbor.RawMessage, padded int) ([]byte, error) {
	key, err := s.sessionKey(peer)
	if err != nil {
		return nil, err
	}
	var blob []byte
	if err := cbor.Unmarshal(enc, &blob); err != nil || len(blob) < 32 {
		return nil, fmt.Errorf("newPinEnc 无效")
	}
	plain, err := aesCBCDecrypt(key, blob[:16], blob[16:])
	if err != nil {
		return nil, err
	}
	for i, b := range plain {
		if b == 0 {
			return plain[:i], nil
		}
	}
	return plain, nil
}

// decryptHash 解密 pinHashEnc 并还原 16 字节 PIN 哈希对应的明文 PIN 不可行，
// 因此改为直接比较哈希：调用方传入的 m[6] 是 hash 的密文。
func (s *PINService) decryptHash(peer cbor.RawMessage, enc cbor.RawMessage) ([]byte, error) {
	key, err := s.sessionKey(peer)
	if err != nil {
		return nil, err
	}
	var blob []byte
	if err := cbor.Unmarshal(enc, &blob); err != nil || len(blob) != 32 {
		return nil, fmt.Errorf("pinHashEnc 无效")
	}
	hash, err := aesCBCDecrypt(key, make([]byte, 16), blob)
	if err != nil {
		return nil, err
	}
	return hash, nil
}
