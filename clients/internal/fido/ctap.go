package fido

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	errCredentialExcluded = fmt.Errorf("凭据已存在")
	errPINAuthInvalid     = fmt.Errorf("pinUvAuthParam 校验失败")
)

// AAGUID 固定为全零：这是软件虚拟认证器，不是厂商硬件。
var aaguid = make([]byte, 16)

// HandleCTAP 处理 MAKE_CREDENTIAL / GET_ASSERTION，返回 base64 的 cbor_resp。
func HandleCTAP(store *KeyStore, pins *PINService, cmd uint32, body map[string]any) (map[string]any, error) {
	raw, _ := body["cbor_req"].(string)
	req, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(req) == 0 {
		return map[string]any{"rv": 1}, nil
	}
	var out []byte
	switch cmd {
	case CmdMakeCredential:
		out, err = makeCredential(store, pins, req)
	case CmdGetAssertion:
		out, err = getAssertion(store, pins, req)
	default:
		return map[string]any{"rv": 1}, nil
	}
	if err != nil {
		if err == errCredentialExcluded {
			return map[string]any{"rv": 0x19}, nil
		}
		if err == errPINAuthInvalid {
			return map[string]any{"rv": 0x33}, nil
		}
		return map[string]any{"rv": 1, "data": map[string]string{"error": err.Error()}}, nil
	}
	return map[string]any{"rv": 0, "data": map[string]string{
		"cbor_resp": base64.StdEncoding.EncodeToString(out),
	}}, nil
}

func makeCredential(store *KeyStore, pins *PINService, req []byte) ([]byte, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(req, &m); err != nil {
		return nil, fmt.Errorf("解析请求失败: %w", err)
	}
	var clientDataHash []byte
	var rp struct {
		ID   string `cbor:"id"`
		Name string `cbor:"name"`
	}
	var user struct {
		ID          []byte `cbor:"id"`
		Name        string `cbor:"name"`
		DisplayName string `cbor:"displayName"`
	}
	if err := cbor.Unmarshal(m[1], &clientDataHash); err != nil {
		return nil, fmt.Errorf("缺少 clientDataHash")
	}
	if err := cbor.Unmarshal(m[2], &rp); err != nil || rp.ID == "" {
		return nil, fmt.Errorf("缺少 rp.id")
	}
	_ = cbor.Unmarshal(m[3], &user)

	// excludeList：已存在同一凭据时按 CTAP2 返回 0x19（CREDENTIAL_EXCLUDED）。
	var exclude []struct {
		ID []byte `cbor:"id"`
	}
	if raw, ok := m[5]; ok {
		_ = cbor.Unmarshal(raw, &exclude)
	}
	for _, e := range exclude {
		if found, err := store.Find(e.ID); err == nil && found != nil {
			return nil, errCredentialExcluded
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}
	cred := StoredCredential{
		ID: credID, RPID: rp.ID, UserHandle: user.ID,
		UserName: user.Name, DisplayName: user.DisplayName, PrivateKey: der,
	}
	if err := store.Put(cred); err != nil {
		return nil, err
	}

	flags := byte(0x41) // UP | AT
	if len(m[8]) > 0 {
		var param []byte
		_ = cbor.Unmarshal(m[8], &param)
		if pins == nil || !pins.VerifyAuth(clientDataHash, param) {
			return nil, errPINAuthInvalid
		}
		flags |= 0x04 // UV
	}
	authData := authenticatorData(rp.ID, flags, 0)
	authData = append(authData, aaguid...)
	authData = append(authData, byte(len(credID)>>8), byte(len(credID)))
	authData = append(authData, credID...)
	cose, err := coseKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	authData = append(authData, cose...)

	return cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
}

func getAssertion(store *KeyStore, pins *PINService, req []byte) ([]byte, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(req, &m); err != nil {
		return nil, fmt.Errorf("解析请求失败: %w", err)
	}
	var rpID string
	var clientDataHash []byte
	if err := cbor.Unmarshal(m[1], &rpID); err != nil {
		return nil, fmt.Errorf("缺少 rpId")
	}
	if err := cbor.Unmarshal(m[2], &clientDataHash); err != nil {
		return nil, fmt.Errorf("缺少 clientDataHash")
	}
	var allow []struct {
		ID []byte `cbor:"id"`
	}
	if raw, ok := m[3]; ok {
		_ = cbor.Unmarshal(raw, &allow)
	}
	var cred *StoredCredential
	for _, a := range allow {
		if found, err := store.Find(a.ID); err == nil && found != nil {
			cred = found
			break
		}
	}
	credentialCount := 0
	if len(allow) == 0 {
		if list, err := store.ListByRP(rpID); err == nil && len(list) > 0 {
			cred = &list[0]
			credentialCount = len(list)
		}
	}
	if cred == nil {
		return nil, fmt.Errorf("没有匹配的凭据")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(cred.PrivateKey)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("凭据私钥类型不支持")
	}
	counter, err := store.Increment(cred.ID)
	if err != nil {
		return nil, err
	}
	flags := byte(0x01)
	if len(m[6]) > 0 {
		var param []byte
		_ = cbor.Unmarshal(m[6], &param)
		if pins == nil || !pins.VerifyAuth(clientDataHash, param) {
			return nil, errPINAuthInvalid
		}
		flags |= 0x04
	}
	authData := authenticatorData(rpID, flags, counter)
	digest := sha256.Sum256(append(authData, clientDataHash...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(map[int]any{
		1: map[string]any{"type": "public-key", "id": cred.ID},
		2: authData,
		3: sig,
		4: map[string]any{"id": cred.UserHandle, "name": cred.UserName, "displayName": cred.DisplayName},
		5: max(credentialCount, 1),
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func authenticatorData(rpID string, flags byte, counter uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, hash[:]...)
	out = append(out, flags, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
	return out
}

func coseKey(pub *ecdsa.PublicKey) ([]byte, error) {
	return cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: pub.X.FillBytes(make([]byte, 32)),
		-3: pub.Y.FillBytes(make([]byte, 32)),
	})
}
