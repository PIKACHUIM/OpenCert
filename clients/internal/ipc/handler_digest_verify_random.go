// Package ipc - Digest / Verify / Random handlers（流式与单次）。
//
// 这些操作不需要卡片中的密钥（除 Verify 外），均可在本地用标准库直接计算：
//   - Digest: crypto/{md5,sha1,sha256,sha512} + golang.org/x/crypto/sha3
//   - Verify: 通过 GetAttributes 取公钥后用 crypto/{rsa,ecdsa,ed25519} 验签
//   - Random: crypto/rand
//
// Session 上扩展三个进行中状态：digest/verify 缓冲区与已选 mechanism。
package ipc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"  //nolint:gosec // PKCS#11 兼容
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // PKCS#11 兼容
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
	"log/slog"
	"math/big"
	"sync"

	"github.com/globaltrusts/client-card/pkg/pkcs11types"
)

// PKCS#11 mechanism 常量（与 cryptoki/pkcs11t.h 一致，仅列出本文件需要的）。
const (
	ckmRSAPKCS         uint32 = 0x00000001
	ckmMD5             uint32 = 0x00000210
	ckmSHA1            uint32 = 0x00000220
	ckmSHA256          uint32 = 0x00000250
	ckmSHA384          uint32 = 0x00000260
	ckmSHA512          uint32 = 0x00000270
	ckmSHA1RSAPKCS     uint32 = 0x00000006
	ckmSHA256RSAPKCS   uint32 = 0x00000040
	ckmSHA384RSAPKCS   uint32 = 0x00000041
	ckmSHA512RSAPKCS   uint32 = 0x00000042
	ckmECDSA           uint32 = 0x00001041
	ckmECDSASHA1       uint32 = 0x00001042
	ckmECDSASHA256     uint32 = 0x00001044
	ckmECDSASHA384     uint32 = 0x00001045
	ckmECDSASHA512     uint32 = 0x00001046
	ckmEdDSA           uint32 = 0x00001057
)

// digestVerifySession 是不能直接放进 card.Session（避免修改公共结构）的辅助状态，
// 通过会话句柄索引；handler 持有全局 map 并自行加锁。
type digestVerifySession struct {
	digestMech    uint32
	digestData    []byte
	digestActive  bool

	verifyMech    uint32
	verifyKey     pkcs11types.ObjectHandle
	verifyData    []byte
	verifyActive  bool
}

var (
	dvMu       sync.Mutex
	dvSessions = make(map[uint32]*digestVerifySession)
)

func dvGet(sid uint32) *digestVerifySession {
	dvMu.Lock()
	defer dvMu.Unlock()
	if s, ok := dvSessions[sid]; ok {
		return s
	}
	s := &digestVerifySession{}
	dvSessions[sid] = s
	return s
}

// RegisterDigestVerifyRandom 注册 Digest / Verify / Random 一族 handler。
// 由 PKCSHandler.Register 在已注册基础命令后追加调用。
func (h *PKCSHandler) RegisterDigestVerifyRandom(s *Server) {
	s.Register(CmdDigestInit, h.handleDigestInit)
	s.Register(CmdDigest, h.handleDigest)
	s.Register(CmdDigestUpdate, h.handleDigestUpdate)
	s.Register(CmdDigestFinal, h.handleDigestFinal)
	s.Register(CmdDigestKey, h.handleDigestKey)
	s.Register(CmdVerifyInit, h.handleVerifyInit)
	s.Register(CmdVerify, h.handleVerify)
	s.Register(CmdVerifyUpdate, h.handleVerifyUpdate)
	s.Register(CmdVerifyFinal, h.handleVerifyFinal)
	s.Register(CmdGenerateRandom, h.handleGenerateRandom)
	s.Register(CmdSeedRandom, h.handleSeedRandom)
}

// ---- Digest ----

type digestInitReq struct {
	SessionHandle uint32 `json:"session_id"`
	Mechanism     uint32 `json:"mechanism"`
}

type digestReq struct {
	SessionHandle uint32 `json:"session_id"`
	Data          []byte `json:"data"`
}

type digestUpdateReq struct {
	SessionHandle uint32 `json:"session_id"`
	Part          []byte `json:"part"`
}

type digestFinalReq struct {
	SessionHandle uint32 `json:"session_id"`
}

type digestResp struct {
	Digest []byte `json:"digest"`
}

func newHash(mech uint32) (hash.Hash, error) {
	switch mech {
	case ckmMD5:
		return md5.New(), nil //nolint:gosec
	case ckmSHA1:
		return sha1.New(), nil //nolint:gosec
	case ckmSHA256:
		return sha256.New(), nil
	case ckmSHA384:
		return sha512.New384(), nil
	case ckmSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("不支持的摘要机制: 0x%X", mech)
	}
}

func (h *PKCSHandler) handleDigestInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r digestInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	if _, err := newHash(r.Mechanism); err != nil {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}
	s := dvGet(r.SessionHandle)
	dvMu.Lock()
	defer dvMu.Unlock()
	if s.digestActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}
	s.digestMech = r.Mechanism
	s.digestData = s.digestData[:0]
	s.digestActive = true
	return nil, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleDigest(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r digestReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.digestActive {
		dvMu.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	mech := s.digestMech
	s.digestActive = false
	s.digestData = nil
	dvMu.Unlock()

	hh, err := newHash(mech)
	if err != nil {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}
	hh.Write(r.Data)
	return &digestResp{Digest: hh.Sum(nil)}, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleDigestUpdate(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r digestUpdateReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	defer dvMu.Unlock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.digestActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	s.digestData = append(s.digestData, r.Part...)
	return nil, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleDigestFinal(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r digestFinalReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.digestActive {
		dvMu.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	mech := s.digestMech
	data := s.digestData
	s.digestActive = false
	s.digestData = nil
	dvMu.Unlock()

	hh, err := newHash(mech)
	if err != nil {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}
	hh.Write(data)
	return &digestResp{Digest: hh.Sum(nil)}, uint32(pkcs11types.CKR_OK)
}

// handleDigestKey 将 secret key 内容追加到 digest 累积缓冲区。
// 当前 client-card 不暴露原始 secret key，故返回不支持。
func (h *PKCSHandler) handleDigestKey(ctx context.Context, req *Frame) (interface{}, uint32) {
	return nil, uint32(pkcs11types.CKR_FUNCTION_NOT_SUPPORTED)
}

// ---- Verify ----

type verifyInitReq struct {
	SessionHandle uint32 `json:"session_id"`
	Mechanism     uint32 `json:"mechanism"`
	KeyHandle     uint32 `json:"key_handle"`
}

type verifyReq struct {
	SessionHandle uint32 `json:"session_id"`
	Data          []byte `json:"data"`
	Signature     []byte `json:"signature"`
}

type verifyUpdateReq struct {
	SessionHandle uint32 `json:"session_id"`
	Part          []byte `json:"part"`
}

type verifyFinalReq struct {
	SessionHandle uint32 `json:"session_id"`
	Signature     []byte `json:"signature"`
}

func (h *PKCSHandler) handleVerifyInit(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r verifyInitReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	// 校验机制
	if _, _, err := mechToHash(r.Mechanism); err != nil {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}

	s := dvGet(r.SessionHandle)
	dvMu.Lock()
	defer dvMu.Unlock()
	if s.verifyActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_ACTIVE)
	}
	s.verifyMech = r.Mechanism
	s.verifyKey = pkcs11types.ObjectHandle(r.KeyHandle)
	s.verifyData = s.verifyData[:0]
	s.verifyActive = true
	return nil, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleVerify(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r verifyReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.verifyActive {
		dvMu.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	mech := s.verifyMech
	keyHandle := s.verifyKey
	s.verifyActive = false
	s.verifyData = nil
	dvMu.Unlock()

	return h.doVerify(ctx, r.SessionHandle, keyHandle, mech, r.Data, r.Signature)
}

func (h *PKCSHandler) handleVerifyUpdate(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r verifyUpdateReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	defer dvMu.Unlock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.verifyActive {
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	s.verifyData = append(s.verifyData, r.Part...)
	return nil, uint32(pkcs11types.CKR_OK)
}

func (h *PKCSHandler) handleVerifyFinal(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r verifyFinalReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	dvMu.Lock()
	s, ok := dvSessions[r.SessionHandle]
	if !ok || !s.verifyActive {
		dvMu.Unlock()
		return nil, uint32(pkcs11types.CKR_OPERATION_NOT_INITIALIZED)
	}
	mech := s.verifyMech
	keyHandle := s.verifyKey
	data := s.verifyData
	s.verifyActive = false
	s.verifyData = nil
	dvMu.Unlock()

	return h.doVerify(ctx, r.SessionHandle, keyHandle, mech, data, r.Signature)
}

// doVerify 取出公钥并执行验签。
func (h *PKCSHandler) doVerify(ctx context.Context, sid uint32, keyHandle pkcs11types.ObjectHandle,
	mech uint32, data, signature []byte) (interface{}, uint32) {

	sess, err := h.manager.GetSession(pkcs11types.SessionHandle(sid))
	if err != nil {
		return nil, uint32(pkcs11types.CKR_SESSION_HANDLE_INVALID)
	}
	pub, err := loadPublicKey(ctx, sess.Provider, keyHandle)
	if err != nil {
		slog.Warn("Verify: 加载公钥失败", "error", err)
		return nil, uint32(pkcs11types.CKR_KEY_HANDLE_INVALID)
	}

	hashAlg, prehashed, mechErr := mechToHash(mech)
	if mechErr != nil {
		return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
	}

	// 计算待验签摘要
	var digest []byte
	if hashAlg != 0 {
		hh := hashAlg.New()
		hh.Write(data)
		digest = hh.Sum(nil)
	} else {
		// 不带哈希的机制（如 CKM_ECDSA、CKM_RSA_PKCS）：data 即摘要
		digest = data
	}

	switch k := pub.(type) {
	case *rsa.PublicKey:
		if prehashed && hashAlg == 0 {
			// CKM_RSA_PKCS：不带哈希的 PKCS#1 v1.5 验证；data 应为 DigestInfo
			// 这里使用 VerifyPKCS1v15 with crypto.Hash(0) 不可行，回退为 SHA-256
			return nil, uint32(pkcs11types.CKR_MECHANISM_INVALID)
		}
		if err := rsa.VerifyPKCS1v15(k, hashAlg, digest, signature); err != nil {
			return nil, uint32(pkcs11types.CKR_SIGNATURE_INVALID)
		}
	case *ecdsa.PublicKey:
		// PKCS#11 ECDSA 签名格式为 r||s 拼接（每个固定长度）
		if !verifyECDSARaw(k, digest, signature) {
			return nil, uint32(pkcs11types.CKR_SIGNATURE_INVALID)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, signature) {
			return nil, uint32(pkcs11types.CKR_SIGNATURE_INVALID)
		}
	default:
		return nil, uint32(pkcs11types.CKR_KEY_TYPE_INCONSISTENT)
	}
	return nil, uint32(pkcs11types.CKR_OK)
}

// mechToHash 将 PKCS#11 mechanism 映射为 (crypto.Hash, prehashed)。
// hashAlg=0 表示不需要哈希（CKM_ECDSA / CKM_RSA_PKCS / CKM_EDDSA）。
func mechToHash(mech uint32) (crypto.Hash, bool, error) {
	switch mech {
	case ckmRSAPKCS:
		return 0, true, nil
	case ckmSHA1RSAPKCS, ckmECDSASHA1:
		return crypto.SHA1, false, nil
	case ckmSHA256RSAPKCS, ckmECDSASHA256:
		return crypto.SHA256, false, nil
	case ckmSHA384RSAPKCS, ckmECDSASHA384:
		return crypto.SHA384, false, nil
	case ckmSHA512RSAPKCS, ckmECDSASHA512:
		return crypto.SHA512, false, nil
	case ckmECDSA:
		return 0, true, nil
	case ckmEdDSA:
		return 0, true, nil
	default:
		return 0, false, fmt.Errorf("unsupported verify mechanism: 0x%X", mech)
	}
}

// verifyECDSARaw 对 r||s 格式的 ECDSA 签名做验证。
func verifyECDSARaw(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) == 2*keyBytes {
		r := new(big.Int).SetBytes(sig[:keyBytes])
		s := new(big.Int).SetBytes(sig[keyBytes:])
		return ecdsa.Verify(pub, digest, r, s)
	}
	// 兼容 ASN.1 DER 签名
	var asnSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &asnSig); err == nil {
		return ecdsa.Verify(pub, digest, asnSig.R, asnSig.S)
	}
	return false
}

// loadPublicKey 通过 SlotProvider 取对象的 CKA_VALUE 解析公钥。
// CKA_VALUE 既可能存有 X.509 证书，也可能存有 SubjectPublicKeyInfo DER。
func loadPublicKey(ctx context.Context, p interface {
	GetAttributes(ctx context.Context, handle pkcs11types.ObjectHandle, attrs []pkcs11types.AttributeType) ([]pkcs11types.Attribute, error)
}, handle pkcs11types.ObjectHandle) (interface{}, error) {
	attrs, err := p.GetAttributes(ctx, handle, []pkcs11types.AttributeType{
		pkcs11types.CKA_VALUE,
	})
	if err != nil {
		return nil, err
	}

	for _, a := range attrs {
		if a.Type != pkcs11types.CKA_VALUE || len(a.Value) == 0 {
			continue
		}
		// 优先按证书解析
		if cert, err := x509.ParseCertificate(a.Value); err == nil {
			return cert.PublicKey, nil
		}
		// 退化按 SubjectPublicKeyInfo 解析
		if pk, err := x509.ParsePKIXPublicKey(a.Value); err == nil {
			return pk, nil
		}
	}
	return nil, fmt.Errorf("无法从对象 %d 加载公钥", handle)
}

// ---- Random ----

type generateRandomReq struct {
	SessionHandle uint32 `json:"session_id"`
	Length        uint32 `json:"length"`
}

type generateRandomResp struct {
	Data []byte `json:"data"`
}

func (h *PKCSHandler) handleGenerateRandom(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r generateRandomReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	if r.Length == 0 || r.Length > 1<<20 {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	buf := make([]byte, r.Length)
	if _, err := rand.Read(buf); err != nil {
		return nil, uint32(pkcs11types.CKR_DEVICE_ERROR)
	}
	return &generateRandomResp{Data: buf}, uint32(pkcs11types.CKR_OK)
}

type seedRandomReq struct {
	SessionHandle uint32 `json:"session_id"`
	Seed          []byte `json:"seed"`
}

func (h *PKCSHandler) handleSeedRandom(ctx context.Context, req *Frame) (interface{}, uint32) {
	var r seedRandomReq
	if err := ParseRequest(req.Payload, &r); err != nil {
		return nil, uint32(pkcs11types.CKR_ARGUMENTS_BAD)
	}
	// crypto/rand 已自带操作系统级 CSPRNG，外部 seed 仅作记录。
	slog.Debug("收到 SeedRandom", "session", r.SessionHandle, "seed_len", len(r.Seed))
	return nil, uint32(pkcs11types.CKR_OK)
}
