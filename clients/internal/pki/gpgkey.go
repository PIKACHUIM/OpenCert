// Package pki - gpgkey.go：OpenPGP V4 公钥与 SubjectPublicKeyInfo 互转，及 keyid/fingerprint。
//
// 设计目标：在不引入 golang.org/x/crypto/openpgp（已弃用）的前提下，提供：
//   1) RFC 4880 §12.2 V4 公钥指纹（SHA-1 over 0x99 || len(2B) || pubkey packet body）
//   2) 由 V4 fingerprint 派生的 64-bit keyid（fingerprint 末 8 字节）
//   3) RSA / Ed25519 / ECDSA(P-256/384/521) 公钥的 OpenPGP 包体打包，足够生成正确指纹
//
// 注意：本实现仅覆盖"枚举所需"的属性映射，不进行 OpenPGP 签名/加密。
// 完整 OpenPGP 操作请使用第三方库（如 protonmail/go-crypto）。
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OpenPGP V4 fingerprint 强制使用 SHA-1
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// GPGV4PacketBody 构建 OpenPGP V4 公钥包体（不含包头），用于派生 fingerprint。
//
// 报文体格式（RFC 4880 §5.5.2 V4）：
//   1B    version=4
//   4B    创建时间（Unix 秒，大端）
//   1B    公钥算法 ID
//   ...   算法相关 MPI 序列
func GPGV4PacketBody(pub interface{}, createdAt time.Time) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(0x04)
	tBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tBuf, uint32(createdAt.Unix()))
	buf.Write(tBuf)

	switch k := pub.(type) {
	case *rsa.PublicKey:
		buf.WriteByte(0x01) // algo: RSA (encrypt+sign)
		writeMPI(&buf, k.N.Bytes())
		// e 转为字节
		eBytes := bigEndianUint(uint64(k.E))
		writeMPI(&buf, eBytes)
	case ed25519.PublicKey:
		buf.WriteByte(0x16) // algo: EdDSA (22)
		// OID for Ed25519: 1.3.6.1.4.1.11591.15.1
		oid := []byte{0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}
		buf.Write(oid)
		// 公钥 MPI：0x40 || 32-byte 公钥 (RFC 4880bis)
		raw := append([]byte{0x40}, []byte(k)...)
		writeMPI(&buf, raw)
	case *ecdsa.PublicKey:
		buf.WriteByte(0x13) // algo: ECDSA
		var oid []byte
		switch k.Curve {
		case elliptic.P256():
			// 1.2.840.10045.3.1.7
			oid = []byte{0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
		case elliptic.P384():
			// 1.3.132.0.34
			oid = []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
		case elliptic.P521():
			// 1.3.132.0.35
			oid = []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
		default:
			return nil, fmt.Errorf("不支持的 ECDSA 曲线: %s", k.Curve.Params().Name)
		}
		buf.Write(oid)
		// 未压缩点 0x04 || X || Y
		coordLen := (k.Curve.Params().BitSize + 7) / 8
		x := k.X.Bytes()
		y := k.Y.Bytes()
		raw := make([]byte, 1+2*coordLen)
		raw[0] = 0x04
		copy(raw[1+coordLen-len(x):1+coordLen], x)
		copy(raw[1+2*coordLen-len(y):], y)
		writeMPI(&buf, raw)
	default:
		return nil, fmt.Errorf("不支持的 GPG 公钥类型: %T", pub)
	}
	return buf.Bytes(), nil
}

// GPGFingerprint 计算 RFC 4880 V4 fingerprint：SHA-1(0x99 || len_2B || body)。
func GPGFingerprint(pub interface{}, createdAt time.Time) ([]byte, error) {
	body, err := GPGV4PacketBody(pub, createdAt)
	if err != nil {
		return nil, err
	}
	h := sha1.New() //nolint:gosec
	h.Write([]byte{0x99})
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(body)))
	h.Write(lb)
	h.Write(body)
	return h.Sum(nil), nil
}

// GPGKeyIDFromFingerprint 从 V4 fingerprint 派生 64-bit keyid（取末 8 字节）。
func GPGKeyIDFromFingerprint(fp []byte) []byte {
	if len(fp) < 8 {
		return nil
	}
	out := make([]byte, 8)
	copy(out, fp[len(fp)-8:])
	return out
}

// GPGFingerprintHex 返回大写十六进制（每 4 字符空格分隔）的 fingerprint，便于 UI 展示。
func GPGFingerprintHex(fp []byte) string {
	const hexd = "0123456789ABCDEF"
	var sb strings.Builder
	for i, b := range fp {
		if i > 0 && i%2 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteByte(hexd[b>>4])
		sb.WriteByte(hexd[b&0x0f])
	}
	return sb.String()
}

// GPGPublicKeyToPKIX 将 GPG 公钥（V4 包体）转换为 SubjectPublicKeyInfo DER。
// 当前仅支持 RSA、Ed25519、ECDSA(P-256/384/521)；其他算法返回错误。
func GPGPublicKeyToPKIX(packetBody []byte) ([]byte, error) {
	pub, err := parseV4PacketBody(packetBody)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// GPGPublicKeyFromPKIX 将 PKIX 公钥编码为 V4 包体。
func GPGPublicKeyFromPKIX(spkiDER []byte, createdAt time.Time) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return nil, fmt.Errorf("解析 PKIX 公钥失败: %w", err)
	}
	return GPGV4PacketBody(pub, createdAt)
}

// ---- 内部工具 ----

func writeMPI(buf *bytes.Buffer, raw []byte) {
	// RFC 4880 §3.2 MPI：2 字节 bit length，再写紧凑的二进制数。
	bitLen := bitLength(raw)
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(bitLen))
	buf.Write(lb)
	buf.Write(raw)
}

func bitLength(b []byte) int {
	for i, v := range b {
		if v == 0 {
			continue
		}
		// 找到第一个非零字节
		bits := (len(b) - i) * 8
		for shift := 7; shift >= 0; shift-- {
			if v>>uint(shift) != 0 {
				return bits - (7 - shift)
			}
		}
	}
	return 0
}

func bigEndianUint(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	// 去除前导零字节
	i := 0
	for i < len(out)-1 && out[i] == 0 {
		i++
	}
	return out[i:]
}

// parseV4PacketBody 仅处理本文件可生成的 4 种算法（RSA/EdDSA/ECDSA-P256/384/521）。
func parseV4PacketBody(body []byte) (interface{}, error) {
	if len(body) < 6 || body[0] != 0x04 {
		return nil, fmt.Errorf("非 V4 OpenPGP 公钥包")
	}
	// body[1:5] = createdAt
	algo := body[5]
	rest := body[6:]
	switch algo {
	case 0x01: // RSA
		n, r, err := readMPI(rest)
		if err != nil {
			return nil, err
		}
		e, _, err := readMPI(r)
		if err != nil {
			return nil, err
		}
		var ev int
		for _, b := range e {
			ev = (ev << 8) | int(b)
		}
		k := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ev}
		return k, nil
	case 0x16: // EdDSA
		if len(rest) < 1 {
			return nil, fmt.Errorf("EdDSA 包体过短")
		}
		oidLen := int(rest[0])
		if len(rest) < 1+oidLen {
			return nil, fmt.Errorf("EdDSA OID 长度错误")
		}
		mpi, _, err := readMPI(rest[1+oidLen:])
		if err != nil {
			return nil, err
		}
		if len(mpi) != 33 || mpi[0] != 0x40 {
			return nil, fmt.Errorf("EdDSA 公钥格式错误")
		}
		return ed25519.PublicKey(mpi[1:]), nil
	case 0x13: // ECDSA
		if len(rest) < 1 {
			return nil, fmt.Errorf("ECDSA 包体过短")
		}
		oidLen := int(rest[0])
		if len(rest) < 1+oidLen {
			return nil, fmt.Errorf("ECDSA OID 长度错误")
		}
		oid := rest[1 : 1+oidLen]
		curve, err := curveFromOID(oid)
		if err != nil {
			return nil, err
		}
		mpi, _, err := readMPI(rest[1+oidLen:])
		if err != nil {
			return nil, err
		}
		if len(mpi) < 1 || mpi[0] != 0x04 {
			return nil, fmt.Errorf("ECDSA 公钥应为未压缩点")
		}
		coordLen := (curve.Params().BitSize + 7) / 8
		if len(mpi) != 1+2*coordLen {
			return nil, fmt.Errorf("ECDSA 公钥长度不匹配")
		}
		x := new(big.Int).SetBytes(mpi[1 : 1+coordLen])
		y := new(big.Int).SetBytes(mpi[1+coordLen:])
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("不支持的 GPG 算法 0x%02x", algo)
	}
}

func readMPI(b []byte) (mpi []byte, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("MPI 头不足")
	}
	bitLen := binary.BigEndian.Uint16(b[:2])
	byteLen := (int(bitLen) + 7) / 8
	if len(b) < 2+byteLen {
		return nil, nil, fmt.Errorf("MPI 数据不足")
	}
	return b[2 : 2+byteLen], b[2+byteLen:], nil
}

func curveFromOID(oid []byte) (elliptic.Curve, error) {
	switch {
	case bytes.Equal(oid, []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}):
		return elliptic.P256(), nil
	case bytes.Equal(oid, []byte{0x2B, 0x81, 0x04, 0x00, 0x22}):
		return elliptic.P384(), nil
	case bytes.Equal(oid, []byte{0x2B, 0x81, 0x04, 0x00, 0x23}):
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("不支持的 ECDSA OID")
}
