// Package pki - 宽松证书解析支持
//
// Go 1.23+ 标准库对 Certificate Policies 扩展（OID 2.5.29.32）中的非标准
// qualifier 检查较严，导致部分合法证书解析失败。本文件提供一种轻量的
// "扩展剥离" 方案：在标准库解析失败时，从 DER 中移除特定扩展后再次解析。
//
// 我们只用于读取证书字段（subject/issuer/有效期/SAN 等），不用于签名验证，
// 因此剥离扩展不会影响信息提取。如果需要验证签名，必须使用原始 Raw。
package pki

import (
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// oidCertPolicies 是 X.509 Certificate Policies 扩展的 OID: 2.5.29.32。
// DER 编码字节为 0x55 0x1D 0x20 (3 字节)。
var oidCertPoliciesDER = []byte{0x55, 0x1D, 0x20}

// ParseCertLenientStripping 尝试用标准库解析；失败则剥离 Certificate Policies 扩展后重试。
// 注意：剥离后的 Raw 不再有效，调用方不应将返回证书的 Raw 用于签名验证。
// 但 Subject/Issuer/SAN/有效期/扩展 等字段都是真实的。
func ParseCertLenientStripping(derData []byte) (*x509.Certificate, error) {
	return parseCertLenientStripping(derData)
}

func parseCertLenientStripping(derData []byte) (*x509.Certificate, error) {
	// 先尝试标准库
	cert, err := x509.ParseCertificate(derData)
	if err == nil {
		return cert, nil
	}
	origErr := err

	// 剥离 Certificate Policies 扩展后重试
	stripped, stripErr := stripExtensionsByOID(derData, [][]byte{oidCertPoliciesDER})
	if stripErr != nil {
		return nil, fmt.Errorf("标准库解析失败: %w; 剥离扩展也失败: %v", origErr, stripErr)
	}
	if len(stripped) == 0 {
		return nil, origErr
	}
	cert2, err2 := x509.ParseCertificate(stripped)
	if err2 != nil {
		return nil, fmt.Errorf("标准库解析失败: %w; 剥离 Certificate Policies 后仍失败: %v", origErr, err2)
	}
	// 保留原始 Raw 字节，但解析结果使用剥离后的版本
	cert2.Raw = derData
	return cert2, nil
}

// stripExtensionsByOID 从 X.509 证书 DER 中移除指定 OID 的扩展，并重新构建证书 DER。
// targetOIDs 是要移除的扩展 OID 的 DER 编码（不含 OID tag/length，仅 OID 字节内容）。
//
// X.509 证书结构（RFC 5280）:
//
//	Certificate  ::=  SEQUENCE  {
//	     tbsCertificate       TBSCertificate,
//	     signatureAlgorithm   AlgorithmIdentifier,
//	     signatureValue       BIT STRING  }
//
//	TBSCertificate  ::=  SEQUENCE  {
//	     version         [0]  EXPLICIT Version DEFAULT v1,
//	     serialNumber         CertificateSerialNumber,
//	     signature            AlgorithmIdentifier,
//	     issuer               Name,
//	     validity             Validity,
//	     subject              Name,
//	     subjectPublicKeyInfo SubjectPublicKeyInfo,
//	     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//	     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//	     extensions      [3]  EXPLICIT Extensions OPTIONAL  }
//
//	Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
//	Extension  ::=  SEQUENCE  {
//	     extnID      OBJECT IDENTIFIER,
//	     critical    BOOLEAN DEFAULT FALSE,
//	     extnValue   OCTET STRING  }
func stripExtensionsByOID(certDER []byte, targetOIDs [][]byte) ([]byte, error) {
	input := cryptobyte.String(certDER)

	// 读取最外层 Certificate SEQUENCE
	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 Certificate SEQUENCE")
	}

	// 读取 TBSCertificate SEQUENCE（保留原始字节用于重建）
	var tbs cryptobyte.String
	var tbsRaw cryptobyte.String
	if !cert.ReadASN1Element(&tbsRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 TBSCertificate")
	}
	tbsCopy := cryptobyte.String(tbsRaw)
	if !tbsCopy.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 TBSCertificate 内容")
	}

	// 读取 signatureAlgorithm 和 signatureValue（整段保留）
	var sigAlgRaw cryptobyte.String
	if !cert.ReadASN1Element(&sigAlgRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 signatureAlgorithm")
	}
	var sigValRaw cryptobyte.String
	if !cert.ReadASN1Element(&sigValRaw, cryptobyte_asn1.BIT_STRING) {
		return nil, errors.New("无法读取 signatureValue")
	}

	// 解析 TBSCertificate 内部各字段，定位到 extensions
	// version [0] EXPLICIT
	if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		var versionRaw cryptobyte.String
		if !tbs.ReadASN1Element(&versionRaw, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, errors.New("无法读取 version")
		}
	}
	// serialNumber
	var serialRaw cryptobyte.String
	if !tbs.ReadASN1Element(&serialRaw, cryptobyte_asn1.INTEGER) {
		return nil, errors.New("无法读取 serialNumber")
	}
	// signature AlgorithmIdentifier
	var tbsSigAlgRaw cryptobyte.String
	if !tbs.ReadASN1Element(&tbsSigAlgRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 TBS signature alg")
	}
	// issuer Name
	var issuerRaw cryptobyte.String
	if !tbs.ReadASN1Element(&issuerRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 issuer")
	}
	// validity
	var validityRaw cryptobyte.String
	if !tbs.ReadASN1Element(&validityRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 validity")
	}
	// subject
	var subjectRaw cryptobyte.String
	if !tbs.ReadASN1Element(&subjectRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 subject")
	}
	// SPKI
	var spkiRaw cryptobyte.String
	if !tbs.ReadASN1Element(&spkiRaw, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("无法读取 SubjectPublicKeyInfo")
	}

	// 可选字段 issuerUniqueID [1] IMPLICIT, subjectUniqueID [2] IMPLICIT
	var issuerUIDRaw, subjectUIDRaw cryptobyte.String
	if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		if !tbs.ReadASN1Element(&issuerUIDRaw, cryptobyte_asn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("无法读取 issuerUniqueID")
		}
	}
	if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		if !tbs.ReadASN1Element(&subjectUIDRaw, cryptobyte_asn1.Tag(2).ContextSpecific()) {
			return nil, errors.New("无法读取 subjectUniqueID")
		}
	}

	// extensions [3] EXPLICIT Extensions
	var newExtensionsRaw []byte
	if tbs.PeekASN1Tag(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
		var extWrapper cryptobyte.String
		if !tbs.ReadASN1(&extWrapper, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
			return nil, errors.New("无法读取 extensions [3]")
		}
		var extSeq cryptobyte.String
		if !extWrapper.ReadASN1(&extSeq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("无法读取 extensions SEQUENCE")
		}

		// 遍历每个 Extension，过滤掉指定 OID
		var keptExtensions []byte
		for !extSeq.Empty() {
			var extRaw cryptobyte.String
			if !extSeq.ReadASN1Element(&extRaw, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("无法读取 Extension")
			}
			// 解析 OID 判断是否需要过滤
			extInner := cryptobyte.String(extRaw)
			var extBody cryptobyte.String
			if !extInner.ReadASN1(&extBody, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("无法读取 Extension body")
			}
			var oidBytes cryptobyte.String
			if !extBody.ReadASN1(&oidBytes, cryptobyte_asn1.OBJECT_IDENTIFIER) {
				return nil, errors.New("无法读取 Extension OID")
			}
			if oidMatchesAny([]byte(oidBytes), targetOIDs) {
				continue // 跳过此扩展
			}
			keptExtensions = append(keptExtensions, []byte(extRaw)...)
		}

		if len(keptExtensions) > 0 {
			// 重新构建 [3] EXPLICIT SEQUENCE OF Extension
			var b cryptobyte.Builder
			b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddBytes(keptExtensions)
				})
			})
			built, err := b.Bytes()
			if err != nil {
				return nil, fmt.Errorf("重建 extensions 失败: %w", err)
			}
			newExtensionsRaw = built
		}
	} else {
		// 没有 extensions 字段，原始证书也没有，无需处理
		return nil, errors.New("证书无 extensions 字段，剥离无效")
	}

	// 重建 TBSCertificate
	var tbsBuilder cryptobyte.Builder
	tbsBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// 重新组装各字段
		// 注意：tbsCopy/tbs 已被消耗，需要从原始 tbsRaw 重新解析以获取 version 字节
		inner := cryptobyte.String(tbsRaw)
		var tbsInner cryptobyte.String
		if !inner.ReadASN1(&tbsInner, cryptobyte_asn1.SEQUENCE) {
			b.SetError(errors.New("重建 TBS 时解析失败"))
			return
		}
		// version
		if tbsInner.PeekASN1Tag(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
			var v cryptobyte.String
			tbsInner.ReadASN1Element(&v, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific())
			b.AddBytes(v)
		}
		// serial
		var s cryptobyte.String
		tbsInner.ReadASN1Element(&s, cryptobyte_asn1.INTEGER)
		b.AddBytes(s)
		// sig alg
		var sa cryptobyte.String
		tbsInner.ReadASN1Element(&sa, cryptobyte_asn1.SEQUENCE)
		b.AddBytes(sa)
		// issuer
		var iss cryptobyte.String
		tbsInner.ReadASN1Element(&iss, cryptobyte_asn1.SEQUENCE)
		b.AddBytes(iss)
		// validity
		var val cryptobyte.String
		tbsInner.ReadASN1Element(&val, cryptobyte_asn1.SEQUENCE)
		b.AddBytes(val)
		// subject
		var sub cryptobyte.String
		tbsInner.ReadASN1Element(&sub, cryptobyte_asn1.SEQUENCE)
		b.AddBytes(sub)
		// spki
		var sp cryptobyte.String
		tbsInner.ReadASN1Element(&sp, cryptobyte_asn1.SEQUENCE)
		b.AddBytes(sp)
		// optional UIDs
		if tbsInner.PeekASN1Tag(cryptobyte_asn1.Tag(1).ContextSpecific()) {
			var u cryptobyte.String
			tbsInner.ReadASN1Element(&u, cryptobyte_asn1.Tag(1).ContextSpecific())
			b.AddBytes(u)
		}
		if tbsInner.PeekASN1Tag(cryptobyte_asn1.Tag(2).ContextSpecific()) {
			var u cryptobyte.String
			tbsInner.ReadASN1Element(&u, cryptobyte_asn1.Tag(2).ContextSpecific())
			b.AddBytes(u)
		}
		// extensions（已过滤）
		if len(newExtensionsRaw) > 0 {
			b.AddBytes(newExtensionsRaw)
		}
	})
	newTBS, err := tbsBuilder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("构建新 TBSCertificate 失败: %w", err)
	}

	// 重建外层 Certificate
	var certBuilder cryptobyte.Builder
	certBuilder.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddBytes(sigAlgRaw)
		b.AddBytes(sigValRaw)
	})
	return certBuilder.Bytes()
}

// oidMatchesAny 判断 OID 字节序列是否与目标列表中任一项匹配。
func oidMatchesAny(oid []byte, targets [][]byte) bool {
	for _, t := range targets {
		if bytesEqual(oid, t) {
			return true
		}
	}
	return false
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
