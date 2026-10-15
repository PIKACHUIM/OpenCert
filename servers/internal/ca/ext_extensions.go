// Package ca - 证书扩展构造器：Netscape / Microsoft CSP / 自定义 ASN.1 扩展。
//
// 参考资料：
//   - Netscape Cert Type (2.16.840.1.113730.1.1)：RFC 2459 附录提及的历史扩展
//   - Netscape Comment    (2.16.840.1.113730.1.13)
//   - Netscape Base URL   (2.16.840.1.113730.1.2)
//   - Netscape CA Policy URL (2.16.840.1.113730.1.8)
//   - Netscape SSL Server Name (2.16.840.1.113730.1.12)
//   - Microsoft Cert Template Name (1.3.6.1.4.1.311.20.2)
//   - Microsoft Cert Template V2   (1.3.6.1.4.1.311.21.7)
//   - Microsoft CA Version         (1.3.6.1.4.1.311.21.1)
//   - Microsoft Application Policies (1.3.6.1.4.1.311.21.10)
package ca

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"crypto/x509/pkix"
)

// 预定义 OID（Netscape）
var (
	oidNetscapeCertType        = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	oidNetscapeBaseURL         = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 2}
	oidNetscapeRevocationURL   = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 3}
	oidNetscapeCARevocationURL = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 4}
	oidNetscapeCertRenewalURL  = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 7}
	oidNetscapeCAPolicyURL     = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 8}
	oidNetscapeSSLServerName   = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 12}
	oidNetscapeComment         = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}

	// Microsoft CSP / AD CS
	oidMSCertTemplateName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
	oidMSCAVersion        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 1}
)

// NetscapeConfig 描述 Netscape 扩展配置。
type NetscapeConfig struct {
	// cert_type 位图：bit0=SSL Client, bit1=SSL Server, bit2=S/MIME,
	// bit3=Object Signing, bit5=SSL CA, bit6=S/MIME CA, bit7=Object Signing CA
	// 典型值：client=128(0x80)、server=64(0x40)、ca=176(0xB0)。
	CertType        *int   `json:"cert_type"`
	Comment         string `json:"comment"`
	BaseURL         string `json:"base_url"`
	RevocationURL   string `json:"revocation_url"`
	CARevocationURL string `json:"ca_revocation_url"`
	CertRenewalURL  string `json:"cert_renewal_url"`
	CAPolicyURL     string `json:"ca_policy_url"`
	SSLServerName   string `json:"ssl_server_name"`
}

// CSPConfig 描述 Microsoft CSP / AD CS 证书模板扩展。
type CSPConfig struct {
	TemplateName string `json:"template_name"`
	CAVersion    string `json:"ca_version"` // 形如 "V1.0" 或原始整数（如 "0"）
}

// customASN1Ext 描述单个自定义 ASN.1 扩展。
// ValueHex 与 ValueStr 任选其一；ValueHex 优先。
type customASN1Ext struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	ValueHex string `json:"value_hex"` // 原始 DER 字节的 hex 编码
	ValueStr string `json:"value_str"` // 作为 UTF8String 包装
}

// buildNetscapeExtensions 解析 NetscapeConfig JSON 并返回对应的 pkix.Extension 列表。
// 每个非空字段映射到独立的扩展（使用官方 Netscape OID）。字符串类型编码为 IA5String。
func buildNetscapeExtensions(cfgJSON string) ([]pkix.Extension, error) {
	var cfg NetscapeConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return nil, fmt.Errorf("解析 Netscape 配置失败: %w", err)
	}

	var exts []pkix.Extension

	// cert_type：BIT STRING
	if cfg.CertType != nil {
		der, err := asn1.Marshal(asn1.BitString{
			Bytes:     []byte{byte(*cfg.CertType)},
			BitLength: 8,
		})
		if err == nil {
			exts = append(exts, pkix.Extension{Id: oidNetscapeCertType, Critical: false, Value: der})
		}
	}

	// 字符串类字段：IA5String
	appendIA5 := func(oid asn1.ObjectIdentifier, v string) {
		if v == "" {
			return
		}
		der, err := asn1.MarshalWithParams(v, "ia5")
		if err != nil {
			return
		}
		exts = append(exts, pkix.Extension{Id: oid, Critical: false, Value: der})
	}
	appendIA5(oidNetscapeComment, cfg.Comment)
	appendIA5(oidNetscapeBaseURL, cfg.BaseURL)
	appendIA5(oidNetscapeRevocationURL, cfg.RevocationURL)
	appendIA5(oidNetscapeCARevocationURL, cfg.CARevocationURL)
	appendIA5(oidNetscapeCertRenewalURL, cfg.CertRenewalURL)
	appendIA5(oidNetscapeCAPolicyURL, cfg.CAPolicyURL)
	appendIA5(oidNetscapeSSLServerName, cfg.SSLServerName)

	return exts, nil
}

// buildCSPExtensions 解析 CSP JSON 并返回 Microsoft 证书模板相关扩展。
// TemplateName 以 BMPString 形式编码（Windows 习惯）。
func buildCSPExtensions(cfgJSON string) ([]pkix.Extension, error) {
	var cfg CSPConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return nil, fmt.Errorf("解析 CSP 配置失败: %w", err)
	}

	var exts []pkix.Extension

	// Template Name：BMPString（UTF-16BE）
	if cfg.TemplateName != "" {
		bmp := utf16BigEndian(cfg.TemplateName)
		// 0x1e = BMPString tag
		der := append([]byte{0x1e, byte(len(bmp))}, bmp...)
		exts = append(exts, pkix.Extension{Id: oidMSCertTemplateName, Critical: false, Value: der})
	}

	// CA Version：INTEGER
	if cfg.CAVersion != "" {
		// 将 "V1.0" 或纯数字解析为整数；无法解析时跳过
		var ver int
		if _, err := fmt.Sscanf(cfg.CAVersion, "V%d", &ver); err != nil {
			if _, err := fmt.Sscanf(cfg.CAVersion, "%d", &ver); err != nil {
				ver = 0
			}
		}
		if der, err := asn1.Marshal(ver); err == nil {
			exts = append(exts, pkix.Extension{Id: oidMSCAVersion, Critical: false, Value: der})
		}
	}

	return exts, nil
}

// buildCustomASN1Extensions 解析自定义 ASN.1 扩展 JSON 数组。
// 每项包含 oid、critical 和 value_hex/value_str；ValueHex 直接作为扩展值；
// ValueStr 作为 UTF8String 包装后作为扩展值。
func buildCustomASN1Extensions(arrJSON string) ([]pkix.Extension, error) {
	var arr []customASN1Ext
	if err := json.Unmarshal([]byte(arrJSON), &arr); err != nil {
		return nil, fmt.Errorf("解析自定义 ASN.1 扩展失败: %w", err)
	}

	var exts []pkix.Extension
	for _, item := range arr {
		if item.OID == "" {
			continue
		}
		oid, err := parseOID(item.OID)
		if err != nil {
			continue
		}
		var value []byte
		if item.ValueHex != "" {
			v, err := hex.DecodeString(item.ValueHex)
			if err != nil {
				continue
			}
			value = v
		} else if item.ValueStr != "" {
			// 包装为 UTF8String
			v, err := asn1.MarshalWithParams(item.ValueStr, "utf8")
			if err != nil {
				continue
			}
			value = v
		} else {
			continue
		}
		exts = append(exts, pkix.Extension{Id: oid, Critical: item.Critical, Value: value})
	}
	return exts, nil
}

// utf16BigEndian 将 UTF-8 字符串转为 UTF-16BE 字节序列（BMPString 用）。
func utf16BigEndian(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		if r > 0xFFFF {
			// 超出 BMP，退化为 '?'（BMPString 限制）
			out = append(out, 0x00, 0x3F)
			continue
		}
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}
