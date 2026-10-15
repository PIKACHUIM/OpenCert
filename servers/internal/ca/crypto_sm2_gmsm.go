//go:build gmsm

// Package ca - SM2 国密算法真实实现（需 `-tags gmsm` 构建启用）。
//
// 依赖第三方库：github.com/tjfoc/gmsm
// 启用后 SM2 密钥生成将返回 *sm2.PrivateKey，其公钥类型 *sm2.PublicKey
// 兼容 crypto.Signer 接口，可用于签名。
//
// 注意：
//  1. Go 标准库 x509.CreateCertificate 不能直接签发 SM2 证书，
//     需要调用 gmsm 提供的 sm2.CreateCertificateToPem；
//  2. 本占位文件仅实现密钥生成；完整 SM2 证书链签发需要在
//     后续 Phase 中重构 issuer.go 的 CreateCertificate 调用。
package ca

import (
	"crypto"
	"crypto/rand"

	"github.com/tjfoc/gmsm/sm2"
)

// generateSM2Key 生成 SM2 P256 密钥对。
func generateSM2Key() (crypto.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// sm2Available 报告当前构建是否已启用 SM2。
func sm2Available() bool {
	return true
}
