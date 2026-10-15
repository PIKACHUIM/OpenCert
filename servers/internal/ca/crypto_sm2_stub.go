//go:build !gmsm

// Package ca - SM2 国密算法占位实现。
//
// 默认构建下（未启用 gmsm build tag）不链接第三方国密库，
// SM2 相关调用返回明确错误，提示开发者如何启用真实实现。
//
// 启用方式：
//  1. 引入依赖：`go get github.com/tjfoc/gmsm/sm2`
//  2. 以 `-tags gmsm` 构建：`go build -tags gmsm ./...`
//
// 启用后，将链接 crypto_sm2_gmsm.go 中的真实 SM2 密钥生成、签名、验签实现。
package ca

import (
	"crypto"
	"fmt"
)

// generateSM2Key 默认构建下返回错误；启用 gmsm tag 后由 crypto_sm2_gmsm.go 提供实现。
func generateSM2Key() (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("SM2 算法未启用，请使用 '-tags gmsm' 构建并引入 github.com/tjfoc/gmsm")
}

// sm2Available 报告当前构建是否已启用 SM2。
func sm2Available() bool {
	return false
}
