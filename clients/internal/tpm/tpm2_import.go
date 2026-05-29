//go:build windows || linux

// Package tpm - 基于 go-tpm 的真实 TPM2 密钥导入后端。
//
// 本文件实现 TPM2_Import 流程，将外部 RSA/ECC 私钥导入 TPM 芯片内部，
// 使得后续签名/解密操作在 TPM 硬件中完成，私钥永不以明文出现在用户进程。
//
// 与 CNG/PCP 后端的区别：
//   - CNG/PCP 的 NCryptImportKey 对 Platform Crypto Provider 返回 NTE_NOT_SUPPORTED
//   - 本实现直接通过 TBS (Windows) 或 /dev/tpmrm0 (Linux) 操作 TPM2 命令
//   - 密钥由 SRK (Storage Root Key) 包装保护
//
// 使用方式：
//
//	provider, err := tpm.NewTPM2ImportProvider()
//	wrapped, pub, err := provider.ImportKeyToTPM(privDER, authValue)
//	handle, err := provider.LoadKeyTPM(wrapped, authValue)
//	sig, err := provider.SignTPM(handle, digest, scheme)
//	provider.FlushHandleTPM(handle)
//
// 注意事项：
//   - 需要 github.com/google/go-tpm 依赖
//   - Windows 上通过 TBS 访问 TPM，与 PCP 共享同一 TPM 设备
//   - 建议序列化 TPM 访问（避免与 PCP 并发冲突）
//   - SRK 使用 persistent handle 0x81000001（TCG 规范推荐值）
package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// srkPersistentHandle 是 SRK 的持久化句柄（TCG 规范推荐值）。
const srkPersistentHandle = 0x81000001

// tpm2ImportProvider 基于 go-tpm 的真实 TPM2 Provider 实现。
// 专门用于密钥导入场景（high-import-tpm 模式）。
type tpm2ImportProvider struct {
	mu sync.Mutex

	// loaded 存储已加载的 TPM 句柄映射
	loaded      map[LoadedHandle]tpm2LoadedState
	nextLoadedH uint32
}

// tpm2LoadedState 已加载密钥的状态。
type tpm2LoadedState struct {
	tpmHandle tpm2.TPMHandle // TPM 内部句柄
	alg       KeyAlg
}

// tpm2ImportedKey 是导入密钥的序列化格式，存入 WrappedKey.Private。
type tpm2ImportedKey struct {
	// TPM2B_PUBLIC 序列化
	Public []byte `json:"public"`
	// TPM2B_PRIVATE 序列化（由 TPM2_Import 返回，SRK 包装）
	Private []byte `json:"private"`
	// 密钥算法
	Alg KeyAlg `json:"alg"`
}

// NewTPM2ImportProvider 创建基于 go-tpm 的 TPM2 导入 Provider。
// 此 Provider 仅实现导入相关的方法（ImportKeyToTPM / LoadKeyTPM / SignTPM）。
// 完整 Provider 接口的其他方法（NV, Seal 等）仍走 CNG 或 sw-stub 后端。
func NewTPM2ImportProvider() (*tpm2ImportProvider, error) {
	// 验证 TPM 可用性
	dev, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("无法打开 TPM 设备: %w", err)
	}
	dev.Close()

	return &tpm2ImportProvider{
		loaded:      make(map[LoadedHandle]tpm2LoadedState),
		nextLoadedH: 0x80000000, // 避免与 CNG 后端的 handle 冲突
	}, nil
}

// ImportKeyToTPM 将外部私钥导入 TPM 芯片内部。
//
// 流程：
//  1. 打开 TPM 设备
//  2. 获取 SRK（Storage Root Key）作为父密钥
//  3. 构造 TPM2_Import 所需的 sensitive 数据和 public area
//  4. 执行 TPM2_Import → 获得 SRK 包装的 private blob
//  5. 验证：TPM2_Load → TPM2_FlushContext
//  6. 返回 WrappedKey（可持久化存储）
//
// 支持的密钥类型：RSA-2048/3072/4096, ECDSA-P256/P384
func (p *tpm2ImportProvider) ImportKeyToTPM(privDER []byte, authValue []byte) (*WrappedKey, crypto.PublicKey, error) {
	// 解析私钥
	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		// 尝试 PKCS#1
		if rsaKey, err2 := x509.ParsePKCS1PrivateKey(privDER); err2 == nil {
			privKey = rsaKey
		} else if ecKey, err3 := x509.ParseECPrivateKey(privDER); err3 == nil {
			privKey = ecKey
		} else {
			return nil, nil, fmt.Errorf("解析私钥失败: %w", err)
		}
	}

	dev, err := transport.OpenTPM()
	if err != nil {
		return nil, nil, fmt.Errorf("打开 TPM 失败: %w", err)
	}
	defer dev.Close()

	// 获取 SRK
	srkHandle, srkPub, err := p.getOrCreateSRK(dev)
	if err != nil {
		return nil, nil, fmt.Errorf("获取 SRK 失败: %w", err)
	}

	var pubArea tpm2.TPMTPublic
	var sensitive tpm2.TPMTSensitive
	var alg KeyAlg
	var pub crypto.PublicKey

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		pubArea, sensitive, alg, err = buildRSAImportParams(k, authValue)
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubArea, sensitive, alg, err = buildECCImportParams(k, authValue)
		pub = &k.PublicKey
	default:
		return nil, nil, fmt.Errorf("不支持的私钥类型: %T（TPM2_Import 仅支持 RSA/ECC）", privKey)
	}
	if err != nil {
		return nil, nil, err
	}

	// 执行 TPM2_Import
	importedPrivate, importedPublic, err := p.doImport(dev, srkHandle, srkPub, pubArea, sensitive)
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_Import 失败: %w", err)
	}

	// 验证：Load + Flush
	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: importedPrivate,
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](importedPublic),
	}.Execute(dev)
	if err != nil {
		return nil, nil, fmt.Errorf("TPM2_Load 验证失败: %w", err)
	}
	_, _ = (tpm2.FlushContext{FlushHandle: loadRsp.ObjectHandle}).Execute(dev)

	slog.Info("[TPM2/Import] 密钥导入 TPM 成功",
		"alg", string(alg), "verified", true)

	// 序列化
	ikJSON, _ := json.Marshal(tpm2ImportedKey{
		Public:  importedPublic,
		Private: importedPrivate.Buffer,
		Alg:     alg,
	})

	// 导出公钥 DER
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("序列化公钥失败: %w", err)
	}

	wk := &WrappedKey{
		Alg:        alg,
		Backend:    "tpm2-import",
		Public:     pubDER,
		Private:    ikJSON,
		AuthDigest: nvAuthDigest(authValue, []byte("tpm2-import")),
	}
	return wk, pub, nil
}

// LoadKeyTPM 将已导入的 wrapped key 加载到 TPM，返回会话句柄。
func (p *tpm2ImportProvider) LoadKeyTPM(wrapped *WrappedKey, authValue []byte) (LoadedHandle, error) {
	if wrapped.Backend != "tpm2-import" {
		return 0, fmt.Errorf("非 tpm2-import 后端的密钥: %s", wrapped.Backend)
	}

	var ik tpm2ImportedKey
	if err := json.Unmarshal(wrapped.Private, &ik); err != nil {
		return 0, fmt.Errorf("反序列化 imported key 失败: %w", err)
	}

	dev, err := transport.OpenTPM()
	if err != nil {
		return 0, fmt.Errorf("打开 TPM 失败: %w", err)
	}
	defer dev.Close()

	// 获取 SRK
	srkHandle, _, err := p.getOrCreateSRK(dev)
	if err != nil {
		return 0, fmt.Errorf("获取 SRK 失败: %w", err)
	}

	// Load
	loadRsp, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: srkHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: tpm2.TPM2BPrivate{Buffer: ik.Private},
		InPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](ik.Public),
	}.Execute(dev)
	if err != nil {
		return 0, fmt.Errorf("TPM2_Load 失败: %w", err)
	}

	p.mu.Lock()
	h := LoadedHandle(p.nextLoadedH)
	p.nextLoadedH++
	p.loaded[h] = tpm2LoadedState{
		tpmHandle: loadRsp.ObjectHandle,
		alg:       ik.Alg,
	}
	p.mu.Unlock()

	slog.Info("[TPM2/Import] LoadKey 完成",
		"handle", fmt.Sprintf("0x%X", uint32(h)),
		"tpm_handle", fmt.Sprintf("0x%X", uint32(loadRsp.ObjectHandle)),
		"alg", string(ik.Alg))

	return h, nil
}

// SignTPM 使用 TPM 内部的密钥进行签名。
// digest 必须是已经哈希过的值。
func (p *tpm2ImportProvider) SignTPM(h LoadedHandle, digest []byte, scheme SignScheme) ([]byte, error) {
	p.mu.Lock()
	state, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}

	dev, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("打开 TPM 失败: %w", err)
	}
	defer dev.Close()

	// 构造签名方案
	inScheme, err := signSchemeToTPM2(scheme, state.alg, len(digest))
	if err != nil {
		return nil, err
	}

	// 构造 validation ticket（表示 digest 来源于外部）
	validation := tpm2.TPMTTKHashCheck{
		Tag:       tpm2.TPMSTHashCheck,
		Hierarchy: tpm2.TPMRHNull,
	}

	signRsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: state.tpmHandle,
			Auth:   tpm2.PasswordAuth(nil), // 如需 authValue 可在此设置
		},
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		InScheme:   inScheme,
		Validation: validation,
	}.Execute(dev)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Sign 失败: %w", err)
	}

	// 解析签名结果
	return marshalTPM2Signature(signRsp.Signature, state.alg)
}

// DecryptTPM 使用 TPM 内部的 RSA 密钥进行 PKCS1v15 解密。
func (p *tpm2ImportProvider) DecryptTPM(h LoadedHandle, ciphertext []byte) ([]byte, error) {
	p.mu.Lock()
	state, ok := p.loaded[h]
	p.mu.Unlock()
	if !ok {
		return nil, ErrHandleNotLoaded
	}

	dev, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("打开 TPM 失败: %w", err)
	}
	defer dev.Close()

	// RSA PKCS1v15 解密
	decScheme := tpm2.TPMTRSADecrypt{
		Scheme: tpm2.TPMAlgRSAES,
	}

	rsp, err := tpm2.RSADecrypt{
		KeyHandle: tpm2.AuthHandle{
			Handle: state.tpmHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: ciphertext},
		InScheme:   decScheme,
	}.Execute(dev)
	if err != nil {
		return nil, fmt.Errorf("TPM2_RSA_Decrypt 失败: %w", err)
	}
	return rsp.Message.Buffer, nil
}

// FlushHandleTPM 释放 TPM 中已加载的密钥句柄。
func (p *tpm2ImportProvider) FlushHandleTPM(h LoadedHandle) error {
	p.mu.Lock()
	state, ok := p.loaded[h]
	delete(p.loaded, h)
	p.mu.Unlock()
	if !ok {
		return nil
	}

	dev, err := transport.OpenTPM()
	if err != nil {
		return fmt.Errorf("打开 TPM 失败: %w", err)
	}
	defer dev.Close()

	_, err = (tpm2.FlushContext{FlushHandle: state.tpmHandle}).Execute(dev)
	return err
}

// ---- 内部方法 ----

// getOrCreateSRK 获取 SRK（Storage Root Key）。
// 先尝试读取 persistent handle，不存在则创建并持久化。
func (p *tpm2ImportProvider) getOrCreateSRK(dev transport.TPM) (tpm2.TPMHandle, *tpm2.TPMTPublic, error) {
	persistHandle := tpm2.TPMHandle(srkPersistentHandle)

	// 尝试读取已持久化的 SRK 公钥
	readPubRsp, err := tpm2.ReadPublic{
		ObjectHandle: persistHandle,
	}.Execute(dev)
	if err == nil {
		// 已存在
		pub, err := readPubRsp.OutPublic.Contents()
		if err != nil {
			return 0, nil, err
		}
		return persistHandle, pub, nil
	}

	// 不存在，创建一个标准 RSA-2048 SRK
	slog.Info("[TPM2/Import] 创建 SRK (Storage Root Key)")

	createRsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(dev)
	if err != nil {
		return 0, nil, fmt.Errorf("TPM2_CreatePrimary(SRK) 失败: %w", err)
	}

	// 持久化到 0x81000001
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createRsp.ObjectHandle,
			Name:   createRsp.Name,
		},
		PersistentHandle: persistHandle,
	}.Execute(dev)
	if err != nil {
		// 如果持久化失败（可能权限不足），使用临时句柄
		slog.Warn("[TPM2/Import] SRK 持久化失败，使用临时句柄", "error", err)
		pub, _ := createRsp.OutPublic.Contents()
		return createRsp.ObjectHandle, pub, nil
	}

	// 刷掉临时句柄，使用持久化句柄
	_, _ = (tpm2.FlushContext{FlushHandle: createRsp.ObjectHandle}).Execute(dev)

	pub, _ := createRsp.OutPublic.Contents()
	slog.Info("[TPM2/Import] SRK 已持久化", "handle", fmt.Sprintf("0x%08X", srkPersistentHandle))
	return persistHandle, pub, nil
}

// doImport 执行 TPM2_Import 命令，将敏感数据用 SRK 包装。
//
// 对于"无保护"导入（innerWrapper=none, outerWrapper=none），
// 直接构造 duplicate 结构体传递给 TPM。
func (p *tpm2ImportProvider) doImport(
	dev transport.TPM,
	parentHandle tpm2.TPMHandle,
	parentPub *tpm2.TPMTPublic,
	objectPublic tpm2.TPMTPublic,
	sensitive tpm2.TPMTSensitive,
) (tpm2.TPM2BPrivate, []byte, error) {
	// 序列化 public area
	pubBytes := tpm2.Marshal(tpm2.New2B(objectPublic))

	// 对于明文导入（无 inner/outer wrapper），sensitive 直接放入 duplicate
	sensBytes := tpm2.Marshal(tpm2.New2B(sensitive))

	// 构造 Duplicate blob = TPM2B_SENSITIVE（TPM2_Import 的 duplicate 参数）
	// 当 encryptionKey 为空且 inSymSeed 为空时，duplicate 就是明文 sensitive
	importRsp, err := tpm2.Import{
		ParentHandle: tpm2.AuthHandle{
			Handle: parentHandle,
			Auth:   tpm2.PasswordAuth(nil),
		},
		EncryptionKey: tpm2.TPM2BData{},
		ObjectPublic:  tpm2.BytesAs2B[tpm2.TPMTPublic](pubBytes),
		Duplicate:     tpm2.TPM2BPrivate{Buffer: sensBytes},
		InSymSeed:     tpm2.TPM2BEncryptedSecret{},
		Symmetric: tpm2.TPMTSymDef{
			Algorithm: tpm2.TPMAlgNull,
		},
	}.Execute(dev)
	if err != nil {
		return tpm2.TPM2BPrivate{}, nil, err
	}

	return importRsp.OutPrivate, pubBytes, nil
}

// ---- RSA 参数构造 ----

func buildRSAImportParams(key *rsa.PrivateKey, authValue []byte) (tpm2.TPMTPublic, tpm2.TPMTSensitive, KeyAlg, error) {
	bits := key.N.BitLen()
	var alg KeyAlg
	switch {
	case bits <= 2048:
		alg = KeyAlgRSA2048
	case bits <= 3072:
		alg = KeyAlgRSA3072
	default:
		alg = KeyAlgRSA4096
	}

	// TPM public area
	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Decrypt:            true,
			FixedTPM:           false, // 导入的密钥不绑定 TPM
			FixedParent:        false,
			SensitiveDataOrigin: false, // 外部生成
			UserWithAuth:       true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull}, // 灵活 scheme
			KeyBits:   tpm2.TPMKeyBits(bits),
			Exponent:  uint32(key.PublicKey.E),
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{
			Buffer: key.N.Bytes(),
		}),
	}

	// TPM sensitive area：包含私钥的 prime p
	// TPM RSA 私钥格式只存储 p（第一个素数），不存完整的 d
	p := key.Primes[0].Bytes()
	sensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgRSA,
		AuthValue:     tpm2.TPM2BAuth{Buffer: authValue},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgRSA, &tpm2.TPM2BPrivateKeyRSA{
			Buffer: p,
		}),
	}

	return pubArea, sensitive, alg, nil
}

// ---- ECC 参数构造 ----

func buildECCImportParams(key *ecdsa.PrivateKey, authValue []byte) (tpm2.TPMTPublic, tpm2.TPMTSensitive, KeyAlg, error) {
	var curveID tpm2.TPMECCCurve
	var alg KeyAlg
	byteLen := (key.Curve.Params().BitSize + 7) / 8

	switch key.Curve {
	case elliptic.P256():
		curveID = tpm2.TPMECCNistP256
		alg = KeyAlgECP256
	case elliptic.P384():
		curveID = tpm2.TPMECCNistP384
		alg = KeyAlgECP384
	default:
		return tpm2.TPMTPublic{}, tpm2.TPMTSensitive{}, "", fmt.Errorf("不支持的 ECC 曲线: %v", key.Curve.Params().Name)
	}

	// 公钥坐标（填充到固定长度）
	xBytes := padToLen(key.PublicKey.X.Bytes(), byteLen)
	yBytes := padToLen(key.PublicKey.Y.Bytes(), byteLen)

	pubArea := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:           false,
			FixedParent:        false,
			SensitiveDataOrigin: false,
			UserWithAuth:       true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
			CurveID:   curveID,
			KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: xBytes},
			Y: tpm2.TPM2BECCParameter{Buffer: yBytes},
		}),
	}

	// 私钥标量 d
	dBytes := padToLen(key.D.Bytes(), byteLen)
	sensitive := tpm2.TPMTSensitive{
		SensitiveType: tpm2.TPMAlgECC,
		AuthValue:     tpm2.TPM2BAuth{Buffer: authValue},
		Sensitive: tpm2.NewTPMUSensitiveComposite(tpm2.TPMAlgECC, &tpm2.TPM2BECCParameter{
			Buffer: dBytes,
		}),
	}

	return pubArea, sensitive, alg, nil
}

// ---- 签名方案转换 ----

func signSchemeToTPM2(scheme SignScheme, alg KeyAlg, digestLen int) (tpm2.TPMTSigScheme, error) {
	switch scheme {
	case SignSchemeRSAPKCS1SHA256:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		}, nil
	case SignSchemeRSAPKCS1SHA384:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA384,
			}),
		}, nil
	case SignSchemeRSAPKCS1SHA512:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA512,
			}),
		}, nil
	case SignSchemeRSAPSSSHA256:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSAPSS, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		}, nil
	case SignSchemeECDSASHA256:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		}, nil
	case SignSchemeECDSASHA384:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA384,
			}),
		}, nil
	case SignSchemeECDSASHA512:
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA512,
			}),
		}, nil
	case SignSchemeRaw:
		// Raw 模式：根据 alg 和 digest 长度推断 scheme
		return inferRawScheme(alg, digestLen)
	default:
		return tpm2.TPMTSigScheme{}, fmt.Errorf("不支持的签名方案: %s", scheme)
	}
}

func inferRawScheme(alg KeyAlg, digestLen int) (tpm2.TPMTSigScheme, error) {
	hashAlg := tpm2.TPMAlgSHA256
	switch digestLen {
	case 20:
		hashAlg = tpm2.TPMAlgSHA1
	case 32:
		hashAlg = tpm2.TPMAlgSHA256
	case 48:
		hashAlg = tpm2.TPMAlgSHA384
	case 64:
		hashAlg = tpm2.TPMAlgSHA512
	}

	switch {
	case isRSAAlg(alg):
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSchemeHash{
				HashAlg: hashAlg,
			}),
		}, nil
	case isECCAlg(alg):
		return tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: hashAlg,
			}),
		}, nil
	default:
		return tpm2.TPMTSigScheme{}, fmt.Errorf("无法推断 raw scheme: alg=%s", alg)
	}
}

func isRSAAlg(alg KeyAlg) bool {
	return alg == KeyAlgRSA2048 || alg == KeyAlgRSA3072 || alg == KeyAlgRSA4096
}

func isECCAlg(alg KeyAlg) bool {
	return alg == KeyAlgECP256 || alg == KeyAlgECP384 || alg == KeyAlgECP521
}

// ---- 签名结果序列化 ----

// marshalTPM2Signature 将 TPM2 签名结构体转为字节数组。
// RSA → raw signature bytes
// ECDSA → ASN.1 DER 编码
func marshalTPM2Signature(sig tpm2.TPMTSignature, alg KeyAlg) ([]byte, error) {
	switch {
	case isRSAAlg(alg):
		rsaSig, err := sig.Signature.RSASSA()
		if err != nil {
			rsaPSS, err2 := sig.Signature.RSAPSS()
			if err2 != nil {
				return nil, fmt.Errorf("解析 RSA 签名失败: %w / %w", err, err2)
			}
			return rsaPSS.Sig.Buffer, nil
		}
		return rsaSig.Sig.Buffer, nil
	case isECCAlg(alg):
		ecSig, err := sig.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("解析 ECDSA 签名失败: %w", err)
		}
		// 转为 ASN.1 DER 格式
		r := new(big.Int).SetBytes(ecSig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecSig.SignatureS.Buffer)
		return marshalECDSAASN1(r, s), nil
	default:
		return nil, fmt.Errorf("不支持的签名算法: %s", alg)
	}
}

// marshalECDSAASN1 将 r, s 编码为 ASN.1 SEQUENCE { INTEGER r, INTEGER s }。
func marshalECDSAASN1(r, s *big.Int) []byte {
	rBytes := asn1Integer(r)
	sBytes := asn1Integer(s)
	seqLen := len(rBytes) + len(sBytes)
	var out []byte
	out = append(out, 0x30)
	out = appendASN1Len(out, seqLen)
	out = append(out, rBytes...)
	out = append(out, sBytes...)
	return out
}

func asn1Integer(n *big.Int) []byte {
	b := n.Bytes()
	// 高位为 1 时需要前置 0x00
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	var out []byte
	out = append(out, 0x02)
	out = appendASN1Len(out, len(b))
	out = append(out, b...)
	return out
}

func appendASN1Len(buf []byte, l int) []byte {
	if l < 128 {
		return append(buf, byte(l))
	}
	// 多字节长度
	var lenBytes []byte
	v := l
	for v > 0 {
		lenBytes = append([]byte{byte(v & 0xFF)}, lenBytes...)
		v >>= 8
	}
	buf = append(buf, byte(0x80|len(lenBytes)))
	buf = append(buf, lenBytes...)
	return buf
}

// ---- 工具函数 ----

// padToLen 左填充字节切片到指定长度。
func padToLen(b []byte, length int) []byte {
	if len(b) >= length {
		return b[len(b)-length:]
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}

// nvAuthDigest 已在 swstub.go 中定义，此处直接复用。
