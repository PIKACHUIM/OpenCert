//go:build windows

package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CNG 常量（部分未在 x/sys/windows 中导出）。
const (
	ncryptPlatformProvider = "Microsoft Platform Crypto Provider"
	ncryptSoftwareProvider = "Microsoft Software Key Storage Provider"

	bcryptRSAAlg       = "RSA"
	bcryptECDSAP256Alg = "ECDSA_P256"
	bcryptECDSAP384Alg = "ECDSA_P384"
	bcryptECDSAP521Alg = "ECDSA_P521"

	ncryptLengthProperty       = "Length"
	ncryptExportPolicyProperty = "Export Policy"
	ncryptKeyUsageProperty     = "Key Usage"

	ncryptAllowNothingExport = 0x00000000
	ncryptSigningFlag        = 0x00000002
	ncryptDecryptFlag        = 0x00000001

	bcryptPadPKCS1 = 0x00000002
	bcryptPadOAEP  = 0x00000004
	bcryptPadPSS   = 0x00000008

	nteBadKeyset = 0x80090016
	nteNotFound  = 0x80090011
	nteExists    = 0x8009000F
)

// BCRYPT_PKCS1_PADDING_INFO
type bcryptPKCS1PaddingInfo struct {
	pszAlgId *uint16
}

// BCRYPT_PSS_PADDING_INFO
type bcryptPSSPaddingInfo struct {
	pszAlgId *uint16
	cbSalt   uint32
}

// BCRYPT_OAEP_PADDING_INFO
type bcryptOAEPPaddingInfo struct {
	pszAlgId *uint16
	pbLabel  *byte
	cbLabel  uint32
}

var (
	ncryptDLL = windows.NewLazySystemDLL("ncrypt.dll")

	procNCryptOpenStorageProvider = ncryptDLL.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncryptDLL.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = ncryptDLL.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncryptDLL.NewProc("NCryptFinalizeKey")
	procNCryptOpenKey             = ncryptDLL.NewProc("NCryptOpenKey")
	procNCryptSignHash            = ncryptDLL.NewProc("NCryptSignHash")
	procNCryptDecrypt             = ncryptDLL.NewProc("NCryptDecrypt")
	procNCryptDeleteKey           = ncryptDLL.NewProc("NCryptDeleteKey")
	procNCryptExportKey           = ncryptDLL.NewProc("NCryptExportKey")
	procNCryptFreeObject          = ncryptDLL.NewProc("NCryptFreeObject")
	procNCryptGetProperty         = ncryptDLL.NewProc("NCryptGetProperty")
)

type cngImpl struct {
	hProv    uintptr
	provName string
	isTPM    bool
}

// newTPMImpl 返回 Windows 平台的 CNG 实现。
func newTPMImpl() tpmImpl { return &cngImpl{} }

func (c *cngImpl) Open(soft bool) error {
	name := ncryptPlatformProvider
	if soft {
		name = ncryptSoftwareProvider
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var hProv uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(namePtr)),
		0,
	)
	if r != 0 {
		if !soft {
			return fmt.Errorf("打开 TPM 提供程序失败（0x%08X）：本机可能没有可用的 TPM 2.0，或 TPM 未在 BIOS 中启用；"+
				"如需先验证流程，可在存储区域配置中把提供程序改为 software", r)
		}
		return fmt.Errorf("打开 CNG 提供程序 %s 失败: 0x%08X", name, r)
	}
	c.hProv = hProv
	c.provName = name
	c.isTPM = !soft
	return nil
}

func (c *cngImpl) Detail() string {
	if c.isTPM {
		return "CNG / " + ncryptPlatformProvider + "（TPM 内生成与运算）"
	}
	return "CNG / " + ncryptSoftwareProvider + "（系统密钥库）"
}

func (c *cngImpl) Health() error {
	if c.hProv == 0 {
		return fmt.Errorf("CNG 提供程序未打开")
	}
	return nil
}

func (c *cngImpl) Close() error {
	if c.hProv != 0 {
		procNCryptFreeObject.Call(c.hProv)
		c.hProv = 0
	}
	return nil
}

func (c *cngImpl) Delete(name string) error {
	hKey, err := c.openKey(name)
	if err != nil {
		return err
	}
	r, _, _ := procNCryptDeleteKey.Call(hKey, 0)
	if r != 0 {
		procNCryptFreeObject.Call(hKey)
		return fmt.Errorf("删除 CNG 密钥 %s 失败: 0x%08X", name, r)
	}
	return nil
}

func (c *cngImpl) PublicKeyDER(name string) ([]byte, error) {
	hKey, err := c.openKey(name)
	if err != nil {
		return nil, err
	}
	defer procNCryptFreeObject.Call(hKey)
	alg, err := c.keyAlgName(hKey)
	if err != nil {
		return nil, err
	}
	return exportPublicKey(hKey, alg)
}

func (c *cngImpl) CreateKey(keyType, name string, exportable bool) (string, []byte, error) {
	if c.hProv == 0 {
		return "", nil, fmt.Errorf("CNG 提供程序未打开")
	}
	algID, bits, isRSA, err := keyAlgToCNG(keyType)
	if err != nil {
		return "", nil, err
	}
	// 名称唯一化，避免 NTE_EXISTS
	keyName := fmt.Sprintf("%s-%s", name, randSuffix())
	namePtr, err := windows.UTF16PtrFromString(keyName)
	if err != nil {
		return "", nil, err
	}
	algPtr, err := windows.UTF16PtrFromString(algID)
	if err != nil {
		return "", nil, err
	}

	var hKey uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(
		c.hProv,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(algPtr)),
		uintptr(unsafe.Pointer(namePtr)),
		0, 0,
	)
	if r != 0 {
		if uint32(r) == nteExists {
			return "", nil, fmt.Errorf("CNG 密钥容器 %s 已存在，请更换前缀", keyName)
		}
		return "", nil, fmt.Errorf("创建 CNG 密钥失败（%s/%s）: 0x%08X", algID, keyName, r)
	}

	if bits > 0 {
		c.setProperty(hKey, ncryptLengthProperty, bits)
	}
	if !exportable {
		c.setProperty(hKey, ncryptExportPolicyProperty, ncryptAllowNothingExport)
	}
	usage := uint32(ncryptSigningFlag)
	if isRSA {
		usage |= ncryptDecryptFlag
	}
	c.setProperty(hKey, ncryptKeyUsageProperty, usage)

	r, _, _ = procNCryptFinalizeKey.Call(hKey, 0)
	if r != 0 {
		procNCryptFreeObject.Call(hKey)
		return "", nil, fmt.Errorf("完成 CNG 密钥创建失败: 0x%08X", r)
	}

	pubDER, err := exportPublicKey(hKey, algID)
	procNCryptFreeObject.Call(hKey)
	if err != nil {
		// 回滚，避免留下无法使用的密钥
		_ = c.Delete(keyName)
		return "", nil, err
	}
	return keyName, pubDER, nil
}

func (c *cngImpl) Sign(name string, scheme signScheme, digest []byte, keyType string) ([]byte, error) {
	hKey, err := c.openKey(name)
	if err != nil {
		return nil, err
	}
	defer procNCryptFreeObject.Call(hKey)
	return signHash(hKey, scheme, digest)
}

func (c *cngImpl) Decrypt(name string, ciphertext []byte, oaep bool) ([]byte, error) {
	hKey, err := c.openKey(name)
	if err != nil {
		return nil, err
	}
	defer procNCryptFreeObject.Call(hKey)
	return decryptHash(hKey, ciphertext, oaep)
}

func (c *cngImpl) openKey(name string) (uintptr, error) {
	if c.hProv == 0 {
		return 0, fmt.Errorf("CNG 提供程序未打开")
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var hKey uintptr
	r, _, _ := procNCryptOpenKey.Call(
		c.hProv,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(namePtr)),
		0, 0,
	)
	if r != 0 {
		if uint32(r) == nteNotFound {
			return 0, fmt.Errorf("未找到 TPM/CNG 密钥 %s（可能已被删除，或换到了另一台机器）", name)
		}
		return 0, fmt.Errorf("打开 CNG 密钥 %s 失败: 0x%08X", name, r)
	}
	return hKey, nil
}

func (c *cngImpl) setProperty(hKey uintptr, prop string, value uint32) {
	propPtr, err := windows.UTF16PtrFromString(prop)
	if err != nil {
		return
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	procNCryptSetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(propPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		4,
		0,
	)
}

// keyAlgName 读取密钥的算法名称。
func (c *cngImpl) keyAlgName(hKey uintptr) (string, error) {
	algPtr, err := windows.UTF16PtrFromString("Algorithm Name")
	if err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	var outLen uint32
	r, _, _ := procNCryptGetProperty.Call(
		hKey,
		uintptr(unsafe.Pointer(algPtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&outLen)),
		0,
	)
	if r != 0 {
		return "", fmt.Errorf("读取 CNG 密钥算法失败: 0x%08X", r)
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buf[0]))), nil
}

// ---- 密钥算法 ----

func keyAlgToCNG(keyType string) (algID string, bits uint32, isRSA bool, err error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "rsa1024":
		return bcryptRSAAlg, 1024, true, nil
	case "rsa2048", "":
		return bcryptRSAAlg, 2048, true, nil
	case "rsa3072":
		return bcryptRSAAlg, 3072, true, nil
	case "rsa4096":
		return bcryptRSAAlg, 4096, true, nil
	case "ec256", "p256":
		return bcryptECDSAP256Alg, 0, false, nil
	case "ec384", "p384":
		return bcryptECDSAP384Alg, 0, false, nil
	case "ec521", "p521":
		return bcryptECDSAP521Alg, 0, false, nil
	default:
		return "", 0, false, fmt.Errorf("TPM 后端不支持密钥类型 %s（支持 rsa2048/3072/4096 与 ec256/384/521）", keyType)
	}
}

// ---- 签名与解密 ----

func signHash(hKey uintptr, scheme signScheme, digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("待签名摘要为空")
	}
	var (
		paddingInfo uintptr
		flags       uintptr
		keepAlive   any
	)
	if scheme.RSA {
		switch {
		case scheme.PSS:
			algName, err := hashAlgName(scheme.Hash)
			if err != nil {
				return nil, err
			}
			algPtr, _ := windows.UTF16PtrFromString(algName)
			info := &bcryptPSSPaddingInfo{pszAlgId: algPtr, cbSalt: uint32(len(digest))}
			paddingInfo = uintptr(unsafe.Pointer(info))
			flags = bcryptPadPSS
			keepAlive = info
		default:
			algName, err := hashAlgName(scheme.Hash)
			if err != nil {
				return nil, err
			}
			algPtr, _ := windows.UTF16PtrFromString(algName)
			info := &bcryptPKCS1PaddingInfo{pszAlgId: algPtr}
			paddingInfo = uintptr(unsafe.Pointer(info))
			flags = bcryptPadPKCS1
			keepAlive = info
		}
	}

	var sigLen uint32
	r, _, _ := procNCryptSignHash.Call(
		hKey,
		paddingInfo,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0, 0,
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash 取长度失败: 0x%08X（请确认算法与密钥类型匹配）", r)
	}
	sig := make([]byte, sigLen)
	r, _, _ = procNCryptSignHash.Call(
		hKey,
		paddingInfo,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])),
		uintptr(sigLen),
		uintptr(unsafe.Pointer(&sigLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash 失败: 0x%08X", r)
	}
	_ = keepAlive
	out := sig[:sigLen]

	// CNG 的 ECDSA 输出是 r||s；本项目软件的 ECDSA 签名同样是 r||s，保持一致。
	return out, nil
}

func decryptHash(hKey uintptr, ciphertext []byte, oaep bool) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("密文为空")
	}
	var (
		paddingInfo uintptr
		flags       uintptr
		keepAlive   any
	)
	if oaep {
		algPtr, _ := windows.UTF16PtrFromString("SHA256")
		info := &bcryptOAEPPaddingInfo{pszAlgId: algPtr}
		paddingInfo = uintptr(unsafe.Pointer(info))
		flags = bcryptPadOAEP
		keepAlive = info
	} else {
		flags = bcryptPadPKCS1
	}

	var outLen uint32
	r, _, _ := procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		paddingInfo,
		0, 0,
		uintptr(unsafe.Pointer(&outLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt 取长度失败: 0x%08X", r)
	}
	out := make([]byte, outLen)
	r, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&ciphertext[0])),
		uintptr(len(ciphertext)),
		paddingInfo,
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(outLen),
		uintptr(unsafe.Pointer(&outLen)),
		flags,
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptDecrypt 失败: 0x%08X", r)
	}
	_ = keepAlive
	return out[:outLen], nil
}

func hashAlgName(name string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "SHA1":
		return "SHA1", nil
	case "SHA256":
		return "SHA256", nil
	case "SHA384":
		return "SHA384", nil
	case "SHA512":
		return "SHA512", nil
	default:
		return "", fmt.Errorf("CNG/TPM 不支持摘要算法 %s", name)
	}
}

// ---- 公钥导出 ----

func exportPublicKey(hKey uintptr, algID string) ([]byte, error) {
	blobType := "RSAPUBLICBLOB"
	if strings.HasPrefix(algID, "ECDSA_") {
		blobType = "ECCPUBLICBLOB"
	}
	blobPtr, err := windows.UTF16PtrFromString(blobType)
	if err != nil {
		return nil, err
	}
	var blobLen uint32
	r, _, _ := procNCryptExportKey.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(blobPtr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("导出 CNG 公钥长度失败: 0x%08X", r)
	}
	blob := make([]byte, blobLen)
	r, _, _ = procNCryptExportKey.Call(
		hKey, 0,
		uintptr(unsafe.Pointer(blobPtr)),
		0,
		uintptr(unsafe.Pointer(&blob[0])),
		uintptr(blobLen),
		uintptr(unsafe.Pointer(&blobLen)),
		0,
	)
	if r != 0 {
		return nil, fmt.Errorf("导出 CNG 公钥失败: 0x%08X", r)
	}
	return cngBlobToPKIX(blob[:blobLen], algID)
}

// cngBlobToPKIX 把 CNG 公钥 blob 转为标准 SubjectPublicKeyInfo DER。
func cngBlobToPKIX(blob []byte, algID string) ([]byte, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("CNG 公钥 blob 过短（%d 字节）", len(blob))
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	switch {
	case magic == 0x31415352: // "RSA1"
		if len(blob) < 24 {
			return nil, fmt.Errorf("RSA 公钥 blob 头部过短")
		}
		cbPubExp := binary.LittleEndian.Uint32(blob[8:12])
		cbModulus := binary.LittleEndian.Uint32(blob[12:16])
		start := uint32(24)
		if uint32(len(blob)) < start+cbPubExp+cbModulus {
			return nil, fmt.Errorf("RSA 公钥 blob 数据截断")
		}
		exp := new(big.Int).SetBytes(blob[start : start+cbPubExp])
		mod := new(big.Int).SetBytes(blob[start+cbPubExp : start+cbPubExp+cbModulus])
		pub := &rsa.PublicKey{N: mod, E: int(exp.Int64())}
		return x509.MarshalPKIXPublicKey(pub)
	case magic == 0x31534345 || magic == 0x33534345 || magic == 0x35534345:
		cbKey := binary.LittleEndian.Uint32(blob[4:8])
		start := uint32(8)
		if uint32(len(blob)) < start+2*cbKey {
			return nil, fmt.Errorf("EC 公钥 blob 数据截断")
		}
		x := new(big.Int).SetBytes(blob[start : start+cbKey])
		y := new(big.Int).SetBytes(blob[start+cbKey : start+2*cbKey])
		var curve elliptic.Curve
		switch cbKey {
		case 32:
			curve = elliptic.P256()
		case 48:
			curve = elliptic.P384()
		case 66:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("不支持的 EC 曲线长度: %d", cbKey)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return x509.MarshalPKIXPublicKey(pub)
	default:
		return nil, fmt.Errorf("未知的 CNG 公钥 blob 类型: 0x%08X", magic)
	}
}
