//go:build windows

package certprop

import (
	"context"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"syscall"
	"unsafe"
)

// Windows CryptoAPI 常量
const (
	// 证书存储名称
	certStoreMY = "MY"

	// 编码类型
	x509ASNEncoding  = 0x00000001
	pkcs7ASNEncoding = 0x00010000
	encodingDefault  = x509ASNEncoding | pkcs7ASNEncoding

	// 存储标志
	certStoreProvSystem       = 10
	certSystemStoreCurrentUser = 0x00010000
	certStoreAddReplaceExisting = 3

	// 证书属性 ID
	certKeyProvInfoPropID = 2
	certFriendlyNamePropID = 11

	// 密钥规格
	atKeyExchange = 1
	atSignature   = 2

	// CNG KSP 密钥规格（表示使用 KSP 而非传统 CSP）
	certNCryptKeySpec = 0xFFFFFFFF

	// CSP 类型
	provRSAFull = 1

	// KSP 名称：使用 OpenCert 自定义 KSP
	// 该 KSP 通过 IPC 将签名/解密请求转发给 client-card 后端
	kspName = "OpenCert Key Storage Provider"
)

var (
	crypt32                          = syscall.NewLazyDLL("crypt32.dll")
	procCertOpenStore                = crypt32.NewProc("CertOpenStore")
	procCertCloseStore               = crypt32.NewProc("CertCloseStore")
	procCertAddEncodedCertToStore    = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertSetCertContextProperty   = crypt32.NewProc("CertSetCertificateContextProperty")
	procCertFindCertInStore          = crypt32.NewProc("CertFindCertificateInStore")
	procCertDeleteCertFromStore      = crypt32.NewProc("CertDeleteCertificateFromStore")
	procCertFreeCertContext          = crypt32.NewProc("CertFreeCertificateContext")
	procCertEnumCertsInStore         = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertGetCertContextProperty   = crypt32.NewProc("CertGetCertificateContextProperty")
	procCertDuplicateCertContext     = crypt32.NewProc("CertDuplicateCertificateContext")
)

// 证书查找类型
const (
	certFindSHA1Hash = 0x10000 | 1 // CERT_FIND_SHA1_HASH
)

// CRYPT_KEY_PROV_INFO 结构体（Windows API）
type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ParamCount    uint32
	Params        uintptr
	KeySpec       uint32
}

// CRYPT_DATA_BLOB 结构体
type cryptDataBlob struct {
	Size uint32
	Data *byte
}

// windowsPropagator 是 Windows 平台的证书传播实现。
type windowsPropagator struct{}

// New 创建 Windows 平台的证书传播器。
func New() Propagator {
	return &windowsPropagator{}
}

// Sync 将证书列表同步到 Windows MY 证书存储。
func (p *windowsPropagator) Sync(ctx context.Context, certs []CertInfo) (*SyncResult, error) {
	result := &SyncResult{}

	// 1. 获取当前系统中由 OpenCert 注册的证书指纹列表
	existingThumbs, err := p.listManagedCerts()
	if err != nil {
		logger().Warn("列举已注册证书失败，将执行全量添加", "error", err)
		existingThumbs = make(map[string]string) // thumbprint -> container_name
	}

	// 2. 构建目标证书指纹集合
	targetThumbs := make(map[string]CertInfo)
	for _, cert := range certs {
		if len(cert.CertDER) == 0 && cert.CertPEM != "" {
			der, err := pemToDER(cert.CertPEM)
			if err != nil {
				result.Errors++
				result.Details = append(result.Details, PropagateResult{
					CertUUID: cert.UUID, CommonName: cert.CommonName,
					Action: "error", Error: fmt.Sprintf("PEM 解码失败: %v", err),
				})
				continue
			}
			cert.CertDER = der
		}
		if len(cert.CertDER) == 0 {
			result.Skipped++
			result.Details = append(result.Details, PropagateResult{
				CertUUID: cert.UUID, CommonName: cert.CommonName,
				Action: "skipped", Error: "无证书内容",
			})
			continue
		}
		thumb := thumbprint(cert.CertDER)
		targetThumbs[thumb] = cert
	}

	// 3. 添加/更新证书
	for thumb, cert := range targetThumbs {
		if _, exists := existingThumbs[thumb]; exists {
			// 已存在，跳过
			delete(existingThumbs, thumb)
			result.Skipped++
			result.Details = append(result.Details, PropagateResult{
				CertUUID: cert.UUID, CommonName: cert.CommonName, Action: "skipped",
			})
			continue
		}

		if err := p.addCert(cert); err != nil {
			result.Errors++
			result.Details = append(result.Details, PropagateResult{
				CertUUID: cert.UUID, CommonName: cert.CommonName,
				Action: "error", Error: err.Error(),
			})
		} else {
			result.Added++
			result.Details = append(result.Details, PropagateResult{
				CertUUID: cert.UUID, CommonName: cert.CommonName, Action: "added",
			})
		}
	}

	// 4. 移除不再存在的证书（仅移除由 OpenCert 管理的）
	for thumb := range existingThumbs {
		if err := p.removeCertByThumbprint(thumb); err != nil {
			result.Errors++
			logger().Warn("移除旧证书失败", "thumbprint", thumb, "error", err)
		} else {
			result.Removed++
		}
	}

	logger().Info("证书同步完成",
		"added", result.Added, "removed", result.Removed,
		"skipped", result.Skipped, "errors", result.Errors)

	return result, nil
}

// Add 将单个证书添加到 Windows MY 证书存储。
func (p *windowsPropagator) Add(ctx context.Context, cert CertInfo) error {
	if len(cert.CertDER) == 0 && cert.CertPEM != "" {
		der, err := pemToDER(cert.CertPEM)
		if err != nil {
			return fmt.Errorf("PEM 解码失败: %w", err)
		}
		cert.CertDER = der
	}
	if len(cert.CertDER) == 0 {
		return fmt.Errorf("证书内容为空")
	}
	return p.addCert(cert)
}

// Remove 从 Windows MY 证书存储中移除指定 UUID 的证书。
func (p *windowsPropagator) Remove(ctx context.Context, certUUID string) error {
	store, err := openMYStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	// 遍历所有证书，找到容器名包含 certUUID 的证书并删除
	containerPrefix := ContainerPrefix + certUUID
	var certCtx uintptr

	for {
		certCtx, _ = enumCerts(store, certCtx)
		if certCtx == 0 {
			break
		}

		container := getCertContainerName(certCtx)
		if strings.Contains(container, containerPrefix) || strings.HasSuffix(container, certUUID) {
			// 复制上下文用于删除（枚举后原上下文会失效）
			dupCtx, _, _ := procCertDuplicateCertContext.Call(certCtx)
			if dupCtx != 0 {
				procCertDeleteCertFromStore.Call(dupCtx)
				logger().Info("已从 Windows 证书存储移除证书", "uuid", certUUID)
				return nil
			}
		}
	}

	return nil // 未找到也不报错
}

// RemoveAll 移除所有由 OpenCert 注册的证书。
func (p *windowsPropagator) RemoveAll(ctx context.Context) error {
	store, err := openMYStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	var toDelete []uintptr
	var certCtx uintptr

	for {
		certCtx, _ = enumCerts(store, certCtx)
		if certCtx == 0 {
			break
		}

		container := getCertContainerName(certCtx)
		if strings.HasPrefix(container, ContainerPrefix) {
			dupCtx, _, _ := procCertDuplicateCertContext.Call(certCtx)
			if dupCtx != 0 {
				toDelete = append(toDelete, dupCtx)
			}
		}
	}

	for _, ctx := range toDelete {
		procCertDeleteCertFromStore.Call(ctx)
	}

	if len(toDelete) > 0 {
		logger().Info("已移除所有 OpenCert 管理的证书", "count", len(toDelete))
	}
	return nil
}

// ---- 内部方法 ----

// addCert 将证书添加到 MY 存储并设置密钥容器属性。
func (p *windowsPropagator) addCert(cert CertInfo) error {
	store, err := openMYStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	// 添加证书到存储
	var certCtx uintptr
	ret, _, lastErr := procCertAddEncodedCertToStore.Call(
		store,
		uintptr(encodingDefault),
		uintptr(unsafe.Pointer(&cert.CertDER[0])),
		uintptr(len(cert.CertDER)),
		uintptr(certStoreAddReplaceExisting),
		uintptr(unsafe.Pointer(&certCtx)),
	)
	if ret == 0 {
		return fmt.Errorf("CertAddEncodedCertificateToStore 失败: %w", lastErr)
	}
	defer procCertFreeCertContext.Call(certCtx)

	// 设置友好名称
	friendlyName := fmt.Sprintf("OpenCert: %s", cert.CommonName)
	if err := setCertFriendlyName(certCtx, friendlyName); err != nil {
		logger().Warn("设置证书友好名称失败", "error", err)
	}

	// 设置 KeyProvInfo，关联到 OpenCert KSP。
	// OpenCert KSP DLL 会通过 IPC 将签名/解密请求转发给 client-card 后端。
	if cert.HasKey {
		containerName := cert.ContainerName()
		if err := setCertKeyProvInfo(certCtx, containerName, cert.KeyType); err != nil {
			logger().Warn("设置密钥容器关联失败", "error", err, "container", containerName)
		}
	}

	logger().Info("证书已添加到 Windows MY 存储",
		"cn", cert.CommonName, "uuid", cert.UUID, "has_key", cert.HasKey)
	return nil
}

// listManagedCerts 列出 MY 存储中由 OpenCert 管理的证书。
// 返回 map[thumbprint]containerName
func (p *windowsPropagator) listManagedCerts() (map[string]string, error) {
	store, err := openMYStore()
	if err != nil {
		return nil, err
	}
	defer closeStore(store)

	result := make(map[string]string)
	var certCtx uintptr

	for {
		certCtx, _ = enumCerts(store, certCtx)
		if certCtx == 0 {
			break
		}

		container := getCertContainerName(certCtx)
		if strings.HasPrefix(container, ContainerPrefix) {
			thumb := getCertThumbprint(certCtx)
			if thumb != "" {
				result[thumb] = container
			}
		}
	}

	return result, nil
}

// removeCertByThumbprint 按指纹从 MY 存储中删除证书。
func (p *windowsPropagator) removeCertByThumbprint(thumbHex string) error {
	store, err := openMYStore()
	if err != nil {
		return err
	}
	defer closeStore(store)

	var certCtx uintptr
	for {
		certCtx, _ = enumCerts(store, certCtx)
		if certCtx == 0 {
			break
		}
		if getCertThumbprint(certCtx) == thumbHex {
			dupCtx, _, _ := procCertDuplicateCertContext.Call(certCtx)
			if dupCtx != 0 {
				procCertDeleteCertFromStore.Call(dupCtx)
			}
			return nil
		}
	}
	return nil
}

// ---- Windows API 辅助函数 ----

// openMYStore 打开当前用户的 MY 证书存储。
func openMYStore() (uintptr, error) {
	storeName, _ := syscall.UTF16PtrFromString(certStoreMY)
	store, _, lastErr := procCertOpenStore.Call(
		uintptr(certStoreProvSystem),
		uintptr(encodingDefault),
		0,
		uintptr(certSystemStoreCurrentUser),
		uintptr(unsafe.Pointer(storeName)),
	)
	if store == 0 {
		return 0, fmt.Errorf("CertOpenStore 失败: %w", lastErr)
	}
	return store, nil
}

// closeStore 关闭证书存储。
func closeStore(store uintptr) {
	procCertCloseStore.Call(store, 0)
}

// enumCerts 枚举证书存储中的下一个证书。
func enumCerts(store uintptr, prev uintptr) (uintptr, error) {
	next, _, lastErr := procCertEnumCertsInStore.Call(store, prev)
	if next == 0 {
		return 0, lastErr
	}
	return next, nil
}

// setCertFriendlyName 设置证书的友好名称。
func setCertFriendlyName(certCtx uintptr, name string) error {
	nameUTF16, _ := syscall.UTF16FromString(name)
	blob := cryptDataBlob{
		Size: uint32(len(nameUTF16) * 2),
		Data: (*byte)(unsafe.Pointer(&nameUTF16[0])),
	}
	ret, _, lastErr := procCertSetCertContextProperty.Call(
		certCtx,
		uintptr(certFriendlyNamePropID),
		0,
		uintptr(unsafe.Pointer(&blob)),
	)
	if ret == 0 {
		return fmt.Errorf("设置友好名称失败: %w", lastErr)
	}
	return nil
}

// setCertKeyProvInfo 设置证书的密钥容器关联信息。
// 使用 Microsoft Smart Card Key Storage Provider (KSP) 作为提供程序，
// 这样 Windows 会通过 minidriver 架构来访问密钥。
func setCertKeyProvInfo(certCtx uintptr, containerName string, keyType string) error {
	containerUTF16, _ := syscall.UTF16PtrFromString(containerName)

	// 根据密钥类型选择合适的提供程序和密钥规格
	// 对于 CNG/KSP 模式，ProvType 必须为 0，KeySpec 使用 CERT_NCRYPT_KEY_SPEC
	provName := kspName
	provNameUTF16, _ := syscall.UTF16PtrFromString(provName)

	info := cryptKeyProvInfo{
		ContainerName: containerUTF16,
		ProvName:      provNameUTF16,
		ProvType:      0,                  // KSP 模式下 ProvType 必须为 0
		Flags:         0,
		ParamCount:    0,
		Params:        0,
		KeySpec:       certNCryptKeySpec,   // CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF
	}

	ret, _, lastErr := procCertSetCertContextProperty.Call(
		certCtx,
		uintptr(certKeyProvInfoPropID),
		0,
		uintptr(unsafe.Pointer(&info)),
	)
	if ret == 0 {
		return fmt.Errorf("设置 KeyProvInfo 失败: %w", lastErr)
	}
	return nil
}

// getCertContainerName 获取证书关联的密钥容器名称。
func getCertContainerName(certCtx uintptr) string {
	// 先获取属性大小
	var size uint32
	procCertGetCertContextProperty.Call(
		certCtx,
		uintptr(certKeyProvInfoPropID),
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if size == 0 {
		return ""
	}

	// 分配缓冲区并获取属性
	buf := make([]byte, size)
	ret, _, _ := procCertGetCertContextProperty.Call(
		certCtx,
		uintptr(certKeyProvInfoPropID),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ""
	}

	// 解析 CRYPT_KEY_PROV_INFO 结构体中的 ContainerName
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	if info.ContainerName == nil {
		return ""
	}
	return syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(info.ContainerName))[:])
}

// getCertThumbprint 获取证书的 SHA1 指纹（十六进制）。
func getCertThumbprint(certCtx uintptr) string {
	// CERT_CONTEXT 结构体前几个字段：
	// DWORD dwCertEncodingType
	// BYTE* pbCertEncoded
	// DWORD cbCertEncoded
	type certContext struct {
		EncodingType uint32
		EncodedCert  *byte
		EncodedLen   uint32
	}
	ctx := (*certContext)(unsafe.Pointer(certCtx))
	if ctx.EncodedCert == nil || ctx.EncodedLen == 0 {
		return ""
	}

	certBytes := unsafe.Slice(ctx.EncodedCert, ctx.EncodedLen)
	hash := sha1.Sum(certBytes)
	return fmt.Sprintf("%X", hash[:])
}

// ---- 工具函数 ----

// pemToDER 将 PEM 编码的证书转换为 DER。
func pemToDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解码 PEM 数据")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM 类型不是 CERTIFICATE: %s", block.Type)
	}
	return block.Bytes, nil
}

// thumbprint 计算证书 DER 的 SHA1 指纹。
func thumbprint(der []byte) string {
	hash := sha1.Sum(der)
	return fmt.Sprintf("%X", hash[:])
}

// 确保编译时不会因为 slog 未使用而报错
var _ = slog.Info
