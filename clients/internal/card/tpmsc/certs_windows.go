//go:build windows

package tpmsc

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows"
)

// CardCertificate 是一张 VSC 上可被 Windows 使用的证书（来自当前用户“个人”存储）。
type CardCertificate struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	SHA1          string    `json:"sha1"`
	ContainerName string    `json:"container_name"`
	ProviderName  string    `json:"provider_name"`
	CertPEM       string    `json:"cert_pem"`
	SSHPublicKey  string    `json:"ssh_public_key,omitempty"`
}

const (
	certKeyProvInfoPropID = 2
	certNameSimpleDisplay = 4
)

var (
	crypt32DLL                 = windows.NewLazySystemDLL("crypt32.dll")
	procCertGetContextProperty = crypt32DLL.NewProc("CertGetCertificateContextProperty")
)

type certKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParamCnt  uint32
	_             uint32
	ProvParam     uintptr
	KeySpec       uint32
	_             uint32
}

// ListCardCertificates 枚举当前用户“个人”存储中、密钥容器指向指定 VSC 读卡器的证书。
//
// 这是零 OpenSC 方案的口径：只能看到已经进入 Windows 证书存储、且私钥挂在卡上的证书；
// 卡内未导入 Windows 存储的孤立证书不可见。返回空列表不代表卡上没有证书。
func ListCardCertificates(readerName string) ([]CardCertificate, error) {
	if strings.TrimSpace(readerName) == "" {
		return nil, ErrReaderUnavailable
	}
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return nil, fmt.Errorf("打开当前用户证书存储失败: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var result []CardCertificate
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			break
		}
		prev = ctx
		cert, ok := readCardCertificate(ctx, readerName)
		if !ok {
			continue
		}
		result = append(result, cert)
	}
	return result, nil
}

func readCardCertificate(ctx *windows.CertContext, readerName string) (CardCertificate, bool) {
	prov, ok := readKeyProvInfo(ctx)
	if !ok {
		return CardCertificate{}, false
	}
	container := windows.UTF16PtrToString(prov.ContainerName)
	provider := windows.UTF16PtrToString(prov.ProvName)
	if container == "" {
		return CardCertificate{}, false
	}
	// KSP 容器形如 \\.\Microsoft Virtual Smart Card 0\<uuid>；CSP 只存容器名。
	matchesReader := strings.Contains(strings.ToLower(container), strings.ToLower(readerName))
	isSmartCardProvider := strings.Contains(strings.ToLower(provider), "smart card") ||
		strings.EqualFold(provider, SmartCardKSPProviderName)
	if !matchesReader && !isSmartCardProvider {
		return CardCertificate{}, false
	}
	der, err := certificateDER(ctx)
	if err != nil {
		return CardCertificate{}, false
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return CardCertificate{}, false
	}
	sum := sha1.Sum(der)
	sshKey := ""
	if pk, err := ssh.NewPublicKey(parsed.PublicKey); err == nil {
		sshKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " opencert:" + parsed.Subject.CommonName
	}
	return CardCertificate{
		Subject:       parsed.Subject.String(),
		Issuer:        parsed.Issuer.String(),
		SerialNumber:  parsed.SerialNumber.Text(16),
		NotBefore:     parsed.NotBefore,
		NotAfter:      parsed.NotAfter,
		SHA1:          strings.ToUpper(hex.EncodeToString(sum[:])),
		ContainerName: container,
		ProviderName:  provider,
		CertPEM:       string(pemEncodeCert(der)),
		SSHPublicKey:  sshKey,
	}, true
}

func readKeyProvInfo(ctx *windows.CertContext) (*certKeyProvInfo, bool) {
	var size uint32
	result, _, _ := procCertGetContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certKeyProvInfoPropID,
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 || size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	result, _, _ = procCertGetContextProperty.Call(
		uintptr(unsafe.Pointer(ctx)),
		certKeyProvInfoPropID,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if result == 0 {
		return nil, false
	}
	return (*certKeyProvInfo)(unsafe.Pointer(&buf[0])), true
}

// certificateDER 返回证书上下文中已编码的 DER 数据副本。
func certificateDER(ctx *windows.CertContext) ([]byte, error) {
	if ctx.EncodedCert == nil || ctx.Length == 0 || ctx.Length > 1<<20 {
		return nil, fmt.Errorf("证书上下文缺少有效的 DER 数据")
	}
	der := make([]byte, ctx.Length)
	copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
	return der, nil
}

func pemEncodeCert(der []byte) []byte {
	const begin = "-----BEGIN CERTIFICATE-----\r\n"
	const end = "\r\n-----END CERTIFICATE-----\r\n"
	b64 := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	out.WriteString(begin)
	for i := 0; i < len(b64); i += 64 {
		j := i + 64
		if j > len(b64) {
			j = len(b64)
		}
		out.WriteString(b64[i:j])
		out.WriteString("\r\n")
	}
	out.WriteString(end)
	return []byte(out.String())
}

// ImportPFXToCard 通过 certutil 把 PFX 导入 VSC。
//
// 受 Windows Base CSP 限制，仅支持 RSA 1024/2048 + SHA1/256 的单证书 PFX；
// 导入过程中会由 Windows 自己弹出卡片 PIN 对话框，本函数不读取、不缓存 PIN。
func ImportPFXToCard(ctx context.Context, readerName string, pfx []byte, password string) error {
	if len(pfx) == 0 {
		return fmt.Errorf("PFX 内容为空")
	}
	if strings.TrimSpace(readerName) == "" {
		return ErrReaderUnavailable
	}
	file, err := os.CreateTemp("", "opencert-*.pfx")
	if err != nil {
		return fmt.Errorf("创建临时 PFX 文件失败: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("设置临时文件权限失败: %w", err)
	}
	if _, err := file.Write(pfx); err != nil {
		file.Close()
		return fmt.Errorf("写入临时 PFX 失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭临时 PFX 失败: %w", err)
	}

	cmd := exec.CommandContext(ctx, "certutil",
		"-csp", "Microsoft Base Smart Card Crypto Provider",
		"-p", password,
		"-importpfx", path,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if len(msg) > 400 {
			msg = msg[:400]
		}
		if msg == "" {
			return fmt.Errorf("导入 PFX 失败: %w", err)
		}
		return fmt.Errorf("导入 PFX 失败: %s", msg)
	}
	return nil
}
