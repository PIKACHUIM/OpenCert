// fido-go 是 OpenCert FIDO2 虚拟设备服务。
// 使用 virtual-fido 库通过 USB/IP 协议模拟 USB HID FIDO2 设备，
// 完全在用户态运行，无需内核驱动签名。
//
// 工作原理：
//
//	浏览器 WebAuthn
//	  → Windows webauthn.dll
//	  → usbip 虚拟 USB 总线（用户态驱动，一次性安装）
//	  → fido-go 进程（USB/IP 服务器，监听 :3240）
//	  → IPCCTAPProxy（CTAP2 CBOR 透传）
//	  → Named Pipe → client-card Go 后端
//
// 使用方法：
//
//	1. 安装 usbip 驱动（仅首次）：scripts\install_usbip.bat
//	2. 启动 client-card 后端
//	3. 运行 fido-go.exe
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/bulwarkid/virtual-fido/ctap_hid"
	"github.com/bulwarkid/virtual-fido/usb"
	"github.com/bulwarkid/virtual-fido/usbip"
	"github.com/bulwarkid/virtual-fido/util"

	"github.com/globaltrusts/fido-go/internal/client"
)

var (
	verbose  = flag.Bool("v", false, "启用详细日志")
	noAttach = flag.Bool("no-attach", false, "仅启动 USB/IP 服务器，不自动 attach（调试用）")
	usbipDir = flag.String("usbip-dir", "", "usbip 工具目录（默认：可执行文件同目录下的 usbip/）")
)

func main() {
	flag.Parse()

	// 配置日志级别
	if *verbose {
		util.SetLogLevel(util.LogLevelTrace)
	} else {
		util.SetLogLevel(util.LogLevelDebug)
	}
	util.SetLogOutput(os.Stdout)

	slog.Info("OpenCert FIDO2 虚拟设备启动")

	// 创建 IPC CTAP 代理（透传 CBOR 给 client-card）
	ctapProxy := client.NewIPCCTAPProxy()

	// 构建 virtual-fido 服务器栈：
	//   IPCCTAPProxy → CTAPHIDServer → USBDevice → USBIPServer
	// U2F 层使用空实现（返回不支持，避免 nil panic）
	ctapHIDServer := ctap_hid.NewCTAPHIDServer(ctapProxy, &noopU2FServer{})
	usbDevice := usb.NewUSBDevice(ctapHIDServer)
	server := usbip.NewUSBIPServer([]usbip.USBIPDevice{usbDevice})

	// 处理退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 启动 USB/IP 服务器（goroutine）
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		slog.Info("USB/IP 服务器启动（监听 :3240）")
		server.Start()
	}()

	// 等待服务器就绪后自动 attach
	if !*noAttach && runtime.GOOS == "windows" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			if err := attachUSBIP(*usbipDir); err != nil {
				slog.Error("USB/IP attach 失败", "error", err)
				slog.Warn("请手动运行: usbip.exe attach -r 127.0.0.1 -b 2-2")
			}
		}()
	}

	// 等待退出信号或服务器停止
	select {
	case <-sigCh:
		slog.Info("收到退出信号，正在关闭...")
	case <-serverDone:
		slog.Info("USB/IP 服务器已停止")
	}
}

// attachUSBIP 执行 usbip attach 命令，将虚拟设备挂载到 Windows。
func attachUSBIP(usbipDirOverride string) error {
	usbipExe := findUSBIPExe(usbipDirOverride)
	if usbipExe == "" {
		return fmt.Errorf("找不到 usbip.exe，请指定 --usbip-dir 参数")
	}

	slog.Info("执行 USB/IP attach", "exe", usbipExe)
	cmd := exec.Command(usbipExe, "attach", "-r", "127.0.0.1", "-b", "2-2")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("usbip attach 失败: %w", err)
	}
	slog.Info("USB/IP attach 成功，FIDO2 设备已就绪")
	return nil
}

// findUSBIPExe 查找 usbip.exe 的路径。
// 搜索顺序：
//  1. --usbip-dir 参数指定目录
//  2. 可执行文件同目录下的 usbip/
//  3. 可执行文件同目录（usbip.exe 直接放旁边）
//  4. 源码目录 bin/usbip/（开发调试用）
//  5. PATH
func findUSBIPExe(override string) string {
	candidates := []string{}

	if override != "" {
		candidates = append(candidates,
			filepath.Join(override, "usbip.exe"),
			override, // override 本身就是 usbip.exe 路径
		)
	}

	// 可执行文件目录
	if exeDir, err := filepath.Abs(filepath.Dir(os.Args[0])); err == nil {
		candidates = append(candidates,
			filepath.Join(exeDir, "usbip", "usbip.exe"),
			filepath.Join(exeDir, "usbip.exe"),
		)
	}

	// 源码目录（开发调试：GoLand 运行时 os.Args[0] 在临时目录）
	// 向上查找 bin/usbip/usbip.exe
	if srcDir, err := findProjectRoot(); err == nil {
		candidates = append(candidates,
			filepath.Join(srcDir, "bin", "usbip", "usbip.exe"),
		)
	}

	for _, p := range candidates {
		if fileExists(p) {
			return p
		}
	}

	// PATH 中查找
	if p, err := exec.LookPath("usbip.exe"); err == nil {
		return p
	}

	return ""
}

// findProjectRoot 从当前工作目录向上查找包含 go.mod 的目录。
func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("未找到 go.mod")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// noopU2FServer 是空的 U2F 服务器，返回「不支持」错误。
// 避免 CTAPHIDServer 在收到 U2F 消息时 nil panic。
type noopU2FServer struct{}

func (s *noopU2FServer) HandleMessage(data []byte) []byte {
	// U2F SW_INS_NOT_SUPPORTED = 0x6D00
	return []byte{0x6D, 0x00}
}
