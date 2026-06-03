//go:build windows

// Package client 实现 Windows 平台的 PIN 输入对话框。
// 使用 Win32 API 创建自定义对话框：ComboBox 选择卡片 + Edit 输入 PIN。
package client

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procCreateWindowExW     = user32.NewProc("CreateWindowExW")
	procDefWindowProcW      = user32.NewProc("DefWindowProcW")
	procRegisterClassExW    = user32.NewProc("RegisterClassExW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procUpdateWindow        = user32.NewProc("UpdateWindow")
	procGetMessageW         = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessageW    = user32.NewProc("DispatchMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procSendMessageW        = user32.NewProc("SendMessageW")
	procSetFocus            = user32.NewProc("SetFocus")
	procGetDlgCtrlID        = user32.NewProc("GetDlgCtrlID")
	procSetWindowTextW      = user32.NewProc("SetWindowTextW")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procIsDialogMessageW    = user32.NewProc("IsDialogMessageW")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procSetWindowPos        = user32.NewProc("SetWindowPos")
	procEnableWindow        = user32.NewProc("EnableWindow")

	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")

	gdi32            = syscall.NewLazyDLL("gdi32.dll")
	procGetStockObject = gdi32.NewProc("GetStockObject")
)

// Win32 常量
const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsVisible      = 0x10000000
	wsChild        = 0x40000000
	wsTabStop      = 0x00010000
	wsGroup        = 0x00020000
	wsClipChildren = 0x02000000
	wsBorder       = 0x00800000
	wsVScroll      = 0x00200000

	wsExClientEdge = 0x00000200

	esPassword  = 0x0020
	esAutoHScroll = 0x0080

	cbsDropDownList = 0x0003
	cbsHasStrings   = 0x0200

	bsPushButton  = 0x00000000
	bsDefPushButton = 0x00000001

	ssLeft = 0x00000000

	wmCreate   = 0x0001
	wmDestroy  = 0x0002
	wmClose    = 0x0010
	wmCommand  = 0x0111
	wmSetFont  = 0x0030
	wmSetFocus = 0x0007

	cbAddString    = 0x0143
	cbSetCurSel    = 0x014E
	cbGetCurSel    = 0x0147

	bnClicked = 0

	swShow = 5

	smCXScreen = 0
	smCYScreen = 1

	defaultGUIFont = 17

	idOK     = 1
	idCancel = 2
	idCombo  = 100
	idEdit   = 101
	idLabel1 = 102
	idLabel2 = 103
)

// WNDCLASSEXW 结构体
type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

// MSG 结构体
type msg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      struct{ x, y int32 }
}

// CardInfo 表示一张可用卡片的信息。
type CardInfo struct {
	CardUUID string `json:"card_uuid"`
	CardName string `json:"card_name"`
}

// PINResult 是 PIN 对话框的结果。
type PINResult struct {
	CardUUID string // 选择的卡片 UUID
	PIN      string // 用户输入的 PIN
}

// dialogState 保存对话框运行时状态
type dialogState struct {
	cards     []CardInfo
	result    *PINResult
	err       error
	hwnd      uintptr
	hCombo    uintptr
	hEdit     uintptr
	hBtnOK    uintptr
	hBtnCancel uintptr
	hFont     uintptr
}

var (
	currentDialog *dialogState
	dialogMu      sync.Mutex
)

// PromptPIN 弹出自定义 PIN 输入对话框。
// 包含 ComboBox 选择卡片 + Edit 输入 PIN，一个对话框完成。
func PromptPIN(cards []CardInfo) (*PINResult, error) {
	if len(cards) == 0 {
		return nil, fmt.Errorf("没有可用的卡片")
	}

	// 对话框必须在主线程（或固定 OS 线程）上运行
	var result *PINResult
	var err error

	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result, err = showPINDialog(cards)
		close(done)
	}()
	<-done

	return result, err
}

// showPINDialog 创建并显示自定义 PIN 对话框。
func showPINDialog(cards []CardInfo) (*PINResult, error) {
	dialogMu.Lock()
	currentDialog = &dialogState{
		cards: cards,
		err:   fmt.Errorf("用户取消"),
	}
	dialogMu.Unlock()

	hInstance, _, _ := procGetModuleHandleW.Call(0)

	// 注册窗口类
	className, _ := syscall.UTF16PtrFromString("OpenCertPINDialog")
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		style:         0x0003, // CS_HREDRAW | CS_VREDRAW
		lpfnWndProc:   syscall.NewCallback(pinDialogProc),
		hInstance:     hInstance,
		hbrBackground: 16, // COLOR_BTNFACE + 1
		lpszClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	// 计算窗口位置（屏幕居中）
	dlgWidth := int32(380)
	dlgHeight := int32(220)
	screenW, _, _ := procGetSystemMetrics.Call(uintptr(smCXScreen))
	screenH, _, _ := procGetSystemMetrics.Call(uintptr(smCYScreen))
	x := (int32(screenW) - dlgWidth) / 2
	y := (int32(screenH) - dlgHeight) / 2

	// 创建主窗口
	title, _ := syscall.UTF16PtrFromString("OpenCert FIDO2 - 智能卡认证")
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		uintptr(wsOverlapped|wsCaption|wsSysMenu|wsClipChildren),
		uintptr(x), uintptr(y),
		uintptr(dlgWidth), uintptr(dlgHeight),
		0, 0, hInstance, 0,
	)

	if hwnd == 0 {
		return nil, fmt.Errorf("创建对话框窗口失败")
	}

	procShowWindow.Call(hwnd, uintptr(swShow))
	procUpdateWindow.Call(hwnd)
	procSetForegroundWindow.Call(hwnd)

	// 消息循环
	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(
			uintptr(unsafe.Pointer(&m)), 0, 0, 0,
		)
		if ret == 0 || int32(ret) == -1 {
			break
		}
		// 处理 Tab 键导航
		isDialog, _, _ := procIsDialogMessageW.Call(hwnd, uintptr(unsafe.Pointer(&m)))
		if isDialog == 0 {
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}

	dialogMu.Lock()
	result := currentDialog.result
	err := currentDialog.err
	currentDialog = nil
	dialogMu.Unlock()

	return result, err
}

// pinDialogProc 是对话框的窗口过程。
func pinDialogProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCreate:
		createDialogControls(hwnd)
		return 0

	case wmCommand:
		ctrlID := int32(wParam & 0xFFFF)
		notifyCode := int32((wParam >> 16) & 0xFFFF)

		if notifyCode == bnClicked {
			switch ctrlID {
			case idOK:
				handleOK()
			case idCancel:
				handleCancel()
			}
		}
		return 0

	case wmClose:
		handleCancel()
		return 0

	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	ret, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return ret
}

// createDialogControls 创建对话框内的所有控件。
func createDialogControls(hwnd uintptr) {
	dialogMu.Lock()
	ds := currentDialog
	ds.hwnd = hwnd
	dialogMu.Unlock()

	hInstance, _, _ := procGetModuleHandleW.Call(0)

	// 获取默认 GUI 字体
	hFont, _, _ := procGetStockObject.Call(uintptr(defaultGUIFont))
	ds.hFont = hFont

	staticClass, _ := syscall.UTF16PtrFromString("STATIC")
	comboClass, _ := syscall.UTF16PtrFromString("COMBOBOX")
	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	buttonClass, _ := syscall.UTF16PtrFromString("BUTTON")

	// 标签1: "选择智能卡:"
	label1Text, _ := syscall.UTF16PtrFromString("选择智能卡(&C):")
	hLabel1, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)),
		uintptr(unsafe.Pointer(label1Text)),
		uintptr(wsChild|wsVisible|ssLeft),
		20, 20, 340, 20,
		hwnd, idLabel1, hInstance, 0,
	)
	setFont(hLabel1, hFont)

	// ComboBox: 卡片选择下拉框
	ds.hCombo, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(comboClass)),
		0,
		uintptr(wsChild|wsVisible|wsTabStop|wsVScroll|cbsDropDownList|cbsHasStrings),
		20, 42, 340, 200,
		hwnd, idCombo, hInstance, 0,
	)
	setFont(ds.hCombo, hFont)

	// 填充卡片列表
	for _, card := range ds.cards {
		itemText, _ := syscall.UTF16PtrFromString(card.CardName)
		procSendMessageW.Call(ds.hCombo, uintptr(cbAddString), 0, uintptr(unsafe.Pointer(itemText)))
	}
	// 默认选中第一项
	procSendMessageW.Call(ds.hCombo, uintptr(cbSetCurSel), 0, 0)

	// 标签2: "PIN 码:"
	label2Text, _ := syscall.UTF16PtrFromString("PIN 码(&P):")
	hLabel2, _, _ := procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(staticClass)),
		uintptr(unsafe.Pointer(label2Text)),
		uintptr(wsChild|wsVisible|ssLeft),
		20, 78, 340, 20,
		hwnd, idLabel2, hInstance, 0,
	)
	setFont(hLabel2, hFont)

	// Edit: PIN 输入框（密码模式）
	ds.hEdit, _, _ = procCreateWindowExW.Call(
		uintptr(wsExClientEdge), uintptr(unsafe.Pointer(editClass)),
		0,
		uintptr(wsChild|wsVisible|wsTabStop|esPassword|esAutoHScroll|wsBorder),
		20, 100, 340, 26,
		hwnd, idEdit, hInstance, 0,
	)
	setFont(ds.hEdit, hFont)

	// 确定按钮
	okText, _ := syscall.UTF16PtrFromString("确定")
	ds.hBtnOK, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(buttonClass)),
		uintptr(unsafe.Pointer(okText)),
		uintptr(wsChild|wsVisible|wsTabStop|bsDefPushButton),
		160, 145, 90, 30,
		hwnd, idOK, hInstance, 0,
	)
	setFont(ds.hBtnOK, hFont)

	// 取消按钮
	cancelText, _ := syscall.UTF16PtrFromString("取消")
	ds.hBtnCancel, _, _ = procCreateWindowExW.Call(
		0, uintptr(unsafe.Pointer(buttonClass)),
		uintptr(unsafe.Pointer(cancelText)),
		uintptr(wsChild|wsVisible|wsTabStop|bsPushButton),
		270, 145, 90, 30,
		hwnd, idCancel, hInstance, 0,
	)
	setFont(ds.hBtnCancel, hFont)

	// 如果只有一张卡片，禁用 ComboBox 并聚焦到 PIN 输入框
	if len(ds.cards) == 1 {
		procEnableWindow.Call(ds.hCombo, 0)
		procSetFocus.Call(ds.hEdit)
	} else {
		procSetFocus.Call(ds.hCombo)
	}
}

// setFont 设置控件字体。
func setFont(hwnd, hFont uintptr) {
	procSendMessageW.Call(hwnd, uintptr(wmSetFont), hFont, 1)
}

// handleOK 处理确定按钮点击。
func handleOK() {
	dialogMu.Lock()
	ds := currentDialog
	dialogMu.Unlock()

	if ds == nil {
		return
	}

	// 获取选中的卡片索引
	idx, _, _ := procSendMessageW.Call(ds.hCombo, uintptr(cbGetCurSel), 0, 0)
	if int32(idx) < 0 || int(idx) >= len(ds.cards) {
		idx = 0
	}

	// 获取 PIN 文本
	pinLen, _, _ := procGetWindowTextLengthW.Call(ds.hEdit)
	if pinLen == 0 {
		// PIN 为空，不允许确认（可以弹提示，这里简单忽略）
		procSetFocus.Call(ds.hEdit)
		return
	}

	pinBuf := make([]uint16, pinLen+1)
	procGetWindowTextW.Call(ds.hEdit, uintptr(unsafe.Pointer(&pinBuf[0])), uintptr(pinLen+1))
	pin := syscall.UTF16ToString(pinBuf)

	// 安全清除 Edit 控件内容
	emptyStr, _ := syscall.UTF16PtrFromString("")
	procSetWindowTextW.Call(ds.hEdit, uintptr(unsafe.Pointer(emptyStr)))

	dialogMu.Lock()
	ds.result = &PINResult{
		CardUUID: ds.cards[idx].CardUUID,
		PIN:      pin,
	}
	ds.err = nil
	dialogMu.Unlock()

	// 安全清除 PIN 内存
	for i := range pinBuf {
		pinBuf[i] = 0
	}

	procDestroyWindow.Call(ds.hwnd)
}

// handleCancel 处理取消按钮点击。
func handleCancel() {
	dialogMu.Lock()
	ds := currentDialog
	dialogMu.Unlock()

	if ds == nil {
		return
	}

	// 清除 Edit 控件内容
	emptyStr, _ := syscall.UTF16PtrFromString("")
	procSetWindowTextW.Call(ds.hEdit, uintptr(unsafe.Pointer(emptyStr)))

	dialogMu.Lock()
	ds.result = nil
	ds.err = fmt.Errorf("用户取消了认证")
	dialogMu.Unlock()

	procDestroyWindow.Call(ds.hwnd)
}