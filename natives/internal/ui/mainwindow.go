package ui

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// NavItem 导航项
type NavItem struct {
	Label string
	Icon  fyne.Resource
	Page  fyne.CanvasObject
}

// MainWindow 主窗口
type MainWindow struct {
	appCore *appcore.App
	fyneApp fyne.App
	window  fyne.Window

	// 页面
	cards   *CardsPage
	certs   *CertsPage
	totp    *TOTPPage
	fido    *FIDOPage
	creds   *CredsPage
	login   *LoginDialog
	options *OptionsDialog

	// UI 组件
	navItems    []NavItem
	contentArea *container.AppTabs
	status      *widget.Label
	cardSelect  *widget.Select
	allCards    []api.Card
	currentIdx  int
}

// NewMainWindow 创建主窗口
func NewMainWindow(a *appcore.App, fyneApp fyne.App) *MainWindow {
	mw := &MainWindow{
		appCore:    a,
		fyneApp:    fyneApp,
		currentIdx: 0,
	}

	mw.window = fyneApp.NewWindow(i18n.T("app.name"))
	mw.window.SetMaster()
	mw.window.Resize(fyne.NewSize(800, 520))

	mw.cards = NewCardsPage(a, mw.window)
	mw.certs = NewCertsPage(a, mw.window)
	mw.totp = NewTOTPPage(a, mw.window)
	mw.fido = NewFIDOPage(a, mw.window)
	mw.creds = NewCredsPage(a, mw.window)
	mw.login = NewLoginDialog(a, mw.window)
	mw.login.SetOnLoginSuccess(func() {
		mw.reloadAllPages()
	})
	mw.options = NewOptionsDialog(a, mw.window)

	mw.buildUI()
	mw.buildTray()

	a.OnStateChange(func(s appcore.State) {
		mw.updateStatus()
	})

	mw.window.SetCloseIntercept(func() {
		mw.window.Hide()
	})

	return mw
}

// buildUI 构建界面
func (mw *MainWindow) buildUI() {
	mw.navItems = []NavItem{
		{Label: i18n.T("card.title"), Icon: theme.StorageIcon(), Page: mw.cards.Build()},
		{Label: i18n.T("cert.title"), Icon: theme.DocumentIcon(), Page: mw.certs.Build()},
		{Label: i18n.T("totp.title"), Icon: theme.MailComposeIcon(), Page: mw.totp.Build()},
		{Label: i18n.T("fido.title"), Icon: theme.ComputerIcon(), Page: mw.fido.Build()},
		{Label: i18n.T("creds.title"), Icon: theme.AccountIcon(), Page: mw.creds.Build()},
	}

	mw.contentArea = container.NewAppTabs()
	for _, item := range mw.navItems {
		mw.contentArea.Append(container.NewTabItem(item.Label, item.Page))
	}
	mw.contentArea.SetTabLocation(container.TabLocationTop)
	mw.contentArea.OnSelected = func(tab *container.TabItem) {
		for i, item := range mw.navItems {
			if item.Label == tab.Text {
				mw.currentIdx = i
				if mw.appCore.IsLoggedIn() {
					mw.reloadCurrentPage()
				}
				break
			}
		}
	}
	mw.contentArea.SelectTabIndex(0)

	mw.status = widget.NewLabel(mw.appCore.StateText())

	loginBtn := widget.NewButtonWithIcon(i18n.T("login.title"), theme.AccountIcon(), func() {
		if mw.appCore.IsLoggedIn() {
			mw.appCore.Logout()
			mw.cardSelect.Options = nil
			mw.cardSelect.ClearSelected()
			mw.allCards = nil
		} else {
			mw.login.Show()
		}
	})

	importBtn := widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
		if !mw.appCore.IsLoggedIn() {
			dialog.ShowInformation(i18n.T("app.error"), i18n.T("login.failed"), mw.window)
			return
		}
		NewImportDialog(mw.appCore, mw.window).Show()
	})

	refreshBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		mw.reloadCurrentPage()
	})

	settingsBtn := widget.NewButtonWithIcon("", theme.SettingsIcon(), func() {
		mw.options.Show()
	})

	// 统一卡片选择器
	allLabel := i18n.T("cert.all_cards")
	mw.cardSelect = widget.NewSelect([]string{}, func(s string) {
		if s == allLabel {
			mw.dispatchCardUUID("")
		} else {
			for _, c := range mw.allCards {
				if fmt.Sprintf("%s (%s)", c.CardName, slotTypeText(c.SlotType)) == s {
					mw.dispatchCardUUID(c.UUID)
					break
				}
			}
		}
	})
	mw.cardSelect.PlaceHolder = i18n.T("cert.card")

	cardSelectWrapper := container.New(layout.NewGridWrapLayout(fyne.NewSize(220, 32)), mw.cardSelect)

	toolbar := container.NewHBox(
		mw.status,
		layout.NewSpacer(),
		widget.NewLabel(i18n.T("cert.card")+":"),
		cardSelectWrapper,
		importBtn,
		refreshBtn,
		settingsBtn,
		loginBtn,
	)

	mainContent := container.NewBorder(nil, toolbar, nil, nil, mw.contentArea)
	mw.window.SetContent(mainContent)
}

// dispatchCardUUID 将卡片 UUID 同步给所有需要的页面
func (mw *MainWindow) dispatchCardUUID(uuid string) {
	mw.certs.SetCardUUID(uuid)
	mw.totp.SetCardUUID(uuid)
	mw.fido.SetCardUUID(uuid)
	mw.creds.SetCardUUID(uuid)
}

// loadCards 从后端加载卡片列表并更新选择器
func (mw *MainWindow) loadCards() {
	if !mw.appCore.IsLoggedIn() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cards, err := mw.appCore.Client().ListCards(ctx)
	if err != nil {
		return
	}
	mw.allCards = cards

	allLabel := i18n.T("cert.all_cards")
	names := make([]string, 0, len(cards)+1)
	names = append(names, allLabel)
	for _, c := range cards {
		names = append(names, fmt.Sprintf("%s (%s)", c.CardName, slotTypeText(c.SlotType)))
	}
	mw.cardSelect.Options = names
	mw.cardSelect.SetSelected(allLabel)
	// 触发 dispatchCardUUID("") → 所有页面加载全部数据
}

// switchPage 切换页面
func (mw *MainWindow) switchPage(idx int) {
	if idx < 0 || idx >= len(mw.navItems) {
		return
	}
	mw.currentIdx = idx
	mw.contentArea.SelectTabIndex(idx)
}

// reloadCurrentPage 重新加载当前页面
func (mw *MainWindow) reloadCurrentPage() {
	switch mw.currentIdx {
	case 0:
		mw.cards.Reload()
	case 1:
		mw.certs.Reload()
	case 2:
		mw.totp.Reload()
	case 3:
		mw.fido.Reload()
	case 4:
		mw.creds.Reload()
	}
}

// reloadAllPages 刷新所有页面数据
func (mw *MainWindow) reloadAllPages() {
	mw.loadCards()
	mw.cards.Reload()
}

// trayPNGIcon generates a minimal 32x32 PNG icon for the OS system tray.
// The OS tray layer does not accept SVG, so a raster resource is required.
func trayPNGIcon() fyne.Resource {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	blue := color.NRGBA{R: 21, G: 101, B: 192, A: 255}
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.SetNRGBA(x, y, blue)
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return fyne.NewStaticResource("tray.png", buf.Bytes())
}

// buildTray 构建系统托盘
func (mw *MainWindow) buildTray() {
	if desk, ok := mw.fyneApp.(desktop.App); ok {
		menu := fyne.NewMenu("GlobalTrusts",
			fyne.NewMenuItem(i18n.T("tray.manage_certs"), func() {
				mw.window.Show()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem(i18n.T("tray.connect"), func() {
				mw.login.Show()
			}),
			fyne.NewMenuItem(i18n.T("tray.disconnect"), func() {
				mw.appCore.Logout()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem(i18n.T("tray.options"), func() {
				mw.options.Show()
			}),
			fyne.NewMenuItem(i18n.T("tray.about"), func() {
				mw.showAbout()
			}),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem(i18n.T("tray.quit"), func() {
				mw.fyneApp.Quit()
			}),
		)
		// 必须先调用 SetSystemTrayMenu 以触发 systray 初始化循环，
		// 然后再设置自定义图标，避免 "tray not ready yet" 错误
		desk.SetSystemTrayMenu(menu)
		desk.SetSystemTrayIcon(trayPNGIcon())
	}
}

// Show 显示主窗口
func (mw *MainWindow) Show() {
	mw.window.Show()
	mw.appCore.CheckBackend()
	if !mw.appCore.IsLoggedIn() {
		mw.login.Show()
	}
}

// updateStatus 更新状态栏
func (mw *MainWindow) updateStatus() {
	mw.status.SetText(mw.appCore.StateText())
}

// showAbout 显示关于对话框
func (mw *MainWindow) showAbout() {
	content := widget.NewLabel(
		i18n.TF("app.version", "1.0.0") + "\n" +
			i18n.T("app.copyright"),
	)
	dialog.ShowCustom(i18n.T("tray.about"), i18n.T("app.close"), content, mw.window)
}
