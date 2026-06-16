package ui

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// TOTPPage TOTP 管理页面
type TOTPPage struct {
	appCore     *appcore.App
	window      fyne.Window
	scroll      *container.Scroll
	totpBox     *fyne.Container
	cardUUID    string
	refreshTimer *time.Timer
}

func NewTOTPPage(a *appcore.App, w fyne.Window) *TOTPPage {
	return &TOTPPage{appCore: a, window: w}
}

func (p *TOTPPage) Build() fyne.CanvasObject {
	p.totpBox = container.NewVBox()
	p.scroll = container.NewVScroll(p.totpBox)
	return p.scroll
}

// SetCardUUID 由主窗口统一调用
func (p *TOTPPage) SetCardUUID(uuid string) {
	p.stopAutoRefresh()
	p.cardUUID = uuid
	p.loadTOTPs()
}

func (p *TOTPPage) Reload() {
	p.stopAutoRefresh()
	if !p.appCore.IsLoggedIn() {
		p.totpBox.Objects = nil
		p.totpBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.totpBox.Refresh()
		return
	}
	p.loadTOTPs()
}

func (p *TOTPPage) loadTOTPs() {
	p.totpBox.Objects = nil

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var uuids []string
	if p.cardUUID == "" {
		cards, err := p.appCore.Client().ListCards(ctx)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}
		for _, c := range cards {
			uuids = append(uuids, c.UUID)
		}
	} else {
		uuids = []string{p.cardUUID}
	}

	var all []api.TOTPEntry
	for _, uuid := range uuids {
		entries, err := p.appCore.Client().ListTOTPs(ctx, uuid)
		if err != nil {
			continue
		}
		all = append(all, entries...)
	}

	if len(all) == 0 {
		p.totpBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.totpBox.Refresh()
		return
	}
	for i := range all {
		entry := all[i]
		p.totpBox.Add(p.buildTOTPWidget(&entry))
	}
	p.totpBox.Refresh()
}

func (p *TOTPPage) buildTOTPWidget(entry *api.TOTPEntry) fyne.CanvasObject {
	text := fmt.Sprintf("编号:      %s\n来源:      %s\n账户:      %s",
		entry.UUID, entry.Issuer, entry.Account)
	infoLabel := widget.NewLabel(text)
	infoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	infoLabel.Wrapping = fyne.TextWrapOff

	codeLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true, Monospace: true})
	var getCodeBtn *widget.Button
	getCodeBtn = widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() {
		p.showGetCodeDialog(entry, codeLabel, getCodeBtn)
	})
	detailBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		p.showTOTPDetailDialog(entry)
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		p.confirmDeleteTOTP(*entry)
	})
	deleteBtn.Importance = widget.DangerImportance

	actions := container.NewHBox(getCodeBtn, codeLabel, detailBtn, deleteBtn)
	border := canvas.NewRectangle(theme.DisabledColor())
	border.StrokeWidth = 1
	border.StrokeColor = theme.DisabledColor()
	border.FillColor = theme.InputBackgroundColor()
	return container.NewStack(border, container.NewPadded(container.NewBorder(nil, nil, nil, actions, infoLabel)))
}

func (p *TOTPPage) showGetCodeDialog(entry *api.TOTPEntry, codeLabel *widget.Label, getCodeBtn *widget.Button) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(i18n.T("totp.card_password_hint"))

	form := widget.NewForm(
		widget.NewFormItem(i18n.T("totp.card_password"), passEntry),
	)

	d := dialog.NewCustomConfirm(
		i18n.T("totp.get_code"),
		i18n.T("app.ok"),
		i18n.T("app.cancel"),
		form,
		func(ok bool) {
			if !ok || passEntry.Text == "" {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			code, remaining, err := p.appCore.Client().GetTOTPCode(ctx, entry.UUID, passEntry.Text)
			if err != nil {
				dialog.ShowError(err, p.window)
				return
			}
			p.startAutoRefresh(entry, passEntry.Text, code, remaining, codeLabel, getCodeBtn)
		},
		p.window,
	)
	d.Resize(fyne.NewSize(400, 150))
	d.Show()
}

func (p *TOTPPage) showTOTPDetailDialog(entry *api.TOTPEntry) {
	text := fmt.Sprintf(
		"UUID:      %s\n来源:      %s\n账户:      %s\n算法:      %s\n位数:      %d\n周期:      %ds",
		entry.UUID, entry.Issuer, entry.Account, entry.Algorithm, entry.Digits, entry.Period,
	)
	lbl := widget.NewLabel(text)
	lbl.TextStyle = fyne.TextStyle{Monospace: true}
	d := dialog.NewCustom("TOTP 详情", i18n.T("app.close"), container.NewPadded(lbl), p.window)
	d.Resize(fyne.NewSize(400, 220))
	d.Show()
}

func (p *TOTPPage) confirmDeleteTOTP(entry api.TOTPEntry) {
	dialog.ShowConfirm(i18n.T("app.confirm"), i18n.T("app.confirm_delete"), func(ok bool) {
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := p.appCore.Client().DeleteTOTP(ctx, entry.UUID)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}
		dialog.ShowInformation(i18n.T("app.success"), i18n.T("app.success"), p.window)
		p.loadTOTPs()
	}, p.window)
}

// stopAutoRefresh 停止自动刷新定时器
func (p *TOTPPage) stopAutoRefresh() {
	if p.refreshTimer != nil {
		p.refreshTimer.Stop()
		p.refreshTimer = nil
	}
}

// startAutoRefresh 启动TOTP验证码自动刷新
func (p *TOTPPage) startAutoRefresh(entry *api.TOTPEntry, cardPassword, code string, remaining int, codeLabel *widget.Label, getCodeBtn *widget.Button) {
	p.stopAutoRefresh()

	codeLabel.SetText(fmt.Sprintf("%s  (%ds)", code, remaining))
	getCodeBtn.Hide()

	// 每秒倒计时，remaining为0时重新获取验证码
	p.refreshTimer = time.AfterFunc(time.Second, func() {
		remaining--
		if remaining > 0 {
			codeLabel.SetText(fmt.Sprintf("%s  (%ds)", code, remaining))
			// 继续倒计时
			p.refreshTimer = time.AfterFunc(time.Second, func() {
				p.startAutoRefresh(entry, cardPassword, code, remaining, codeLabel, getCodeBtn)
			})
		} else {
			// 验证码过期，重新获取
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			newCode, newRemaining, err := p.appCore.Client().GetTOTPCode(ctx, entry.UUID, cardPassword)
			if err != nil {
				// 获取失败，显示按钮让用户手动重试
				codeLabel.SetText("")
				getCodeBtn.Show()
				p.refreshTimer = nil
				return
			}
			p.startAutoRefresh(entry, cardPassword, newCode, newRemaining, codeLabel, getCodeBtn)
		}
	})
}
