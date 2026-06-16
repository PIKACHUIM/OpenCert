// Package ui 提供应用的界面组件。
package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// LoginDialog 登录对话框
type LoginDialog struct {
	appCore  *appcore.App
	window   fyne.Window
	dialog   dialog.Dialog

	// 本地登录表单
	localUsername *widget.Entry
	localPassword *widget.Entry

	// 云端登录表单
	cloudURL      *widget.Entry
	cloudUsername *widget.Entry
	cloudPassword *widget.Entry

	// 2FA
	totpCode    *widget.Entry
	need2FA     bool
	pendingUser string
	pendingPass string

	// 记住密码（每个tab独立的check widget）
	localRememberUser *widget.Check
	localRememberPass *widget.Check
	cloudRememberUser *widget.Check
	cloudRememberPass *widget.Check

	// 登录成功回调
	onLoginSuccess func()
}

// NewLoginDialog 创建登录对话框
func NewLoginDialog(a *appcore.App, parent fyne.Window) *LoginDialog {
	ld := &LoginDialog{
		appCore: a,
		window:  parent,
	}

	ld.localUsername = widget.NewEntry()
	ld.localUsername.SetPlaceHolder(i18n.T("login.username_hint"))

	ld.localPassword = widget.NewPasswordEntry()
	ld.localPassword.SetPlaceHolder(i18n.T("login.password_hint"))

	ld.cloudURL = widget.NewEntry()
	ld.cloudURL.SetPlaceHolder(i18n.T("login.cloud_url_hint"))

	ld.cloudUsername = widget.NewEntry()
	ld.cloudUsername.SetPlaceHolder(i18n.T("login.username_hint"))

	ld.cloudPassword = widget.NewPasswordEntry()
	ld.cloudPassword.SetPlaceHolder(i18n.T("login.password_hint"))

	ld.totpCode = widget.NewEntry()
	ld.totpCode.SetPlaceHolder(i18n.T("login.2fa_hint"))

	// 本地tab的记住选项
	ld.localRememberUser = widget.NewCheck(i18n.T("login.remember_username"), nil)
	ld.localRememberPass = widget.NewCheck(i18n.T("login.remember_password"), nil)

	// 云端tab的记住选项
	ld.cloudRememberUser = widget.NewCheck(i18n.T("login.remember_username"), nil)
	ld.cloudRememberPass = widget.NewCheck(i18n.T("login.remember_password"), nil)

	// 设置联动回调（单向同步，避免循环触发）
	ld.localRememberUser.OnChanged = func(b bool) {
		if ld.cloudRememberUser.Checked != b {
			ld.cloudRememberUser.SetChecked(b)
		}
	}
	ld.localRememberPass.OnChanged = func(b bool) {
		if ld.cloudRememberPass.Checked != b {
			ld.cloudRememberPass.SetChecked(b)
		}
	}
	ld.cloudRememberUser.OnChanged = func(b bool) {
		if ld.localRememberUser.Checked != b {
			ld.localRememberUser.SetChecked(b)
		}
	}
	ld.cloudRememberPass.OnChanged = func(b bool) {
		if ld.localRememberPass.Checked != b {
			ld.localRememberPass.SetChecked(b)
		}
	}

	// 设置默认值
	ld.localRememberUser.SetChecked(true)
	ld.cloudRememberUser.SetChecked(true)

	// 自动填充已保存的账号密码
	ld.loadSavedCredentials()

	return ld
}

// SetOnLoginSuccess 设置登录成功回调
func (ld *LoginDialog) SetOnLoginSuccess(fn func()) {
	ld.onLoginSuccess = fn
}

// loadSavedCredentials 从偏好设置中加载已保存的凭证
func (ld *LoginDialog) loadSavedCredentials() {
	prefs := ld.appCore.FyneApp().Preferences()

	// 加载本地登录凭证
	if savedUsername := prefs.String("login.local.username"); savedUsername != "" {
		ld.localUsername.SetText(savedUsername)
		ld.localRememberUser.SetChecked(true)
		ld.cloudRememberUser.SetChecked(true)
	}
	if savedPassword := prefs.String("login.local.password"); savedPassword != "" {
		ld.localPassword.SetText(savedPassword)
		ld.localRememberPass.SetChecked(true)
		ld.cloudRememberPass.SetChecked(true)
	}

	// 加载云端登录凭证
	if savedCloudURL := prefs.String("login.cloud.url"); savedCloudURL != "" {
		ld.cloudURL.SetText(savedCloudURL)
	}
	if savedCloudUsername := prefs.String("login.cloud.username"); savedCloudUsername != "" {
		ld.cloudUsername.SetText(savedCloudUsername)
	}
	if savedCloudPassword := prefs.String("login.cloud.password"); savedCloudPassword != "" {
		ld.cloudPassword.SetText(savedCloudPassword)
		ld.cloudRememberPass.SetChecked(true)
		ld.localRememberPass.SetChecked(true)
	}
}

// saveCredentials 保存凭证到偏好设置
func (ld *LoginDialog) saveCredentials(isCloud bool) {
	prefs := ld.appCore.FyneApp().Preferences()

	if isCloud {
		// 保存云端登录凭证
		if ld.cloudRememberUser.Checked {
			prefs.SetString("login.cloud.url", ld.cloudURL.Text)
			prefs.SetString("login.cloud.username", ld.cloudUsername.Text)
		} else {
			prefs.SetString("login.cloud.url", "")
			prefs.SetString("login.cloud.username", "")
		}
		if ld.cloudRememberPass.Checked {
			prefs.SetString("login.cloud.password", ld.cloudPassword.Text)
		} else {
			prefs.SetString("login.cloud.password", "")
		}
	} else {
		// 保存本地登录凭证
		if ld.localRememberUser.Checked {
			prefs.SetString("login.local.username", ld.localUsername.Text)
		} else {
			prefs.SetString("login.local.username", "")
		}
		if ld.localRememberPass.Checked {
			prefs.SetString("login.local.password", ld.localPassword.Text)
		} else {
			prefs.SetString("login.local.password", "")
		}
	}
}

// Show 显示登录对话框
func (ld *LoginDialog) Show() {
	localForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("login.username"), Widget: ld.localUsername},
			{Text: i18n.T("login.password"), Widget: ld.localPassword},
		},
		OnSubmit: func() {
			ld.doLocalLogin()
		},
		SubmitText: i18n.T("login.submit"),
	}

	cloudForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("login.cloud_url"), Widget: ld.cloudURL},
			{Text: i18n.T("login.username"), Widget: ld.cloudUsername},
			{Text: i18n.T("login.password"), Widget: ld.cloudPassword},
		},
		OnSubmit: func() {
			ld.doCloudLogin()
		},
		SubmitText: i18n.T("login.submit"),
	}

	// 每个tab独立的记住密码选项行
	localRememberRow := container.NewHBox(
		ld.localRememberUser,
		ld.localRememberPass,
	)
	cloudRememberRow := container.NewHBox(
		ld.cloudRememberUser,
		ld.cloudRememberPass,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem(i18n.T("login.local"), container.NewVBox(
			layout.NewSpacer(),
			localForm,
			localRememberRow,
			layout.NewSpacer(),
		)),
		container.NewTabItem(i18n.T("login.cloud"), container.NewVBox(
			layout.NewSpacer(),
			cloudForm,
			cloudRememberRow,
			layout.NewSpacer(),
		)),
	)

	content := container.NewPadded(tabs)
	ld.dialog = dialog.NewCustom(i18n.T("login.title"), i18n.T("app.cancel"), content, ld.window)
	ld.dialog.Resize(fyne.NewSize(400, 320))
	ld.dialog.Show()
}

// Hide 隐藏对话框
func (ld *LoginDialog) Hide() {
	if ld.dialog != nil {
		ld.dialog.Hide()
	}
}

func (ld *LoginDialog) doLocalLogin() {
	username := ld.localUsername.Text
	password := ld.localPassword.Text
	if username == "" || password == "" {
		return
	}

	err := ld.appCore.Login(username, password)
	if err != nil {
		if api.IsNeed2FA(err) {
			ld.pendingUser = username
			ld.pendingPass = password
			ld.need2FA = true
			ld.saveCredentials(false)
			ld.show2FADialog()
			return
		}
		dialog.ShowError(err, ld.window)
		return
	}

	ld.saveCredentials(false)
	ld.Hide()
	if ld.onLoginSuccess != nil {
		ld.onLoginSuccess()
	}
}

func (ld *LoginDialog) doCloudLogin() {
	cloudURL := ld.cloudURL.Text
	username := ld.cloudUsername.Text
	password := ld.cloudPassword.Text
	if cloudURL == "" || username == "" || password == "" {
		return
	}

	err := ld.appCore.CloudLogin(cloudURL, username, password)
	if err != nil {
		dialog.ShowError(err, ld.window)
		return
	}

	ld.saveCredentials(true)
	ld.Hide()
	if ld.onLoginSuccess != nil {
		ld.onLoginSuccess()
	}
}

func (ld *LoginDialog) show2FADialog() {
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("login.2fa_code"), Widget: ld.totpCode},
		},
		OnSubmit: func() {
			code := ld.totpCode.Text
			if code == "" {
				return
			}
			err := ld.appCore.LoginWith2FA(ld.pendingUser, ld.pendingPass, code)
			if err != nil {
				dialog.ShowError(err, ld.window)
				return
			}
			ld.saveCredentials(false)
			ld.Hide()
			if ld.onLoginSuccess != nil {
				ld.onLoginSuccess()
			}
		},
		SubmitText: i18n.T("login.submit"),
	}

	d := dialog.NewCustom(i18n.T("login.2fa_required"), i18n.T("app.cancel"), form, ld.window)
	d.Show()
}
