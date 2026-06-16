package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/config"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// OptionsDialog 选项配置对话框
type OptionsDialog struct {
	appCore *appcore.App
	window  fyne.Window

	backendURLEntry *widget.Entry
	languageSelect  *widget.Select
	hideExpiredCheck *widget.Check
}

// NewOptionsDialog 创建选项对话框
func NewOptionsDialog(a *appcore.App, w fyne.Window) *OptionsDialog {
	return &OptionsDialog{
		appCore: a,
		window:  w,
	}
}

// Show 显示选项对话框
func (od *OptionsDialog) Show() {
	cfg := config.Get()

	od.backendURLEntry = widget.NewEntry()
	od.backendURLEntry.SetText(cfg.BackendURL)

	od.languageSelect = widget.NewSelect([]string{"zh-CN", "en-US"}, nil)
	od.languageSelect.SetSelected(cfg.Language)

	od.hideExpiredCheck = widget.NewCheck(i18n.T("options.hide_expired"), nil)
	od.hideExpiredCheck.SetChecked(cfg.HideExpired)

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("options.backend_url"), Widget: od.backendURLEntry},
			{Text: i18n.T("options.language"), Widget: od.languageSelect},
			{Text: "", Widget: od.hideExpiredCheck},
		},
		OnSubmit: func() {
			od.saveConfig()
		},
		OnCancel:   func() {},
		SubmitText: i18n.T("app.save"),
		CancelText: i18n.T("app.cancel"),
	}

	d := dialog.NewCustom(i18n.T("options.title"), i18n.T("app.close"), form, od.window)
	d.Resize(fyne.NewSize(400, 240))
	d.Show()
}

func (od *OptionsDialog) saveConfig() {
	cfg := config.Get()

	oldURL := cfg.BackendURL
	cfg.BackendURL = od.backendURLEntry.Text
	cfg.Language = od.languageSelect.Selected
	cfg.HideExpired = od.hideExpiredCheck.Checked

	if err := config.Save(cfg); err != nil {
		dialog.ShowError(err, od.window)
		return
	}

	// 更新语言
	i18n.SetLanguage(cfg.Language)

	// 如果后端地址改变了，重新连接
	if oldURL != cfg.BackendURL {
		od.appCore.UpdateBackendURL(cfg.BackendURL)
		dialog.ShowInformation(i18n.T("app.success"), i18n.T("options.restart_hint"), od.window)
		return
	}

	dialog.ShowInformation(i18n.T("app.success"), i18n.T("options.save_success"), od.window)
}