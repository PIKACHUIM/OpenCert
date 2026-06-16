package ui

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// ImportDialog 导入证书对话框
type ImportDialog struct {
	appCore  *appcore.App
	window   fyne.Window
	dialog   dialog.Dialog
	cards    []api.Card

	cardSelect   *widget.Select
	formatSelect *widget.Select
	certFile     *widget.Entry
	keyFile      *widget.Entry
	pfxFile      *widget.Entry
	pfxPassword  *widget.Entry
	cardPassword *widget.Entry
	remark       *widget.Entry

	certContent string
	keyContent  string
	pfxContent  string
}

// NewImportDialog 创建导入证书对话框
func NewImportDialog(a *appcore.App, w fyne.Window) *ImportDialog {
	id := &ImportDialog{
		appCore: a,
		window: w,
	}

	id.cardSelect = widget.NewSelect([]string{}, nil)
	id.formatSelect = widget.NewSelect([]string{"PEM", "PFX"}, func(s string) {
		// 切换格式时更新表单（由 Build 动态处理）
	})

	id.certFile = widget.NewEntry()
	id.certFile.SetPlaceHolder(i18n.T("import.select_file"))
	id.keyFile = widget.NewEntry()
	id.keyFile.SetPlaceHolder(i18n.T("import.select_file"))
	id.pfxFile = widget.NewEntry()
	id.pfxFile.SetPlaceHolder(i18n.T("import.select_file"))
	id.pfxPassword = widget.NewPasswordEntry()
	id.cardPassword = widget.NewPasswordEntry()
	id.remark = widget.NewEntry()

	return id
}

// Show 显示导入证书对话框
func (id *ImportDialog) Show() {
	// 加载卡片列表
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cards, err := id.appCore.Client().ListCards(ctx)
	if err != nil {
		dialog.ShowError(err, id.window)
		return
	}
	id.cards = cards

	cardNames := make([]string, len(cards))
	for i, c := range cards {
		cardNames[i] = fmt.Sprintf("%s (%s)", c.CardName, slotTypeText(c.SlotType))
	}
	id.cardSelect.Options = cardNames
	if len(cards) > 0 {
		id.cardSelect.SetSelectedIndex(0)
	}

	// 证书文件选择按钮
	certFileBtn := widget.NewButton(i18n.T("import.select_file"), func() {
		id.selectFile(id.certFile, &id.certContent)
	})
	keyFileBtn := widget.NewButton(i18n.T("import.select_file"), func() {
		id.selectFile(id.keyFile, &id.keyContent)
	})
	pfxFileBtn := widget.NewButton(i18n.T("import.select_file"), func() {
		id.selectFile(id.pfxFile, &id.pfxContent)
	})

	// PEM 表单
	pemForm := container.NewVBox(
		widget.NewForm(
			&widget.FormItem{Text: i18n.T("import.cert_file"), Widget: container.NewBorder(nil, nil, nil, certFileBtn, id.certFile)},
		),
		widget.NewForm(
			&widget.FormItem{Text: i18n.T("import.key_file"), Widget: container.NewBorder(nil, nil, nil, keyFileBtn, id.keyFile)},
		),
	)

	// PFX 表单
	pfxForm := container.NewVBox(
		widget.NewForm(
			&widget.FormItem{Text: i18n.T("import.pfx_file"), Widget: container.NewBorder(nil, nil, nil, pfxFileBtn, id.pfxFile)},
			&widget.FormItem{Text: i18n.T("import.pfx_password"), Widget: id.pfxPassword},
		),
	)

	// 格式切换
	formatContent := container.NewVBox()
	id.formatSelect.OnChanged = func(s string) {
		formatContent.Objects = nil
		if s == "PEM" {
			formatContent.Add(pemForm)
		} else {
			formatContent.Add(pfxForm)
		}
		formatContent.Refresh()
	}
	id.formatSelect.SetSelected("PEM")
	formatContent.Add(pemForm)

	// 公共部分
	commonForm := widget.NewForm(
		&widget.FormItem{Text: i18n.T("import.card_password"), Widget: id.cardPassword},
		&widget.FormItem{Text: i18n.T("import.remark"), Widget: id.remark},
	)

	submitBtn := widget.NewButton(i18n.T("import.title"), func() {
		id.doImport()
	})

	content := container.NewVBox(
		widget.NewForm(&widget.FormItem{Text: i18n.T("import.target_card"), Widget: id.cardSelect}),
		widget.NewForm(&widget.FormItem{Text: i18n.T("import.format"), Widget: id.formatSelect}),
		formatContent,
		commonForm,
		submitBtn,
	)

	id.dialog = dialog.NewCustom(i18n.T("import.title"), i18n.T("app.cancel"), content, id.window)
	id.dialog.Resize(fyne.NewSize(500, 450))
	id.dialog.Show()
}

func (id *ImportDialog) selectFile(entry *widget.Entry, content *string) {
	fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer reader.Close()

		data, err := os.ReadFile(reader.URI().Path())
		if err != nil {
			dialog.ShowError(err, id.window)
			return
		}

		entry.SetText(reader.URI().Path())
		*content = string(data)
	}, id.window)

	fd.SetFilter(storage.NewExtensionFileFilter([]string{".pem", ".crt", ".cer", ".pfx", ".p12"}))
	fd.Show()
}

func (id *ImportDialog) doImport() {
	idx := id.cardSelect.SelectedIndex()
	if idx < 0 || idx >= len(id.cards) {
		return
	}
	cardUUID := id.cards[idx].UUID

	req := &api.ImportCertRequest{
		CardPassword: id.cardPassword.Text,
		Remark:       id.remark.Text,
	}

	if id.formatSelect.Selected == "PEM" {
		req.Mode = "pem"
		req.CertPEM = id.certContent
		req.KeyPEM = id.keyContent
	} else {
		req.Mode = "pfx"
		req.PFXB64 = base64.StdEncoding.EncodeToString([]byte(id.pfxContent))
		req.PFXPassword = id.pfxPassword.Text
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := id.appCore.Client().ImportCert(ctx, cardUUID, req)
	if err != nil {
		dialog.ShowError(err, id.window)
		return
	}

	id.dialog.Hide()
	dialog.ShowInformation(i18n.T("app.success"), i18n.T("import.success"), id.window)
}
