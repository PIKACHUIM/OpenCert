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

// FIDOPage FIDO 管理页面
type FIDOPage struct {
	appCore  *appcore.App
	window   fyne.Window
	scroll   *container.Scroll
	fidoBox  *fyne.Container
	cardUUID string
}

func NewFIDOPage(a *appcore.App, w fyne.Window) *FIDOPage {
	return &FIDOPage{appCore: a, window: w}
}

func (p *FIDOPage) Build() fyne.CanvasObject {
	p.fidoBox = container.NewVBox()
	p.scroll = container.NewVScroll(p.fidoBox)
	return p.scroll
}

// SetCardUUID 由主窗口统一调用
func (p *FIDOPage) SetCardUUID(uuid string) {
	p.cardUUID = uuid
	p.loadFIDOs()
}

func (p *FIDOPage) Reload() {
	if !p.appCore.IsLoggedIn() {
		p.fidoBox.Objects = nil
		p.fidoBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.fidoBox.Refresh()
		return
	}
	p.loadFIDOs()
}

func (p *FIDOPage) loadFIDOs() {
	p.fidoBox.Objects = nil

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

	var fidoCerts []api.Certificate
	for _, uuid := range uuids {
		certs, err := p.appCore.Client().ListCerts(ctx, uuid)
		if err != nil {
			continue
		}
		for _, c := range certs {
			if string(c.CertType) == "fido-umdf" {
				fidoCerts = append(fidoCerts, c)
			}
		}
	}

	if len(fidoCerts) == 0 {
		p.fidoBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.fidoBox.Refresh()
		return
	}
	for i := range fidoCerts {
		cert := fidoCerts[i]
		p.fidoBox.Add(p.buildFIDOWidget(&cert))
	}
	p.fidoBox.Refresh()
}

func (p *FIDOPage) buildFIDOWidget(cert *api.Certificate) fyne.CanvasObject {
	text := fmt.Sprintf(
		"编号:      %s\n算法:      %s\n时间:      %s",
		cert.UUID, cert.CommonName, cert.KeyType, formatTime(cert.CreatedAt),
	)
	infoLabel := widget.NewLabel(text)
	infoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	infoLabel.Wrapping = fyne.TextWrapOff

	detailBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		p.showFIDODetailDialog(cert)
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		p.confirmDeleteFIDO(*cert)
	})
	deleteBtn.Importance = widget.DangerImportance

	actions := container.NewHBox(detailBtn, deleteBtn)
	border := canvas.NewRectangle(theme.DisabledColor())
	border.StrokeWidth = 1
	border.StrokeColor = theme.DisabledColor()
	border.FillColor = theme.InputBackgroundColor()
	return container.NewStack(border, container.NewPadded(container.NewBorder(nil, nil, nil, actions, infoLabel)))
}

func (p *FIDOPage) showFIDODetailDialog(cert *api.Certificate) {
	text := fmt.Sprintf(
		"编号:      %s\n算法:      %s\n时间:      %s\n备注:      %s",
		cert.UUID, cert.CommonName, cert.KeyType,
		formatTime(cert.CreatedAt), cert.Remark,
	)
	lbl := widget.NewLabel(text)
	lbl.TextStyle = fyne.TextStyle{Monospace: true}
	d := dialog.NewCustom("FIDO 详情", i18n.T("app.close"), container.NewPadded(lbl), p.window)
	d.Resize(fyne.NewSize(400, 220))
	d.Show()
}

func (p *FIDOPage) confirmDeleteFIDO(cert api.Certificate) {
	dialog.ShowConfirm(i18n.T("app.confirm"), i18n.T("app.confirm_delete"), func(ok bool) {
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := p.appCore.Client().DeleteCert(ctx, cert.CardUUID, cert.UUID)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}
		dialog.ShowInformation(i18n.T("app.success"), i18n.T("app.success"), p.window)
		p.loadFIDOs()
	}, p.window)
}
