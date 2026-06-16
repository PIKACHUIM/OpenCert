package ui

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/globaltrusts/native-client/internal/api"
	"github.com/globaltrusts/native-client/internal/appcore"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// DeliverDialog 云端证书下发对话框
type DeliverDialog struct {
	appCore  *appcore.App
	window   fyne.Window
	dialog   dialog.Dialog
	cert     api.Certificate
	cardUUID string

	targetSelect  *widget.Select
	cardSelect    *widget.Select
	cardPassword  *widget.Entry
	remark        *widget.Entry
	cards         []api.Card
}

// NewDeliverDialog 创建云端下发对话框
func NewDeliverDialog(a *appcore.App, w fyne.Window, cert api.Certificate, sourceCardUUID string) *DeliverDialog {
	dd := &DeliverDialog{
		appCore:  a,
		window:   w,
		cert:     cert,
		cardUUID: sourceCardUUID,
	}

	dd.targetSelect = widget.NewSelect([]string{
		i18n.T("deliver.target_db"),
		i18n.T("deliver.target_card"),
	}, func(s string) {
		// TODO: 动态显示/隐藏卡片选择
	})

	dd.cardSelect = widget.NewSelect([]string{}, nil)
	dd.cardPassword = widget.NewPasswordEntry()
	dd.remark = widget.NewEntry()

	return dd
}

// Show 显示下发对话框
func (dd *DeliverDialog) Show() {
	// 加载本地卡片列表
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cards, err := dd.appCore.Client().ListCards(ctx)
	if err != nil {
		dialog.ShowError(err, dd.window)
		return
	}

	// 仅显示本地卡片
	dd.cards = []api.Card{}
	cardNames := []string{}
	for _, c := range cards {
		if c.SlotType != api.SlotTypeCloud {
			dd.cards = append(dd.cards, c)
			cardNames = append(cardNames, fmt.Sprintf("%s (%s)", c.CardName, slotTypeText(c.SlotType)))
		}
	}
	dd.cardSelect.Options = cardNames
	if len(cardNames) > 0 {
		dd.cardSelect.SetSelectedIndex(0)
	}

	dd.targetSelect.SetSelectedIndex(0)

	cardSelectRow := container.NewHBox(
		widget.NewLabel(i18n.T("deliver.target_card_uuid")+":"),
		dd.cardSelect,
	)

	form := container.NewVBox(
		widget.NewForm(
			&widget.FormItem{Text: i18n.T("deliver.target"), Widget: dd.targetSelect},
		),
		cardSelectRow,
		widget.NewForm(
			&widget.FormItem{Text: i18n.T("deliver.card_password"), Widget: dd.cardPassword},
			&widget.FormItem{Text: i18n.T("deliver.remark"), Widget: dd.remark},
		),
		widget.NewButton(i18n.T("cert.deliver"), func() {
			dd.doDeliver()
		}),
	)

	dd.dialog = dialog.NewCustom(i18n.T("deliver.title"), i18n.T("app.cancel"), form, dd.window)
	dd.dialog.Resize(fyne.NewSize(450, 300))
	dd.dialog.Show()
}

func (dd *DeliverDialog) doDeliver() {
	req := &api.DeliverRequest{
		CertUUID:   dd.cert.UUID,
		SourceCloud: dd.cardUUID,
		Remark:     dd.remark.Text,
	}

	if dd.targetSelect.SelectedIndex() == 0 {
		req.Target = "database"
	} else {
		req.Target = "card"
		idx := dd.cardSelect.SelectedIndex()
		if idx >= 0 && idx < len(dd.cards) {
			req.TargetCard = dd.cards[idx].UUID
			req.CardPassword = dd.cardPassword.Text
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := dd.appCore.Client().CloudDeliver(ctx, req)
	if err != nil {
		dialog.ShowError(err, dd.window)
		return
	}

	dd.dialog.Hide()
	msg := fmt.Sprintf("%s: %s (%s)", i18n.T("deliver.success"), result.CommonName, result.UUID)
	dialog.ShowInformation(i18n.T("app.success"), msg, dd.window)
}
