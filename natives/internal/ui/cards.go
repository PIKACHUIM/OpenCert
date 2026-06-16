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

// CardsPage 智能卡列表页面
type CardsPage struct {
	appCore *appcore.App
	window  fyne.Window
	cards   []api.Card
	scroll  *container.Scroll
	cardBox *fyne.Container
}

// NewCardsPage 创建卡片列表页面
func NewCardsPage(a *appcore.App, w fyne.Window) *CardsPage {
	return &CardsPage{
		appCore: a,
		window:  w,
	}
}

// Build 构建页面UI
func (cp *CardsPage) Build() fyne.CanvasObject {
	cp.cardBox = container.NewVBox()
	cp.scroll = container.NewVScroll(cp.cardBox)
	cp.scroll.SetMinSize(fyne.NewSize(400, 300))
	return cp.scroll
}

// Reload 重新加载数据
func (cp *CardsPage) Reload() {
	if !cp.appCore.IsLoggedIn() {
		cp.cards = nil
		cp.renderCards()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cards, err := cp.appCore.Client().ListCards(ctx)
	if err != nil {
		dialog.ShowError(err, cp.window)
		return
	}
	cp.cards = cards
	cp.renderCards()
}

// renderCards 渲染卡片列表
func (cp *CardsPage) renderCards() {
	cp.cardBox.Objects = nil

	if len(cp.cards) == 0 {
		cp.cardBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		cp.cardBox.Refresh()
		return
	}

	for i := range cp.cards {
		card := cp.cards[i]
		cp.cardBox.Add(cp.buildCardWidget(&card))
	}

	cp.cardBox.Refresh()
}

// buildCardWidget 构建单个智能卡卡片组件（参照SimplySign Desktop风格）
func (cp *CardsPage) buildCardWidget(card *api.Card) fyne.CanvasObject {
	// 构建紧凑的多行文本信息（参照SimplySign截图风格）
	certStats := "0"
	if card.CertStats != nil {
		certStats = fmt.Sprintf("X509:%d FIDO:%d TOTP:%d Creds:%d",
			card.CertStats.X509, card.CertStats.FIDO, card.CertStats.TOTP, card.CertStats.Creds)
	}

	expiresText := "-"
	if card.ExpiresAt != "" {
		expiresText = formatTime(card.ExpiresAt)
	}

	text := fmt.Sprintf(
		"Card:          %s\n"+
			"Type:          %s\n"+
			"Security:      %s\n"+
			"Certs:         %s\n"+
			"Created:       %s\n"+
			"Expires:       %s",
		card.CardName,
		slotTypeText(card.SlotType),
		securityLevelText(card.SecurityLevel),
		certStats,
		formatTime(card.CreatedAt),
		expiresText,
	)

	infoLabel := widget.NewLabel(text)
	infoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	infoLabel.Wrapping = fyne.TextWrapOff

	// 操作按钮（紧凑图标按钮）
	genKeyBtn := widget.NewButtonWithIcon("", theme.ContentAddIcon(), func() {
		cp.showKeyGenDialog(*card)
	})
	resetPINBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
		cp.showResetPINDialog(*card)
	})
	detailBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		cp.showCardDetailDialog(*card)
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		cp.confirmDeleteCard(*card)
	})
	deleteBtn.Importance = widget.DangerImportance
	actionRow := container.NewHBox(genKeyBtn, resetPINBtn, detailBtn, deleteBtn)

	// 带边框的卡片
	border := canvas.NewRectangle(theme.DisabledColor())
	border.StrokeWidth = 1
	border.StrokeColor = theme.DisabledColor()
	border.FillColor = theme.InputBackgroundColor()

	cardContent := container.NewBorder(nil, nil, nil, actionRow, infoLabel)
	card2 := container.NewStack(border, container.NewPadded(cardContent))

	return card2
}

func (cp *CardsPage) showKeyGenDialog(card api.Card) {
	keyTypes := []string{"rsa2048", "rsa4096", "ec256", "ec384", "ec521"}
	keyTypeSelect := widget.NewSelect(keyTypes, nil)
	keyTypeSelect.SetSelected("rsa2048")

	passwordEntry := widget.NewPasswordEntry()
	remarkEntry := widget.NewEntry()

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("keygen.type"), Widget: keyTypeSelect},
			{Text: i18n.T("keygen.password"), Widget: passwordEntry},
			{Text: i18n.T("keygen.remark"), Widget: remarkEntry},
		},
		OnSubmit: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			err := cp.appCore.Client().GenerateKey(ctx, card.UUID, keyTypeSelect.Selected, passwordEntry.Text, remarkEntry.Text)
			if err != nil {
				dialog.ShowError(err, cp.window)
				return
			}
			dialog.ShowInformation(i18n.T("app.success"), i18n.T("keygen.success"), cp.window)
			cp.Reload()
		},
		SubmitText: i18n.T("app.ok"),
	}

	d := dialog.NewCustom(i18n.T("keygen.title"), i18n.T("app.cancel"), form, cp.window)
	d.Resize(fyne.NewSize(400, 250))
	d.Show()
}

func (cp *CardsPage) showResetPINDialog(card api.Card) {
	newPIN := widget.NewPasswordEntry()
	confirmPIN := widget.NewPasswordEntry()

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: i18n.T("card.reset_pin"), Widget: newPIN},
			{Text: i18n.T("app.confirm"), Widget: confirmPIN},
		},
		OnSubmit: func() {
			if newPIN.Text != confirmPIN.Text {
				dialog.ShowError(fmt.Errorf("PIN不匹配"), cp.window)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			err := cp.appCore.Client().ResetPIN(ctx, card.UUID, newPIN.Text)
			if err != nil {
				dialog.ShowError(err, cp.window)
				return
			}
			dialog.ShowInformation(i18n.T("app.success"), i18n.T("app.success"), cp.window)
		},
		SubmitText: i18n.T("app.ok"),
	}

	d := dialog.NewCustom(i18n.T("card.reset_pin"), i18n.T("app.cancel"), form, cp.window)
	d.Show()
}

// ---- 辅助函数 ----

func slotTypeText(t api.SlotType) string {
	switch t {
	case api.SlotTypeLocal:
		return i18n.T("card.local")
	case api.SlotTypeTPM2:
		return i18n.T("card.tpm2")
	case api.SlotTypeTPMSC:
		return i18n.T("card.tpmsc")
	case api.SlotTypeCloud:
		return i18n.T("card.cloud")
	default:
		return string(t)
	}
}

func securityLevelText(l api.SecurityLevel) string {
	switch l {
	case api.SecurityLevelHigh:
		return i18n.T("card.level_high")
	case api.SecurityLevelMedium:
		return i18n.T("card.level_medium")
	case api.SecurityLevelLow:
		return i18n.T("card.level_low")
	default:
		return string(l)
	}
}

func (cp *CardsPage) showCardDetailDialog(card api.Card) {
	pinInfo := fmt.Sprintf("%d / %d", card.PINFailedCount, card.PINRetries)
	if card.PINLocked {
		pinInfo += " (已锁定)"
	}
	text := fmt.Sprintf(
		"UUID:           %s\n名称:           %s\n类型:           %s\n安全等级:       %s\n启用:           %v\nPIN失败/上限:   %s\n备注:           %s\n创建时间:       %s\n过期时间:       %s",
		card.UUID, card.CardName, slotTypeText(card.SlotType), securityLevelText(card.SecurityLevel),
		card.Enabled, pinInfo, card.Remark,
		formatTime(card.CreatedAt), formatTime(card.ExpiresAt),
	)
	lbl := widget.NewLabel(text)
	lbl.TextStyle = fyne.TextStyle{Monospace: true}
	d := dialog.NewCustom(i18n.T("card.view_detail"), i18n.T("app.close"), container.NewPadded(lbl), cp.window)
	d.Resize(fyne.NewSize(480, 280))
	d.Show()
}

func (cp *CardsPage) confirmDeleteCard(card api.Card) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(i18n.T("login.password_hint"))
	dialog.NewCustomConfirm(i18n.T("card.delete"), i18n.T("app.ok"), i18n.T("app.cancel"), passEntry, func(ok bool) {
		if !ok || passEntry.Text == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		token := cp.appCore.Token()
		userUUID := ""
		if token != nil {
			userUUID = token.UserUUID
		}
		if err := cp.appCore.Client().DeleteCard(ctx, card.UUID, userUUID, passEntry.Text); err != nil {
			dialog.ShowError(err, cp.window)
			return
		}
		dialog.ShowInformation(i18n.T("app.success"), i18n.T("app.success"), cp.window)
		cp.Reload()
	}, cp.window).Show()
}

func formatTime(s string) string {
	if s == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02 15:04:05")
}