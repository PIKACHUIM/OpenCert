package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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

// CredsPage 安全凭据管理页面
type CredsPage struct {
	appCore  *appcore.App
	window   fyne.Window
	scroll   *container.Scroll
	credsBox *fyne.Container
	cardUUID string
}

// NewCredsPage 创建安全凭据管理页面
func NewCredsPage(a *appcore.App, w fyne.Window) *CredsPage {
	return &CredsPage{appCore: a, window: w}
}

func (p *CredsPage) Build() fyne.CanvasObject {
	p.credsBox = container.NewVBox()
	p.scroll = container.NewVScroll(p.credsBox)
	return p.scroll
}

// SetCardUUID 由主窗口统一调用
func (p *CredsPage) SetCardUUID(uuid string) {
	p.cardUUID = uuid
	p.loadCreds()
}

func (p *CredsPage) Reload() {
	if !p.appCore.IsLoggedIn() {
		p.credsBox.Objects = nil
		p.credsBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.credsBox.Refresh()
		return
	}
	p.loadCreds()
}

func (p *CredsPage) loadCreds() {
	p.credsBox.Objects = nil

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

	var credCerts []api.Certificate
	for _, uuid := range uuids {
		certs, err := p.appCore.Client().ListCerts(ctx, uuid)
		if err != nil {
			continue
		}
		for _, c := range certs {
			ct := string(c.CertType)
			if ct == "login" || ct == "text" || ct == "note" || ct == "payment" {
				credCerts = append(credCerts, c)
			}
		}
	}

	if len(credCerts) == 0 {
		p.credsBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		p.credsBox.Refresh()
		return
	}
	for i := range credCerts {
		cert := credCerts[i]
		p.credsBox.Add(p.buildCredWidget(&cert))
	}
	p.credsBox.Refresh()
}

// parseMeta 将 base64 编码的 JSON 字节解析为 map
func parseMeta(certContent string) map[string]string {
	if certContent == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(certContent)
	if err != nil {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil
	}
	return m
}

// metaSummary 返回按类型格式化的公开元数据摘要
func metaSummary(certType string, meta map[string]string) string {
	if meta == nil {
		return ""
	}
	switch certType {
	case "login":
		parts := []string{}
		if v := meta["site"]; v != "" {
			parts = append(parts, "网站: "+v)
		}
		if v := meta["username"]; v != "" {
			parts = append(parts, "用户: "+v)
		}
		return strings.Join(parts, "  |  ")
	case "note":
		return "标题: " + meta["title"]
	case "payment":
		parts := []string{}
		if v := meta["cardholder"]; v != "" {
			parts = append(parts, "持卡人: "+v)
		}
		if v := meta["bank"]; v != "" {
			parts = append(parts, "银行: "+v)
		}
		if v := meta["last4"]; v != "" {
			parts = append(parts, "尾号: "+v)
		}
		return strings.Join(parts, "  |  ")
	case "text":
		return "标签: " + meta["label"]
	}
	return ""
}

// secretSummary 返回解密后 JSON 的可读摘要
func secretSummary(certType string, secretJSON string) string {
	var m map[string]string
	if err := json.Unmarshal([]byte(secretJSON), &m); err != nil {
		return secretJSON
	}
	switch certType {
	case "login":
		return "密码: " + m["password"]
	case "note":
		return "内容: " + m["content"]
	case "payment":
		parts := []string{}
		if v := m["card_number"]; v != "" {
			parts = append(parts, "卡号: "+v)
		}
		if v := m["expiry"]; v != "" {
			parts = append(parts, "有效期: "+v)
		}
		if v := m["cvv"]; v != "" {
			parts = append(parts, "CVV: "+v)
		}
		return strings.Join(parts, "  |  ")
	case "text":
		return "内容: " + m["secret"]
	}
	return secretJSON
}

func (p *CredsPage) buildCredWidget(cert *api.Certificate) fyne.CanvasObject {
	meta := parseMeta(cert.CertContent)
	text := fmt.Sprintf("编号:      %s\n类型:      %s", cert.UUID, string(cert.CertType))
	if meta != nil {
		if v := meta["site"]; v != "" {
			text += "\n网站:      " + v
		}
		if v := meta["username"]; v != "" {
			text += "\n用户:      " + v
		}
		if v := meta["title"]; v != "" {
			text += "\n标题:      " + v
		}
		if v := meta["label"]; v != "" {
			text += "\n标签:      " + v
		}
	}
	if cert.Remark != "" {
		text += "\n备注:    " + cert.Remark
	}

	infoLabel := widget.NewLabel(text)
	infoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	infoLabel.Wrapping = fyne.TextWrapOff

	username := ""
	if meta != nil {
		username = meta["username"]
	}

	viewBtn := widget.NewButtonWithIcon("", theme.VisibilityIcon(), func() { p.showViewDialog(cert) })
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() { p.confirmDeleteCred(*cert) })
	deleteBtn.Importance = widget.DangerImportance

	actions := container.NewHBox()
	if username != "" {
		u := username
		actions.Add(widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
			p.window.Clipboard().SetContent(u)
		}))
	}
	if string(cert.CertType) == "login" {
		actions.Add(widget.NewButtonWithIcon("", theme.AccountIcon(), func() {
			p.showCopyPasswordDialog(cert)
		}))
	}
	actions.Add(viewBtn)
	actions.Add(deleteBtn)

	border := canvas.NewRectangle(theme.DisabledColor())
	border.StrokeWidth = 1
	border.StrokeColor = theme.DisabledColor()
	border.FillColor = theme.InputBackgroundColor()
	return container.NewStack(border, container.NewPadded(container.NewBorder(nil, nil, nil, actions, infoLabel)))
}

func (p *CredsPage) showViewDialog(cert *api.Certificate) {
	meta := parseMeta(cert.CertContent)

	// 公开信息区（无需密码）
	var pubRows []fyne.CanvasObject
	if meta != nil {
		for k, v := range meta {
			if v == "" {
				continue
			}
			row := container.NewHBox(
				widget.NewLabel(k+":"),
				widget.NewLabel(v),
			)
			pubRows = append(pubRows, row)
		}
	}

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(i18n.T("creds.card_password_hint"))

	secretLabel := widget.NewLabel("")
	secretLabel.TextStyle = fyne.TextStyle{Monospace: true}
	secretLabel.Wrapping = fyne.TextWrapWord
	secretLabel.Hide()

	decryptBtn := widget.NewButton(i18n.T("creds.decrypt"), nil)
	decryptBtn.OnTapped = func() {
		if passEntry.Text == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		raw, err := p.appCore.Client().GetCredentialSecret(ctx, cert.CardUUID, cert.UUID, passEntry.Text)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}
		text := secretSummary(string(cert.CertType), string(raw))
		secretLabel.SetText(text)
		secretLabel.Show()
		passEntry.Hide()
		decryptBtn.Hide()
	}

	content := container.NewVBox()
	if len(pubRows) > 0 {
		pubSection := container.NewVBox(pubRows...)
		content.Add(pubSection)
		content.Add(widget.NewSeparator())
	}
	content.Add(passEntry)
	content.Add(decryptBtn)
	content.Add(secretLabel)

	d := dialog.NewCustom(i18n.T("creds.content"), i18n.T("app.close"), container.NewPadded(content), p.window)
	d.Resize(fyne.NewSize(400, 280))
	d.Show()
}

func (p *CredsPage) showCopyPasswordDialog(cert *api.Certificate) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder(i18n.T("creds.card_password_hint"))
	d := dialog.NewCustomConfirm(i18n.T("creds.copy_password"), i18n.T("app.ok"), i18n.T("app.cancel"), passEntry, func(ok bool) {
		if !ok || passEntry.Text == "" {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		raw, err := p.appCore.Client().GetCredentialSecret(ctx, cert.CardUUID, cert.UUID, passEntry.Text)
		if err != nil {
			dialog.ShowError(err, p.window)
			return
		}
		var m map[string]string
		pass := string(raw)
		if json.Unmarshal(raw, &m) == nil {
			if v := m["password"]; v != "" {
				pass = v
			}
		}
		p.window.Clipboard().SetContent(pass)
	}, p.window)
	d.Resize(fyne.NewSize(400, 150))
	d.Show()
}

func (p *CredsPage) confirmDeleteCred(cert api.Certificate) {
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
		p.loadCreds()
	}, p.window)
}
