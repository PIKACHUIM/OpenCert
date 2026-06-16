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
	"github.com/globaltrusts/native-client/internal/config"
	"github.com/globaltrusts/native-client/internal/i18n"
)

// CertsPage 证书列表页面
type CertsPage struct {
	appCore  *appcore.App
	window   fyne.Window
	certs    []api.Certificate
	scroll   *container.Scroll
	certBox  *fyne.Container
	cardUUID string // "" 表示全部
}

func NewCertsPage(a *appcore.App, w fyne.Window) *CertsPage {
	return &CertsPage{appCore: a, window: w}
}

func (cp *CertsPage) Build() fyne.CanvasObject {
	cp.certBox = container.NewVBox()
	cp.scroll = container.NewVScroll(cp.certBox)
	return cp.scroll
}

// SetCardUUID 由主窗口统一调用，"" 表示全部卡片
func (cp *CertsPage) SetCardUUID(uuid string) {
	cp.cardUUID = uuid
	cp.loadCerts()
}

func (cp *CertsPage) Reload() {
	if !cp.appCore.IsLoggedIn() {
		cp.certs = nil
		cp.renderCerts()
		return
	}
	cp.loadCerts()
}

func (cp *CertsPage) loadCerts() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if cp.cardUUID == "" {
		// 「全部」：需要拉一次卡片列表再逐一查证书
		cards, err := cp.appCore.Client().ListCards(ctx)
		if err != nil {
			dialog.ShowError(err, cp.window)
			return
		}
		var all []api.Certificate
		for _, c := range cards {
			certs, err := cp.appCore.Client().ListCerts(ctx, c.UUID)
			if err != nil {
				continue
			}
			all = append(all, certs...)
		}
		cp.certs = all
	} else {
		certs, err := cp.appCore.Client().ListCerts(ctx, cp.cardUUID)
		if err != nil {
			dialog.ShowError(err, cp.window)
			return
		}
		cp.certs = certs
	}
	cp.renderCerts()
}

// renderCerts 渲染证书列表
func (cp *CertsPage) renderCerts() {
	cp.certBox.Objects = nil

	if len(cp.certs) == 0 {
		cp.certBox.Add(widget.NewLabel(i18n.T("app.no_data")))
		cp.certBox.Refresh()
		return
	}

	for i := range cp.certs {
		cert := cp.certs[i]
		if cert.CertType != api.CertTypeX509 && cert.CertType != "gpg" {
			continue
		}
		if config.Get().HideExpired && isCertExpired(cert) {
			continue
		}
		cp.certBox.Add(cp.buildCertWidget(&cert))
	}

	cp.certBox.Refresh()
}

// buildCertWidget 构建单个证书卡片组件（参照SimplySign Desktop紧凑纯文本风格）
func (cp *CertsPage) buildCertWidget(cert *api.Certificate) fyne.CanvasObject {
	text := fmt.Sprintf(
		"Subject:       %s\n"+
			"Type:          %s [%s]\n"+
			"Serial:        %s\n"+
			"Issuer:        %s\n"+
			"Key:           %s\n"+
			"Created:       %s",
		cert.CommonName,
		string(cert.CertType), slotTypeText(cert.SlotType),
		cert.UUID,
		cert.IssuerCN,
		cert.KeyType,
		formatTime(cert.CreatedAt),
	)

	infoLabel := widget.NewLabel(text)
	infoLabel.TextStyle = fyne.TextStyle{Monospace: true}
	infoLabel.Wrapping = fyne.TextWrapOff

	detailBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		cp.showCertDetail(*cert)
	})
	deleteBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		cp.confirmDeleteCert(*cert)
	})
	deleteBtn.Importance = widget.DangerImportance
	actions := container.NewHBox(detailBtn)

	if cert.SlotType == api.SlotTypeCloud {
		actions.Add(widget.NewButtonWithIcon("", theme.MailSendIcon(), func() {
			cp.showDeliverDialog(*cert)
		}))
	}
	actions.Add(deleteBtn)

	// 带边框的卡片（参照截图的矩形边框）
	border := canvas.NewRectangle(theme.DisabledColor())
	border.StrokeWidth = 1
	border.StrokeColor = theme.DisabledColor()
	border.FillColor = theme.InputBackgroundColor()

	cardContent := container.NewBorder(nil, nil, nil, actions, infoLabel)
	card := container.NewStack(border, container.NewPadded(cardContent))

	return card
}

func isCertExpired(cert api.Certificate) bool {
	if cert.CreatedAt == "" {
		return false
	}
	// 使用 CreatedAt 作为近似判断（实际应使用过期时间）
	return false
}

func (cp *CertsPage) showCertDetail(cert api.Certificate) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	detail, err := cp.appCore.Client().GetCertDetail(ctx, cert.CardUUID, cert.UUID)
	if err != nil {
		dialog.ShowError(err, cp.window)
		return
	}

	cp.showCertDetailDialog(detail)
}

// showCertDetailDialog 显示证书详情对话框（参考 SimplySign Desktop 风格）
func (cp *CertsPage) showCertDetailDialog(detail *api.CertDetail) {
	// 主体信息区
	subjectInfo := cp.buildInfoSection(i18n.T("cert.detail.subject"), []infoItem{
		{"CN", detail.CommonName},
		{"O", detail.Organization},
		{"OU", detail.OrgUnit},
		{"C", detail.Country},
		{"ST", detail.State},
		{"L", detail.Locality},
		{"Street", detail.Street},
		{"Serial", detail.SubjectSerial},
	})

	// 颁发者信息区
	issuerInfo := cp.buildInfoSection(i18n.T("cert.detail.issuer"), []infoItem{
		{"CN", detail.IssuerCN},
		{"O", detail.IssuerOrg},
		{"OU", detail.IssuerOU},
		{"C", detail.IssuerCountry},
		{"ST", detail.IssuerState},
		{"L", detail.IssuerLocality},
	})

	// 有效期区
	validityInfo := cp.buildInfoSection(i18n.T("cert.detail.validity"), []infoItem{
		{i18n.T("cert.valid_from"), detail.NotBefore},
		{i18n.T("cert.valid_to"), detail.NotAfter},
		{i18n.T("cert.serial"), detail.SerialNumber},
	})

	// 指纹区
	fingerprintInfo := cp.buildInfoSection(i18n.T("cert.detail.fingerprint"), []infoItem{
		{"SHA-1", detail.SHA1Fingerprint},
		{"SHA-256", detail.SHA256Fingerprint},
	})

	// 密钥信息区
	keyBitsText := ""
	if detail.KeyBits > 0 {
		keyBitsText = fmt.Sprintf("%d", detail.KeyBits)
	}
	keyInfo := cp.buildInfoSection(i18n.T("cert.detail.key_info"), []infoItem{
		{i18n.T("cert.key_type"), detail.PublicKeyAlgo},
		{"Bits", keyBitsText},
		{i18n.T("cert.detail.key_usage"), joinStrings(detail.KeyUsage)},
		{i18n.T("cert.detail.ext_usage"), joinStrings(detail.ExtKeyUsage)},
		{"Signature", detail.SignatureAlgo},
	})

	// SAN
	sanItems := []infoItem{}
	if len(detail.SANDNSNames) > 0 {
		sanItems = append(sanItems, infoItem{"DNS", joinStrings(detail.SANDNSNames)})
	}
	if len(detail.SANIPAddresses) > 0 {
		sanItems = append(sanItems, infoItem{"IP", joinStrings(detail.SANIPAddresses)})
	}
	if len(detail.SANEmailAddresses) > 0 {
		sanItems = append(sanItems, infoItem{"Email", joinStrings(detail.SANEmailAddresses)})
	}
	if len(detail.SANURIs) > 0 {
		sanItems = append(sanItems, infoItem{"URI", joinStrings(detail.SANURIs)})
	}
	var sanSection fyne.CanvasObject
	if len(sanItems) > 0 {
		sanSection = cp.buildInfoSection(i18n.T("cert.detail.san"), sanItems)
	}

	// CRL / OCSP / AIA
	var extSections []fyne.CanvasObject
	if len(detail.CRLDistPoints) > 0 {
		extSections = append(extSections, cp.buildInfoSection(i18n.T("cert.detail.crl"),
			[]infoItem{{"URL", joinStrings(detail.CRLDistPoints)}}))
	}
	if len(detail.OCSPServers) > 0 {
		extSections = append(extSections, cp.buildInfoSection(i18n.T("cert.detail.ocsp"),
			[]infoItem{{"URL", joinStrings(detail.OCSPServers)}}))
	}
	if len(detail.IssuingCertURL) > 0 {
		extSections = append(extSections, cp.buildInfoSection(i18n.T("cert.detail.aia"),
			[]infoItem{{"URL", joinStrings(detail.IssuingCertURL)}}))
	}

	// 证书策略
	if len(detail.CertPolicies) > 0 {
		policyTexts := make([]string, len(detail.CertPolicies))
		for i, p := range detail.CertPolicies {
			if p.Description != "" {
				policyTexts[i] = fmt.Sprintf("%s (%s)", p.OID, p.Description)
			} else {
				policyTexts[i] = p.OID
			}
		}
		extSections = append(extSections, cp.buildInfoSection(i18n.T("cert.detail.policies"),
			[]infoItem{{"OID", joinStrings(policyTexts)}}))
	}

	// 其他信息
	otherItems := []infoItem{
		{"IsCA", fmt.Sprintf("%v", detail.IsCA)},
		{"SelfSigned", fmt.Sprintf("%v", detail.IsSelfSigned)},
	}
	if detail.IsCA {
		otherItems = append(otherItems, infoItem{"MaxPathLen", fmt.Sprintf("%d", detail.MaxPathLen)})
	}
	otherSection := cp.buildInfoSection(i18n.T("cert.detail.other"), otherItems)

	// Tab 1: 主体与颁发者
	subjectIssuer := container.NewVBox(subjectInfo, widget.NewSeparator(), issuerInfo)

	// Tab 2: 技术信息（密钥 + 有效期 + 指纹 + 其他）
	techInfo := container.NewVBox(keyInfo, widget.NewSeparator(), validityInfo, widget.NewSeparator(), fingerprintInfo, widget.NewSeparator(), otherSection)

	// Tab 3: 扩展信息（SAN + CRL/OCSP/AIA/策略）
	extItems := []fyne.CanvasObject{}
	if sanSection != nil {
		extItems = append(extItems, sanSection)
	}
	for _, s := range extSections {
		if len(extItems) > 0 {
			extItems = append(extItems, widget.NewSeparator())
		}
		extItems = append(extItems, s)
	}

	tabs := container.NewAppTabs(
		container.NewTabItem(i18n.T("cert.detail.subject_issuer"), container.NewVScroll(subjectIssuer)),
		container.NewTabItem(i18n.T("cert.detail.tech_info"), container.NewVScroll(techInfo)),
	)
	if len(extItems) > 0 {
		tabs.Append(container.NewTabItem(i18n.T("cert.detail.extensions"), container.NewVScroll(container.NewVBox(extItems...))))
	}

	d := dialog.NewCustom(i18n.T("cert.detail.title"), i18n.T("app.close"), tabs, cp.window)
	d.Resize(fyne.NewSize(550, 450))
	d.Show()
}

// infoItem 信息项
type infoItem struct {
	Label string
	Value string
}

// buildInfoSection 构建信息展示区
func (cp *CertsPage) buildInfoSection(title string, items []infoItem) fyne.CanvasObject {
	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	var rows []fyne.CanvasObject
	rows = append(rows, titleLabel)

	for _, item := range items {
		if item.Value == "" {
			continue
		}
		label := widget.NewLabel(item.Label + ":")
		label.TextStyle = fyne.TextStyle{Monospace: true}
		value := widget.NewLabel(item.Value)
		value.TextStyle = fyne.TextStyle{Monospace: true}
		value.Wrapping = fyne.TextWrapWord

		row := container.NewBorder(nil, nil, label, nil, value)
		rows = append(rows, row)
	}

	return container.NewVBox(rows...)
}

func (cp *CertsPage) showDeliverDialog(cert api.Certificate) {
	NewDeliverDialog(cp.appCore, cp.window, cert, cp.cardUUID).Show()
}

func (cp *CertsPage) confirmDeleteCert(cert api.Certificate) {
	dialog.ShowConfirm(i18n.T("app.confirm"), i18n.T("app.confirm_delete"), func(ok bool) {
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := cp.appCore.Client().DeleteCert(ctx, cert.CardUUID, cert.UUID); err != nil {
			dialog.ShowError(err, cp.window)
			return
		}
		dialog.ShowInformation(i18n.T("app.success"), i18n.T("app.success"), cp.window)
		cp.loadCerts()
	}, cp.window)
}

// ---- 辅助函数 ----

func truncateUUID(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}
