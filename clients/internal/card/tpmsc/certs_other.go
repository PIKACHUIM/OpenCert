//go:build !windows

package tpmsc

import (
	"context"
	"time"
)

// CardCertificate 是一张 VSC 上可用的证书。
type CardCertificate struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	SHA1          string    `json:"sha1"`
	ContainerName string    `json:"container_name"`
	ProviderName  string    `json:"provider_name"`
	CertPEM       string    `json:"cert_pem"`
}

// ListCardCertificates 在非 Windows 平台不可用。
func ListCardCertificates(string) ([]CardCertificate, error) {
	return nil, ErrProvisioningNotImplemented
}

// ImportPFXToCard 在非 Windows 平台不可用。
func ImportPFXToCard(context.Context, string, []byte, string) error {
	return ErrProvisioningNotImplemented
}
