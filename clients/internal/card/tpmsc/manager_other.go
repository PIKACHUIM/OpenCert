//go:build !windows

package tpmsc

import (
	"context"
	"crypto"
)

func createCardPlatform(context.Context, CreateCardArgs) (*CreateCardResult, error) {
	return nil, ErrProvisioningNotImplemented
}

func destroyCardPlatform(context.Context, string) (bool, error) {
	return false, ErrProvisioningNotImplemented
}

func discoverReaderNamePlatform(context.Context, string) (string, error) {
	return "", ErrProvisioningNotImplemented
}

type unavailableSmartCardKSP struct{}

func newSmartCardKeyProvider() SmartCardKeyProvider { return unavailableSmartCardKSP{} }

func (unavailableSmartCardKSP) CreateKey(context.Context, string, string, string) (crypto.Signer, error) {
	return nil, ErrSmartCardKSPUnavailable
}

func (unavailableSmartCardKSP) OpenKey(context.Context, string, string, string, crypto.PublicKey) (crypto.Signer, error) {
	return nil, ErrSmartCardKSPUnavailable
}

func (unavailableSmartCardKSP) DeleteKey(context.Context, string, string) error {
	return ErrSmartCardKSPUnavailable
}
