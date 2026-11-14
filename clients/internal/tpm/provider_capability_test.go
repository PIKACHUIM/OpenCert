package tpm

import "testing"

type nvCapabilityProvider struct {
	Provider
	available bool
}

func (p nvCapabilityProvider) HardwareNVStorageAvailable() bool { return p.available }

func TestHardwareNVRequiresExplicitBackendCapability(t *testing.T) {
	provider := NewMock()
	if SupportsHardwareNV(provider) {
		t.Fatal("mock provider must not claim hardware NV")
	}
	if !SupportsHardwareNV(nvCapabilityProvider{Provider: provider, available: true}) {
		t.Fatal("explicitly declared hardware NV capability was ignored")
	}
	if SupportsHardwareNV(nvCapabilityProvider{Provider: provider}) {
		t.Fatal("provider without hardware NV must not be accepted")
	}
}
