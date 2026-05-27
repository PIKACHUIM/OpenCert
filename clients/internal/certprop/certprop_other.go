//go:build !windows

package certprop

import (
	"context"
)

// noopPropagator 是非 Windows 平台的空实现。
type noopPropagator struct{}

// New 在非 Windows 平台返回空实现（no-op）。
func New() Propagator {
	return &noopPropagator{}
}

func (p *noopPropagator) Sync(ctx context.Context, certs []CertInfo) (*SyncResult, error) {
	logger().Info("证书传播仅在 Windows 平台生效，当前平台跳过")
	return &SyncResult{}, nil
}

func (p *noopPropagator) Add(ctx context.Context, cert CertInfo) error {
	return nil
}

func (p *noopPropagator) Remove(ctx context.Context, certUUID string) error {
	return nil
}

func (p *noopPropagator) RemoveAll(ctx context.Context) error {
	return nil
}
