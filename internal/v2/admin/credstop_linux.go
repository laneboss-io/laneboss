//go:build linux

package admin

import (
	"context"
	"errors"
)

// Attempt the cgroup kill and the owned pidfd kill independently, then wait.
// A failure remains an error even when the other kill route succeeds.
func (m *leaseManager) killAndWait(ctx context.Context, record leaseRecord) error {
	killErr := m.killContainment(ctx, record)
	live := m.gates[record.Lease.ID]
	var closeErr, waitErr error
	if live != nil && record.Gate != nil {
		closeErr = live.Close()
	}
	if record.Gate != nil && record.Gate.PID > 0 {
		waitErr = waitRevokedGate(ctx, record, live, func() error { return m.waitContainmentEmpty(ctx, record) })
	} else {
		waitErr = m.waitContainmentEmpty(ctx, record)
	}
	return errors.Join(killErr, closeErr, waitErr)
}

var _ containmentController = (*linuxResources)(nil)
