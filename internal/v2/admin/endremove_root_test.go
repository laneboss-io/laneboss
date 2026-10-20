//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"errors"
	"testing"
)

type endRemoveFault struct {
	leaseResources
	store leaseStorage
	hit   bool
	err   error
}

func (r *endRemoveFault) Remove(ctx context.Context, record leaseRecord) error {
	records, err := r.store.Records()
	if err != nil {
		return err
	}
	if len(records) != 1 || !committedExit(records[0]) || records[0].Lease != record.Lease || records[0].Revoked {
		return errors.New("cgroup removal preceded its committed native exit")
	}
	if !r.hit {
		r.hit = true
		return r.err
	}
	return r.leaseResources.Remove(ctx, record)
}

func TestEndRemovalNative(t *testing.T) {
	normalReleaseNative(t, false, true)
}

func TestEndRemovalControl(t *testing.T) {
	runEndControl(t, "gate.go", "if committedExit(*record) {", "if false && committedExit(*record) {",
		"TestEndRemovalNative", "restart lost its durable native exit before removal",
		"laneboss_root_canary,laneboss_gate_integration")
}
