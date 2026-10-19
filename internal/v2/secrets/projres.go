package secrets

import (
	"errors"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type projectionRefreshLease struct {
	slot  api.ID
	lease bstate.RefreshLease
}

func (f *projectionFlight) acquireRefreshLeases(j bstate.Journal, slots []bstate.Slot) error {
	for _, slot := range slots {
		if slot.Credential.Mode != "codex-file" {
			continue
		}
		lease, err := j.AcquireRefreshLease(slot.LoginID)
		if err != nil {
			return err
		}
		if wire.Nil(lease) {
			return wire.Error(api.CodePrerequisite, "credential projection requires its live kernel refresh lease")
		}
		f.refresh = append(f.refresh, projectionRefreshLease{slot: slot.ID, lease: lease})
	}
	return nil
}

func (f *projectionFlight) checkRefreshLease(slot api.ID) error {
	for _, live := range f.refresh {
		if live.slot == slot && !wire.Nil(live.lease) {
			return live.lease.Check()
		}
	}
	return wire.Error(api.CodeConflict, "credential projection has no live canonical refresh lease")
}

func (f *projectionFlight) checkRefreshLeases() error {
	if runner := f.transfer.Authority.Request.Handoff.Spec.Runner; runner != nil && runner.Slot.Mode == "codex-file" {
		return f.checkRefreshLease(runner.Slot.ID)
	}
	return nil
}

func (f *projectionFlight) closeRefreshLeases() error {
	for _, live := range f.refresh {
		if wire.Nil(live.lease) {
			return wire.Error(api.CodeIntegrity, "credential refresh lease inventory is unknown")
		}
		if err := live.lease.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Count the flight's actual owned export handles, including when a stale
// closed flag says otherwise. Any result other than open or ErrClosed refuses.
func (f *projectionFlight) brokerDescriptorCount() (uint64, error) {
	var count uint64
	for _, file := range f.transfer.Files {
		if file == nil {
			return count, wire.Error(api.CodeIntegrity, "credential export descriptor inventory is unknown")
		}
		if _, err := file.Stat(); err == nil {
			count++
		} else if !errors.Is(err, os.ErrClosed) {
			return count, wire.Error(api.CodeIntegrity, "credential export descriptor lifetime is unknown")
		}
	}
	return count, nil
}

// This probes live kernel locks, never Login.SlotID or Projection metadata.
// Durable ownership remains retained until store completion and slot cleanup.
func (f *projectionFlight) refreshLeaseCount() (uint64, error) {
	var count uint64
	for _, live := range f.refresh {
		if wire.Nil(live.lease) {
			return count, wire.Error(api.CodeIntegrity, "credential refresh lease inventory is unknown")
		}
		held, err := live.lease.Held()
		if err != nil {
			return count, err
		}
		if held {
			count++
		}
	}
	if runner := f.transfer.Authority.Request.Handoff.Spec.Runner; runner != nil && runner.Slot.Mode == "codex-file" {
		found := false
		for _, live := range f.refresh {
			found = found || live.slot == runner.Slot.ID
		}
		if !found {
			return count, wire.Error(api.CodePrerequisite, "credential refresh lease measurement requires its original live inventory")
		}
	}
	return count, nil
}
