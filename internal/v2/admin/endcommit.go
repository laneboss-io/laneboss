package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

// Normal release publishes its native end before lending the operation lock
// to the credential broker or removing a registration/resource. Stop and
// revocation keep their independently committed disposition.
func (m *leaseManager) commitExitForRelease(ctx context.Context, record *leaseRecord, claim api.ProcessObservation) error {
	if record.Gate == nil || record.Revoked || record.Gate.Stop != nil {
		return nil
	}
	if record.BootID != m.bootID || record.Spec == nil || claim.Handle != gateHandle(*record) ||
		record.Gate.State != "opened" && record.Gate.State != "ended" {
		return failure(api.CodeContainmentUnknown, "normal release lost its exact current native gate")
	}
	if committedExit(*record) {
		return m.resources.Quiescent(ctx, *record)
	}
	live := m.gates[record.Lease.ID]
	if live == nil || live.PID() != record.Gate.PID || live.Generation() != record.Gate.Prepared.ProcessGeneration {
		return failure(api.CodeContainmentUnknown, "normal release lost its original native wait owner")
	}
	observation, err := live.Observe(ctx, gateHandle(*record))
	if err != nil {
		return err
	}
	if observation.Handle != gateHandle(*record) || observation.State != "exited" {
		return failure(api.CodeContainmentUnknown, "normal release has no original terminal wait")
	}
	if err := m.resources.Quiescent(ctx, *record); err != nil {
		return err
	}
	zero := uint64(0) // The native resource owner measured cgroup and UID quiescence.
	observation.Survivors = &zero
	if err := validateObservation(*record, observation); err != nil {
		return err
	}
	actual, expected := observation, claim
	actual.ObservedAt, expected.ObservedAt = "", ""
	if !reflect.DeepEqual(actual, expected) {
		return failure(api.CodeContainmentUnknown, "normal release claim differs from its original native end")
	}
	// Do not mutate the caller or a store's shared pointers before Save has
	// succeeded. An uncertain write reply still leaves any published end in
	// the protected journal, while this operation retains all other ownership.
	next, gate := *record, *record.Gate
	gate.State, gate.Observation = "ended", &observation
	next.Gate = &gate
	if err := m.save(next); err != nil {
		return err
	}
	*record = next
	return nil
}
