//go:build linux

package store

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestArchiveBootEvidence(t *testing.T) {
	for _, mode := range []string{"valid", "process", "allocation", "same-boot", "survivor", "unknown", "cgroup", "competing"} {
		t.Run(mode, func(t *testing.T) {
			f := newArch(t)
			ctx := context.Background()
			proof := retiredProof(t, f)
			zero, one := uint64(0), uint64(1)
			proof.Release = nil
			proof.Boot = &archivejob.BootRetirement{PreviousBootID: "previous-boot", BootID: "current-boot", Process: f.record.Process, CgroupAbsent: true, Survivors: &zero, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: proof.ObservedAt}
			switch mode {
			case "process":
				proof.Boot.Process.ID = testID(t)
			case "allocation":
				proof.Allocation.UID++
			case "same-boot":
				proof.Boot.BootID = proof.Boot.PreviousBootID
			case "survivor":
				proof.Boot.Survivors = &one
			case "unknown":
				proof.Boot.Survivors = nil
			case "cgroup":
				proof.Boot.CgroupAbsent = false
			case "competing":
				proof.Abort = &api.AbortReceipt{}
			}
			err := f.s.RecordArchiveRetirement(ctx, f.executor, f.record.Claim, proof)
			if mode != "valid" {
				if err == nil {
					t.Fatal("acceptance: store accepted foreign or unmeasured boot retirement")
				}
				expectCode(t, err, api.CodeContainmentUnknown)
				state, readErr := f.s.ArchiveRecovery(ctx, f.executor, f.record.Claim)
				if readErr != nil || state.Retirement != nil || state.Process != f.record.Process || state.Allocation != f.record.Allocation {
					t.Fatal("refused boot evidence changed the durable original allocation")
				}
				return
			}
			if err != nil {
				t.Fatal("acceptance: store refused the original measured boot retirement", err)
			}
			state, err := f.s.ArchiveRecovery(ctx, f.executor, f.record.Claim)
			if err != nil || state.Retirement == nil || !reflect.DeepEqual(*state.Retirement, proof) || state.Process != f.record.Process {
				t.Fatal("store did not retain boot evidence and the unchanged original process", err)
			}
			if err := f.s.RecordArchiveRetirement(ctx, f.executor, f.record.Claim, proof); err != nil {
				t.Fatal("store refused identical boot evidence replay", err)
			}
			changed := proof
			changedBoot := *proof.Boot
			changedBoot.BootID = "another-current-boot"
			changed.Boot = &changedBoot
			if err := f.s.RecordArchiveRetirement(ctx, f.executor, f.record.Claim, changed); err == nil {
				t.Fatal("store replaced immutable boot evidence")
			} else {
				expectCode(t, err, api.CodeConflict)
			}
			failure := &api.Error{Code: api.CodeContainmentUnknown, Message: "archive exit status was lost across reboot", Instead: "Inspect the retained boot retirement and preserve original archive bytes."}
			commit, err := callOwnedFailure(f.s, ctx, f.executor, f.record.Claim, failure, nil)
			if err != nil || commit.Operation.Status != "failed" {
				t.Fatal("acceptance: measured boot retirement could not finish without an invented exit", err)
			}
		})
	}
}
