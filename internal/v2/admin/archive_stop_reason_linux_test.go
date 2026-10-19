//go:build linux

package admin

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// These are comparison inputs for the archive ownership validator, not a
// claim of native withdrawal or filesystem freeze. The native reason test
// separately measures the real canary's independent exit and stop attempts.
func TestStoppedArchiveWithdrawalReason(t *testing.T) {
	for _, mode := range []string{"release", "cancelled", "revoked", "release-operation", "release-epoch", "release-foreign-cause", "withdrawal-end"} {
		t.Run(mode, func(t *testing.T) {
			m, memory, _ := testManager()
			lease, err := m.allocate(context.Background(), testAllocation())
			if err != nil {
				t.Fatal(err)
			}
			record := memory.records[0]
			observed := testObservation(lease)
			stop := testCause(api.InternalHelperStop, observed.Handle.Target.LifeID)
			stop.CancellationEpoch = 2
			reason := "release"
			if mode == "cancelled" || mode == "revoked" {
				reason = mode
			}
			record.Revoked, record.Phase = true, "released"
			record.Spec = &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{LaunchID: observed.Handle.ID}}}
			record.Gate = &gateJournal{State: "ended", Stop: &stop, Observation: &observed, Permit: &api.LaunchPermit{LaunchID: observed.Handle.ID},
				Prepared: api.PreparedLaunch{Target: observed.Handle.Target, ProcessGeneration: observed.Handle.Generation}}
			record.Storage = &launchStorageRecord{Ready: true, Withdrawn: true,
				OriginalModes: []storageMode{{RootID: "component-root", Name: ".", Kind: "directory", Device: 1, Inode: 1, Mode: 0700}}}
			zero, executed := uint64(0), true
			projection := &api.CredentialProjectionRecord{State: "withdrawn", Fence: &api.CredentialWithdrawalRequest{Cause: stop, Reason: reason},
				Withdrawal: &api.CredentialWithdrawalReceipt{AgentExecuted: &executed, RotationRequired: true, Observation: observed}}
			record.Credentials = &credentialJournal{State: "withdrawn", Stop: &credentialStop{Cause: stop, Reason: reason}, Record: projection}
			release := testRelease(lease, observed)
			release.Cause.CancellationEpoch = stop.CancellationEpoch
			release.Cause.ID, release.Cause.EffectID = "component-release", "component-release-effect"
			record.Release = &release
			record.Receipt = &api.ReleaseReceipt{ID: "component-receipt", LeaseID: lease.ID, ContainmentID: lease.ContainmentID,
				Backend: record.Request.Backend, OperationID: release.Cause.CauseOperationID, EffectID: release.Cause.EffectID,
				ObservedAt: observed.ObservedAt, Quiescence: observed, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
			switch mode {
			case "revoked":
				projection.Revoked = true
			case "release-operation":
				record.Release.Cause.CauseOperationID += "-other"
				record.Receipt.OperationID = record.Release.Cause.CauseOperationID
			case "release-epoch":
				record.Release.Cause.CancellationEpoch++
			case "release-foreign-cause":
				record.Credentials.Stop.Cause.ID += "-other"
			case "withdrawal-end":
				exit := 1
				projection.Withdrawal.Observation.ExitCode = &exit
			}
			intent := archivejob.Intent{Request: api.ArchiveRequest{Target: observed.Handle.Target}, CancellationEpoch: 3}
			err = stoppedArchiveOwner(record, intent)
			if mode == "release" || mode == "cancelled" {
				if err != nil {
					t.Fatal("completed ordinary stop lost its read-only archive owner", reason, err)
				}
			} else if err == nil {
				t.Fatal("archive accepted revoked credentials or changed release/end binding", mode)
			}
		})
	}
}
