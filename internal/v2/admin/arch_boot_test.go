package admin

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestArchiveBootProof(t *testing.T) {
	for _, mode := range []string{"valid", "same-boot", "missing-boot", "cgroup", "unknown", "survivor", "connection", "job", "export", "future", "target", "containment", "release", "abort", "absent"} {
		t.Run(mode, func(t *testing.T) {
			r := archiveClaimFixture()
			zero, one := uint64(0), uint64(1)
			at := gateTimestamp()
			allocation := api.HelperLease{ID: "original-allocation", ContainmentID: "original-cgroup", UID: 61002, GID: 61002, EndpointGeneration: 1}
			proof := archivejob.Retirement{JobID: r.Job.ID, OperationID: r.Job.Intent.OperationID, EffectID: r.Job.Lease.EffectID, Target: r.Job.Lease.Target, Allocation: allocation, ObservedAt: at,
				Boot: &archivejob.BootRetirement{PreviousBootID: "old-boot", BootID: "current-boot", Process: api.ProcessHandle{ID: r.LaunchID, Target: r.Job.Lease.Target, ContainmentID: allocation.ContainmentID, Generation: "old-boot:7"}, CgroupAbsent: true, Survivors: &zero, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero, ObservedAt: at}}
			switch mode {
			case "same-boot":
				proof.Boot.BootID = proof.Boot.PreviousBootID
			case "missing-boot":
				proof.Boot.PreviousBootID = ""
			case "cgroup":
				proof.Boot.CgroupAbsent = false
			case "unknown":
				proof.Boot.Survivors = nil
			case "survivor":
				proof.Boot.Survivors = &one
			case "connection":
				proof.Boot.LiveConnections = &one
			case "job":
				proof.Boot.QueuedJobs = &one
			case "export":
				proof.Boot.WritableExports = &one
			case "future":
				proof.Boot.ObservedAt = api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
			case "target":
				proof.Boot.Process.Target.LifeID = "foreign-life"
			case "containment":
				proof.Boot.Process.ContainmentID = "foreign-cgroup"
			case "release":
				proof.Release = &api.ReleaseReceipt{}
			case "abort":
				proof.Abort = &api.AbortReceipt{}
			case "absent":
				proof.Absent = true
			}
			err := validateRetirementProof(r.Job, proof, time.Now())
			if mode == "valid" {
				if err != nil {
					t.Fatal("acceptance: measured boot retirement proof was refused", err)
				}
			} else if err == nil {
				t.Fatal("acceptance: boot retirement accepted competing or unmeasured evidence")
			}
		})
	}
}
