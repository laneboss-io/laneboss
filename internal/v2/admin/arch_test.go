package admin

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// These are protocol component inputs, not native execution evidence.
func archiveClaimFixture() archiveReg {
	target := api.LifeRef{LifeID: "archive-life", Run: 2}
	deadline := api.Timestamp(time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339Nano))
	worker := api.WorkerLease{ID: "archive-worker", Kind: "archive", Target: target, OperationID: "archive-operation", EffectID: "archive-effect", GrantSetID: "archive-grants", ExpiresAt: deadline, Generation: 1, Input: api.BlobRef{ID: "archive-input", Class: "archive_input", SHA256: testDigest("input"), Bytes: 5}}
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", GrantSetID: worker.GrantSetID, Input: worker.Input, Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(worker.ID)}}
	cause := testCause(api.InternalLifecycleEffect, target.LifeID)
	cause.Target = target
	cause.Actor.ID = "store-actor"
	cause.EffectID = worker.EffectID
	cause.CauseOperationID = worker.OperationID
	effect := api.Effect{ID: worker.EffectID, OperationID: worker.OperationID, Context: &cause, Worker: &plan}
	claim := api.EffectLease{ClaimID: "archive-claim", ExpiresAt: deadline, Record: api.EffectRecord{Effect: effect, State: api.EffectClaimed, Generation: 2, ClaimID: "archive-claim", ClaimantID: "executor-actor", ClaimExpiresAt: deadline}}
	return archiveReg{Job: archivejob.Job{ID: "archive-job", Intent: archivejob.Intent{Request: api.ArchiveRequest{Target: target}, OperationID: worker.OperationID}, Lease: worker, Plan: plan}, Claim: claim, LaunchID: "archive-launch"}
}

func TestArchiveClaim(t *testing.T) {
	for _, mode := range []string{"argv", "plan", "claim", "lease", "target", "outcome"} {
		t.Run(mode, func(t *testing.T) {
			r := archiveClaimFixture()
			if err := validArchiveReg(r, "admin-case"); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "argv":
				r.Job.Plan.Argv = append([]string{}, r.Job.Plan.Argv...)
				r.Job.Plan.Argv[2] = "shell"
				plan := r.Job.Plan
				r.Claim.Record.Effect.Worker = &plan
			case "plan":
				r.Job.Plan.Kind = "materialize"
			case "claim":
				r.Claim.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
				r.Claim.Record.ClaimExpiresAt = r.Claim.ExpiresAt
			case "lease":
				r.Job.Lease.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
			case "target":
				r.Claim.Record.Effect.Context.Target.Run++
			case "outcome":
				r.Claim.Record.Outcome = &api.EffectOutcome{Status: "succeeded"}
			}
			if err := validArchiveReg(r, "admin-case"); err == nil {
				t.Fatal("acceptance: archive accepted a foreign or expired fixed claim")
			}
		})
	}
}

func TestArchivePool(t *testing.T) {
	b := testBinding()
	p := leaseRecord{Lease: api.HelperLease{ID: "parent", UID: b.Lanes[0].UID, GID: b.Lanes[0].GID, ContainmentID: "parent-cg"}, Request: testAllocation(), Phase: "active", Storage: &launchStorageRecord{Withdrawn: true}}
	r := archiveClaimFixture()
	r.Job.Intent.Request.Target.LifeID = p.Request.LifeID
	r.Job.Lease.Target = r.Job.Intent.Request.Target
	r.Claim.Record.Effect.Context.Target = r.Job.Intent.Request.Target
	p.Archive = &archiveJournal{Intent: r.Job.Intent, LaunchID: "original-launch", Phase: "withdrawing", Tree: api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "workspace", Kind: "directory", Mode: 0700}}}, Inventory: []storageInode{{Device: 1, Inode: 2}}, Worker: &archiveWorker{Reg: r, Lease: api.HelperLease{ID: "archive-native", UID: b.Lanes[1].UID, GID: b.Lanes[1].GID, ContainmentID: "archive-cg", EndpointGeneration: b.Generation}, State: "allocated", Created: "component-created"}}
	if err := validateArchiveOwners([]leaseRecord{p}, b); err != nil {
		t.Fatal(err)
	}
	foreign := leaseRecord{Lease: api.HelperLease{ID: "foreign", UID: b.Lanes[1].UID, GID: b.Lanes[1].GID, ContainmentID: "foreign-cg"}, Phase: "active"}
	if err := validateArchiveOwners([]leaseRecord{p, foreign}, b); err == nil {
		t.Fatal("acceptance: archive worker borrowed another native UID")
	}
	used := map[uint32]bool{}
	p.Phase = "released"
	reserveArchiveUIDs([]leaseRecord{p}, used)
	if !used[p.Lease.UID] || !used[p.Archive.Worker.Lease.UID] {
		t.Fatal("acceptance: retained archive UID became allocatable")
	}
}
