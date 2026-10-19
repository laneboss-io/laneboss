package dataworker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// This adapter deliberately exposes only the original readback interface.
type cleanupBasicReads struct{ api.CleanupReadbacks }

func (p *cleanupPorts) seal(id api.ID, value any) api.BlobRef {
	p.t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		p.t.Fatal(err)
	}
	p.blobs[id] = append([]byte(nil), data...)
	return api.BlobRef{ID: id, Class: "manifest", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
}

// Historical leases reach the collector only through this installed store port.
// It authenticates the current job and reopens protected claim/journal bytes.
// Effect/generation corruption exercises the consumer validator; the real store
// additionally validates those fields before returning the retained lease.
func (p *cleanupPorts) ReadCleanupRemovalClaim(ctx context.Context, job api.CleanupJob, journal api.WorkspaceRemoval) (api.EffectLease, error) {
	p.claimReads++
	if err := p.auth(ctx, api.Scope{Config: p.job.Intent.Cause.Config, Actor: api.Actor{Kind: "service", ID: p.job.Claim.Record.ClaimantID}}, job); err != nil {
		return api.EffectLease{}, err
	}
	var claim api.EffectLease
	if err := p.decode(p.removingClaim, &claim); err != nil {
		return api.EffectLease{}, err
	}
	if journal.ClaimID != claim.ClaimID {
		return api.EffectLease{}, cleanupError(api.CodeIntegrity, "lb-v2-service", "workspace journal has no retained claim that performed removal")
	}
	var retained api.WorkspaceRemoval
	if err := p.decode(p.removalJournal, &retained); err != nil {
		return api.EffectLease{}, err
	}
	if !reflect.DeepEqual(retained, journal) {
		return api.EffectLease{}, cleanupError(api.CodeIntegrity, "lb-v2-service", "workspace removal journal changed after retention")
	}
	return claim, nil
}

type cleanupSaved struct {
	Job                           api.CleanupJob
	Inventory                     api.CleanupInventory
	Objects, Blobs                map[api.ID][]byte
	Results                       []api.ObjectDisposition
	Removal                       api.WorkspaceRemoval
	Receipt                       api.CleanupReceipt
	RemovingClaim, RemovalJournal api.BlobRef
	Sequence                      int
	Removed                       bool
}

// Reopen serialized component state, expire A, and let the fixture writer make
// B current. No historical lease is passed to the worker. This models protocol
// restart, not native process or SQLite durability.
func cleanupReclaim(t *testing.T, stage string) (*Service, *cleanupPorts, api.CleanupReceipt) {
	t.Helper()
	mode := "valid"
	if stage == "after-remove" {
		mode = "crash-after-remove"
	}
	s, old := cleanupFixture(t, mode)
	first, err := s.CollectCleanup(context.Background(), old.job)
	if stage == "after-remove" {
		if !errors.Is(err, old.probe) || first.ID != "" || old.retentions != 0 {
			t.Fatal("cleanup crash did not occur after native removal", err)
		}
	} else if err != nil || first.ID == "" {
		t.Fatal("cleanup claim A did not collect", err)
	}
	if !old.removed || old.removals != 1 || old.removal.ClaimID != old.job.Claim.ClaimID || old.removingClaim.ID == "" {
		t.Fatal("cleanup claim A did not retain its removing authority")
	}
	if _, present := old.objects["scratch"]; present {
		t.Fatal("cleanup claim A did not remove transient bytes")
	}
	saved := cleanupCopy(t, cleanupSaved{old.job, old.inventory, old.objects, old.blobs, old.results, old.removal, old.receipt, old.removingClaim, old.removalJournal, old.sequence, old.removed})
	expiry, err := time.Parse(time.RFC3339Nano, string(saved.Job.Claim.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	now := expiry.Add(time.Second)
	p := &cleanupPorts{t: t, job: saved.Job, inventory: saved.Inventory, objects: saved.Objects, blobs: saved.Blobs, results: saved.Results,
		removal: saved.Removal, receipt: saved.Receipt, removingClaim: saved.RemovingClaim, removalJournal: saved.RemovalJournal,
		sequence: saved.Sequence, removed: saved.Removed, valid: true, mode: "valid", clock: workerClock{now},
		probe: cleanupError(api.CodeUnavailable, "lb-v2-service", "injected cleanup owner error")}
	p.job.Claim.ClaimID = "successor-claim"
	p.job.Claim.Record.ClaimID = p.job.Claim.ClaimID
	p.job.Claim.Record.ClaimantID = "successor-executor"
	p.job.Claim.Record.Generation += 2
	p.job.Claim.ExpiresAt = api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))
	p.job.Claim.Record.ClaimExpiresAt = p.job.Claim.ExpiresAt
	if err := api.ValidateCleanupJob(p.job, now); err != nil {
		t.Fatal("invalid successor fixture job", err)
	}
	s, err = New(Dependencies{Config: p.job.Intent.Cause.Config, Store: p, Helper: &unopenedHelper{}, Workspace: p, Launcher: &probeLauncher{}, Clock: p.clock})
	if err != nil {
		t.Fatal(err)
	}
	return s, p, first
}

func TestCleanupReclaim(t *testing.T) {
	for _, stage := range []string{"after-remove", "after-receipt"} {
		t.Run(stage, func(t *testing.T) {
			s, p, first := cleanupReclaim(t, stage)
			journal := cleanupCopy(t, p.removal)
			oldBytes := append([]byte(nil), p.blobs[first.Manifest.ID]...)
			receipt, err := s.CollectCleanup(context.Background(), p.job)
			if err != nil || receipt.ID == "" || receipt.ClaimID != p.job.Claim.ClaimID || receipt.Workspace.ClaimID == receipt.ClaimID ||
				!reflect.DeepEqual(receipt.Workspace, journal) || !reflect.DeepEqual(receipt, p.receipt) || p.claimReads != 2 ||
				p.calls() != (cleanupCalls{inventory: 1, writer: 1, retain: 1, lookup: 1, verify: 1}) || p.objectReads != len(p.inventory.Objects) {
				t.Fatal("reclaimed cleanup did not return a current-claim receipt", stage, err, p.calls(), p.claimReads)
			}
			if first.ID != "" && (receipt.ID == first.ID || receipt.Manifest.ID == first.Manifest.ID || string(p.blobs[first.Manifest.ID]) != string(oldBytes)) {
				t.Fatal("reclaim reused or overwrote claim A receipt")
			}
			verified, err := api.VerifyCleanup(context.Background(), p, p.job, p.inventory, receipt, p.clock)
			if err != nil || !reflect.DeepEqual(verified.Receipt(), receipt) || p.claimReads != 3 || p.objectReads != 2*len(p.inventory.Objects) {
				t.Fatal("reclaimed cleanup failed independent verification", err)
			}
			again, err := s.CollectCleanup(context.Background(), p.job)
			if err != nil || !reflect.DeepEqual(again, receipt) || !reflect.DeepEqual(p.removal, journal) || p.removals != 0 || p.claimReads != 5 {
				t.Fatal("reclaimed cleanup retry changed journal or receipt", err)
			}
			for _, id := range []api.ID{"archive", "shared", "foreign", "audit"} {
				if string(p.objects[id]) != string(id) {
					t.Fatal("reclaimed cleanup lost protected bytes", id)
				}
			}
		})
	}
}

func TestCleanupStrictClaim(t *testing.T) {
	s, p := cleanupFixture(t, "no-removal-reads")
	receipt, err := s.CollectCleanup(context.Background(), p.job)
	if err != nil || receipt.ID == "" || p.claimReads != 0 || p.removals != 1 {
		t.Fatal("current-claim cleanup required historical authority", err)
	}
	again, err := s.CollectCleanup(context.Background(), p.job)
	if err != nil || !reflect.DeepEqual(again, receipt) || p.claimReads != 0 || p.removals != 1 {
		t.Fatal("current-claim cleanup required historical authority", err)
	}
}

func TestCleanupReclaimRefusals(t *testing.T) {
	for _, check := range []struct {
		mode, owner, message, assertion string
		code                            api.ErrorCode
		reads                           int
	}{
		{"unknown-remover", "lb-v2-service", "workspace journal has no retained claim that performed removal", "unretained remover escaped reclaim gate", api.CodeIntegrity, 1},
		{"foreign-effect", "lb-v2-integrate", "cleanup intent differs from its original live clean claim", "foreign remover effect escaped reclaim gate", api.CodeInvalid, 1},
		{"higher-generation", "lb-v2-integrate", "workspace removal was not performed by an earlier original claim", "later remover generation escaped reclaim gate", api.CodeInvalid, 1},
		{"foreign-intent", "lb-v2-service", "workspace removal journal changed after retention", "foreign removal intent escaped reclaim gate", api.CodeIntegrity, 1},
		{"no-removal-reads", "lb-v2-service", "historical removal lacks its installed retained claim source", "unretained remover escaped reclaim gate", api.CodeIntegrity, 0},
	} {
		t.Run(check.mode, func(t *testing.T) {
			s, p, _ := cleanupReclaim(t, "after-remove")
			p.mode = check.mode
			if check.mode == "foreign-effect" || check.mode == "higher-generation" {
				var claim api.EffectLease
				if err := p.decode(p.removingClaim, &claim); err != nil {
					t.Fatal(err)
				}
				if check.mode == "foreign-effect" {
					claim.Record.Effect.ID = "foreign-effect"
				} else {
					claim.Record.Generation = p.job.Claim.Record.Generation + 1
				}
				p.removingClaim = p.seal(p.removingClaim.ID, claim)
			}
			receipt, err := s.CollectCleanup(context.Background(), p.job)
			assertCleanupRefusal(t, p, receipt, err, check.code, check.owner, check.message, check.assertion, cleanupCalls{inventory: 1, writer: 1})
			if p.claimReads != check.reads {
				t.Fatal(check.assertion, "claim reads:", p.claimReads)
			}
		})
	}
}
