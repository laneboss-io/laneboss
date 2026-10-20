//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func TestRestoreNativePack(t *testing.T) {
	m, record, index, request := workspaceProducerFixture(t)
	ctx := context.Background()
	if err := m.ensureNativeWorkspace(ctx, &record, index, request); err != nil {
		t.Fatal("native restore workspace producer:", err)
	}
	before := mustCanaryJSON(t, record)
	git, pack, err := archiveGitPack(ctx, record)
	if err != nil || git == nil || git.Head != record.Storage.Workspace.Enrollment.Workspace.Head || len(pack) < 12 || string(pack[:4]) != "PACK" {
		t.Fatal("native archive lacks its recorded Git head and objects", err)
	}
	again, second, err := archiveGitPack(ctx, record)
	if err != nil || !reflect.DeepEqual(git, again) || !bytes.Equal(pack, second) {
		t.Fatal("native read-only Git pack is not stable", err)
	}
	tree, objects, _, err := m.archiveTree(ctx, record, false, false)
	if err != nil || !reflect.DeepEqual(tree.Git, git) {
		t.Fatal("native frozen manifest omitted its recorded Git metadata", err)
	}
	found := false
	for _, source := range objects {
		if source.Root == "git" && source.Name == "pack" && source.Ref.SHA256 == digestBytes(pack) {
			found = true
		}
	}
	if !found || !bytes.Equal(before, mustCanaryJSON(t, record)) {
		t.Fatal("native archive omitted the bounded pack or changed its retained producer journal")
	}
}

func TestRestoreNativeScope(t *testing.T) {
	m, record, index, request := workspaceProducerFixture(t)
	ctx := context.Background()
	if err := m.ensureNativeWorkspace(ctx, &record, index, request); err != nil {
		t.Fatal(err)
	}
	q := restoreRootQuery{Actor: api.Actor{Kind: "lane", ID: "caller", LifeID: record.Request.LifeID}, LaunchID: request.Reg.Reservation.LaunchID}
	roots, err := m.restoreRoots(ctx, mustCanaryJSON(t, q))
	want := filepath.Join(storageBase(m.binding, record), string(record.Storage.Binding.WorkspaceID))
	if err != nil || !slices.Equal(roots, []string{want}) {
		t.Fatal("native root resolver lost the caller's actual workspace", err, roots)
	}
	for _, kind := range []string{"life", "launch"} {
		other := q
		if kind == "life" {
			other.Actor.LifeID = "other-life"
		} else {
			other.LaunchID = "other-launch"
		}
		roots, err := m.restoreRoots(ctx, mustCanaryJSON(t, other))
		if err != nil || len(roots) != 0 {
			t.Fatal("native root resolver lent another caller's workspace", kind, err)
		}
	}
	// Terminal journal fields are component inputs. The workspace above is
	// really published; ending the lease must still exclude that same inode.
	ended := record
	observation := testObservation(record.Lease)
	observation.Handle.Target = request.Reg.Reservation.Target
	cause := record.Request.Cause
	cause.Kind, cause.EffectID = api.InternalHelperRelease, "scope-release"
	cause.Target = observation.Handle.Target
	ended.Phase = "released"
	ended.Release = &api.HelperReleaseRequest{LeaseID: record.Lease.ID, Observation: observation, Cause: cause}
	zero := uint64(0)
	ended.Receipt = &api.ReleaseReceipt{ID: "scope-release", LeaseID: record.Lease.ID,
		ContainmentID: record.Lease.ContainmentID, Backend: record.Request.Backend,
		OperationID: cause.CauseOperationID, EffectID: cause.EffectID,
		Quiescence: observation, ObservedAt: observation.ObservedAt,
		LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero}
	records, err := m.records()
	if err != nil {
		t.Fatal(err)
	}
	for i := range records {
		if records[i].Lease.ID == record.Lease.ID {
			records[i] = ended
		}
	}
	m.store = &memoryLeases{records: records}
	for _, actor := range []api.Actor{q.Actor, {Kind: "human", ID: "owner"}} {
		q.Actor = actor
		roots, err := m.restoreRoots(ctx, mustCanaryJSON(t, q))
		if err != nil || len(roots) != 0 {
			t.Fatal("ended published workspace remained a restore root", err, roots)
		}
		target := filepath.Join(want, "ended-copy")
		_, err = archivejob.Restore(ctx, target, api.ObjectManifest{}, nil, 1<<20,
			archivejob.RestoreOptions{Roots: roots})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "restore_target_scope" {
			t.Fatal("real restore accepted the ended host", err)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatal("ended host refusal created a target", err)
		}
	}
	t.Log("ended host: native roots empty; real restore refuses restore_target_scope")
}
