//go:build linux

package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the installed namespace observation is a component fixture. Manifest
// history, original object writes, collection, journals and completion use the
// production SQLite writer; native file bytes are read and hashed unchanged.
type collectRuntimeNamespaceNative struct {
	*collectRuntimeNative
	manifest api.BlobRef
	runtime  api.RuntimeManifest
}

func (n *collectRuntimeNamespaceNative) ReadCleanupRuntimeManifest(ctx context.Context) (api.BlobRef, api.RuntimeManifest, error) {
	if err := ctx.Err(); err != nil {
		return api.BlobRef{}, api.RuntimeManifest{}, err
	}
	return n.manifest, n.runtime, nil
}

func newRuntimeCollectCase(t *testing.T) (*collectFixture, *collectRuntimeNamespaceNative) {
	t.Helper()
	f := newCollect(t)
	native := &collectRuntimeNamespaceNative{collectRuntimeNative: &collectRuntimeNative{collectNative: f.native, root: t.TempDir(), refs: map[api.ID]api.BlobRef{}},
		runtime: api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}}
	for _, name := range []string{"claude", "claudock"} {
		raw := []byte("retained runtime file " + name)
		ref := api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: int64(len(raw)), SHA256: testDigest(raw)}
		if err := os.WriteFile(filepath.Join(native.root, name), raw, 0555); err != nil {
			t.Fatal(err)
		}
		native.refs[ref.ID] = ref
		native.runtime.Objects = append(native.runtime.Objects, api.RuntimeObject{ID: ref.ID, Role: name, RootID: "runtime", RelativePath: name, Mode: 0555, Content: ref})
	}
	native.manifest = retainRuntimeManifest(t, f, native.runtime)
	f.arch.s.deps.CleanupNative = native
	var err error
	f.inventory, err = f.arch.s.CleanupInventory(context.Background(), f.arch.executor, f.job)
	if err != nil {
		t.Fatal(err)
	}
	return f, native
}

func repinCollectRuntime(t *testing.T, f *collectFixture, native *collectRuntimeNamespaceNative, newIDs bool) {
	t.Helper()
	next := native.runtime
	next.Generation++
	next.Objects = append([]api.RuntimeObject{}, native.runtime.Objects...)
	native.refs = map[api.ID]api.BlobRef{}
	for i := range next.Objects {
		object := &next.Objects[i]
		raw := []byte("replacement runtime file " + object.Role)
		if newIDs {
			object.Content.ID = api.ID("next-" + object.Role)
		}
		object.Content.SHA256, object.Content.Bytes = testDigest(raw), int64(len(raw))
		path := filepath.Join(native.root, string(object.Content.ID))
		if !newIDs {
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, raw, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
		native.refs[object.Content.ID] = object.Content
	}
	// The next publication is global, not a new owned input of the old lane.
	record := f.arch.record
	record.Lane.LifeID = ""
	tx, err := f.arch.s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.arch.s.archiveBytes(context.Background(), tx, record, "manifest", archJSON(t, next))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	native.runtime, native.manifest = next, ref
}

func TestCollectRuntimeReviewUpgrade(t *testing.T) {
	for _, mode := range []string{"same-id-before", "new-id-before", "same-id-after", "new-id-after"} {
		t.Run(mode, func(t *testing.T) {
			f, native := newRuntimeCollectCase(t)
			var receipt api.CleanupReceipt
			if strings.HasSuffix(mode, "after") {
				receipt = f.collect(t)
			}
			repinCollectRuntime(t, f, native, strings.HasPrefix(mode, "new-id"))
			if strings.HasSuffix(mode, "before") {
				receipt = f.collect(t)
			}
			verified, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock)
			if err != nil {
				t.Fatal("retained historical runtime pin wedged after re-pin", err)
			}
			absent := 0
			for _, read := range verified.Evidence().Objects {
				for _, object := range f.inventory.Objects {
					if object.Role == "runtime" && object.Ref.ID == read.ObjectID {
						if read.State != "absent" || read.Bytes != 0 || read.SHA256 != "" || read.Identity != "" {
							t.Fatal("old pin was presented as current vendor bytes")
						}
						absent++
					}
				}
			}
			if absent != 2 {
				t.Fatal("upgrade lost a retained runtime node", absent)
			}
			if _, err := f.arch.s.CompleteCleanup(context.Background(), f.arch.executor, f.job, verified); err != nil {
				t.Fatal("historical retain-only pins blocked completion", err)
			}
			for _, result := range receipt.Objects {
				if result.ObjectID == "claude" || result.ObjectID == "claudock" {
					if result.Action != "retain" {
						t.Fatal("upgraded runtime became deletable")
					}
				}
			}
		})
	}
}

func TestCollectRuntimeReviewReaderRefusals(t *testing.T) {
	for _, mode := range []string{"unenrolled", "digest"} {
		t.Run(mode, func(t *testing.T) {
			f := newCollect(t)
			current := api.BlobRef{ID: "claude", Class: "artifact", Bytes: 7, SHA256: testDigest([]byte("current"))}
			native := &collectRuntimeNative{collectNative: f.native, root: t.TempDir(), refs: map[api.ID]api.BlobRef{current.ID: current}}
			f.arch.s.deps.CleanupNative = native
			ref := current
			code, message := api.CodeNotFound, "runtime reference is not enrolled"
			if mode == "unenrolled" {
				ref.ID = "unenrolled-artifact"
			} else {
				ref.SHA256 = testDigest([]byte("uninstalled bytes"))
				code, message = api.CodeIntegrity, "runtime reference differs from its installed pin"
			}
			retainRuntimeManifest(t, f, api.RuntimeManifest{Schema: "unrelated document", Objects: []api.RuntimeObject{{Content: ref}}})
			_, _, _, err := f.arch.s.collectionGraph(context.Background(), f.job, nil)
			expectCode(t, err, api.CodeIntegrity)
			if native.reads[ref] == 0 || !strings.Contains(err.Error(), string(code)) || !strings.Contains(err.Error(), message) {
				t.Fatal("installed reader refusal lost its code or fixed message", err)
			}
		})
	}
}

func TestCollectRuntimeReviewNoHistory(t *testing.T) {
	f := newCollect(t)
	ref := api.BlobRef{ID: "unpublished-old-pin", Class: "artifact", Bytes: 7, SHA256: testDigest([]byte("unknown"))}
	native := &collectRuntimeNative{collectNative: f.native, root: t.TempDir(), refs: map[api.ID]api.BlobRef{ref.ID: ref}}
	if err := os.WriteFile(filepath.Join(native.root, string(ref.ID)), []byte("unknown"), 0555); err != nil {
		t.Fatal(err)
	}
	f.arch.s.deps.CleanupNative = native
	retainRuntimeManifest(t, f, api.RuntimeManifest{Schema: "not a runtime publication", Objects: []api.RuntimeObject{{Content: ref}}})
	_, _, _, err := f.arch.s.collectionGraph(context.Background(), f.job, nil)
	expectCode(t, err, api.CodeIntegrity)
	if !strings.Contains(err.Error(), string(ref.ID)) {
		t.Fatal("historical absence was accepted without retained provenance", err)
	}
}

func TestCollectRuntimeReviewOperationCache(t *testing.T) {
	f, native := newRuntimeCollectCase(t)
	native.reads = map[api.BlobRef]int{}
	if _, err := f.arch.s.CollectCleanupObjects(context.Background(), f.arch.executor, f.job, f.inventory); err != nil {
		t.Fatal(err)
	}
	for _, ref := range native.refs {
		if native.reads[ref] != 1 {
			t.Fatal("collector rehashed a runtime pin within one operation", ref.ID, native.reads[ref])
		}
	}
	receipt := f.collect(t)
	reads := f.arch.s.CleanupReadbacks(f.arch.executor)
	native.reads = map[api.BlobRef]int{}
	if _, err := api.VerifyCleanup(context.Background(), reads, f.job, f.inventory, receipt, f.arch.s.deps.Clock); err != nil {
		t.Fatal(err)
	}
	for _, ref := range native.refs {
		if native.reads[ref] != 1 {
			t.Fatal("verification rehashed a pin within one operation", ref.ID, native.reads[ref])
		}
	}
	path := filepath.Join(native.root, "claude")
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed runtime bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := api.VerifyCleanup(context.Background(), reads, f.job, f.inventory, receipt, f.arch.s.deps.Clock); err == nil {
		t.Fatal("runtime measurement cache survived into a second operation")
	}
}

func TestCollectRuntimeReviewUnownedBytes(t *testing.T) {
	f, _ := newRuntimeCollectCase(t)
	receipt := f.collect(t)
	verified, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, f.inventory, receipt, f.arch.s.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.arch.s.CompleteCleanup(context.Background(), f.arch.executor, f.job, verified)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := f.arch.s.db.QueryRow("SELECT data FROM events WHERE json_extract(data,'$.kind')='lane.cleaned' AND json_extract(data,'$.life_id')=? ORDER BY seq DESC LIMIT 1", string(f.job.Intent.Cause.Target.LifeID)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var event api.Event
	if err := api.DecodeObject(raw, &event); err != nil {
		t.Fatal(err)
	}
	var body api.CleanEvent
	if err := api.DecodeObject(event.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.UnownedRetained.Bytes != 0 || body.UnownedRetained.Objects != 0 {
		t.Fatal("vendor executables were counted as unowned lane data", body.UnownedRetained)
	}
}
