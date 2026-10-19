//go:build linux

package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// The native port is a filesystem measurement fixture, not installed-helper
// authority. SQLite retention, graph construction, collection and independent
// readbacks below use the production writer, including its original dangling
// JSON edge shape. No objects are inserted with fixture SQL.
type collectRuntimeNative struct {
	*collectNative
	root  string
	refs  map[api.ID]api.BlobRef
	reads map[api.BlobRef]int
}

func (n *collectRuntimeNative) ReadCleanupRuntime(ctx context.Context, ref api.BlobRef) (api.CleanupObject, error) {
	if err := ctx.Err(); err != nil {
		return api.CleanupObject{}, err
	}
	if n.reads == nil {
		n.reads = map[api.BlobRef]int{}
	}
	n.reads[ref]++
	if _, known := n.refs[ref.ID]; !known {
		return api.CleanupObject{}, fault(api.CodeNotFound, "runtime reference is not enrolled")
	}
	if n.refs[ref.ID] != ref {
		return api.CleanupObject{}, fault(api.CodeIntegrity, "runtime reference differs from its installed pin")
	}
	path := filepath.Join(n.root, string(ref.ID))
	raw, err := os.ReadFile(path)
	if err != nil {
		return api.CleanupObject{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return api.CleanupObject{}, err
	}
	if int64(len(raw)) != ref.Bytes || testDigest(raw) != ref.SHA256 {
		return api.CleanupObject{}, fault(api.CodeIntegrity, "runtime bytes differ")
	}
	return api.CleanupObject{Ref: ref, RootID: "installed-runtime", RootIdentity: string(testDigest([]byte(n.root))),
		Identity: fmt.Sprintf("%s:%d:%d", ref.SHA256, info.Size(), info.ModTime().UnixNano()), Role: "runtime"}, nil
}

func retainRuntimeManifest(t *testing.T, f *collectFixture, runtime api.RuntimeManifest) api.BlobRef {
	t.Helper()
	ctx := context.Background()
	tx, err := f.arch.s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// archiveBytes delegates to retain, the same immutable-object writer used
	// by Transact for the administrator's initial publication. The file-backed
	// vendor refs stay in the serialized manifest exactly as authored.
	ref, err := f.arch.s.archiveBytes(ctx, tx, f.arch.record, "manifest", archJSON(t, runtime))
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestCollectInstalledRuntime(t *testing.T) {
	f := newCollect(t)
	native := &collectRuntimeNative{collectNative: f.native, root: t.TempDir(), refs: map[api.ID]api.BlobRef{}}
	runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
	for _, name := range []string{"claude", "claudock"} {
		raw := []byte("unexecuted installed component file: " + name)
		ref := api.BlobRef{ID: api.ID(name), Class: "artifact", SHA256: testDigest(raw), Bytes: int64(len(raw))}
		if err := os.WriteFile(filepath.Join(native.root, name), raw, 0555); err != nil {
			t.Fatal(err)
		}
		native.refs[ref.ID] = ref
		runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: ref.ID, Role: name, RootID: "runtime", RelativePath: name, Content: ref, Mode: 0555})
	}
	manifest := retainRuntimeManifest(t, f, runtime)
	f.arch.s.deps.CleanupNative = native
	inventory, err := f.arch.s.CleanupInventory(context.Background(), f.arch.executor, f.job)
	if err != nil {
		t.Fatal("published runtime manifest cannot resolve its two installed artifact references", err)
	}
	f.inventory = inventory
	for _, ref := range native.refs {
		found := false
		for _, object := range inventory.Objects {
			if object.Ref == ref {
				found = object.Role == "runtime" && object.RootID != f.arch.s.storeID && object.OwnerLifeID == "" && object.References > 0
			}
		}
		if !found {
			t.Fatal("installed artifact edge was skipped or lost its measured namespace", ref.ID)
		}
		if _, _, err := objectRow(context.Background(), f.arch.s.db, ref.ID); !absent(err) {
			t.Fatal("vendor file was invented as a SQLite object", ref.ID, err)
		}
	}
	receipt := f.collect(t)
	for _, result := range receipt.Objects {
		if _, runtime := native.refs[result.ObjectID]; runtime && (result.Action != "retain" || result.Reason != "unowned" || result.Before.State != "present" || result.After.State != "present") {
			t.Fatal("installed runtime was not independently retained", result.ObjectID)
		}
	}
	if _, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, inventory, receipt, f.arch.s.deps.Clock); err != nil {
		t.Fatal("runtime retention failed independent verification", err)
	}
	if err := os.Chmod(filepath.Join(native.root, "claude"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native.root, "claude"), []byte("changed"), 0555); err != nil {
		t.Fatal(err)
	}
	if _, err := api.VerifyCleanup(context.Background(), f.arch.s.CleanupReadbacks(f.arch.executor), f.job, inventory, receipt, f.arch.s.deps.Clock); err == nil {
		t.Fatal("changed installed runtime passed fresh verification", manifest.ID)
	}
}

func TestCollectMissingReferenceDiagnostic(t *testing.T) {
	f := newCollect(t)
	missing := api.BlobRef{ID: testID(t), Class: "artifact", SHA256: testDigest([]byte("absent")), Bytes: 6}
	runtime := api.RuntimeManifest{Schema: "private payload must not be printed", Objects: []api.RuntimeObject{{ID: "vendor", Content: missing}}}
	manifest := retainRuntimeManifest(t, f, runtime)
	_, _, _, err := f.arch.s.collectionGraph(context.Background(), f.job, nil)
	expectCode(t, err, api.CodeIntegrity)
	if !strings.Contains(err.Error(), "manifest:"+string(manifest.ID)+" -> artifact:"+string(missing.ID)) || strings.Contains(err.Error(), runtime.Schema) {
		t.Fatal("missing-reference diagnosis lost source/target classes and IDs or exposed content", err)
	}
}
