//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/dataworker"
)

type recItem struct {
	Mode fs.FileMode
	Data string
}

func recGit(t *testing.T, root string, input []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("/usr/bin/git", append([]string{"-C", root, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@invalid"}
	cmd.Stdin = bytes.NewReader(input)
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %s: %v: %s", args[0], err, data)
	}
	return data
}

func recTree(t *testing.T, root string) map[string]recItem {
	t.Helper()
	items := map[string]recItem{}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if rel == ".git" {
			return fs.SkipDir
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		item := recItem{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(name)
			if err != nil {
				return err
			}
			item.Data = string(data)
		} else if info.Mode()&os.ModeSymlink != 0 {
			item.Data, err = os.Readlink(name)
			if err != nil {
				return err
			}
		}
		items[filepath.ToSlash(rel)] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func recSnapshot(t *testing.T) (archivejob.Snapshot, map[string]recItem, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	recGit(t, root, nil, "init", "--template=")
	for _, name := range []string{"edited", "deleted"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("base\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	recGit(t, root, nil, "add", ".")
	recGit(t, root, nil, "commit", "-m", "fixture")
	head := strings.TrimSpace(string(recGit(t, root, nil, "rev-parse", "HEAD")))
	pack := recGit(t, root, []byte(head+"\n"), "pack-objects", "--stdout", "--revs", "--threads=1", "--window=0")
	if err := os.Remove(filepath.Join(root, "deleted")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edited", "new name"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("unsaved\x00work\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("edited", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	want := recTree(t, root)
	result := archivejob.Snapshot{}
	put := func(class string, data []byte) api.BlobRef {
		ref := api.BlobRef{ID: launchIDForTest(), Class: class, Bytes: int64(len(data)), SHA256: digestOfBytes(data)}
		result.Objects = append(result.Objects, api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: append([]byte{}, data...), SHA256: ref.SHA256, Origin: "service"})
		return ref
	}
	packRef := put("artifact", pack)
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Git: &api.ArchiveGit{Head: head, Branch: "lane/recorded"},
		Entries: []api.ObjectEntry{{Path: "git", Kind: "directory", Mode: 0700}, {Path: "git/pack", Kind: "file", Mode: 0400, Content: &packRef}}}
	for name, item := range want {
		entry := api.ObjectEntry{Path: "workspace", Mode: uint32(item.Mode.Perm())}
		if name != "." {
			entry.Path += "/" + name
		}
		switch {
		case item.Mode.IsDir():
			entry.Kind = "directory"
		case item.Mode&os.ModeSymlink != 0:
			entry.Kind, entry.LinkTarget = "symlink", item.Data
		default:
			ref := put("artifact", []byte(item.Data))
			entry.Kind, entry.Content = "file", &ref
		}
		tree.Entries = append(tree.Entries, entry)
	}
	sort.Slice(tree.Entries, func(i, j int) bool { return tree.Entries[i].Path < tree.Entries[j].Path })
	result.Freeze.Snapshot = put("manifest", mustJSON(t, tree))
	if err := os.Rename(root, root+"-stopped"); err != nil {
		t.Fatal(err)
	}
	return result, want, head
}

func recCall(t *testing.T, f *stoppedFixture, caller api.Scope, request api.RestoreRequest) (context.Context, api.Scope) {
	t.Helper()
	caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config, Method: "lane.restore",
		RequestID: launchIDForTest(), IdempotencyKey: launchIDForTest(), Params: mustJSON(t, request)}
	var err error
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &stoppedFrame{Raw: mustJSON(t, caller.Request)}
	ctx, retire := f.State.TrackMutation(context.Background())
	t.Cleanup(retire)
	_, won, err := f.State.ReserveMutation(ctx, api.RequestReservation{Scope: caller, RawRequest: caller.Frame.Bytes(), Deadline: f.Plan.Inputs.Grants.ExpiresAt})
	if err != nil || !won {
		t.Fatal("cannot reserve actual restore", err)
	}
	return ctx, caller
}

func recRead(t *testing.T, f *stoppedFixture, ref api.BlobRef) []byte {
	t.Helper()
	var data []byte
	for int64(len(data)) < ref.Bytes {
		part, err := f.State.Blob(context.Background(), f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(data)), Limit: api.MaxChunkBytes})
		if err != nil || len(part.Data) == 0 {
			t.Fatal("cannot read retained archive object", err)
		}
		data = append(data, part.Data...)
	}
	if int64(len(data)) != ref.Bytes || digestOfBytes(data) != ref.SHA256 {
		t.Fatal("retained archive object differs from its pin")
	}
	return data
}

func recParts(t *testing.T, f *stoppedFixture, receipt api.ArchiveReceipt) []api.BlobRef {
	t.Helper()
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID, Run: f.Lane.Run})
	if err != nil {
		t.Fatal(err)
	}
	var operation api.ID
	for _, event := range page.Events {
		if event.Kind == "archive.verified" {
			var found api.ArchiveReceipt
			if api.DecodeObject(event.Payload, &found) != nil {
				t.Fatal("archive event has no receipt")
			}
			if found == receipt {
				operation = event.OperationID
			}
		}
	}
	job, err := f.State.ArchiveJob(context.Background(), f.Execution, operation)
	if err != nil {
		t.Fatal(err)
	}
	effect, err := f.State.Effect(context.Background(), f.Execution, job.Lease.EffectID)
	if err != nil || effect.Outcome == nil || effect.Outcome.Output == nil {
		t.Fatal("archive lacks the actual completed worker output", err)
	}
	var completion archivejob.Completion
	if api.DecodeObject(recRead(t, f, *effect.Outcome.Output), &completion) != nil || completion.Receipt != receipt || len(completion.Archive.Parts) == 0 {
		t.Fatal("archive has no complete retained assembly")
	}
	return completion.Archive.Parts
}

// Native identity/process/freeze ports are explicit component fixtures. Stop,
// archive worker, canonical tar, SQLite authority and restore are production.
func TestRestoreStoppedLane(t *testing.T) {
	snapshot, want, head := recSnapshot(t)
	stopEndedJournal(t, 0, func(f *stoppedFixture, stopped api.Operation) {
		if stopped.Stop == nil {
			t.Fatal("restore lacks the actual stopped life")
		}
		for i := range snapshot.Objects {
			snapshot.Objects[i].ACL = api.ObjectACL{Config: f.Deps.Config, LifeID: f.Reservation.Target.LifeID}
		}
		scene := f.ArchiveEnded(t, func(ctx context.Context, scope api.Scope, principal api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
			return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: principal, Scope: scope, Bootstrap: f.State, Sink: f.State, Clock: f.Deps.Clock,
				Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
					return f.State.WorkerObject(ctx, scope, q)
				}})
		}, snapshot)
		service, err := New(Dependencies{Store: f.State, Identity: &fixtureIdentity{}, Clock: f.Deps.Clock})
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		scene.SetRestoreRoot(parent)
		request := api.RestoreRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Path: filepath.Join(parent, "restored"), ArchiveReceiptID: scene.Archive.ID}
		parts := recParts(t, f, scene.Archive)
		refs := append([]api.BlobRef{scene.Archive.Manifest}, parts...)
		for _, object := range snapshot.Objects {
			refs = append(refs, api.BlobRef{ID: object.ObjectKey, Class: object.Class, Bytes: int64(len(object.Bytes)), SHA256: object.SHA256})
		}
		kept := map[api.ID][]byte{}
		for _, ref := range refs {
			kept[ref.ID] = recRead(t, f, ref)
		}
		ctx, caller := recCall(t, f, f.Human, request)
		before := mustJSON(t, scene.Archive)
		got, err := service.LaneRestore(ctx, caller, request)
		if err != nil {
			t.Fatal("stopped dirty lane cannot restore:", err)
		}
		if got.Head != head || got.Manifest != scene.Archive.Manifest || !reflect.DeepEqual(recTree(t, request.Path), want) ||
			strings.TrimSpace(string(recGit(t, request.Path, nil, "rev-parse", "HEAD"))) != head {
			t.Fatal("stopped lane restore changed names, bytes, modes or recorded head")
		}
		if !bytes.Equal(before, mustJSON(t, scene.Archive)) {
			t.Fatal("restore changed the retained archive receipt")
		}
		for _, ref := range refs {
			if !bytes.Equal(kept[ref.ID], recRead(t, f, ref)) {
				t.Fatal("restore changed the actual archive manifest, content or part bytes")
			}
		}
		replay, err := service.LaneRestore(ctx, caller, request)
		if err != nil || !reflect.DeepEqual(replay, got) {
			t.Fatal("restore did not replay its exact committed reply", err)
		}
		for _, kind := range []string{"outside", "symlink", "owner"} {
			t.Run(kind, func(t *testing.T) {
				attempt := request
				outside := filepath.Join(t.TempDir(), "private")
				if err := os.Mkdir(outside, 0700); err != nil {
					t.Fatal(err)
				}
				attempt.Path = filepath.Join(outside, "restored")
				if kind == "symlink" {
					if err := os.Symlink(outside, filepath.Join(parent, "alias")); err != nil {
						t.Fatal(err)
					}
					attempt.Path = filepath.Join(parent, "alias/restored")
				}
				if kind == "owner" {
					attempt.Path, attempt.AllowNestedGit = filepath.Join(parent, "owner"), true
				}
				badCtx, badScope := recCall(t, f, f.Human, attempt)
				_, err := service.LaneRestore(badCtx, badScope, attempt)
				requireCode(t, err, api.CodeForbidden)
				if _, err := os.Lstat(attempt.Path); !os.IsNotExist(err) {
					t.Fatal("restore used service authority outside the caller's roots")
				}
			})
		}
		// A new invocation must refuse the same existing destination.
		otherCtx, other := recCall(t, f, f.Human, request)
		_, err = service.LaneRestore(otherCtx, other, request)
		requireCode(t, err, api.CodeConflict)
		// The child cannot restore itself, even with the actual archive ID.
		request.Path = filepath.Join(parent, "executor")
		childCtx, child := recCall(t, f, f.LaneScope(t), request)
		_, err = service.LaneRestore(childCtx, child, request)
		if err == nil {
			t.Fatal("executor acquired parent-only restore authority")
		}
		if _, err := os.Lstat(request.Path); !os.IsNotExist(err) {
			t.Fatal("unauthorized restore created a destination")
		}
		verified, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"})
		if err != nil || !verified.OK {
			t.Fatal("restore damaged archive bytes or the real journal", err)
		}
	})
}

func TestRestoreOldReply(t *testing.T) {
	f := newFixture(t)
	request := api.RestoreRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Path: "/work/main/restored", ArchiveReceiptID: "archive"}
	scope := f.scope("lane.restore", request, f.parent)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(scope, key)
	retained := f.store.receipts[domain]
	want := api.RestoreReceipt{Target: request.Target, Path: request.Path, Head: string(digestOfBytes(mustJSON(t, f.child.Workspace))),
		ArchiveReceiptID: request.ArchiveReceiptID, Manifest: f.child.Workspace.Snapshot}
	// An old completed receipt has no adjustment report fields. The fixture
	// supplies that historical reply only; it has no restore writer capability.
	retained.Operation.Status = "succeeded"
	retained.Reply = &api.RPCReply{Result: mustJSON(t, map[string]any{"target": want.Target, "path": want.Path, "head": want.Head,
		"archive_receipt_id": want.ArchiveReceiptID, "manifest": want.Manifest})}
	f.store.receipts[domain] = retained
	got, err := f.service.LaneRestore(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(got, want) || len(f.store.transactions) != 0 {
		t.Fatal("old completed restore reply no longer replays exactly", err)
	}
}
