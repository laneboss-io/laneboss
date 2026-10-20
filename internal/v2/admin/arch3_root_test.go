//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

// The vendor home and ended-lane DTO are component inputs, without credentials
// or a model request. Git publication, data-worker collection, ownership
// withdrawal, the helper's archive_freeze dispatch, journal validation and
// frozen byte reads all use their real native implementations.
func TestClaudockArchiveFreeze(t *testing.T) {
	m, record, index, request := workspaceProducerFixture(t)
	ctx := context.Background()
	if err := m.ensureNativeWorkspace(ctx, &record, index, request); err != nil {
		t.Fatal("native workspace publication:", err)
	}
	base := storageBase(m.binding, record)
	want := []byte("dirty Claudock workspace bytes\n")
	settings := []byte("{\"permissions\":{\"allow\":[]}}\n")
	for _, item := range []struct {
		root api.ID
		name string
		body []byte
		mode os.FileMode
	}{
		{record.Storage.Binding.WorkspaceID, "dirty.txt", want, 0600},
		{record.Storage.Binding.Home.RootID, ".claude/settings.json", settings, 0400},
	} {
		name := filepath.Join(base, string(item.root), item.name)
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, item.body, item.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(name, int(record.Lease.UID), int(record.Lease.GID)); err != nil {
			t.Fatal(err)
		}
	}
	if matched, err := m.collectData(ctx, record.DataJobs[index].Lease.ID); err != nil || !matched {
		t.Fatal("native materializer collection:", err)
	}
	record, err := m.find(record.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	r := record.LaunchAllocations[len(record.LaunchAllocations)-1].Reservation
	intent := archivejob.Intent{OperationID: "claudock-archive", Request: api.ArchiveRequest{Target: r.Target, ExpectedGeneration: 3},
		CancellationEpoch: r.CancellationEpoch, EndEventID: "claudock-ended", EndSeq: 9}
	lane := api.Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: 3, CancellationEpoch: r.CancellationEpoch,
		LaunchID: r.LaunchID, StarterChain: []api.ID{}, Workspace: api.Workspace{ID: record.Storage.Binding.WorkspaceID}}
	raw := mustCanaryJSON(t, archiveQuery{Intent: intent, Lane: lane})
	result, err := m.dispatchArchiveStorage(ctx, "archive_freeze", json.RawMessage(raw))
	if err != nil {
		t.Fatal("native Claudock archive_freeze:", err)
	}
	header := result.(archiveHeader)
	record, err = m.find(record.Lease.ID)
	if err != nil || record.Archive == nil || record.Archive.Phase != "frozen" {
		t.Fatal("native archive journal read-back:", err)
	}
	if record.Archive.Tree.Git == nil || record.Archive.Tree.Git.Head != record.Storage.Workspace.Enrollment.Workspace.Head {
		t.Fatal("frozen archive lost the recorded Git head")
	}
	found := map[string]bool{}
	for _, entry := range record.Archive.Tree.Entries {
		if entry.Path == "workspace/dirty.txt" {
			found[entry.Path] = entry.Mode == 0600 && entry.Content != nil && entry.Content.SHA256 == digestBytes(want)
		}
		if entry.Path == "home/.claude/settings.json" {
			found[entry.Path] = entry.Mode == 0400 && entry.Content != nil && entry.Content.SHA256 == digestBytes(settings)
		}
	}
	if !found["workspace/dirty.txt"] || !found["home/.claude/settings.json"] {
		t.Fatal("frozen archive lost dirty bytes, modes or the vendor home")
	}
	for i, ref := range header.Objects {
		chunk, err := m.archiveBytes(ctx, archiveQuery{Intent: intent, Freeze: header.Freeze, Index: i, Limit: api.MaxChunkBytes})
		if err != nil || chunk.ObjectID != ref.ID || int64(len(chunk.Data)) != ref.Bytes || digestBytes(chunk.Data) != ref.SHA256 {
			t.Fatal("frozen native object read-back:", err)
		}
		if bytes.HasPrefix(chunk.Data, []byte("PACK")) {
			found["git/pack"] = true
		}
	}
	if !found["git/pack"] {
		t.Fatal("frozen archive omitted Git objects")
	}
	again, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane})
	if err != nil || !reflect.DeepEqual(again, header) {
		t.Fatal("native frozen retry changed its original capture:", err)
	}
	if _, err := m.findActive(record.Lease.ID, storageReady); err == nil {
		t.Fatal("frozen storage regained writable launch access")
	}
	roots, err := m.archiveRoots(record)
	if err != nil || roots["git"] == "" {
		t.Fatal("archive omitted its physical Git root:", err)
	}
	for i, name := range []string{roots["git"], filepath.Join(roots["git"], "pack")} {
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		var info unix.Stat_t
		readErr := unix.Fstat(int(file.Fd()), &info)
		closeErr := file.Close()
		mode := uint32(0500)
		if i == 1 {
			mode = 0400
		}
		inode := storageInode{Device: uint64(info.Dev), Inode: info.Ino}
		if readErr != nil || closeErr != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&07777 != mode || !slices.Contains(record.Archive.Inventory, inode) {
			t.Fatal("Git capture lacks a frozen, inventoried physical inode:", readErr, closeErr)
		}
	}
	bad := record
	journal := *record.Archive
	bad.Archive = &journal
	journal.Inventory = journal.Inventory[:len(journal.Tree.Entries)-1]
	if err := validateArchiveOwners([]leaseRecord{bad}, m.binding); err == nil {
		t.Fatal("retained journal accepted missing physical inventory")
	}
	if err := m.collectPrivateStorage(ctx, &record); err != nil {
		t.Fatal("native collection could not collect the Git capture:", err)
	}
	if _, err := os.Lstat(roots["git"]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native collection retained the physical Git capture:", err)
	}
	retained, err := m.find(record.Lease.ID)
	if err != nil || !retained.Storage.Collected {
		t.Fatal("native collection lost its durable storage receipt:", err)
	}
}
