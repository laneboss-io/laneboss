//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "restore-dac" {
		root, err := os.OpenRoot(os.Args[2])
		if err != nil {
			os.Stdout.WriteString("denied")
		} else {
			root.Close()
			os.Stdout.WriteString("allowed")
		}
		os.Exit(0)
	}
}

func TestRestoreInstalled(t *testing.T) {
	restoreInstalled(t, nil)
}

func restoreInstalled(t *testing.T, observe func(leaseRecord)) {
	t.Helper()
	ctx := context.Background()
	source, r, index, material := workspaceProducerFixture(t)
	if err := source.ensureNativeWorkspace(ctx, &r, index, material); err != nil {
		t.Fatal(err)
	}
	want := []byte("installed frozen dirty bytes\n")
	file := filepath.Join(storageBase(source.binding, r), string(r.Storage.Binding.WorkspaceID), "dirty")
	if err := os.WriteFile(file, want, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.collectData(ctx, r.DataJobs[index].Lease.ID); err != nil {
		t.Fatal(err)
	}
	r, err := source.find(r.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	res := r.LaunchAllocations[0].Reservation
	intent := archivejob.Intent{OperationID: "restore-source", Request: api.ArchiveRequest{Target: res.Target, ExpectedGeneration: 3},
		CancellationEpoch: res.CancellationEpoch, EndEventID: "restore-ended", EndSeq: 9}
	lane := api.Lane{LifeID: res.Target.LifeID, Run: res.Target.Run, Generation: 3, CancellationEpoch: res.CancellationEpoch,
		LaunchID: res.LaunchID, Workspace: api.Workspace{ID: r.Storage.Binding.WorkspaceID}}
	header, err := source.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane})
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[api.ID][]byte{}
	for i, ref := range header.Objects {
		for int64(len(bodies[ref.ID])) < ref.Bytes {
			chunk, err := source.archiveBytes(ctx, archiveQuery{Intent: intent, Freeze: header.Freeze, Index: i, Offset: int64(len(bodies[ref.ID])), Limit: api.MaxChunkBytes})
			if err != nil || len(chunk.Data) == 0 {
				t.Fatal("native frozen read:", err)
			}
			bodies[ref.ID] = append(bodies[ref.ID], chunk.Data...)
		}
	}
	var tree api.ObjectManifest
	if err := api.DecodeObject(bodies[header.Freeze.Snapshot.ID], &tree); err != nil {
		t.Fatal(err)
	}
	m, dest, di, dq := workspaceProducerFixture(t)
	if err := m.ensureNativeWorkspace(ctx, &dest, di, dq); err != nil {
		t.Fatal(err)
	}
	// The direct native fixture creates its own cgroup hierarchy. Match the
	// installed helper's controller delegation before creating restore children.
	for _, name := range []string{filepath.Dir(m.binding.cgroupPath()), m.binding.cgroupPath()} {
		group, err := os.OpenRoot(name)
		if err != nil {
			t.Fatal(err)
		}
		err = enableControllers(group)
		closeErr := group.Close()
		if err != nil || closeErr != nil {
			t.Fatal("restore fixture controller delegation failed", err, closeErr)
		}
	}
	base := storageBase(m.binding, dest)
	workspace := filepath.Join(base, string(dest.Storage.Binding.WorkspaceID))
	for i, name := range []string{base, workspace} {
		var st unix.Stat_t
		mode, uid := uint32(0710), uint32(0)
		if i == 1 {
			mode, uid = 0700, dest.Lease.UID
		}
		if unix.Lstat(name, &st) != nil || st.Mode&07777 != mode || st.Uid != uid || st.Gid != dest.Lease.GID {
			t.Fatal("fixture is not the actual installed private layout")
		}
	}
	for _, identity := range []struct {
		uid, gid uint32
		want     string
	}{{m.binding.Service.UID, m.binding.Service.GID, "denied"}, {dest.Lease.UID, dest.Lease.GID, "allowed"}} {
		name := workspace
		var held *os.File
		if identity.want == "allowed" {
			held, err = os.Open(workspace)
			if err != nil {
				t.Fatal(err)
			}
			name = "/proc/self/fd/3"
		}
		cmd := exec.Command("/proc/self/exe", "restore-dac", name)
		if held != nil {
			cmd.ExtraFiles = []*os.File{held}
		}
		cmd.Env = []string{}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: identity.uid, Gid: identity.gid, Groups: []uint32{}}}
		out, err := cmd.Output()
		if held != nil {
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if err != nil || string(out) != identity.want {
			t.Fatalf("native DAC control want=%s got=%q: %v", identity.want, string(out), err)
		}
	}
	caller := restoreRootQuery{Actor: api.Actor{Kind: "lane", ID: "restore-caller", LifeID: dest.Request.LifeID}, LaunchID: dq.Reg.Reservation.LaunchID}
	if observe != nil {
		observe(dest)
	}
	for _, targetName := range []string{"restored", "empty"} {
		request := api.RestoreRequest{Target: res.Target, ExpectedGeneration: 3, Path: filepath.Join(workspace, targetName)}
		if targetName == "empty" {
			if err := os.Mkdir(request.Path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(request.Path, int(dest.Lease.UID), int(dest.Lease.GID)); err != nil {
				t.Fatal(err)
			}
		}
		value, err := m.dispatch(ctx, "restore_begin", mustCanaryJSON(t, map[string]any{"Caller": caller, "Request": request, "Tree": tree, "Ceiling": uint64(8 << 20)}))
		if err != nil {
			t.Fatal("installed helper cannot begin restore:", err)
		}
		id := value.(api.ID)
		for _, entry := range tree.Entries {
			if entry.Content == nil {
				continue
			}
			body := bodies[entry.Content.ID]
			for offset := 0; offset < len(body); {
				end := min(len(body), offset+api.MaxChunkBytes)
				_, err := m.dispatch(ctx, "restore_chunk", mustCanaryJSON(t, map[string]any{"ID": id, "ObjectID": entry.Content.ID, "Offset": int64(offset), "Data": body[offset:end]}))
				if err != nil {
					t.Fatal(err)
				}
				offset = end
			}
		}
		selector := mustCanaryJSON(t, map[string]any{"ID": id, "Caller": caller})
		if _, err := m.dispatch(ctx, "restore_stage", selector); err != nil {
			t.Fatal("native staging:", err)
		}
		if targetName == "empty" {
			items, err := os.ReadDir(request.Path)
			if err != nil || len(items) != 0 {
				t.Fatal("staging changed the empty target:", err)
			}
		} else if _, err := os.Lstat(request.Path); !os.IsNotExist(err) {
			t.Fatal("staging published before the store's commit fence")
		}
		if _, err := m.dispatch(ctx, "restore_publish", selector); err != nil {
			t.Fatal("native publication:", err)
		}
		got, err := os.ReadFile(filepath.Join(request.Path, "dirty"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("installed restore changed frozen bytes:", err)
		}
		if err := filepath.WalkDir(request.Path, func(name string, item os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			var st unix.Stat_t
			if unix.Lstat(name, &st) != nil || st.Uid != dest.Lease.UID || st.Gid != dest.Lease.GID {
				t.Error("restored inode is not lane-owned")
			}
			if name == filepath.Join(request.Path, "dirty") && st.Mode&07777 != 0600 {
				t.Error("installed restore dropped the 0600 mode")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("bad-pack", func(t *testing.T) {
		testBadRestore(t, m, caller, tree, bodies, workspace, dest.Lease.UID, dest.Lease.GID)
	})
	if _, err := source.checkArchive(ctx, archiveQuery{Intent: intent, Freeze: header.Freeze}); err != nil {
		t.Fatal("restore changed the original native archive:", err)
	}
}
