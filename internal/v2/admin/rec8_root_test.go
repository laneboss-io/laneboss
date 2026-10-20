//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Trace the actual Git exec stops, not the helper or a stand-in executable.
// At each stop /proc/exe must match the installed Git inode before status is
// checked. The native installed fixture supplies the destination identity.
func TestRestoreGitIDs(t *testing.T) {
	if os.Args[len(os.Args)-1] == "restore-trace" {
		restoreInstalled(t, func(r leaseRecord) {
			file := os.NewFile(3, "restore-identity")
			defer file.Close()
			if err := json.NewEncoder(file).Encode([]uint32{r.Lease.UID, r.Lease.GID}); err != nil {
				t.Fatal(err)
			}
		})
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("restore exec trace requires disposable Linux root")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	output, err := os.Create(filepath.Join(t.TempDir(), "trace-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	command := exec.Command("/proc/self/exe", "-test.run=^TestRestoreGitIDs$", "-test.v", "--", "restore-trace")
	command.Env, command.ExtraFiles = []string{}, []*os.File{write}
	command.Stdout, command.Stderr = output, output
	command.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { command.Process.Kill() })
	defer stop()
	var status unix.WaitStatus
	if _, err := unix.Wait4(command.Process.Pid, &status, 0, nil); err != nil || !status.Stopped() {
		t.Fatal("trace child did not stop at exec", err)
	}
	options := unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK | unix.PTRACE_O_TRACECLONE | unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL
	if err := unix.PtraceSetOptions(command.Process.Pid, options); err != nil {
		t.Fatal(err)
	}
	if err := unix.PtraceCont(command.Process.Pid, 0); err != nil {
		t.Fatal(err)
	}
	git, err := os.Stat("/usr/bin/git")
	if err != nil {
		t.Fatal(err)
	}
	var identity []uint32
	seen := map[string]int{}
	wanted := []string{"init", "check-ref-format", "index-pack", "cat-file", "symbolic-ref", "update-ref", "read-tree"}
	mainExit := -1
	for {
		pid, err := unix.Wait4(-1, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ECHILD) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if status.Exited() || status.Signaled() {
			if pid == command.Process.Pid {
				mainExit = status.ExitStatus()
			}
			continue
		}
		if status.TrapCause() == unix.PTRACE_EVENT_EXEC {
			exe, statErr := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
			if statErr == nil && os.SameFile(exe, git) {
				raw, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
				if readErr != nil {
					t.Fatal(readErr)
				}
				args := strings.Split(string(raw), "\x00")
				restore := false
				for _, arg := range args {
					restore = restore || arg == "--git-dir=/proc/self/fd/3/.git" || arg == "--git-dir=.git"
				}
				if restore {
					if identity == nil {
						if err := json.NewDecoder(read).Decode(&identity); err != nil || len(identity) != 2 || identity[0] == 0 || identity[1] == 0 {
							t.Fatal("trace lost the actual destination identity", err)
						}
					}
					step := ""
					for _, arg := range args {
						for _, name := range wanted {
							if arg == name {
								step = name
							}
						}
					}
					if step == "" {
						t.Fatal("restore executed an unknown Git step")
					}
					seen[step]++
					checkRestoreIDs(t, pid, identity, step)
				}
			}
		}
		signal := 0
		if status.StopSignal() != unix.SIGTRAP && status.StopSignal() != unix.SIGSTOP {
			signal = int(status.StopSignal())
		}
		if err := unix.PtraceCont(pid, signal); err != nil && !errors.Is(err, unix.ESRCH) {
			t.Fatal(err)
		}
	}
	stop()
	if err := command.Process.Release(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || mainExit != 0 {
		raw, err := os.ReadFile(output.Name())
		t.Fatalf("native restore trace fixture failed: exit=%d steps=%v read=%v\n%s", mainExit, seen, err, raw)
	}
	for _, step := range wanted {
		want := 2
		if step == "init" || step == "check-ref-format" || step == "index-pack" {
			want++ // The malformed pack reaches the real parser too.
		}
		if seen[step] != want {
			t.Errorf("actual restore Git %s exec count=%d, want %d", step, seen[step], want)
		}
	}
}

func testBadRestore(t *testing.T, m *leaseManager, caller restoreRootQuery, tree api.ObjectManifest, bodies map[api.ID][]byte, workspace string, uid, gid uint32) {
	t.Helper()
	base := filepath.Dir(workspace)
	before, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	prior := map[string]bool{}
	for _, item := range before {
		prior[item.Name()] = true
	}
	tree.Entries = append([]api.ObjectEntry{}, tree.Entries...)
	badBodies := map[api.ID][]byte{}
	for id, body := range bodies {
		badBodies[id] = body
	}
	found := false
	for i, entry := range tree.Entries {
		if entry.Path != "git/pack" {
			continue
		}
		pack := append([]byte{}, bodies[entry.Content.ID]...)
		if len(pack) < 12 || string(pack[:4]) != "PACK" {
			t.Fatal("native source did not produce an actual Git pack")
		}
		pack[4] = 255 // Valid frozen digest, unsupported Git pack version.
		ref := *entry.Content
		ref.SHA256 = digestBytes(pack)
		tree.Entries[i].Content = &ref
		badBodies[ref.ID] = pack
		found = true
	}
	if !found {
		t.Fatal("native archive omitted its Git pack")
	}
	ctx := context.Background()
	request := api.RestoreRequest{Target: api.LifeRef{LifeID: "bad-source", Run: 1}, ExpectedGeneration: 3, Path: filepath.Join(workspace, "bad-pack")}
	value, err := m.dispatch(ctx, "restore_begin", mustCanaryJSON(t, restoreBegin{Caller: caller, Request: request, Tree: tree, Ceiling: 8 << 20}))
	if err != nil {
		t.Fatal(err)
	}
	id := value.(api.ID)
	for _, entry := range tree.Entries {
		if entry.Content == nil {
			continue
		}
		body := badBodies[entry.Content.ID]
		for offset := 0; offset < len(body); {
			end := min(len(body), offset+api.MaxChunkBytes)
			if _, err := m.dispatch(ctx, "restore_chunk", mustCanaryJSON(t, restoreChunk{ID: id, ObjectID: entry.Content.ID, Offset: int64(offset), Data: body[offset:end]})); err != nil {
				t.Fatal(err)
			}
			offset = end
		}
	}
	selector := mustCanaryJSON(t, restoreSelect{ID: id, Caller: caller})
	var typed *api.Error
	if _, err := m.dispatch(ctx, "restore_stage", selector); !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("crafted pack did not fail its actual Git parser", err)
	}
	if _, err := m.dispatch(ctx, "restore_publish", selector); err == nil {
		t.Fatal("failed Git parse authorized publication")
	}
	if _, err := os.Lstat(request.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed Git parse published a destination", err)
	}
	after, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range after {
		if strings.HasPrefix(item.Name(), "restore-") && !prior[item.Name()] {
			t.Error("failed Git parse retained new staging output")
		}
	}
	job := m.restores[id]
	if job.Stage != "" {
		if err := filepath.WalkDir(filepath.Join(job.Stage, "result"), func(name string, item os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			var info unix.Stat_t
			if unix.Lstat(name, &info) != nil || info.Uid != uid || info.Gid != gid {
				t.Error("failed Git parse left output owned by root or another lane")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.dispatch(ctx, "restore_abort", selector); err != nil {
		t.Fatal(err)
	}
}

func checkRestoreIDs(t *testing.T, pid int, ids []uint32, step string) {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		switch name {
		case "Uid", "Gid":
			want := ids[0]
			if name == "Gid" {
				want = ids[1]
			}
			ok := len(fields) == 5
			for _, field := range fields[1:] {
				value, err := strconv.ParseUint(field, 10, 32)
				ok = ok && err == nil && uint32(value) == want
			}
			seen[name] = ok
		case "CapEff", "CapPrm", "CapInh", "CapAmb":
			value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(string(line), fields[0])), 16, 64)
			seen[name] = err == nil && value == 0
		case "Groups":
			seen[name] = len(fields) == 1
		case "NoNewPrivs":
			seen[name] = len(fields) == 2 && fields[1] == "1"
		}
	}
	for _, name := range []string{"Uid", "Gid", "CapEff", "CapPrm", "CapInh", "CapAmb", "Groups", "NoNewPrivs"} {
		if !seen[name] {
			t.Errorf("actual restore Git %s failed privilege check %s", step, name)
		}
	}
}
