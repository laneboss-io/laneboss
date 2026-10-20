//go:build linux && laneboss_root_canary && laneboss_e2e_authenticator

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	linux "laneboss.io/laneboss/internal/v2/isolation/linux"
)

// Only the CLI response is a component input. The real fixture run reads its
// rendered prompt, launches both CLI calls with sealed descriptors, and writes
// in a nonroot mount namespace. This is not an authentication/service test.
func init() {
	if len(os.Args) < 3 || os.Args[1] != "identity" && os.Args[1] != "lane" {
		return
	}
	var config, request string
	for i := 3; i+1 < len(os.Args); i += 2 {
		switch os.Args[i] {
		case "--config":
			config = os.Args[i+1]
		case "--request":
			request = os.Args[i+1]
		}
	}
	binding, err := wire.ReadBinding(wire.LaneBindingPath, config, release.Version)
	if err != nil || binding.Target == nil {
		os.Exit(41)
	}
	value := map[string]any{"config": binding.Config, "launch_id": binding.LaunchID,
		"actor": map[string]any{"kind": "lane", "life_id": binding.Target.LifeID}}
	if os.Args[1] == "lane" {
		var target map[string]any
		raw, err := os.ReadFile(request)
		if err != nil || json.Unmarshal(raw, &target) != nil {
			os.Exit(42)
		}
		if target["life_id"] != string(binding.Target.LifeID) || target["run"] != float64(binding.Target.Run) {
			os.Exit(44)
		}
		value = map[string]any{"name": target["life_id"]}
	}
	if json.NewEncoder(os.Stdout).Encode(value) != nil {
		os.Exit(43)
	}
	os.Exit(0)
}

func TestDirtyLane(t *testing.T) {
	if os.Args[len(os.Args)-1] == "dirty-child" {
		runtime.LockOSThread()
		seqLandlock(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if os.Args[len(os.Args)-2] == "restore" {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			control := os.NewFile(8, "host-control")
			defer control.Close()
			go func() {
				var stop [1]byte
				if _, err := io.ReadFull(control, stop[:]); err != nil || stop[0] != 's' {
					t.Error("held host lost its explicit stop", err)
				}
				cancel()
			}()
		}
		defer cancel()
		f := fixture{options: options{Config: "dirty-seq", Client: "/fixture-test",
			Binding: wire.LaneBindingPath, Challenge: strings.Repeat("a", 32),
			Life: "g11-dirty", Driver: "claudock-cli", Run: 1, Mode: "lifecycle", WaitMS: 60000}}
		if os.Args[len(os.Args)-2] == "plain" {
			f.Driver = "codex"
		}
		if os.Args[len(os.Args)-2] == "restore" {
			f.Life, f.WaitMS = "g11-restore", 300000
		}
		if err := f.run(ctx); err != nil {
			t.Fatalf("in-lane sequence failed: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("dirty sequence needs the disposable root box")
	}
	for _, mode := range []string{"dirty", "envelope", "outside", "earlier-heading", "bad-task", "readonly", "foreign-owned", "plain", "ordinary", "restore"} {
		t.Run(mode, func(t *testing.T) {
			directory, err := os.MkdirTemp("/run", "lb-v2-g11-seq-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(directory); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chmod(directory, 0755); err != nil {
				t.Fatal(err)
			}
			work, home := filepath.Join(directory, "work"), filepath.Join(directory, "home")
			const uid = 61101
			for _, path := range []string{work, home} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chown(path, uid, uid); err != nil {
					t.Fatal(err)
				}
			}
			name := filepath.Join(work, "README.md")
			if err := os.WriteFile(name, []byte("tracked project\n"), 0444); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(name, uid, uid); err != nil {
				t.Fatal(err)
			}
			if mode == "foreign-owned" {
				if err := os.Chown(name, 0, 0); err != nil {
					t.Fatal(err)
				}
			}
			outside := filepath.Join(directory, "outside.txt")
			if err := os.WriteFile(outside, []byte("outside canary\n"), 0444); err != nil {
				t.Fatal(err)
			}
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(directory, "socket"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := os.Chmod(listener.Addr().String(), 0666); err != nil {
				t.Fatal(err)
			}
			socketFD, err := unix.Open(listener.Addr().String(), unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			socket := os.NewFile(uintptr(socketFD), "dirty-socket")
			defer socket.Close()
			binding := api.InstalledBinding{Schema: "laneboss.binding.v2", Config: "dirty-seq",
				Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision,
				Class: api.EndpointLane, InstallationGeneration: 1, EndpointGeneration: 1,
				ServiceVersion: release.Version, ServiceUID: 41001, ServiceGID: 41001,
				MappedServiceUID: 65534, MappedServiceGID: 65534, Socket: wire.LaneSocketPath,
				ArtifactSHA256: api.Digest(strings.Repeat("a", 64)), Backend: "linux-bwrap-landlock",
				LaunchID: "dirty-launch", Target: &api.LifeRef{LifeID: "g11-dirty", Run: 1}}
			if mode == "restore" {
				binding.Target.LifeID = "g11-restore"
			}
			raw, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			fd, err := unix.MemfdCreate("dirty-binding", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			proof := os.NewFile(uintptr(fd), "dirty-binding")
			defer proof.Close()
			if _, err := proof.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := proof.Chmod(0444); err != nil {
				t.Fatal(err)
			}
			seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
			if _, err := unix.FcntlInt(proof.Fd(), unix.F_ADD_SEALS, seals); err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			binary, err := os.ReadFile(self)
			if err != nil {
				t.Fatal(err)
			}
			self = filepath.Join(directory, "fixture-test")
			if err := os.WriteFile(self, binary, 0555); err != nil {
				t.Fatal(err)
			}
			input := dirtyInput{Schema: "laneboss.dirty-task.v1", Nonce: strings.Repeat("a", 32),
				Lane: "g11-dirty", TrackedPath: "README.md", UntrackedPath: "dirty.txt"}
			if mode == "outside" {
				input.TrackedPath = "../outside.txt"
			}
			task, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			prefix := "## Assigned task\n\n"
			if mode == "earlier-heading" {
				prefix = "Role example:\n## Assigned task\n\nexample only\n\n" + prefix
			}
			if mode == "bad-task" {
				task = task[:len(task)-1]
			}
			if mode == "ordinary" {
				task = []byte(`{"schema":"laneboss.serve-task.v1"}`)
			}
			prompt := append([]byte(prefix), task...)
			if mode == "envelope" || mode == "plain" || mode == "ordinary" {
				// lifecycle.planExecution.prompt sends this JSON envelope, with
				// the task and rendered briefing as separate string fields.
				prompt, err = json.Marshal(map[string]any{
					"schema": "laneboss.launch-prompt.v2", "task": string(task),
					"briefing": string(prompt), "guidance": []any{},
					"guidance_id": "component-guidance", "guidance_status": "empty",
					"guidance_notice": "", "message": "", "mail": []any{},
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-net",
				"--cap-drop", "ALL", "--clearenv", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
				"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
				"--symlink", "usr/lib64", "/lib64", "--bind", work, "/work/main", "--bind", home, "/home/lane",
				"--ro-bind", outside, "/work/outside.txt", "--ro-bind", self, "/fixture-test",
				"--symlink", "/proc/self/fd/6", wire.LaneBindingPath, "--symlink", "/proc/self/fd/7", wire.LaneSocketPath,
				"--chdir", "/work/main", "--remount-ro", "/", "--", "/fixture-test", "-test.run=^TestDirtyLane$", "--", mode, "dirty-child"}
			if mode == "readonly" {
				for i := range args {
					if args[i] == "--bind" && args[i+1] == work {
						args[i] = "--ro-bind"
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}}
			var group string
			if mode == "plain" || mode == "ordinary" || mode == "restore" {
				group = filepath.Join("/sys/fs/cgroup", filepath.Base(directory))
				if err := os.Mkdir(group, 0755); err != nil {
					t.Fatal("cannot create real plain-lane census group", err)
				}
				t.Cleanup(func() {
					if err := os.Remove(group); err != nil {
						t.Error(err)
					}
				})
				cgroup, err := os.Open(group)
				if err != nil {
					t.Fatal(err)
				}
				defer cgroup.Close()
				command.SysProcAttr.UseCgroupFD, command.SysProcAttr.CgroupFD = true, int(cgroup.Fd())
			}
			command.ExtraFiles = []*os.File{proof, proof, proof, proof, socket}
			command.Stdin = bytes.NewReader(prompt)
			var output []byte
			var runErr error
			if mode == "restore" {
				control, stop, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer control.Close()
				defer stop.Close()
				command.ExtraFiles = append(command.ExtraFiles, control)
				stdout, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				var diagnostic bytes.Buffer
				command.Stderr = &diagnostic
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(stdout)
				line, readErr := reader.ReadBytes('\n')
				var remainder bytes.Buffer
				waited := make(chan error, 1)
				go func() {
					if _, err := io.Copy(&remainder, reader); err != nil {
						t.Error("held host output read failed", err)
					}
					waited <- command.Wait()
				}()
				procs, censusErr := os.ReadFile(filepath.Join(group, "cgroup.procs"))
				if readErr != nil || !bytes.Contains(line, []byte(`"type":"serve.session"`)) ||
					censusErr != nil || len(bytes.TrimSpace(procs)) == 0 {
					t.Error("restore host did not remain held after its task", readErr, censusErr)
				}
				ended := false
				select {
				case runErr = <-waited:
					ended = true
					t.Error("restore host ended before its explicit stop", runErr)
				case <-time.After(100 * time.Millisecond):
				}
				if !ended {
					if _, err := stop.Write([]byte{'s'}); err != nil {
						t.Error(err)
					}
					runErr = <-waited
				}
				output = append(line, remainder.Bytes()...)
				output = append(output, diagnostic.Bytes()...)
				t.Log("restore host: measured live cgroup before explicit stop")
			} else {
				output, runErr = command.CombinedOutput()
			}
			err = runErr
			if mode == "plain" || mode == "ordinary" || mode == "restore" {
				if err != nil || !bytes.Contains(output, []byte(`"type":"serve.session"`)) {
					t.Fatalf("plain lifecycle did not exit normally: %v\n%s", err, output)
				}
				procs, err := os.ReadFile(filepath.Join(group, "cgroup.procs"))
				if err != nil || len(bytes.TrimSpace(procs)) != 0 {
					t.Fatal("plain lifecycle retained measured cgroup survivors", err)
				}
				t.Log("plain lifecycle: exit=0, measured cgroup survivors=0")
				names := []string{"dirty-result.json", "dirty-result.pending"}
				if mode != "restore" {
					names = append(names, "dirty-status.request.json")
				}
				for _, name := range names {
					if _, err := os.Stat(filepath.Join(home, "serve-state", name)); !os.IsNotExist(err) {
						t.Fatal("plain lifecycle touched dirty-only files", name, err)
					}
				}
				kept, err := os.ReadFile(name)
				if err != nil || string(kept) != "tracked project\n" {
					t.Fatal("plain lifecycle changed project bytes", err)
				}
				return
			}
			positive := mode == "dirty" || mode == "envelope" || mode == "earlier-heading" || mode == "foreign-owned"
			refusal := "outside lane"
			if mode == "bad-task" {
				refusal = "dirty.prompt"
			}
			if mode == "readonly" {
				refusal = "dirty.create_tracked"
			}
			if positive && err != nil || !positive && (err == nil || !bytes.Contains(output, []byte(refusal))) {
				t.Fatalf("in-lane %s sequence failed: %v\n%s", mode, err, output)
			}
			resultBytes, readErr := os.ReadFile(filepath.Join(home, "serve-state", "dirty-result.json"))
			var result dirtyResult
			if readErr != nil || json.Unmarshal(resultBytes, &result) != nil ||
				positive && result.Status != "written" || !positive && (result.Status != "failed" || !strings.Contains(result.Error, refusal)) {
				t.Fatal("fixture did not retain its own reached result", readErr, result)
			}
			if !positive {
				if _, err := os.Stat(filepath.Join(work, "dirty.txt")); !os.IsNotExist(err) {
					t.Fatal("refused sequence created an untracked file", err)
				}
			}
			tracked, readErr := os.ReadFile(name)
			want := "tracked project\n"
			if positive {
				want += "\nG11 dirty tracked " + input.Nonce + "\n"
				data, err := os.ReadFile(filepath.Join(work, "dirty.txt"))
				if err != nil || string(data) != "G11 dirty untracked "+input.Nonce+"\n" {
					t.Fatal("in-lane sequence did not create its untracked bytes", err)
				}
			}
			kept, outsideErr := os.ReadFile(outside)
			if readErr != nil || string(tracked) != want || outsideErr != nil || string(kept) != "outside canary\n" {
				t.Fatal("in-lane sequence changed the wrong bytes")
			}
			fmt.Printf("in-lane %s: measured bytes and outside canary\n", mode)
		})
	}
}

func seqLandlock(t *testing.T) {
	t.Helper()
	paths := []linux.PathAccess{{Path: "/usr", Directory: true, Executable: true},
		{Path: "/fixture-test", Executable: true}, {Path: "/proc", Directory: true},
		{Path: "/work/main", Directory: true, Access: linux.ReadWrite},
		{Path: "/home/lane", Directory: true, Access: linux.ReadWrite},
		{Path: "/tmp", Directory: true, Access: linux.ReadWrite}}
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		t.Fatal(errno)
	}
	rules, err := linux.BuildRuleset(int(abi), paths)
	if err != nil {
		t.Fatal(err)
	}
	access := rules.HandledAccessFS
	raw, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&access)), 8, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	fd := int(raw)
	defer unix.Close(fd)
	for _, rule := range rules.Rules {
		parent, err := unix.Open(rule.Path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		attr := unix.LandlockPathBeneathAttr{Allowed_access: rule.AllowedAccess, Parent_fd: int32(parent)}
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(fd), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&attr)), 0, 0, 0)
		if err := unix.Close(parent); err != nil || errno != 0 {
			t.Fatal(err, errno)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0); errno != 0 {
		t.Fatal(errno)
	}
}
