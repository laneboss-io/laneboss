//go:build linux && laneboss_root_canary && laneboss_e2e_authenticator

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The fixture's real run and writer execute in a private namespace. An inotify
// barrier holds run mid-input while its production writer retains partial input;
// stop/kill happens only after that real write. Git measures the resulting dirt.
// Archive/collection use the real SQLite writer and dataworker in an unprivileged
// child; native identity/removal receipts remain explicit component inputs.
func TestFixtureScratchClean(t *testing.T) {
	switch os.Args[len(os.Args)-1] {
	case "fixture-scratch-child":
		wait := scratchWatch(t, "/home/lane", "/work/main")
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer cancel()
		fmt.Fprintf(os.Stdout, "fixture-pid %d\n", os.Getpid())
		go func() {
			if err := wait(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			partial, err := os.ReadFile("/home/lane/fixture.input")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			if err := write("prompt.input", partial); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			fmt.Fprintln(os.Stdout, "fixture-scratch-written")
		}()
		go func() {
			<-ctx.Done()
			fmt.Fprintln(os.Stdout, "fixture-cancelled")
		}()
		f := fixture{options: options{Mode: "lifecycle", WaitMS: 60000}}
		if err := f.run(ctx); err != nil {
			t.Fatal(err)
		}
		t.Fatal("mid-input fixture unexpectedly completed")
	case "fixture-clean-child":
		var input struct{ Dirty, RealWork bool }
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			t.Fatal(err)
		}
		cleanScratch(t, input.Dirty, input.RealWork)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture scratch canary requires disposable Linux root")
	}
	for _, mode := range []string{"stop", "kill", "return", "real-work"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			root := t.TempDir()
			work, home := filepath.Join(root, "work"), filepath.Join(root, "home")
			for _, directory := range []string{work, home} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			scratchGit(t, ctx, work, "init", "--quiet")
			scratchGit(t, ctx, work, "-c", "user.name=fixture", "-c", "user.email=fixture", "commit", "--quiet", "--allow-empty", "-m", "initial")
			partial := stopFixtureInput(t, ctx, work, home, mode)
			var own []byte
			if mode == "real-work" {
				own = []byte("real lane work " + string(fx.ID(t)))
				if err := os.MkdirAll(filepath.Join(work, "serve-state"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(work, "serve-state", "owned.txt"), own, 0600); err != nil {
					t.Fatal(err)
				}
			}
			status := scratchGit(t, ctx, work, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=all")
			input, err := json.Marshal(struct{ Dirty, RealWork bool }{len(status) != 0, mode == "real-work"})
			if err != nil {
				t.Fatal(err)
			}
			self, err := os.Open("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			defer self.Close()
			collectorHome, err := os.MkdirTemp("/var/lib", "lb-v2-land5-stop-home-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(collectorHome); err != nil {
					t.Error(err)
				}
			})
			if err := os.Chown(collectorHome, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestFixtureScratchClean$", "--", "fixture-clean-child")
			command.Dir = "/"
			command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + collectorHome, "GOMAXPROCS=1"}
			command.ExtraFiles = []*os.File{self}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
			command.Stdin = bytes.NewReader(input)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("Clean failed after fixture interruption: %v\n%s", err, output)
			}
			if mode == "real-work" {
				kept, err := os.ReadFile(filepath.Join(work, "serve-state", "owned.txt"))
				if err != nil || !bytes.Equal(kept, own) {
					t.Fatal("real work was not retained", err)
				}
				return
			}
			info, err := os.Lstat(filepath.Join(home, "serve-state"))
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
				t.Fatal("fixture scratch did not remain in its private home", err)
			}
			retained, err := os.ReadFile(filepath.Join(home, "serve-state", "prompt.input"))
			if err != nil || !bytes.Equal(retained, partial) {
				t.Fatal("fixture scratch lost or substituted actual partial input", err)
			}
			if _, err := os.Lstat(filepath.Join(work, "serve-state")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("fixture created scratch in the Git worktree", err)
			}
		})
	}
}

func cleanScratch(t *testing.T, dirty, realWork bool) {
	t.Helper()
	f := fx.ControlledChild(t)
	ctx := context.Background()
	scene := f.PrepareCleanup(t, func(ctx context.Context, scope api.Scope, p api.WorkerPrincipal) (api.WorkerResultReceipt, error) {
		return dataworker.RunArchive(ctx, dataworker.ArchiveJob{Principal: p, Scope: scope, Bootstrap: f.State,
			Read: func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
				return f.State.WorkerObject(ctx, scope, q)
			}, Sink: f.State, Clock: f.Deps.Clock})
	}, nil, dirty)
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: scene.Effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	job, err := f.State.BeginCleanup(ctx, f.Execution, claim)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := f.State.CleanupInventory(ctx, f.Execution, job)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := dataworker.New(dataworker.Dependencies{Config: f.Deps.Config, Store: f.State,
		Helper: &struct{ api.HelperControl }{}, Launcher: &struct{ api.Launcher }{}, Clock: f.Deps.Clock, Workspace: scene.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := worker.CollectCleanup(ctx, job)
	if realWork {
		var refusal *api.Error
		if !errors.As(err, &refusal) || refusal.Code != api.CodePrerequisite || receipt.ID != "" {
			t.Fatal("real work escaped the unchanged dirty-work gate", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("Clean refused after interrupted fixture scratch: %v", err)
	}
	verified, err := api.VerifyCleanup(ctx, f.State.CleanupReadbacks(f.Execution), job, inventory, receipt, f.Deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.State.CompleteCleanup(ctx, f.Execution, job, verified); err != nil {
		t.Fatal(err)
	}
	operation, err := f.State.Operation(ctx, f.Execution, scene.Effect.OperationID)
	if err != nil || operation.Status != "succeeded" {
		t.Fatal("fixture scratch prevented verified Clean completion", err)
	}
}

func scratchGit(t *testing.T, ctx context.Context, work string, args ...string) []byte {
	t.Helper()
	command := exec.CommandContext(ctx, "/usr/bin/git", append([]string{"-C", work}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("scratch Git operation failed", err)
	}
	return output
}

func scratchCommand(t *testing.T, ctx context.Context, work, home, child string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--unshare-net", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--perms", "01777", "--tmpfs", "/tmp", "--bind", home, "/home/lane", "--bind", work, "/work/main",
		"--ro-bind", self, "/fixture-test", "--", "/fixture-test", "-test.run=^TestFixtureScratchClean$", "--", child}
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/home/lane", "GOMAXPROCS=1"}
	return command
}

func scratchWatch(t *testing.T, directories ...string) func() error {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	watch := os.NewFile(uintptr(fd), "scratch-watch")
	t.Cleanup(func() {
		if err := watch.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, directory := range directories {
		if _, err := unix.InotifyAddWatch(fd, directory, unix.IN_CREATE); err != nil {
			t.Fatal(err)
		}
	}
	return func() error {
		buffer := make([]byte, 4096)
		for {
			n, err := watch.Read(buffer)
			if err != nil {
				return err
			}
			for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
				length := int(binary.NativeEndian.Uint32(buffer[offset+12 : offset+16]))
				end := offset + unix.SizeofInotifyEvent + length
				if end > n {
					return errors.New("incomplete scratch notification")
				}
				name := strings.TrimRight(string(buffer[offset+unix.SizeofInotifyEvent:end]), "\x00")
				if name == "serve-state" {
					return nil
				}
				offset = end
			}
		}
	}
}

func stopFixtureInput(t *testing.T, ctx context.Context, work, home, mode string) []byte {
	t.Helper()
	partial := []byte("interrupted prompt " + string(fx.ID(t)) + "\n")
	if err := os.WriteFile(filepath.Join(home, "fixture.input"), partial, 0400); err != nil {
		t.Fatal(err)
	}
	command := scratchCommand(t, ctx, work, home, "fixture-scratch-child")
	command.Args = append(command.Args[:len(command.Args)-5], "--chdir", "/work/main", "--", "/fixture-test",
		"-test.run=^TestFixtureScratchClean$", "--", "fixture-scratch-child")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err := command.Wait(); err != nil {
				var exited *exec.ExitError
				if !errors.As(err, &exited) {
					t.Error(err)
				}
			}
		}
	}()
	reader := bufio.NewReader(output)
	line, err := reader.ReadString('\n')
	pid, parseErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "fixture-pid ")))
	if err != nil || parseErr != nil || !strings.HasPrefix(line, "fixture-pid ") || pid <= 1 || pid == os.Getpid() {
		t.Fatalf("fixture child did not start: %v %v %s", err, parseErr, diagnostic.Bytes())
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "fixture-scratch-written\n" {
		t.Fatal("fixture did not retain real partial input", err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "stop" {
		if err := process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "fixture-cancelled\n" {
			t.Fatal("fixture did not observe the actual stop", err)
		}
	} else if mode != "return" {
		if err := process.Kill(); err != nil {
			t.Fatal(err)
		}
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	waited = true
	var exited *exec.ExitError
	if !errors.As(err, &exited) || ctx.Err() != nil {
		t.Fatal("fixture did not retain its interrupted/failed process result", err, ctx.Err())
	}
	return partial
}
