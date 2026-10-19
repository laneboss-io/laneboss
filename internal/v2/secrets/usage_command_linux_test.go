//go:build linux

package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
)

// The retained test binary doubles as a native synthetic query program. It
// reads actual private fixture files and exits with their chosen status. This
// measures exec/argv/environment/home/pipe behavior, never a vendor or login.
func TestMain(m *testing.M) {
	if len(os.Args) > 0 && os.Args[0] == "claudock" {
		if !reflect.DeepEqual(os.Args, []string{"claudock", "usage", "--max-age", "0"}) {
			os.Exit(64)
		}
		if _, inherited := os.LookupEnv("LB_USAGE_INHERIT_CANARY"); inherited {
			os.Exit(65)
		}
		if os.Getenv("HOME") != "/proc/self/fd/4" || os.Getenv("XDG_CONFIG_HOME") != "/proc/self/fd/4/.config" || os.Getenv("PATH") != "/usr/bin:/bin" {
			os.Exit(66)
		}
		fromCWD, err := os.ReadFile("usage-fixture.tsv")
		if err != nil {
			os.Exit(67)
		}
		fromHome, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), "usage-fixture.tsv"))
		if err != nil || !bytes.Equal(fromCWD, fromHome) {
			os.Exit(68)
		}
		exitBytes, err := os.ReadFile("usage-fixture.exit")
		if err != nil {
			os.Exit(69)
		}
		exit, err := strconv.Atoi(string(exitBytes))
		if err != nil || exit < 0 || exit > 125 {
			os.Exit(70)
		}
		if _, err := os.Stat("usage-fixture.block"); err == nil {
			ready, err := os.OpenFile("usage-fixture.ready", os.O_WRONLY, 0)
			if err != nil {
				os.Exit(72)
			}
			if _, err := ready.Write([]byte("started")); err != nil {
				os.Exit(73)
			}
			if err := ready.Close(); err != nil {
				os.Exit(74)
			}
			// The parent must cancel/collect this actual started child. The
			// timer is a last bound if the test harness itself is interrupted.
			time.Sleep(30 * time.Second)
			os.Exit(75)
		} else if !errors.Is(err, os.ErrNotExist) {
			os.Exit(76)
		}
		if diagnostic, err := os.ReadFile("usage-fixture.stderr"); err == nil {
			if _, err := os.Stderr.Write(diagnostic); err != nil {
				os.Exit(77)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			os.Exit(78)
		}
		if _, err := os.Stdout.Write(fromCWD); err != nil {
			os.Exit(71)
		}
		os.Exit(exit)
	}
	os.Exit(m.Run())
}

func usageCommandCase(t *testing.T) (*launchCase, api.WorkerPrincipal, api.WorkerJobInput, *os.File, *os.File, []byte) {
	t.Helper()
	c, job := newUsageCase(t)
	var p api.WorkerPrincipal
	if err := c.store.read("usage-principal.json", &p); err != nil {
		t.Fatal("cannot read command worker principal")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal("cannot select the actual native fixture executable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read the actual native fixture executable bytes")
	}
	sourceInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal("cannot inspect native fixture source permissions")
	}
	t.Logf("native fixture source executable_private=%t source_bounded=%t", sourceInfo.Mode().Perm()&0022 == 0, sourceInfo.Size() >= 4 && sourceInfo.Size() <= 128<<20)
	// cmd/go's temporary link output follows its umask; it is not an
	// installed runtime artifact. Install exactly those bytes privately so
	// a group-writable build output cannot mask the command assertions.
	installed := filepath.Join(t.TempDir(), "usage-native-fixture")
	if err := os.WriteFile(installed, data, 0500); err != nil {
		t.Fatal("cannot install the private native fixture executable")
	}
	if err := os.Chmod(installed, 0500); err != nil {
		t.Fatal("cannot close native fixture executable permissions")
	}
	executable, err := os.Open(installed)
	if err != nil {
		t.Fatal("cannot hold the actual native fixture executable")
	}
	t.Cleanup(func() {
		if err := executable.Close(); err != nil {
			t.Error("cannot close fixture executable handle")
		}
	})
	actual, err := io.ReadAll(executable)
	info, statErr := executable.Stat()
	if err != nil || statErr != nil || info.Mode().Perm() != 0500 || !bytes.Equal(actual, data) {
		t.Fatal("installed native fixture executable changed its bytes or mode")
	}
	sum := sha256.Sum256(data)
	var selected UsageInput
	if err := json.Unmarshal(job.input.Bytes, &selected); err != nil {
		t.Fatal("cannot decode command fixture input")
	}
	selected.Request.Executable.SHA256 = api.Digest(hex.EncodeToString(sum[:]))
	input := sealCommandInput(t, job.input, selected)
	p.Lease.Input, p.Claim.Record.Effect.Worker.Input = input.Input, input.Input
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("cannot protect synthetic usage home")
	}
	// Random bytes demonstrate that successful stdout came from the file.
	raw := syntheticBytes(t, 73)
	if err := os.WriteFile(filepath.Join(directory, "usage-fixture.tsv"), raw, 0600); err != nil {
		t.Fatal("cannot retain actual synthetic query input")
	}
	if err := os.WriteFile(filepath.Join(directory, "usage-fixture.exit"), []byte("0"), 0600); err != nil {
		t.Fatal("cannot retain actual synthetic query exit")
	}
	home, err := os.Open(directory)
	if err != nil {
		t.Fatal("cannot hold the synthetic usage home")
	}
	t.Cleanup(func() {
		if err := home.Close(); err != nil {
			t.Error("cannot close fixture home handle")
		}
	})
	return c, p, input, executable, home, raw
}

func sealCommandInput(t *testing.T, input api.WorkerJobInput, selected UsageInput) api.WorkerJobInput {
	t.Helper()
	data, err := json.Marshal(selected)
	if err != nil {
		t.Fatal("cannot encode actual command input")
	}
	data, err = api.CanonicalJSON(data)
	if err != nil {
		t.Fatal("cannot canonicalize actual command input")
	}
	sum := sha256.Sum256(data)
	input.Bytes, input.Input.Bytes, input.Input.SHA256 = data, int64(len(data)), api.Digest(hex.EncodeToString(sum[:]))
	return input
}

func TestUsageCommand(t *testing.T) {
	c, p, input, executable, home, raw := usageCommandCase(t)
	t.Setenv("LB_USAGE_INHERIT_CANARY", "synthetic-host-only-value")
	result, err := RunUsageCommand(context.Background(), p, input, executable, home, c.clock)
	if err != nil || result.ExitCode != 0 || !bytes.Equal(result.Raw, raw) || result.ObservedAt == "" {
		t.Fatalf("native usage command lost its exact argv private home environment or actual stdout (code=%s exit=%d raw_equal=%t observed=%t)", usageCommandCode(err), result.ExitCode, bytes.Equal(result.Raw, raw), result.ObservedAt != "")
	}
	if err := os.WriteFile(filepath.Join(home.Name(), "usage-fixture.exit"), []byte("23"), 0600); err != nil {
		t.Fatal("cannot change measured command exit control")
	}
	result, err = RunUsageCommand(context.Background(), p, input, executable, home, c.clock)
	if err != nil || result.ExitCode != 23 || !bytes.Equal(result.Raw, raw) {
		t.Fatal("native usage command discarded its actual nonzero exit or stdout")
	}
}

func usageCommandCode(err error) string {
	if err == nil {
		return "none"
	}
	var typed *api.Error
	if errors.As(err, &typed) {
		return string(typed.Code)
	}
	return "untyped"
}

func TestUsageCommandCancellation(t *testing.T) {
	c, p, input, executable, home, _ := usageCommandCase(t)
	if err := os.WriteFile(filepath.Join(home.Name(), "usage-fixture.block"), []byte("block"), 0600); err != nil {
		t.Fatal("cannot retain the actual blocking command control")
	}
	readyPath := filepath.Join(home.Name(), "usage-fixture.ready")
	if err := unix.Mkfifo(readyPath, 0600); err != nil {
		t.Fatal("cannot create the private command readiness pipe")
	}
	fd, err := unix.Open(readyPath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("cannot open the actual command readiness pipe")
	}
	ready := os.NewFile(uintptr(fd), "usage-command-ready")
	defer ready.Close()
	if err := ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal("cannot bound the command readiness observation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type completion struct {
		result UsageCommandResult
		err    error
	}
	done := make(chan completion, 1)
	go func() {
		result, err := RunUsageCommand(ctx, p, input, executable, home, c.clock)
		done <- completion{result, err}
	}()
	started := make([]byte, len("started"))
	_, readinessErr := io.ReadFull(ready, started)
	cancel()
	select {
	case actual := <-done:
		if readinessErr != nil || string(started) != "started" {
			t.Fatalf("usage cancellation did not reach the actual started process (code=%s)", usageCommandCode(actual.err))
		}
		stageCode(t, actual.err, api.CodeCancelled)
		if len(actual.result.Raw) != 0 {
			t.Fatal("cancelled started usage command returned successful evidence")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled started usage command was not collected within its bound")
	}
}

func TestUsageExecutableSnapshot(t *testing.T) {
	data := syntheticBytes(t, 83)
	path := filepath.Join(t.TempDir(), "synthetic-executable")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal("cannot create actual executable snapshot control")
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal("cannot hold actual executable snapshot control")
	}
	defer source.Close()
	pinned, err := snapshotUsageExecutable(source, int64(len(data)))
	if err != nil {
		t.Fatal("cannot seal actual executable snapshot control")
	}
	defer pinned.Close()
	if err := os.WriteFile(path, syntheticBytes(t, len(data)), 0700); err != nil {
		t.Fatal("cannot change actual source inode bytes")
	}
	actual := make([]byte, len(data))
	if _, err := pinned.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, data) {
		t.Fatal("sealed executable followed a later source inode write")
	}
	if _, err := pinned.WriteAt([]byte{'x'}, 0); err == nil {
		t.Fatal("usage executable snapshot remained writable after pinning")
	}
}

func TestUsageCommandGuards(t *testing.T) {
	for _, fault := range []string{"pin", "home", "writable-exe", "owner-write", "service-uid", "generation", "input", "cancelled", "overflow", "stderr-overflow"} {
		t.Run(fault, func(t *testing.T) {
			c, p, input, executable, home, _ := usageCommandCase(t)
			ctx := context.Background()
			code := api.CodeIntegrity
			switch fault {
			case "pin":
				var selected UsageInput
				if err := json.Unmarshal(input.Bytes, &selected); err != nil {
					t.Fatal("cannot decode executable pin control")
				}
				selected.Request.Executable.SHA256 = digestFixture("another actual executable")
				input = sealCommandInput(t, input, selected)
				p.Lease.Input, p.Claim.Record.Effect.Worker.Input = input.Input, input.Input
			case "home":
				if err := home.Chmod(0755); err != nil {
					t.Fatal("cannot change actual home permissions")
				}
			case "writable-exe":
				if err := executable.Chmod(0770); err != nil {
					t.Fatal("cannot change actual executable mode control")
				}
			case "owner-write":
				if err := executable.Chmod(0700); err != nil {
					t.Fatal("cannot change actual owner-write executable control")
				}
			case "service-uid":
				p.Endpoint.ServiceUID = p.Peer.HostUID
				code = api.CodeForbidden
			case "generation":
				p.Peer.ProcessGeneration = "retired-process-generation"
				code = api.CodeContainmentUnknown
			case "input":
				input.Bytes = append(input.Bytes, '\n')
				code = api.CodeInvalid
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				code = api.CodeCancelled
			case "overflow":
				if err := os.WriteFile(filepath.Join(home.Name(), "usage-fixture.tsv"), bytes.Repeat([]byte{'x'}, api.MaxFrameBytes+1), 0600); err != nil {
					t.Fatal("cannot retain actual output-bound control")
				}
				code = api.CodeUnavailable
			case "stderr-overflow":
				if err := os.WriteFile(filepath.Join(home.Name(), "usage-fixture.stderr"), bytes.Repeat([]byte{'x'}, 64*1024+1), 0600); err != nil {
					t.Fatal("cannot retain actual diagnostic output-bound control")
				}
				code = api.CodeUnavailable
			}
			result, err := RunUsageCommand(ctx, p, input, executable, home, c.clock)
			t.Logf("usage command guard observed code=%s exit=%d raw_empty=%t", usageCommandCode(err), result.ExitCode, len(result.Raw) == 0)
			stageCode(t, err, code)
			if len(result.Raw) != 0 {
				t.Fatal("refused usage command returned successful raw evidence")
			}
		})
	}
}
