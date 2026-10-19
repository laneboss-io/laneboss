//go:build linux && laneboss_root_canary

package claudock

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Only the companion is a canary. The released wrapper, planned argv, private
// home transaction and fixed namespace paths all execute without credentials.
func init() {
	if os.Args[0] != "/runtime/claude" {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) == 0 {
		os.Exit(121)
	}
	encoded := strings.Join(os.Args[1:], "\x00") + "\x00" + string(data)
	if _, err := os.Stdout.WriteString(string(contentDigest([]byte(encoded)))); err != nil {
		os.Exit(122)
	}
	os.Exit(0)
}

func TestPinnedExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("requires the disposable root Linux box")
	}
	wrapper := releasedWrapper(t)
	vendor, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	f := runnerReady(t, nil)
	deps := &f.service.deps
	for path, data := range map[string][]byte{deps.ExecutablePath: wrapper, deps.ClaudePath: vendor} {
		if err := os.WriteFile(path, data, 0500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
	}
	deps.Executable.SHA256, deps.Claude.SHA256 = contentDigest(wrapper), contentDigest(vendor)
	deps.RuntimePath = "/runtime/claudock"
	f.request.Executable = deps.Executable
	f.launch.dir = temporary(t)
	f.sourceLaunch(t, "start")
	deps.VerifyMode = func(_ context.Context, w, v api.Executable, mode string) error {
		if w != deps.Executable || v != deps.Claude || mode != f.request.Slot.Mode {
			return errors.New("canary compatibility identity differs")
		}
		return deps.verifyExecutables()
	}
	called := false
	deps.HomePath = nil
	deps.PlanHome = func(_ context.Context, input HomePlanRequest) error {
		called = true
		return PlanPrivateHome(f.home.path, f.home.records, input, func(findings []Finding) error {
			f.findings = findings
			return nil
		}, nil)
	}
	f.service, err = NewInstalled(*deps)
	if err != nil {
		t.Fatal("installed runner could not bind the declared CLI", err)
	}
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil || !called {
		t.Fatal("installed plan did not execute the home transaction", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"--unshare-all", "--die-with-parent", "--tmpfs", "/",
		"--dir", "/runtime", "--ro-bind", deps.ExecutablePath, plan.Argv[0],
		"--ro-bind", deps.ClaudePath, "/runtime/claude",
		"--dir", "/usr/bin", "--ro-bind", deps.ClaudePath, "/usr/bin/claude",
		"--bind", f.home.path, "/home/lane", "--dir", plan.CWD,
		"--proc", "/proc", "--dev", "/dev", "--chdir", plan.CWD,
		"--clearenv", "--setenv", "HOME", "/home/lane",
		"--setenv", "XDG_CONFIG_HOME", "/home/lane/.config",
		"--setenv", "PATH", "/usr/bin:/bin"}
	args = append(args, canaryLibraries(t)...)
	args = append(args, "--")
	args = append(args, plan.Argv...)
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = bytes.NewReader([]byte("kept brief\n"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	want := contentDigest([]byte(strings.Join(plan.Argv[4:], "\x00") + "\x00kept brief\n"))
	if err != nil || string(output) != string(want) {
		t.Fatalf("declared CLI was not executed by real Claudock: %v; %s", err, stderr.Bytes())
	}
	t.Log("real Claudock selected the declared CLI over a PATH decoy and consumed the planned argv and retained prompt")
}

// Enroll only the test executable's actual interpreter and imported libraries,
// just as the installed runtime projects individual ABI files.
func canaryLibraries(t *testing.T) []string {
	t.Helper()
	binary, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	paths := []string{}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			raw, err := io.ReadAll(program.Open())
			if err != nil {
				t.Fatal(err)
			}
			paths = append(paths, strings.TrimRight(string(raw), "\x00"))
		}
	}
	names, err := binary.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		found := ""
		for _, directory := range []string{"/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu",
			"/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"} {
			candidate := filepath.Join(directory, name)
			if _, err := os.Stat(candidate); err == nil {
				found = candidate
				break
			}
		}
		if found == "" {
			t.Fatal("canary library is unavailable", name)
		}
		paths = append(paths, found)
	}
	args := []string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		copy := filepath.Join(temporary(t), filepath.Base(path))
		if err := os.WriteFile(copy, data, 0555); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--ro-bind", copy, path)
	}
	return args
}

func releasedWrapper(t *testing.T) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base := "https://github.com/laneboss-io/" + "claudock-cli/releases/download/v0.1.0/"
	asset := "claudock_0.1.0_linux_" + runtime.GOARCH + ".tar.gz"
	fetch := func(name string) []byte {
		cmd := exec.CommandContext(ctx, "/usr/bin/curl", "--fail", "--silent", "--show-error", "--location", base+name)
		cmd.Env = []string{"HOME=" + temporary(t), "PATH=/usr/bin:/bin"}
		data, err := cmd.Output()
		if err != nil {
			t.Fatal("public Claudock release fetch failed", name, err)
		}
		return data
	}
	archive, sums := fetch(asset), fetch("SHA256SUMS")
	matched := 0
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == asset {
			decoded, err := hex.DecodeString(fields[0])
			if err != nil || len(decoded) != 32 || string(contentDigest(archive)) != fields[0] {
				t.Fatal("public Claudock release checksum differs")
			}
			matched++
		}
	}
	if matched != 1 {
		t.Fatal("public Claudock release checksum missing or repeated")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err != nil {
			t.Fatal("public Claudock executable absent", err)
		}
		if filepath.Base(header.Name) == "claudock" && header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(io.LimitReader(reader, 64<<20))
			if err != nil || int64(len(data)) != header.Size {
				t.Fatal("public Claudock executable truncated", err)
			}
			return data
		}
	}
}
