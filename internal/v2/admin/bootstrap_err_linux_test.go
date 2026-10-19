//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "admin-stderr-fixture" {
		if _, err := io.Copy(os.Stderr, os.Stdin); err != nil {
			os.Exit(42)
		}
		os.Exit(1)
	}
}

func TestBootstrapStderr(t *testing.T) {
	private, err := randomID("private-stderr-")
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct{ name, data, want string }{
		{"namespace", "bwrap: Creating new namespace failed: Permission denied\n", "namespace_denied"},
		{"option", "bwrap: Unknown option --" + string(private) + "\n", "option_unsupported"},
		{"descriptor", "bwrap: Can't open /" + string(private) + "\n", "descriptor_or_path_unavailable"},
		{"mount", "bwrap: Can't mount /" + string(private) + "\n", "mount_failed"},
		{"exec", "bwrap: execvp /" + string(private) + "\n", "exec_failed"},
		{"identity", "bwrap: setting up uid map: Operation not permitted\n", "identity_map_failed"},
		{"other", string(private), "other"},
		{"bound", strings.Repeat(string(private), 1024), "other"},
		{"empty", "", "none"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			var forwarded bytes.Buffer
			observer := &bootstrapStderr{destination: &forwarded}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "admin-stderr-fixture")
			cmd.Env, cmd.Stdin, cmd.Stderr = []string{}, strings.NewReader(sample.data), observer
			err := cmd.Run()
			var exited *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exited) || cmd.ProcessState.ExitCode() != 1 {
				t.Fatal("stderr fixture did not retain its real failure exit")
			}
			if forwarded.String() != sample.data || len(observer.prefix) != min(len(sample.data), 8192) {
				t.Fatal("acceptance: bootstrap stderr forwarding lost bytes or exceeded its bound")
			}
			if got := observer.fact(); got != sample.want || strings.Contains(got, string(private)) {
				t.Fatal("acceptance: real bootstrap stderr lost its closed category or disclosed private bytes")
			}
			before := append([]byte(nil), observer.prefix...)
			observer.freeze()
			later := []byte("\nbwrap: Creating new namespace failed: Permission denied\n")
			if n, err := observer.Write(later); err != nil || n != len(later) || !bytes.Equal(before, observer.prefix) || forwarded.String() != sample.data+string(later) {
				t.Fatal("acceptance: stderr after readiness changed the diagnostic or lost forwarding")
			}
		})
	}
}

func TestBootstrapStderrWriteError(t *testing.T) {
	file, err := os.CreateTemp(privateTestDir(t), "stderr-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	observer := &bootstrapStderr{destination: file}
	if n, err := observer.Write([]byte("bounded diagnostic")); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatal("acceptance: bootstrap stderr swallowed its real destination error")
	}
}
