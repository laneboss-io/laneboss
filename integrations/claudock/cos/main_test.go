package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cosProcess(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	argv := append([]string{"-test.run=^TestClaudockPATH$", "--"}, args...)
	cmd := exec.CommandContext(ctx, executable, argv...)
	cmd.Env = append(os.Environ(), "LB_COS_TEST_PROCESS=1")
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("cos did not finish before the test deadline")
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return code, stdout.String(), stderr.String()
}

func TestClaudockPATH(t *testing.T) {
	if os.Getenv("LB_COS_TEST_PROCESS") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Exit(run(os.Args[i+1:]))
			}
		}
		t.Fatal("missing subprocess arguments")
	}

	// Fails if cos ignores PATH, uses the legacy override, changes the vendor
	// argv, or does not deliver the input and render the resulting answer.
	t.Run("uses_PATH_and_ignores_legacy_override", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "path bin")
		if err := os.Mkdir(bin, 0700); err != nil {
			t.Fatal(err)
		}
		record := filepath.Join(t.TempDir(), "argv")
		t.Setenv("PATH", bin)
		t.Setenv("LB_COS_TEST_ARGV", record)
		t.Setenv("COS_CLAUDOCK", filepath.Join(bin, "unavailable-legacy-wrapper"))
		stub := `#!/bin/sh
[ "$1" = run ] || exit 71
printf '%s\n' "$@" > "$LB_COS_TEST_ARGV"
IFS= read -r message || exit 72
printf '{"type":"system","subtype":"init","permissionMode":"default"}\n'
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"echo-%s"}]}}\n' "$message"
printf '{"type":"result","total_cost_usd":0.25}\n'
`
		if err := os.WriteFile(filepath.Join(bin, "claudock"), []byte(stub), 0700); err != nil {
			t.Fatal(err)
		}
		account := fmt.Sprintf("path-profile-%d", os.Getpid())
		message := fmt.Sprintf("message-%d", os.Getpid())
		sid := "d9323b42-6a33-45af-884d-4328a813f217"
		model := "claude-sonnet-5-5"
		code, out, diagnostic := cosProcess(t, message+"\n/exit\n", account, model, "--resume", sid, "--mode", "default")
		if code != 0 || diagnostic != "" || !strings.Contains(out, "echo-"+message) ||
			!strings.Contains(out, "[turn 1 |") || !strings.Contains(out, "session $0.2500") {
			t.Fatalf("cos did not complete the PATH request: exit=%d stdout=%q stderr=%q", code, out, diagnostic)
		}
		got, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Join([]string{"run", account, "--", "-p", "--resume", sid, "--model", model,
			"--output-format", "stream-json", "--verbose", "--include-partial-messages", "--permission-mode", "default", ""}, "\n")
		if string(got) != want {
			t.Fatalf("claudock argv: got %q, want %q", got, want)
		}
	})

	for _, state := range []string{"missing", "not_executable", "working_directory_only"} {
		// Fails if a missing PATH command falls back elsewhere, starts a prompt,
		// or changes either the installation diagnostic or its exit status.
		t.Run(state, func(t *testing.T) {
			bin := t.TempDir()
			t.Setenv("PATH", bin)
			t.Setenv("COS_CLAUDOCK", "/bin/sh")
			if state == "not_executable" {
				if err := os.WriteFile(filepath.Join(bin, "claudock"), []byte("#!/bin/sh\nexit 73\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "working_directory_only" {
				cwd := t.TempDir()
				t.Chdir(cwd)
				if err := os.WriteFile(filepath.Join(cwd, "claudock"), []byte("#!/bin/sh\nexit 73\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			code, out, diagnostic := cosProcess(t, "", "path-profile", "claude-sonnet-5-5", "--mode", "default")
			want := "cos: claudock is not executable on PATH; install claudock-cli from https://github.com/laneboss-io/claudock-cli and add its claudock binary to PATH\n"
			if code != 2 || out != "" || diagnostic != want {
				t.Fatalf("missing PATH executable: exit=%d stdout=%q stderr=%q; want exit 2, empty stdout and %q", code, out, diagnostic, want)
			}
		})
	}
}
