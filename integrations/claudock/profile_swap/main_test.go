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

func swapProcess(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	argv := append([]string{"-test.run=^TestClaudockPATH$", "--"}, args...)
	cmd := exec.CommandContext(ctx, executable, argv...)
	cmd.Env = append(os.Environ(), "LB_SWAP_TEST_PROCESS=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("profile_swap did not finish before the test deadline")
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
	if os.Getenv("LB_SWAP_TEST_PROCESS") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Exit(run(os.Args[i+1:]))
			}
		}
		t.Fatal("missing subprocess arguments")
	}

	// Fails if the PATH executable is not used for both usage and run, if the
	// executable is lost after --cwd, or if argv/cwd/child status are changed.
	t.Run("pick_and_resume_use_PATH", func(t *testing.T) {
		root := t.TempDir()
		bin := filepath.Join(root, "path bin")
		if err := os.Mkdir(bin, 0700); err != nil {
			t.Fatal(err)
		}
		t.Chdir(root)
		t.Setenv("PATH", bin)
		record := filepath.Join(root, "argv")
		usage := filepath.Join(root, "usage.tsv")
		t.Setenv("LB_SWAP_TEST_ARGV", record)
		t.Setenv("LB_SWAP_TEST_USAGE", usage)
		stub := `#!/bin/sh
printf '%s\n' "$@" >> "$LB_SWAP_TEST_ARGV"
case "$1" in
usage) /bin/cat "$LB_SWAP_TEST_USAGE" ;;
run)
  pwd -P >> "$LB_SWAP_TEST_ARGV"
  printf 'resumed:%s\n' "$2"
  exit 29 ;;
*) exit 71 ;;
esac
`
		if err := os.WriteFile(filepath.Join(bin, "claudock"), []byte(stub), 0700); err != nil {
			t.Fatal(err)
		}
		from := fmt.Sprintf("source-%d", os.Getpid())
		picked := fmt.Sprintf("destination-%d", os.Getpid())
		tsv := "PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n" +
			from + "\tTeam Premium\tWeekly\t0.00\tunknown\n" +
			picked + "\tTeam Premium\tWeekly\t12.50\tunknown\n"
		if err := os.WriteFile(usage, []byte(tsv), 0600); err != nil {
			t.Fatal(err)
		}
		code, out, diagnostic := swapProcess(t, "pick", "--exclude", from, "--max-age", "30")
		if code != 0 || out != picked+"\n" || diagnostic != "" {
			t.Fatalf("PATH pick: exit=%d stdout=%q stderr=%q", code, out, diagnostic)
		}
		cwd, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		sid := "dabfd677-b31c-4775-93d7-70ca4d74d730"
		prompt := "Continue this same session."
		code, out, diagnostic = swapProcess(t, "resume", "--session", sid, "--from", from,
			"--cwd", cwd, "--max-age", "30", "--prompt", prompt, "--", "--model", "claude-sonnet-5-5")
		if code != 29 || out != "resumed:"+picked+"\n" || !strings.Contains(diagnostic, "resuming from "+from+" on "+picked+":") {
			t.Fatalf("PATH resume: exit=%d stdout=%q stderr=%q", code, out, diagnostic)
		}
		got, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Join([]string{"usage", "--max-age", "30", "usage", "--max-age", "30",
			"run", picked, "--", "-p", "--resume", sid, prompt, "--model", "claude-sonnet-5-5", cwd, ""}, "\n")
		if string(got) != want {
			t.Fatalf("claudock argv/cwd: got %q, want %q", got, want)
		}
	})

	for _, state := range []string{"missing", "not_executable", "working_directory_only"} {
		// Fails if either command falls back outside PATH, invokes a vendor, or
		// changes the exact installation diagnostic and exit status.
		t.Run(state, func(t *testing.T) {
			bin := t.TempDir()
			t.Setenv("PATH", bin)
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
			for _, args := range [][]string{{"pick"}, {"resume", "--continue", "--from", "source-profile"}} {
				code, out, diagnostic := swapProcess(t, args...)
				want := "profile_swap: claudock is not executable on PATH; install claudock-cli from https://github.com/laneboss-io/claudock-cli and add its claudock binary to PATH\n"
				if code != 2 || out != "" || diagnostic != want {
					t.Fatalf("%s with missing PATH executable: exit=%d stdout=%q stderr=%q; want exit 2, empty stdout and %q", args[0], code, out, diagnostic, want)
				}
			}
		})
	}
}
