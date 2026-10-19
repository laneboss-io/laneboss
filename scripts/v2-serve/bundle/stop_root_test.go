//go:build linux && laneboss_root_canary

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Run the public installed suite, including Stop's real Observe preflight,
// native credential withdrawal and a fresh child using the same profile.
func TestStopServe(t *testing.T) {
	stopServe(t, false)
}

func TestStopServeRed(t *testing.T) {
	stopServe(t, true)
}

func stopServe(t *testing.T, red bool) {
	if os.Geteuid() != 0 {
		t.Fatal("installed stop item requires disposable Linux root")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/opt", "lb-stopcont-")
	if err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(directory, "serve")
	t.Log("installed stop evidence:", evidence)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	entry := "run.py"
	if red {
		entry = "stopcontrol.py"
	}
	command := exec.CommandContext(ctx, "python3", "-I", "-B",
		filepath.Join(root, "scripts/v2-serve", entry), "--source", root,
		"--evidence", evidence, "--item-case", "grants")
	if _, err := os.Lstat(filepath.Join(root, ".git")); os.IsNotExist(err) {
		command.Args = append(command.Args, "--source-snapshot")
	} else if err != nil {
		t.Fatal(err)
	}
	output, err := command.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		stopFailure(t, evidence)
	}
	if red {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("late suite stop quarantined the seat or lost its acknowledged refresh")) {
			t.Fatal("installed control missed its deciding late-stop assertion", err)
		}
		return
	}
	if err != nil {
		t.Fatal("installed late-stop item failed; retain report and native journals", err)
	}
}

func stopFailure(t *testing.T, evidence string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(evidence, "report.json"))
	if err != nil {
		t.Log("failure report unreadable:", err)
		return
	}
	var report struct {
		Config  string `json:"config"`
		Failure struct {
			Command struct {
				Stderr string `json:"stderr"`
			} `json:"command"`
		} `json:"failure"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Log("failure report malformed:", err)
		return
	}
	name := report.Failure.Command.Stderr
	if name == "" || filepath.Base(name) != name {
		t.Log("failure has no direct command stderr")
		return
	}
	raw, err = os.ReadFile(filepath.Join(evidence, report.Config, name))
	if err != nil {
		t.Log("failure stderr unreadable:", err)
		return
	}
	t.Log("failure command stderr:", string(raw))
}
