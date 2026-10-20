//go:build laneboss_e2e_authenticator

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type dirtyInput struct {
	Schema        string `json:"schema"`
	Nonce         string `json:"nonce"`
	Lane          string `json:"lane"`
	TrackedPath   string `json:"tracked_path"`
	UntrackedPath string `json:"untracked_path"`
}

type dirtyResult struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func (f *fixture) dirtyTask(ctx context.Context, prompt []byte) (resultErr error) {
	// The dirty item assigns work to its Claudock lane. Ordinary Codex runs
	// share the published task but must not launch a second CLI or touch the
	// dirty diagnostic path before their lifecycle session starts.
	if f.Driver != "claudock-cli" {
		return nil
	}
	var launch struct {
		Schema string `json:"schema"`
		Task   string `json:"task"`
	}
	var task []byte
	if json.Unmarshal(prompt, &launch) == nil && launch.Schema == "laneboss.launch-prompt.v2" {
		// The installed runner receives the lifecycle JSON envelope. Its
		// briefing is an escaped string; the assigned task has its own field.
		task = []byte(launch.Task)
	} else {
		marker := []byte("## Assigned task\n\n")
		start := bytes.LastIndex(prompt, marker)
		if start < 0 {
			return nil
		}
		task = prompt[start+len(marker):]
	}
	var input dirtyInput
	parseErr := json.Unmarshal(task, &input)
	if parseErr == nil && input.Schema != "laneboss.dirty-task.v1" ||
		parseErr != nil && !bytes.Contains(task, []byte("laneboss.dirty-task")) {
		return nil
	}
	result := dirtyResult{Stage: "prompt", Status: "skipped"}
	defer func() {
		if result.Stage == "another_lane" {
			return
		}
		if resultErr != nil {
			result.Status, result.Error = "failed", resultErr.Error()
		}
		raw, err := encode(result)
		if err == nil {
			err = write("dirty-result.pending", raw)
		}
		if err == nil {
			err = os.Rename(filepath.Join(scratchDirectory, "dirty-result.pending"),
				filepath.Join(scratchDirectory, "dirty-result.json"))
		}
		resultErr = errors.Join(resultErr, err)
	}()
	if err := parseErr; err != nil {
		return fmt.Errorf("dirty.prompt: assigned task is not valid JSON: %w", err)
	}
	result.Stage = "status"
	lane, err := f.call(ctx, "dirty-status", []string{"lane", "status"},
		map[string]any{"life_id": f.Life, "run": f.Run}, false, 0)
	if err != nil {
		return fmt.Errorf("dirty.status: %w", err)
	}
	if lane["name"] == nil || lane["name"] == "" {
		return errors.New("dirty.status: current lane has no name")
	}
	if lane["name"] != input.Lane {
		result.Stage = "another_lane"
		return nil // The separately named clean control keeps its imported tree.
	}
	result.Stage = "workspace"
	cwd, err := os.Getwd()
	if err != nil || cwd != "/work/main" || os.Geteuid() == 0 || input.Nonce != f.Challenge {
		return errors.New("dirty.workspace: task requires its actual nonroot lane workspace and nonce")
	}
	root, err := os.OpenRoot(cwd)
	if err != nil {
		return fmt.Errorf("dirty.root: %w", err)
	}
	defer root.Close()
	result.Stage = "write"
	if err := dirtyFiles(root, input); err != nil {
		return err
	}
	result.Status = "written"
	return nil
}

func dirtyPath(name string) bool {
	if !filepath.IsLocal(name) || filepath.Clean(name) != name || name == "." {
		return false
	}
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		if part == ".git" || part == ".laneboss" {
			return false
		}
	}
	return true
}

func dirtyFiles(root *os.Root, input dirtyInput) error {
	if !dirtyPath(input.TrackedPath) || !dirtyPath(input.UntrackedPath) ||
		input.TrackedPath == input.UntrackedPath || !fixtureNonce(input.Nonce) {
		return errors.New("dirty task selects outside lane or invalid filenames")
	}
	info, err := root.Lstat(input.TrackedPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("dirty tracked selection is not a regular lane file")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Nlink != 1 {
		return errors.New("dirty tracked selection is linked outside lane")
	}
	// Use the lane's directory write view, like an editor saving a replacement.
	// The imported inode itself may be read-only; changing its mode is neither
	// necessary nor permission to broaden the mounted worktree view.
	tracked, err := root.Open(input.TrackedPath)
	if err != nil {
		return fmt.Errorf("dirty.read_tracked: %w", err)
	}
	actual, statErr := tracked.Stat()
	if statErr != nil || !os.SameFile(info, actual) || actual.Size() > 16<<20 {
		return errors.Join(errors.New("dirty tracked selection changed or exceeds its byte bound"), tracked.Close())
	}
	data, err := io.ReadAll(io.LimitReader(tracked, 16<<20+1))
	err = errors.Join(err, tracked.Close())
	if err != nil || int64(len(data)) != actual.Size() {
		return errors.Join(errors.New("dirty tracked bytes changed while reading"), err)
	}
	data = append(data, []byte("\nG11 dirty tracked "+input.Nonce+"\n")...)
	temporary := input.TrackedPath + ".g11-edit-" + input.Nonce[:12]
	if err := replaceDirty(root, temporary, input.TrackedPath, data, info.Mode().Perm()); err != nil {
		return err
	}
	untracked, err := root.OpenFile(input.UntrackedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return fmt.Errorf("dirty.create_untracked: %w", err)
	}
	_, err = io.WriteString(untracked, "G11 dirty untracked "+input.Nonce+"\n")
	if err := errors.Join(err, untracked.Sync(), untracked.Close()); err != nil {
		return fmt.Errorf("dirty.write_untracked: %w", err)
	}
	return nil
}

func replaceDirty(root *os.Root, temporary, name string, data []byte, mode os.FileMode) (resultErr error) {
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("dirty.create_tracked: %w", err)
	}
	renamed := false
	defer func() {
		if !renamed {
			resultErr = errors.Join(resultErr, root.Remove(temporary))
		}
	}()
	n, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Chmod(mode), file.Sync(), file.Close())
	if err != nil || n != len(data) {
		return fmt.Errorf("dirty.write_tracked: %w", errors.Join(errors.New("replacement bytes were not retained"), err))
	}
	if err := root.Rename(temporary, name); err != nil {
		return fmt.Errorf("dirty.replace_tracked: %w", err)
	}
	renamed = true
	return nil
}

func fixtureNonce(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
