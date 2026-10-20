//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// The RPC boundary supplies previously authorized frozen input. CLI parsing,
// request dispatch, Git reconstruction and mode/content restoration are real.
// This is a component command test, not an installed authentication test.
func TestDirtyRestoreCommand(t *testing.T) {
	ctx := context.Background()
	parent := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(parent, "authorized")
	if err := os.Mkdir(authorized, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(input []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("/usr/bin/git", append([]string{"-C", source}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@invalid"}
		cmd.Stdin = bytes.NewReader(input)
		data, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Git component setup: %v\n%s", err, data)
		}
		return data
	}
	git(nil, "init", "--template=")
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("committed\n"), 0444); err != nil {
		t.Fatal(err)
	}
	git(nil, "add", "README.md")
	git(nil, "commit", "-m", "baseline")
	head := strings.TrimSpace(string(git(nil, "rev-parse", "HEAD")))
	pack := git([]byte(head+"\n"), "pack-objects", "--stdout", "--revs", "--threads=1", "--window=0")
	files := map[string][]byte{"README.md": []byte("committed\nunsaved tracked\n"), "dirty.txt": []byte("unsaved\x00untracked\n")}
	objects := map[api.ID][]byte{}
	put := func(id string, raw []byte) *api.BlobRef {
		id = strings.ReplaceAll(id, ".", "-")
		objects[api.ID(id)] = append([]byte{}, raw...)
		return &api.BlobRef{ID: api.ID(id), Class: "artifact", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Git: &api.ArchiveGit{Head: head, Branch: "lane/recorded"},
		Entries: []api.ObjectEntry{{Path: "git", Kind: "directory", Mode: 0700},
			{Path: "git/pack", Kind: "file", Mode: 0400, Content: put("git-pack", pack)},
			{Path: "workspace", Kind: "directory", Mode: 0700}}}
	for _, name := range []string{"README.md", "dirty.txt"} {
		mode := os.FileMode(0600)
		if name == "README.md" {
			mode = 0444
			if err := os.Remove(filepath.Join(source, name)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(source, name), files[name], mode); err != nil {
			t.Fatal(err)
		}
		tree.Entries = append(tree.Entries, api.ObjectEntry{Path: "workspace/" + name, Kind: "file", Mode: uint32(mode), Content: put(name, files[name])})
	}
	read := func(_ context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
		raw, ok := objects[q.ObjectID]
		if !ok || q.Offset < 0 || q.Offset > int64(len(raw)) {
			return api.BlobChunk{}, errors.New("component read escaped inventory")
		}
		data := raw[q.Offset:min(int64(len(raw)), q.Offset+int64(q.Limit))]
		return api.BlobChunk{ObjectID: q.ObjectID, Offset: q.Offset, Data: data, SHA256: manifest.Hash(data)}, nil
	}
	keep := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	measure := func(name string) string {
		t.Helper()
		var tar bytes.Buffer
		if err := archivejob.Write(ctx, &tar, tree, read, 8<<20); err != nil {
			t.Fatal(err)
		}
		return keep(name, map[string]any{"manifest": tree, "objects": objects, "archive": tar.Bytes()})
	}
	before := measure("before.json")
	target := filepath.Join(authorized, "restored")
	transport := &integrateFixtureClient{handle: func(frame api.Request) (any, error) {
		var request api.RestoreRequest
		if frame.Method != "lane.restore" || api.DecodeObject(frame.Params, &request) != nil {
			return nil, errors.New("CLI changed restore request")
		}
		got, err := archivejob.Restore(ctx, request.Path, tree, read, 8<<20,
			archivejob.RestoreOptions{Roots: []string{authorized}})
		return api.RestoreReceipt{Target: request.Target, Path: request.Path, Head: got,
			ArchiveReceiptID: request.ArchiveReceiptID}, err
	}}
	command, ok := integrateCommands["lane restore"]
	if !ok {
		t.Fatal("real restore command is absent")
	}
	var output bytes.Buffer
	call := Invocation{Config: "dirty-command", Method: command.method, Stdout: &output}
	call.Args = []string{"--life", "dirty-life", "--run", "1", "--generation", "2", "--target", target, "--archive-receipt", "dirty-archive"}
	call.IdempotencyKey = api.ID(strings.Repeat("r", 32))
	call.integrateSocket = &integrateSocket{options: client.Options{Config: "dirty-command"}, connection: transport}
	outside := filepath.Join(parent, "outside")
	call.Args[7] = outside
	var typed *api.Error
	if err := command.run(ctx, call); !errors.As(err, &typed) || typed.Message != "restore_target_scope" || typed.Code != api.CodeForbidden {
		t.Fatalf("outside target did not fail the real command: %v", err)
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatal("outside restore created a target")
	}
	t.Log("RED outside: real restore refuses restore_target_scope and creates no target")
	existing := filepath.Join(authorized, "existing")
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(existing, "kept.txt")
	if err := os.WriteFile(sentinel, []byte("existing work\n"), 0600); err != nil {
		t.Fatal(err)
	}
	call.Args[7] = existing
	if err := command.run(ctx, call); !errors.As(err, &typed) || typed.Message != "restore_target_exists" || typed.Code != api.CodeConflict {
		t.Fatalf("existing target did not fail the real command: %v", err)
	}
	kept, err := os.ReadFile(sentinel)
	if err != nil || string(kept) != "existing work\n" {
		t.Fatal("existing target refusal changed its kept bytes", err)
	}
	t.Log("RED existing: real restore command refuses the existing target and preserves its bytes")
	call.Args[7] = target
	call.IdempotencyKey = api.ID(strings.Repeat("s", 32))
	if err := command.run(ctx, call); err != nil {
		t.Fatal("real restore command failed", err)
	}
	var receipt api.RestoreReceipt
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil || receipt.Path != target || receipt.Head != head {
		t.Fatal("restore command returned a different worktree", err)
	}
	after := measure("after.json")
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	check := exec.Command("python3", "-I", "-B", filepath.Join(root, "e2e/v2/cases/dirty/test_restore.py"),
		"--check", source, target, before, after)
	if data, err := check.CombinedOutput(); err != nil {
		t.Fatalf("third restore check failed: %v\n%s", err, data)
	}
	t.Log("GREEN real lane restore: exact pre-stop bytes/modes/head; archive unchanged; existing target refuses")
}
