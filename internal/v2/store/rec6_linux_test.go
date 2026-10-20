//go:build linux

package store

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func restoreGitSource(t *testing.T, body []byte) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	run := func(input []byte, args ...string) []byte {
		cmd := exec.Command("/usr/bin/git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@invalid"}
		cmd.Stdin = bytes.NewReader(input)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("restore Git fixture:", err)
		}
		return out
	}
	run(nil, "init", "--template=")
	if err := os.WriteFile(filepath.Join(dir, "current.txt"), body, 0600); err != nil {
		t.Fatal(err)
	}
	run(nil, "add", ".")
	run(nil, "commit", "-m", "fixture")
	head := strings.TrimSpace(string(run(nil, "rev-parse", "HEAD")))
	return head, run([]byte(head+"\n"), "pack-objects", "--stdout", "--revs", "--threads=1", "--window=0")
}

type recNative struct {
	CleanupNative
	root, stage, target string
}

func (n *recNative) RestoreRoots(context.Context, api.Scope) ([]string, error) {
	return []string{n.root}, nil
}
func (n *recNative) StageRestore(ctx context.Context, scope api.Scope, q api.RestoreRequest, tree api.ObjectManifest, read archivejob.ReadObject, ceiling uint64) (api.ID, api.RestoreReceipt, error) {
	var report api.RestoreReceipt
	parent, err := archivejob.RestoreDestination(q.Path, []string{n.root})
	if err != nil {
		return "", report, err
	}
	parent.Close()
	n.stage, err = os.MkdirTemp(n.root, "stage-")
	if err != nil {
		return "", report, err
	}
	n.target = q.Path
	report.Head, err = archivejob.Restore(ctx, filepath.Join(n.stage, "result"), tree, read, ceiling, archivejob.RestoreOptions{Roots: []string{n.stage}, AllowNestedGit: q.AllowNestedGit, Report: &report})
	return api.ID(filepath.Base(n.stage)), report, err
}
func (n *recNative) PublishRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	return os.Rename(filepath.Join(n.stage, "result"), n.target)
}
func (n *recNative) AbortRestore(ctx context.Context, scope api.Scope, id api.ID) error {
	return os.RemoveAll(n.stage)
}

func restoreHuman(t *testing.T) (*archFixture, api.Scope, api.VerifiedHumanProof, context.Context) {
	t.Helper()
	s, human, session := sessionFixture(t)
	human.PolicyGeneration = 1
	f := buildArch(t, s, s.deps, false, human)
	ref := f.append(t, f.tar)
	f.result(t, ref, f.tar)
	zero, exit := uint64(0), 0
	if _, err := s.CompleteArchive(context.Background(), f.executor, f.record.Claim, api.ProcessObservation{Handle: f.record.Process, State: "exited", PromptStatus: "completed", ExitCode: &exit, Survivors: &zero, ObservedAt: archStamp()}); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	s.deps.CleanupNative = &recNative{root: root}
	q := api.RestoreRequest{Target: f.record.Job.Intent.Request.Target, ExpectedGeneration: f.record.Lane.Generation, Path: filepath.Join(root, "restored"), AllowNestedGit: true}
	human.Request = testRequest(t, "lane.restore", q)
	target, err := s.authorizationTarget(context.Background(), s.db, human, human.Request)
	if err != nil {
		t.Fatal(err)
	}
	proof := api.VerifiedHumanProof{Config: human.Config, PrincipalID: human.Actor.ID, CredentialID: session.CredentialID, NonceID: testID(t), EndpointClass: api.EndpointHuman, EndpointGeneration: human.EndpointGeneration, Target: target,
		Ref: api.ProofRef{ID: testID(t), RequestSHA256: human.Request.RequestSHA256, ExpiresAt: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(timeFormat))}}
	fixtureProjection(t, s, "proof", proof.Ref.ID, 1, proof)
	human.Request.Proof = &proof.Ref
	human.Frame = &archFrame{raw: archJSON(t, human.Request)}
	ctx, retire := s.TrackMutation(context.Background())
	t.Cleanup(retire)
	if _, won, err := s.ReserveMutation(ctx, api.RequestReservation{Scope: human, RawRequest: human.Frame.Bytes(), Deadline: proof.Ref.ExpiresAt}); err != nil || !won {
		t.Fatal("restore reservation:", err)
	}
	return f, human, proof, ctx
}

func TestRestoreHumanProof(t *testing.T) {
	for _, mode := range []string{"valid", "presence", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f, human, proof, ctx := restoreHuman(t)
			if mode == "presence" {
				proof.SimulatedPresence = true
				fixtureProjection(t, f.s, "proof", proof.Ref.ID, 1, proof)
			}
			if mode == "missing" {
				human.Request.Proof = nil
				human.Frame = &archFrame{raw: archJSON(t, human.Request)}
			}
			var q api.RestoreRequest
			if err := api.DecodeObject(human.Request.Params, &q); err != nil {
				t.Fatal(err)
			}
			got, err := f.s.RestoreArchive(ctx, human, q)
			if mode != "valid" {
				if err == nil {
					t.Fatal("human restore omitted its proof guard")
				}
				if _, statErr := os.Lstat(q.Path); !os.IsNotExist(statErr) {
					t.Fatal("refused proof published a target")
				}
				return
			}
			if err != nil || got.Head != f.tree.Git.Head {
				t.Fatal("real human-scope restore:", err)
			}
			var saved api.VerifiedHumanProof
			if err := storedProjection(ctx, f.s.db, "proof", proof.Ref.ID, &saved); err != nil || saved.ConsumedBy == "" {
				t.Fatal("human proof was not consumed:", err)
			}
		})
	}
}

func TestRestoreDoesNotLock(t *testing.T) {
	f, human, _, ctx := restoreHuman(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ctx = context.WithValue(ctx, objectVerificationKey{}, func(api.ID, int64) { once.Do(func() { close(entered); <-release }) })
	var q api.RestoreRequest
	if err := api.DecodeObject(human.Request.Params, &q); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := f.s.RestoreArchive(ctx, human, q); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("restore did not reach its archive read:", err)
	case <-time.After(5 * time.Second):
		t.Fatal("restore never reached archive bytes")
	}
	mutation := make(chan error, 1)
	input := testTransaction(t)
	go func() { _, err := f.s.Transact(context.Background(), input); mutation <- err }()
	select {
	case err := <-mutation:
		if err != nil {
			t.Error("real concurrent mutation:", err)
		}
	case <-time.After(time.Second):
		t.Error("stalled restore blocked the lifecycle writer")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal("restore did not finish after its read resumed:", err)
	}
}
