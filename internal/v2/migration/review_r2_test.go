package migration

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func reviewError(t *testing.T, err error, code api.ErrorCode, field, diagnostic string) {
	t.Helper()
	typed, ok := err.(*api.Error)
	if !ok || typed.Code != code || !strings.Contains(typed.Message, field) {
		t.Fatalf("%s: expected %s for %s, got %v", diagnostic, code, field, err)
	}
}

func reviewCall(t *testing.T, diagnostic string, call func() error) (err error) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("%s: unexpected panic: %v", diagnostic, value)
		}
	}()
	return call()
}

func reviewRelaunch(t *testing.T) (*Service, *memStore, api.Scope, RelaunchOptions) {
	t.Helper()
	service, state, _, scope, plan, _ := migrationApplyFixture(t)
	options := RelaunchOptions{PlanID: plan.ID, Lane: "beta", Level: 3, Role: "executor",
		Driver: api.DriverClaudock, ProfileGrantID: "profile-grant",
		Task:   api.BlobRef{ID: "task-object", SHA256: DigestBytes([]byte("task")), Bytes: 4, Class: "task"},
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 4, DiskBytes: 4096, Currency: "USD"}}
	return service, state, scope, options
}

func TestReviewLegacy(t *testing.T) {
	for _, field := range []string{"session_id", "lane", "branch", "base", "model", "effort", "runner"} {
		t.Run(field, func(t *testing.T) {
			service, _, scope, options := reviewRelaunch(t)
			if _, err := service.PrepareRelaunch(context.Background(), scope, options); err != nil {
				t.Fatalf("accepted legacy input was refused: %v", err)
			}
			target := &service.plans[options.PlanID].bundle.Unfinished[0]
			switch field {
			case "session_id":
				target.SessionID = "--resume"
			case "lane":
				target.Lane, options.Lane = "../escape", "../escape"
			case "branch":
				target.Branch = "--output=/outside"
			case "base":
				target.Base = "HEAD~1;bad"
			case "model":
				target.Model = "--config"
			case "effort":
				target.Effort = " high"
			case "runner":
				target.Driver = "unknown-driver"
			}
			_, err := service.PrepareRelaunch(context.Background(), scope, options)
			reviewError(t, err, api.CodeInvalid, "legacy."+field, "legacy argument escaped its field gate")
		})
	}
	t.Run("missing-session", func(t *testing.T) {
		service, _, scope, options := reviewRelaunch(t)
		service.plans[options.PlanID].bundle.Unfinished[0].SessionID = ""
		_, err := service.PrepareRelaunch(context.Background(), scope, options)
		reviewError(t, err, api.CodeInvalid, "legacy.session_id", "missing vendor session was invented")
	})
}

func TestReviewCredentials(t *testing.T) {
	for _, path := range []string{".netrc", ".git-credentials", ".npmrc", ".pypirc", ".aws/credentials", ".docker/config.json", ".config/gh/hosts.yml", "id_ecdsa", "client.p12", "client.pfx", "client.jks", "notes.txt"} {
		t.Run(path, func(t *testing.T) {
			files := map[string][]byte{"state/lanes/demo/session/history.jsonl": []byte("ordinary history")}
			bundle := &VerifiedBundle{Quiescence: QuiescenceReceipt{UnfinishedLanes: []string{"demo"}},
				Projections: map[string]map[string]any{}, Events: []LegacyEventRecord{{Kind: "lane.started", Lane: "demo",
					Payload: map[string]any{"runner": "claudock", "base": strings.Repeat("deadbeef", 5), "model": "fixture-model", "session_id": "12345678-1234-4234-8234-123456789abc"}}}}
			if err := collectUnfinishedSessions(files, bundle); err != nil {
				t.Fatal(err)
			}
			data := []byte("private material")
			if path == "notes.txt" {
				data = []byte("api_key = \"" + "synthetic9" + strings.Repeat("q", 20) + "\"")
			}
			files["state/lanes/demo/session/"+path] = data
			bundle.Unfinished = nil
			err := collectUnfinishedSessions(files, bundle)
			reviewError(t, err, api.CodeIntegrity, "forbidden credential", "credential material entered legacy history")
		})
	}
	t.Run("worktree", func(t *testing.T) {
		bundle := &VerifiedBundle{Quiescence: QuiescenceReceipt{UnfinishedLanes: []string{"demo"}},
			Projections: map[string]map[string]any{}, Events: []LegacyEventRecord{{Kind: "lane.started", Lane: "demo",
				Payload: map[string]any{"runner": "claudock", "base": strings.Repeat("deadbeef", 5), "model": "fixture-model", "session_id": "12345678-1234-4234-8234-123456789abc"}}}}
		files := map[string][]byte{"state/lanes/demo/worktree/readme.txt": []byte("plain source")}
		if err := collectUnfinishedSessions(files, bundle); err != nil {
			t.Fatal(err)
		}
		files["state/lanes/demo/worktree/readme.txt"] = []byte("Authorization: Bearer " + strings.Repeat("a", 24))
		reviewError(t, collectUnfinishedSessions(files, bundle), api.CodeIntegrity, "legacy.worktree", "worktree credentials were silently accepted")
	})
}

func TestReviewHistoryOrder(t *testing.T) {
	bundle := &VerifiedBundle{Quiescence: QuiescenceReceipt{UnfinishedLanes: []string{"demo"}},
		Projections: map[string]map[string]any{}, Events: []LegacyEventRecord{{Kind: "lane.started", Lane: "demo",
			Payload: map[string]any{"runner": "claudock", "base": strings.Repeat("deadbeef", 5), "model": "fixture-model", "session_id": "12345678-1234-4234-8234-123456789abc"}}}}
	files := map[string][]byte{}
	for i := 25; i >= 0; i-- {
		files[fmt.Sprintf("state/lanes/demo/session/%02d.jsonl", i)] = []byte(fmt.Sprintf("%02d\n", i))
	}
	var expected bytes.Buffer
	for i := 0; i <= 25; i++ {
		fmt.Fprintf(&expected, "%02d\n", i)
	}
	for i := 0; i < 20; i++ {
		bundle.Unfinished = nil
		if err := collectUnfinishedSessions(files, bundle); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bundle.Unfinished[0].SessionHistory, expected.Bytes()) {
			t.Fatal("legacy history order is not deterministic")
		}
	}
}

func TestReviewLegacyTypes(t *testing.T) {
	for _, field := range []string{"runner", "model", "effort", "session_id", "branch", "base"} {
		t.Run(field, func(t *testing.T) {
			payload := map[string]any{"runner": "claudock", "model": "fixture-model", "effort": "high",
				"session_id": "12345678-1234-4234-8234-123456789abc", "branch": "demo", "base": strings.Repeat("a", 40)}
			bundle := &VerifiedBundle{Quiescence: QuiescenceReceipt{UnfinishedLanes: []string{"demo"}},
				Projections: map[string]map[string]any{}, Events: []LegacyEventRecord{{Kind: "lane.started", Lane: "demo", Payload: payload}}}
			if err := collectUnfinishedSessions(nil, bundle); err != nil {
				t.Fatal(err)
			}
			payload[field] = true
			reviewError(t, collectUnfinishedSessions(nil, bundle), api.CodeInvalid, "legacy."+field, "legacy non-string argument was accepted")
		})
	}
}

func TestReviewBranchComponent(t *testing.T) {
	service, _, scope, options := reviewRelaunch(t)
	service.plans[options.PlanID].bundle.Unfinished[0].Branch = "safe/public"
	if _, err := service.PrepareRelaunch(context.Background(), scope, options); err != nil {
		t.Fatal(err)
	}
	service.plans[options.PlanID].bundle.Unfinished[0].Branch = "safe/.hidden"
	_, err := service.PrepareRelaunch(context.Background(), scope, options)
	reviewError(t, err, api.CodeInvalid, "legacy.branch", "unsafe branch component was accepted")
}

type reviewNoPorts struct{ api.StateStore }

func reviewRollback(t *testing.T) (*Service, *memStore, api.Scope, RollbackRequest) {
	t.Helper()
	state := newMemStore()
	service, err := New(Dependencies{Store: state, Human: newMemHuman(), Worker: &memWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	request, backup := buildFixtureInStore(t, state, "0.7.0", "demo")
	var manifest api.MigrationManifest
	if err := api.DecodeObject(state.blobs[request.SourceManifest.ID], &manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "quiescence.json"), state.blobs[manifest.Quiescence.ID], 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "old-binary")
	data := []byte("synthetic old release bytes")
	if err := os.WriteFile(binary, data, 0700); err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "human", ID: "human-1"}}
	return service, state, scope, RollbackRequest{Config: "demo", TargetVersion: "0.7.0",
		OldBinaryPath: binary, ExpectedBinarySHA256: DigestBytes(data), FrozenBackupDir: backup,
		ActiveV2StateDir: t.TempDir(), RestoreTargetDir: filepath.Join(t.TempDir(), "restore"),
		RetainedWorkDir: filepath.Join(t.TempDir(), "retain"), V2Quiescent: true}
}

func TestReviewRollback(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		service, _, scope, request := reviewRollback(t)
		receipt, err := service.ExecuteRollback(context.Background(), scope, request)
		if err != nil || !receipt.Verified {
			t.Fatalf("matched measured rollback was refused: %v", err)
		}
	})
	cases := []struct {
		name  string
		code  api.ErrorCode
		field string
	}{
		{"empty", api.CodeIntegrity, "rollback.frozen_backup"},
		{"root-link", api.CodeIntegrity, "rollback.frozen_backup"},
		{"backup-parent", api.CodeIntegrity, "rollback.frozen_backup"},
		{"restore-parent", api.CodeIntegrity, "rollback.restore_target"},
		{"retained-parent", api.CodeIntegrity, "rollback.retained_work"},
		{"child-link", api.CodeIntegrity, "rollback.frozen_backup"},
		{"fifo", api.CodeIntegrity, "rollback.frozen_backup"},
		{"non-directory", api.CodeIntegrity, "rollback.frozen_backup is not a directory"},
		{"verification", api.CodeIntegrity, "verification.json"},
		{"events", api.CodeIntegrity, "state/events.sqlite"},
		{"quiescence", api.CodeIntegrity, "quiescence.json"},
		{"version", api.CodeIntegrity, "rollback.source_version"},
		{"digest", api.CodeInvalid, "rollback.expected_binary_sha256"},
		{"digest-mismatch", api.CodeIntegrity, "rollback.expected_binary_sha256"},
		{"active-empty", api.CodeInvalid, "rollback.active_v2_state"},
		{"active-overlap", api.CodeConflict, "rollback.restore_target"},
		{"backup-overlap", api.CodeInvalid, "rollback.restore_target"},
		{"retained-overlap", api.CodeInvalid, "rollback.retained_work"},
		{"existing-target", api.CodeConflict, "rollback.restore_target"},
		{"existing-retained", api.CodeConflict, "rollback.retained_work"},
		{"nil-store", api.CodePrerequisite, "rollback.store"},
		{"no-measurement", api.CodeNotImplemented, "rollback.quiescence"},
		{"live-process", api.CodeConflict, "rollback.quiescence"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, state, scope, request := reviewRollback(t)
			canary := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(canary, []byte("canary"), 0600); err != nil {
				t.Fatal(err)
			}
			linkParent := func(destination string) string {
				path := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(filepath.Dir(destination), path); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(path, filepath.Base(destination))
			}
			switch tc.name {
			case "empty":
				request.FrozenBackupDir = t.TempDir()
			case "root-link":
				path := filepath.Join(t.TempDir(), "backup-link")
				if err := os.Symlink(request.FrozenBackupDir, path); err != nil {
					t.Fatal(err)
				}
				request.FrozenBackupDir = path
			case "backup-parent":
				request.FrozenBackupDir = linkParent(request.FrozenBackupDir)
			case "restore-parent":
				request.RestoreTargetDir = linkParent(request.RestoreTargetDir)
			case "retained-parent":
				request.RetainedWorkDir = linkParent(request.RetainedWorkDir)
			case "child-link":
				if err := os.Symlink(canary, filepath.Join(request.FrozenBackupDir, "linked")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(request.FrozenBackupDir, "fifo"), 0600); err != nil {
					t.Fatal(err)
				}
			case "non-directory":
				request.FrozenBackupDir = request.OldBinaryPath
			case "verification":
				if err := os.Remove(filepath.Join(request.FrozenBackupDir, "verification.json")); err != nil {
					t.Fatal(err)
				}
			case "events":
				if err := os.Remove(filepath.Join(request.FrozenBackupDir, "state/events.sqlite")); err != nil {
					t.Fatal(err)
				}
			case "quiescence":
				if err := os.Remove(filepath.Join(request.FrozenBackupDir, "quiescence.json")); err != nil {
					t.Fatal(err)
				}
			case "version":
				request.TargetVersion = "1.0.0-candidate"
			case "digest":
				request.ExpectedBinarySHA256 = ""
			case "digest-mismatch":
				request.ExpectedBinarySHA256 = api.Digest(strings.Repeat("0", 64))
			case "active-empty":
				request.ActiveV2StateDir = ""
			case "active-overlap":
				request.RestoreTargetDir = filepath.Join(request.ActiveV2StateDir, "restore")
			case "backup-overlap":
				request.RestoreTargetDir = filepath.Join(request.FrozenBackupDir, "restore")
			case "retained-overlap":
				request.RetainedWorkDir = filepath.Join(request.ActiveV2StateDir, "retain")
			case "existing-target":
				if err := os.Mkdir(request.RestoreTargetDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(canary, filepath.Join(request.RestoreTargetDir, "verification.json")); err != nil {
					t.Fatal(err)
				}
			case "existing-retained":
				if err := os.Mkdir(request.RetainedWorkDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(canary, filepath.Join(request.RetainedWorkDir, "retained-v2-work.json")); err != nil {
					t.Fatal(err)
				}
			case "nil-store":
				service.deps.Store = nil
			case "no-measurement":
				service.deps.Store = reviewNoPorts{state}
			case "live-process":
				state.events = append(state.events, api.Event{Seq: api.Sequence(len(state.events) + 1), Kind: "lane.started", LifeID: "live-life"})
			}
			_, err := service.ExecuteRollback(context.Background(), scope, request)
			reviewError(t, err, tc.code, tc.field, "unsafe rollback input escaped its field gate")
			actual, err := os.ReadFile(canary)
			if err != nil || string(actual) != "canary" {
				t.Fatal("rollback followed a planted destination link")
			}
		})
	}
}

func TestReviewOverlap(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	if pathsOverlap(root, other) {
		t.Fatal("disjoint real paths overlap")
	}
	if !pathsOverlap(filepath.Join(root, "missing", "child"), other) {
		t.Fatal("unresolved rollback path was treated as disjoint")
	}
}

func TestReviewInventory(t *testing.T) {
	ref := api.BlobRef{ID: "object", SHA256: DigestBytes([]byte("x")), Bytes: 1, Class: "archive"}
	for _, path := range []string{"../escape", "/absolute", "a/../b", "a//b", "a\\b", "a/./b"} {
		t.Run(path, func(t *testing.T) {
			manifest := api.ObjectManifest{Schema: SchemaObjectManifest, Entries: []api.ObjectEntry{{Path: "safe/file", Kind: "file", Mode: 0600, Content: &ref}}}
			if err := ValidateObjectManifest(manifest); err != nil {
				t.Fatal(err)
			}
			manifest.Entries[0].Path = path
			reviewError(t, ValidateObjectManifest(manifest), api.CodeInvalid, "path", "inventory path escaped its refusal")
		})
	}
	t.Run("symlink", func(t *testing.T) {
		manifest := api.ObjectManifest{Schema: SchemaObjectManifest, Entries: []api.ObjectEntry{{Path: "dir/link", Kind: "symlink", Mode: 0600, LinkTarget: "target"}}}
		if err := ValidateObjectManifest(manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Entries[0].LinkTarget = "../../../outside"
		reviewError(t, ValidateObjectManifest(manifest), api.CodeInvalid, "link_target", "inventory symlink escaped its refusal")
	})
}

func TestReviewApply(t *testing.T) {
	for _, name := range []string{"accepted", "proof", "digest", "actor", "connection", "stale", "consumed", "expired"} {
		t.Run(name, func(t *testing.T) {
			service, state, human, scope, _, request := migrationApplyFixture(t)
			scope.Request.Proof.ExpiresAt = "2099-01-01T00:00:00Z"
			var code api.ErrorCode
			field := ""
			switch name {
			case "proof":
				scope.Request.Proof, code, field = nil, api.CodeUnauthenticated, "operation-bound human proof"
			case "digest":
				scope.Request.RequestSHA256, code, field = api.Digest(strings.Repeat("0", 64)), api.CodeInvalid, "exact intent"
			case "actor":
				scope.Actor.Kind, code, field = "lane", api.CodeForbidden, "human-proof authority"
			case "connection":
				scope.Connection, code, field = nil, api.CodeForbidden, "live installed human connection"
			case "stale":
				scope.EndpointGeneration, code, field = 2, api.CodeForbidden, "connection binding"
			case "consumed":
				human.consumed[scope.Request.Proof.ID], code, field = true, api.CodeConflict, "proof already consumed"
			case "expired":
				scope.Request.Proof.ExpiresAt, code, field = "2000-01-01T00:00:00Z", api.CodeForbidden, "proof.expires_at"
			}
			err := reviewCall(t, "apply input escaped its deciding guard", func() error {
				_, err := service.MigrationApply(context.Background(), scope, request)
				return err
			})
			if name == "accepted" {
				if err != nil || len(state.transactions) != 1 {
					t.Fatalf("valid apply failed: %v", err)
				}
			} else {
				reviewError(t, err, code, field, "apply input escaped its deciding guard")
				if len(state.transactions) != 0 {
					t.Fatal("refused apply committed state")
				}
			}
		})
	}
}

type reviewVerifyStore struct {
	*memStore
	bad   bool
	after func()
}

func (store *reviewVerifyStore) Verify(ctx context.Context, request api.VerifyRequest) (api.Verification, error) {
	if store.bad {
		return api.Verification{OK: false, Problems: []string{"injected read-back failure"}}, nil
	}
	return store.memStore.Verify(ctx, request)
}
func (store *reviewVerifyStore) Transact(ctx context.Context, transaction api.Transaction) (api.Commit, error) {
	commit, err := store.memStore.Transact(ctx, transaction)
	if err == nil && store.after != nil {
		for _, deployment := range transaction.Writes.Deployments {
			if deployment.Phase == "activating" {
				store.after()
			}
		}
	}
	return commit, err
}

func TestReviewCompletion(t *testing.T) {
	for _, name := range []string{"accepted", "readback", "problems", "source-problem", "deleted"} {
		t.Run(name, func(t *testing.T) {
			service, state, _, scope, plan, request := migrationApplyFixture(t)
			wrapper := &reviewVerifyStore{memStore: state}
			service.deps.Store = wrapper
			scope.Request.Proof.ExpiresAt = "2099-01-01T00:00:00Z"
			if _, err := service.MigrationApply(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			serviceScope, lease := primeMigrationCompletion(t, service, state, scope, plan)
			switch name {
			case "readback":
				wrapper.bad = true
			case "problems":
				service.plans[plan.ID].plan.Problems = []string{"blocked"}
			case "source-problem":
				service.plans[plan.ID].bundle.Verification.OK = false
			case "deleted":
				wrapper.after = func() { service.mu.Lock(); delete(service.plans, plan.ID); service.mu.Unlock() }
			}
			err := reviewCall(t, "completion escaped its final verification gate", func() error {
				_, err := service.CompleteMigration(context.Background(), serviceScope, lease)
				return err
			})
			if name == "accepted" {
				if err != nil {
					t.Fatal(err)
				}
				report, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
				if err != nil || !report.Verified {
					t.Fatalf("completed read-back failed: %v", err)
				}
				return
			}
			if name == "readback" {
				reviewError(t, err, api.CodeIntegrity, "store verification", "completion was published before read-back")
			} else {
				reviewError(t, err, api.CodeConflict, "migration.plan", "completion ignored unresolved or disappearing plan")
			}
			if state.deployments[plan.ID].Phase == "complete" {
				t.Fatal("failed completion published complete phase")
			}
			for _, event := range state.events {
				if event.Kind == "migration.completed" {
					t.Fatal("completion was published before read-back")
				}
			}
			if state.effects[lease.Record.Effect.ID].Outcome != nil {
				t.Fatal("failed completion sealed the operation")
			}
		})
	}
}

func reviewCompleted(t *testing.T) (*Service, *memStore, api.Scope, api.MigrationPlan) {
	t.Helper()
	service, state, _, scope, plan, request := migrationApplyFixture(t)
	scope.Request.Proof.ExpiresAt = "2099-01-01T00:00:00Z"
	if _, err := service.MigrationApply(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	finishMigration(t, service, state, scope, plan)
	return service, state, scope, plan
}

type reviewPendingStore struct{ *memStore }

func (store reviewPendingStore) PendingEffects(_ context.Context, request api.CursorRequest) ([]api.Effect, error) {
	var ids []string
	for id, record := range store.effects {
		if record.State == api.EffectPending && record.Outcome == nil {
			ids = append(ids, string(id))
		}
	}
	sort.Strings(ids)
	result := []api.Effect{}
	for _, id := range ids {
		if len(result) == request.Limit {
			break
		}
		result = append(result, store.effects[api.ID(id)].Effect)
	}
	return result, nil
}

func TestReviewReadback(t *testing.T) {
	t.Run("activating", func(t *testing.T) {
		service, state, _, scope, plan, request := migrationApplyFixture(t)
		scope.Request.Proof.ExpiresAt = "2099-01-01T00:00:00Z"
		if _, err := service.MigrationApply(context.Background(), scope, request); err != nil {
			t.Fatal(err)
		}
		serviceScope, lease := primeMigrationCompletion(t, service, state, scope, plan)
		transaction, err := buildImportTransaction(serviceScope, plan, service.plans[plan.ID].bundle, *lease.Record.Effect.Context, state.deployments[plan.ID])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.Transact(context.Background(), transaction); err != nil {
			t.Fatal(err)
		}
		_, err = service.VerifyMigratedState(context.Background(), scope, plan.ID)
		reviewError(t, err, api.CodeConflict, "migration.phase", "activating migration was advertised as verified")
	})
	t.Run("authority", func(t *testing.T) {
		service, state, scope, plan := reviewCompleted(t)
		if _, err := service.VerifyMigratedState(context.Background(), scope, plan.ID); err != nil {
			t.Fatal(err)
		}
		state.events = append(state.events, api.Event{Seq: api.Sequence(len(state.events) + 1), Kind: "identity.bound", OperationID: state.deployments[plan.ID].OperationID})
		_, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
		reviewError(t, err, api.CodeIntegrity, "active authority", "read-back accepted imported active authority")
	})
	for _, phase := range []api.EffectState{api.EffectPending, api.EffectClaimed, api.EffectCompleted} {
		t.Run(string(phase), func(t *testing.T) {
			service, state, scope, plan := reviewCompleted(t)
			service.deps.Store = reviewPendingStore{state}
			if _, err := service.VerifyMigratedState(context.Background(), scope, plan.ID); err != nil {
				t.Fatal(err)
			}
			operation := state.deployments[plan.ID].OperationID
			for i := 0; i < 250; i++ {
				id := api.ID(fmt.Sprintf("ordinary-%03d", i))
				state.effects[id] = api.EffectRecord{State: api.EffectPending, Effect: api.Effect{ID: id, OperationID: "other-operation"}}
			}
			duplicate := api.EffectRecord{State: phase, Effect: api.Effect{ID: "zz-duplicate", OperationID: operation, Deliver: &api.Mail{ID: "duplicate"}}}
			if phase == api.EffectCompleted {
				duplicate.Outcome = &api.EffectOutcome{Status: "succeeded"}
			}
			state.effects[duplicate.Effect.ID] = duplicate
			_, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
			reviewError(t, err, api.CodeIntegrity, "duplicate mail delivery", "all-state read-back missed duplicate delivery")
		})
	}
	t.Run("returned", func(t *testing.T) {
		service, state, scope, plan := reviewCompleted(t)
		bundle := service.plans[plan.ID].bundle
		for i := range bundle.Mail {
			if !bundle.Mail[i].Delivered {
				bundle.Mail[i].Returned = true
				id := DeterministicID("mail-mig-", bundle.Mail[i].Lane, fmt.Sprint(bundle.Mail[i].Sequence))
				for j := range state.records {
					if state.records[j].ID == id {
						state.records[j].Action = "returned"
					}
				}
			}
		}
		report, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
		if err != nil || report.MailPending != 0 {
			t.Fatalf("returned mail was counted as pending: %+v %v", report, err)
		}
	})
}

func TestReviewPlanProblems(t *testing.T) {
	state := newMemStore()
	request, _ := buildFixtureInStore(t, state, "0.7.0", "demo")
	scope := api.Scope{Config: "demo", Actor: api.Actor{Kind: "human", ID: "human-1"}}
	service, err := New(Dependencies{Store: state, Human: newMemHuman(), Worker: &memWorker{}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.MigrationPlan(context.Background(), scope, request)
	if err != nil || len(plan.Problems) != 0 {
		t.Fatalf("complete plan has problems: %+v %v", plan, err)
	}
	service.deps.Store = reviewNoPorts{state}
	plan, err = service.MigrationPlan(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(plan.Problems, []string{"migration.effects inventory port is unavailable"}) {
		t.Fatalf("plan problems were not computed from dependencies: %+v %v", plan.Problems, err)
	}
}

func TestReviewProjection(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		events := []LegacyEventRecord{{Seq: 1, Kind: "lane.state", Lane: "demo", Payload: map[string]any{"state": "verifying"}}}
		projections := map[string]map[string]any{"demo": {"events": 1, "last_seq": 1, "run": 0}}
		if err := crossCheckEventsAndFiles(events, projections, nil); err != nil {
			t.Fatal(err)
		}
		delete(projections, "demo")
		reviewError(t, crossCheckEventsAndFiles(events, projections, nil), api.CodeIntegrity, "events.lane", "event lane without projection was accepted")
	})
	for _, field := range []string{"config", "lanes"} {
		t.Run(field, func(t *testing.T) {
			state := newMemStore()
			request, backup := buildFixtureInStore(t, state, "0.7.0", "demo")
			var manifest api.MigrationManifest
			if err := api.DecodeObject(state.blobs[request.SourceManifest.ID], &manifest); err != nil {
				t.Fatal(err)
			}
			var verification VerificationReceipt
			if err := DecodeStrictJSON(state.blobs[manifest.Verification.ID], &verification); err != nil {
				t.Fatal(err)
			}
			files, err := readDirectoryTree(backup)
			if err != nil {
				t.Fatal(err)
			}
			bundle := &VerifiedBundle{ConfigName: "demo", Verification: verification, Projections: map[string]map[string]any{}}
			if err := verifyEventsAndState(files, bundle); err != nil {
				t.Fatal(err)
			}
			bundle.Projections = map[string]map[string]any{}
			expected := "verification.lanes"
			if field == "config" {
				bundle.ConfigName, expected = "foreign", "events.config"
			} else {
				bundle.Verification.Lanes++
			}
			reviewError(t, verifyEventsAndState(files, bundle), api.CodeIntegrity, expected, "source projection metadata mismatch was accepted")
		})
	}
}

func TestReviewCanonical(t *testing.T) {
	actual, err := CanonicalJCS(map[string]any{"n": 0.000001})
	if err != nil || string(actual) != "{\"n\":0.000001}" {
		t.Fatalf("migration canonical JSON diverged from RFC8785: %s %v", actual, err)
	}
}

func TestReviewGrant(t *testing.T) {
	for _, field := range []string{"sha256", "expires_at"} {
		t.Run(field, func(t *testing.T) {
			service, _, scope, options := reviewRelaunch(t)
			options.GrantSet = api.GrantSet{ID: "grant-set", LifeID: "new-life", Generation: 1, PolicyGeneration: 1,
				Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{},
				Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
				ExpiresAt: "2099-01-01T00:00:00Z"}
			seal := func() {
				options.GrantSet.SHA256 = ""
				raw, err := CanonicalJCS(options.GrantSet)
				if err != nil {
					t.Fatal(err)
				}
				options.GrantSet.SHA256 = DigestBytes(raw)
			}
			seal()
			if _, err := service.PrepareRelaunch(context.Background(), scope, options); err != nil {
				t.Fatal(err)
			}
			if field == "sha256" {
				options.GrantSet.SHA256 = api.Digest(strings.Repeat("0", 64))
			} else {
				options.GrantSet.ExpiresAt = "2000-01-01T00:00:00Z"
				seal()
			}
			_, err := service.PrepareRelaunch(context.Background(), scope, options)
			reviewError(t, err, api.CodeInvalid, "relaunch.grant_set."+field, "relaunch accepted an invalid supplied grant set")
		})
	}
}

type reviewProofHuman struct{ *memHuman }

func (human reviewProofHuman) CheckProof(ctx context.Context, scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
	facts, err := human.memHuman.CheckProof(ctx, scope, proof, target)
	facts.PrincipalID = "foreign-principal"
	return facts, err
}
func TestReviewProofFacts(t *testing.T) {
	service, state, human, scope, _, request := migrationApplyFixture(t)
	scope.Request.Proof.ExpiresAt = "2099-01-01T00:00:00Z"
	service.deps.Human = reviewProofHuman{human}
	_, err := service.MigrationApply(context.Background(), scope, request)
	reviewError(t, err, api.CodeForbidden, "mismatched or already consumed", "apply accepted foreign verified proof facts")
	if len(state.transactions) != 0 {
		t.Fatal("foreign proof facts committed state")
	}
}

func TestReviewMissingEffects(t *testing.T) {
	service, state, scope, plan := reviewCompleted(t)
	service.deps.Store = reviewNoPorts{state}
	_, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
	reviewError(t, err, api.CodeNotImplemented, "migration.effects", "missing complete effect inventory was accepted")
}

func TestReviewLargeOutbox(t *testing.T) {
	service, state, scope, plan := reviewCompleted(t)
	service.deps.Store = reviewPendingStore{state}
	for i := 0; i < 250; i++ {
		id := api.ID(fmt.Sprintf("unrelated-%03d", i))
		state.effects[id] = api.EffectRecord{State: api.EffectPending, Effect: api.Effect{ID: id, OperationID: "other-operation"}}
	}
	report, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
	if err != nil || !report.Verified {
		t.Fatalf("unrelated outbox inventory blocked a verified migration: %v", err)
	}
}

type reviewEmptyEffects struct{ *memStore }

func (store reviewEmptyEffects) MigrationEffects(context.Context, api.Scope, api.ID) ([]api.EffectRecord, error) {
	return []api.EffectRecord{}, nil
}
func TestReviewEffectInventory(t *testing.T) {
	service, state, scope, plan := reviewCompleted(t)
	if _, err := service.VerifyMigratedState(context.Background(), scope, plan.ID); err != nil {
		t.Fatal(err)
	}
	service.deps.Store = reviewEmptyEffects{state}
	_, err := service.VerifyMigratedState(context.Background(), scope, plan.ID)
	reviewError(t, err, api.CodeIntegrity, "migration.effects inventory", "complete effect inventory omitted its causal migration")
}

func TestReviewDecisionSource(t *testing.T) {
	state := newMemStore()
	request, backup := buildFixtureInStore(t, state, "0.7.0", "demo")
	var manifest api.MigrationManifest
	if err := api.DecodeObject(state.blobs[request.SourceManifest.ID], &manifest); err != nil {
		t.Fatal(err)
	}
	var verification VerificationReceipt
	if err := DecodeStrictJSON(state.blobs[manifest.Verification.ID], &verification); err != nil {
		t.Fatal(err)
	}
	files, err := readDirectoryTree(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDecisionsAndVectors(files, &VerifiedBundle{Verification: verification}); err != nil {
		t.Fatal(err)
	}
	files["state/decisions.sqlite"] = []byte("competing source")
	reviewError(t, verifyDecisionsAndVectors(files, &VerifiedBundle{Verification: verification}), api.CodeIntegrity, "decisions.source", "ambiguous decision sources were accepted")
}

func TestReviewArchive(t *testing.T) {
	for _, name := range []string{"accepted", "path", "mode", "link", "type"} {
		t.Run(name, func(t *testing.T) {
			header := tar.Header{Name: "safe/file", Mode: 0600, Size: 1, Typeflag: tar.TypeReg}
			entry := map[string]any{"path": header.Name, "mode": header.Mode, "size": 1, "type": "file", "sha256": DigestBytes([]byte("x"))}
			data := []byte("x")
			switch name {
			case "path":
				header.Name, entry["path"] = "a/../outside", "a/../outside"
			case "mode":
				header.Mode, entry["mode"] = 04700, 04700
			case "link":
				header.Typeflag, header.Size, header.Linkname = tar.TypeSymlink, 0, "../../../outside"
				entry["type"], entry["size"], entry["link"], entry["sha256"] = "symlink", 0, header.Linkname, DigestBytes(nil)
				data = nil
			case "type":
				header.Typeflag, header.Size, header.Linkname = tar.TypeLink, 0, "safe/other"
				entry["size"], entry["sha256"], data = 0, DigestBytes(nil), nil
			}
			var buffer bytes.Buffer
			writer := tar.NewWriter(&buffer)
			if err := writer.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(data); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			manifest, err := json.Marshal(map[string]any{"format": 1, "entries": []any{entry}})
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := json.Marshal(map[string]any{"sha256": DigestBytes(buffer.Bytes()), "manifest_sha256": DigestBytes(manifest)})
			if err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{"state/archives/a.tar": buffer.Bytes(), "state/archives/a.manifest.json": manifest, "state/archives/a.receipt.json": receipt}
			err = verifyArchives(files, &VerifiedBundle{})
			if name == "accepted" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			reviewError(t, err, api.CodeIntegrity, "archive.member", "unsafe archive member was accepted")
		})
	}
}
