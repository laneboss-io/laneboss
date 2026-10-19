package lifecyclecase

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

func lifecycleSemanticCases() []struct {
	method api.Method
	valid  any
	bad    any
} {
	digest := sha256.Sum256([]byte("input"))
	task := api.BlobRef{ID: "input", Class: "task", Bytes: 5, SHA256: api.Digest(hex.EncodeToString(digest[:]))}
	diff, inventory := task, task
	diff.Class, inventory.Class = "artifact", "manifest"
	target := api.LifeRef{LifeID: "child", Run: 1}
	budget := api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1024,
		Processes: 1, DiskBytes: 4096, Currency: "USD"}
	start := api.StartRequest{Lane: "child", ProjectID: "project", Level: 3, Role: "executor",
		Task: task, Driver: api.DriverCodex, ProfileGrantID: "profile", Model: "fixture-model", Effort: "high",
		Budget: budget, ExpectedPolicyGeneration: 1,
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
			Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	badStart := start
	badStart.Level = 0
	adopt := api.AdoptRequest{Lane: start.Lane, Level: start.Level, Role: start.Role, Task: task,
		Driver: start.Driver, ProfileGrantID: start.ProfileGrantID, Model: start.Model, Effort: start.Effort,
		Budget: budget, ExpectedPolicyGeneration: 1, Grants: start.Grants, ImportManifest: inventory}
	badAdopt := adopt
	badAdopt.ImportManifest.Class = "task"
	resume := api.ResumeRequest{Target: target, ExpectedGeneration: 1, Message: task, Budget: budget}
	badResume := resume
	badResume.Message.Bytes = 0
	turn := api.TurnRequest{Target: target, ExpectedGeneration: 1, MailIDs: []api.ID{}, IdleMessage: &task, Budget: budget}
	badTurn := turn
	badTurn.MailIDs = []api.ID{"mail", "mail"}
	stop := api.StopRequest{Target: target, ExpectedGeneration: 1, Reason: task}
	badStop := stop
	badStop.ExpectedGeneration = 0
	review := api.ReviewRequest{Target: target, Diff: diff, Checks: []api.BlobRef{diff},
		RecordInventory: inventory, RefusalResolution: []api.ID{}}
	badReview := review
	badReview.Checks = []api.BlobRef{}
	mark := api.MarkRequest{Target: target, ExpectedGeneration: 1, State: "accepted", Review: api.ReviewReceipt{
		ID: "review", Reviewer: api.Actor{Kind: "lane", ID: "parent-actor", LifeID: "parent", Level: 5, Role: "supervisor"},
		Diff: diff, Checks: review.Checks, RecordInventory: inventory, RefusalResolution: []api.ID{}, Coverage: "complete"}}
	badMark := mark
	badMark.State = "invented"
	clean := api.CleanRequest{Target: target, ExpectedGeneration: 1, ArchiveReceiptID: "archive"}
	badClean := clean
	badClean.ArchiveReceiptID = "../archive"
	archive := api.ArchiveRequest{Target: target, ExpectedGeneration: 1}
	badArchive := archive
	badArchive.ExpectedGeneration = 0
	loop := api.LoopRequest{Target: target, ExpectedGeneration: 1, Enabled: true, IdleMessage: &task, BackoffMS: 100}
	badLoop := loop
	badLoop.BackoffMS = 0
	attach := api.AttachRequest{Target: target, Mode: "read"}
	badAttach := attach
	badAttach.Cursor = strings.Repeat("x", 4097)
	input := api.AttachInputRequest{Target: target, ChannelID: "input-channel", Input: []byte("x")}
	badInput := input
	badInput.Input = []byte{}
	events := api.EventTailRequest{LifeID: target.LifeID, Run: target.Run, Follow: true, DeadlineMS: 1000}
	badEvents := events
	badEvents.DeadlineMS = 0
	return []struct {
		method api.Method
		valid  any
		bad    any
	}{
		{"lane.start", start, badStart}, {"lane.adopt", adopt, badAdopt},
		{"lane.resume", resume, badResume}, {"lane.turn", turn, badTurn},
		{"lane.stop", stop, badStop}, {"lane.mark", mark, badMark},
		{"lane.review", review, badReview}, {"lane.clean", clean, badClean},
		{"lane.archive", archive, badArchive}, {"lane.status", target, api.LifeRef{LifeID: "child"}},
		{"lane.list", api.ListRequest{Limit: 10}, api.ListRequest{Limit: 0}},
		{"lane.check", target, api.LifeRef{LifeID: "child"}}, {"lane.loop", loop, badLoop},
		{"lane.attach", attach, badAttach}, {"lane.input", input, badInput},
		{"event.tail", events, badEvents},
	}
}

func TestCLIInputFiles(t *testing.T) {
	for _, row := range lifecycleSemanticCases() {
		name := strings.TrimPrefix(string(row.method), "lane.")
		name = strings.ReplaceAll(name, ".", "-")
		t.Run(name, func(t *testing.T) {
			for _, invalid := range []bool{true, false} {
				kind := "valid"
				value := row.valid
				if invalid {
					kind, value = "invalid", row.bad
				}
				t.Run(kind, func(t *testing.T) {
					directory := t.TempDir()
					if err := os.Chmod(directory, 0700); err != nil {
						t.Fatal(err)
					}
					raw, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(directory, "request.json")
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					args := strings.Split(strings.ReplaceAll(string(row.method), ".", " "), " ")
					args = append(args, "--config", lifecycleConfig(), "--request", path,
						"--binding", filepath.Join(directory, "absent-binding.json"))
					if invalid {
						// An invalid body must be refused before reading this absent
						// proof or checking the deliberately malformed retained key.
						args = append(args, "--proof", filepath.Join(directory, "absent-proof.json"), "--idempotency-key", "short")
					} else if api.Methods[row.method].Mutation {
						args = append(args, "--idempotency-key", "retained-lifecycle-key-0001")
					}
					var stdout, stderr bytes.Buffer
					exit := cli.Run(args, strings.NewReader(""), &stdout, &stderr)
					var result api.Error
					if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
						t.Fatalf("CLI did not return a typed failure: %v", err)
					}
					if invalid {
						if exit != 2 || stdout.Len() != 0 || result.Code != api.CodeInvalid || result.Owner != "lb-v2-lifecycle" {
							t.Fatalf("semantic lifecycle input reached proof, key or socket work: %s", result.Code)
						}
						return
					}
					// A fresh, deliberately uninstalled binding can be refused by
					// binding validation or transport. No feature stub is pinned.
					transport := result.Code == api.CodePrerequisite || result.Code == api.CodeUnavailable ||
						result.Code == api.CodeUnauthenticated
					if exit == 0 || stdout.Len() != 0 || result.Owner == "lb-v2-lifecycle" ||
						result.Code == api.CodeInvalid || !transport {
						t.Fatalf("valid lifecycle input did not reach binding or transport: %s", result.Code)
					}
				})
			}
		})
	}
}
