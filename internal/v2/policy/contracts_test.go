package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func TestApprovedSnapshots(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*fixture)
		code   api.ErrorCode
	}{
		{"wrong-config", func(f *fixture) { f.store.org.Config = "different" }, api.CodeIntegrity},
		{"stale-source", func(f *fixture) { f.store.org.Ref.Generation++ }, api.CodeConflict},
		{"stale-inventory", func(f *fixture) { f.store.org.Sources[0].Source.Generation++ }, api.CodeIntegrity},
		{"unapproved-source", func(f *fixture) { f.store.org.Sources = []api.ResourceFile{} }, api.CodeConflict},
		{"changed-source", func(f *fixture) { f.store.badSource = true }, api.CodeIntegrity},
		{"source-stub", func(f *fixture) { f.store.sourceErr = api.NotImplemented("fixture", "Source") }, api.CodeNotImplemented},
		{"changed-task", func(f *fixture) {
			f.store.badTurn = true
			f.store.inputs["different-task"] = f.store.inputs[f.store.lane.Task.ID]
		}, api.CodeConflict},
		{"turn-stub", func(f *fixture) { f.store.turnErr = api.NotImplemented("fixture", "Turn") }, api.CodeNotImplemented},
		{"metadata", func(f *fixture) { f.store.badMetadata = true }, api.CodeIntegrity},
		{"reply", func(f *fixture) { f.store.badReply = true }, api.CodeIntegrity},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			row.mutate(f)
			_, err := f.evaluateOnce(context.Background())
			wantCode(t, err, row.code)
		})
	}
}

func TestSourceGenerationIsOrg(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.store.org.Ref.Generation = 7
	for i := range f.store.policy.Sources {
		f.store.policy.Sources[i].Generation = 7
	}
	f.store.policy.GuidanceSource.Generation = 7
	for i := range f.store.policy.Rules {
		f.store.policy.Rules[i].Source.Generation = 7
	}
	f.seal(t)
	decision := f.evaluate(t)
	if decision.PolicyGeneration != 1 || f.store.events[0].OperationID == "" {
		t.Fatal("policy generation was replaced by org generation")
	}
	validation, err := f.service.ConfigValidate(context.Background(), f.scope, api.Empty{})
	if err != nil || !validation.Valid {
		t.Fatal("source validator did not receive the org generation")
	}
}

func TestReceiptReplayBeforePreflight(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	first := f.evaluate(t)
	objects := len(f.store.uploads)
	// A completed retry returns the original typed result even after sources
	// change. Current identity is still checked by the receipt/transport port.
	f.store.policy.Rules[0].Band = "invalid"
	f.judge.probability = 1
	requestID, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	f.scope.Request.RequestID = requestID
	raw, err := json.Marshal(f.scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.Frame = testFrame(raw)
	replayed, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	if err != nil || !reflect.DeepEqual(replayed, first) || len(f.judge.requests) != 1 ||
		len(f.store.events) != 1 || len(f.store.uploads) != objects {
		t.Fatalf("retry did not replay its exact original result before preflight: %v", err)
	}
	f.store.launch.Revoked = true
	_, err = f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	wantCode(t, err, api.CodeForbidden)
}

func TestFrameAndReservation(t *testing.T) {
	for _, name := range []string{"frame", "params", "digest", "reservation"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			if err := f.prepare(); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "frame":
				changed := f.scope.Request
				changed.RequestID = "different-request-key-value"
				raw, err := json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				f.scope.Frame = testFrame(raw)
				receipt := f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))]
				receipt.RawRequest = raw
				f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))] = receipt
			case "params":
				f.request.Command.CWD += "/changed"
			case "digest":
				f.scope.Request.RequestSHA256 = digestBytes([]byte("other-intent"))
				raw, err := json.Marshal(f.scope.Request)
				if err != nil {
					t.Fatal(err)
				}
				f.scope.Frame = testFrame(raw)
				receipt := f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))]
				receipt.RawRequest = raw
				f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))] = receipt
			case "reservation":
				receipt := f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))]
				receipt.RawRequest = []byte(`{}`)
				f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))] = receipt
			}
			_, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
			wantCode(t, err, api.CodeIntegrity)
			if len(f.judge.requests) != 0 || len(f.store.uploads) != 0 || len(f.store.events) != 0 {
				t.Fatal("unbound request performed inference, retention or commit")
			}
		})
	}
}

func TestHumanTargetKeepsPrincipal(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.scope.Actor = api.Actor{Kind: "human", ID: "human-reader"}
	f.scope.LaunchID = ""
	result, err := f.evaluateOnce(context.Background())
	if err != nil {
		t.Fatalf("human targeted preview borrowed a lane principal: %v", err)
	}
	if result.Result != "allow" || len(f.store.seenScopes) != 1 || len(f.judge.scopes) != 1 ||
		f.store.seenScopes[0].Actor != f.scope.Actor || f.judge.scopes[0].Actor != f.scope.Actor ||
		f.store.events[0].Actor != f.scope.Actor || f.store.metadata[result.Input.ID].ACL.Owner != f.scope.Actor {
		t.Fatal("human targeted preview borrowed a lane principal")
	}
	f.scope.Request.Method = "config.read"
	view, err := f.service.ConfigRead(context.Background(), f.scope,
		api.ConfigReadRequest{View: "path", Context: &f.store.policy.Context})
	if err != nil || view.Generation != f.store.org.Ref.Generation {
		t.Fatalf("approved human contextual source read failed: %v", err)
	}
}

func TestTurnChangesInvalidateCache(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.evaluate(t)
	f.store.turn.Generation++
	data := []byte("changed retained task")
	f.store.turn.Task.ID, f.store.turn.Task.SHA256, f.store.turn.Task.Bytes = "task-b", digestBytes(data), int64(len(data))
	f.store.inputs["task-b"] = &testUpload{request: api.BlobBeginRequest{Class: f.store.turn.Task.Class,
		Bytes: int64(len(data)), SHA256: digestBytes(data)}, data: data}
	f.store.lane.Task = f.store.turn.Task
	f.judge.probability = 1
	second := f.evaluate(t)
	if second.Result != "refuse" || second.CacheOf != "" || len(f.judge.requests) != 2 {
		t.Fatal("changed retained turn reused a cached semantic allow")
	}
}
