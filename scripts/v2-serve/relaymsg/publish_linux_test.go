//go:build linux

package relaymsg_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/service"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/scripts/v2-serve/relaymsg"
)

// Native identity is a component input; public blob APIs, request reservation,
// SQLite ownership, event provenance and exact read-back are production code.
type relayAuth struct {
	api.Authenticator
	scope api.Scope
}

func (a relayAuth) Authorize(ctx context.Context, scope api.Scope, request api.Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if scope.Actor != a.scope.Actor || scope.LaunchID != a.scope.LaunchID || scope.Connection != a.scope.Connection || request.Method != scope.Request.Method {
		return &api.Error{Code: api.CodeForbidden, Message: "relay component transport changed"}
	}
	return nil
}

func TestRelayPublishedBeforeEOF(t *testing.T) {
	ctx := context.Background()
	f := fx.Ready(t, true)
	f.Opened(t)
	f.Human = f.LaneScope(t)
	core, err := service.New(service.Dependencies{Store: f.State, Clock: f.Deps.Clock, Authenticator: relayAuth{scope: f.Human}})
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	call := func(ctx context.Context, method string, input, output any) error {
		calls = append(calls, method)
		f.Admit(t, api.Method(strings.ReplaceAll(method, " ", ".")), input)
		var value any
		var err error
		switch method {
		case "blob begin":
			value, err = core.BlobBegin(ctx, f.Human, input.(api.BlobBeginRequest))
		case "blob chunk":
			value, err = core.BlobChunk(ctx, f.Human, input.(api.BlobChunk))
		case "blob commit":
			value, err = core.BlobCommit(ctx, f.Human, input.(api.BlobCommitRequest))
		default:
			return errors.New("relay used an unexpected public method")
		}
		if err != nil {
			return err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, output)
	}
	target := f.Reservation.Target
	messages := []map[string]any{
		{"type": "grants.ready", "target": target, "identity": f.Human, "metadata_only": true},
		{"type": "grants.reply", "target": target, "nonce": string(fx.ID(t)), "exit_code": 0,
			"stdout": []byte(`{"profiles":[]}`), "stderr": []byte{}},
		{"type": "grants.exiting", "target": target, "nonce": string(fx.ID(t)), "exit_code": 0,
			"stdout": []byte{}, "stderr": []byte{}},
	}
	objects := map[api.ID][]byte{}
	for _, message := range messages {
		ref, err := relaymsg.Publish(ctx, call, message)
		if err != nil {
			t.Fatal("actual relay report publication", err)
		}
		chunk, err := f.State.Blob(ctx, f.Execution, api.BlobReadRequest{ObjectID: ref.ID, Limit: api.MaxChunkBytes})
		if err != nil || int64(len(chunk.Data)) != ref.Bytes || fx.Digest(chunk.Data) != ref.SHA256 {
			t.Fatal("actual report read-back differs", err)
		}
		objects[ref.ID] = chunk.Data
	}
	if len(calls) != 9 {
		t.Fatal("small reports did not use the exact begin/chunk/commit sequence", calls)
	}
	state, err := f.State.CaptureState(ctx, f.Execution, f.Plan.Capture.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, position := range state.Positions {
		if position.EOF || position.NextOffset != 0 {
			t.Fatal("relay advanced by pretending stdout had drained")
		}
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: target.LifeID, Run: target.Run})
	if err != nil || !page.Complete {
		t.Fatal("actual relay event inventory", err)
	}
	var reports []api.Event
	for _, event := range page.Events {
		if event.Kind != "blob.committed" {
			continue
		}
		var ref api.BlobRef
		if json.Unmarshal(event.Payload, &ref) != nil {
			t.Fatal("actual blob event malformed")
		}
		if _, exists := objects[ref.ID]; exists {
			reports = append(reports, event)
		}
	}
	if len(reports) != len(messages) {
		t.Fatal("live committed reports are absent from the real store")
	}
	trace := fx.JSON(t, map[string]any{"config": f.Deps.Config, "target": target, "operation": f.Reservation.OperationID,
		"events": reports, "objects": objects, "messages": messages})
	path := filepath.Join(t.TempDir(), "relay-trace.json")
	if err := os.WriteFile(path, trace, 0600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join("..", "..", "..", "e2e", "v2", "cases", "grants", "relay_live_test.py")
	command := exec.Command("python3", "-B", probe, "--trace", path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("actual committed ready/RPC/exit trace: %v\n%s", err, output)
	}
	// A changed commit receipt must fail even though the real API committed
	// the original bytes. The fixture cannot declare that receipt trustworthy.
	bad := func(ctx context.Context, method string, input, output any) error {
		if err := call(ctx, method, input, output); err != nil {
			return err
		}
		if method == "blob commit" {
			output.(*api.BlobRef).Bytes++
		}
		return nil
	}
	if _, err := relaymsg.Publish(ctx, bad, messages[0]); err == nil {
		t.Fatal("changed report receipt was accepted")
	}
}
