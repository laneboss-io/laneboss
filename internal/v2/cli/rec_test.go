package cli

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRestoreCommand(t *testing.T) {
	command, ok := integrateCommands["lane restore"]
	if !ok || command.method != "lane.restore" || api.Methods["lane.restore"].Access != "parent" || !api.Methods["lane.restore"].Mutation {
		t.Fatal("restore lost its lifecycle parent mutation route")
	}
	if api.ValidateTransactionShape(api.Transaction{Scope: api.Scope{Request: api.Request{Method: "lane.restore"}}, Reply: &api.RPCReply{Result: json.RawMessage(`{}`)}}) == nil {
		t.Fatal("generic transaction fabricated restore completion")
	}
	call := Invocation{Method: "lane.restore", Args: []string{"--life", "life", "--run", "1", "--generation", "2", "--target", "/work/restored", "--archive-receipt", "archive"}}
	options, err := lbV2LifecycleParse(call)
	if err != nil {
		t.Fatal(err)
	}
	var request api.RestoreRequest
	if err := lbV2LifecycleBuild(context.Background(), call, options, &request); err != nil || request.Target.LifeID != "life" || request.Target.Run != 1 || request.ExpectedGeneration != 2 || request.Path != "/work/restored" || request.ArchiveReceiptID != "archive" {
		t.Fatal("restore flags lost the exact target or archive selector", err)
	}
	for _, target := range []string{"/work/restored", "../escape", "/", "/work/../restored"} {
		request.Path = target
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		err = integrateInputChecks.methods["lane.restore"](raw)
		if (err == nil) != (target == "/work/restored") {
			t.Fatal("restore file validator accepted an invalid destination", target, err)
		}
	}
}

func TestRestoreOwnerFlag(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		call := Invocation{Method: "lane.restore", Args: []string{"--life", "life", "--run", "1", "--generation", "2", "--target", "/work/restored"}}
		if supplied {
			call.Args = append(call.Args, "--allow-nested-git")
		}
		options, err := lbV2LifecycleParse(call)
		if err != nil {
			t.Fatal("owner flag is not exposed by restore", err)
		}
		var request api.RestoreRequest
		if err := lbV2LifecycleBuild(context.Background(), call, options, &request); err != nil || request.AllowNestedGit != supplied {
			t.Fatal("owner flag lost its explicit opt-in or enabled itself", err)
		}
	}
}
