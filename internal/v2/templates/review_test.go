package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestCLIFileSemantics(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	task := api.BlobRef{ID: "task", Class: "artifact", Bytes: 1, SHA256: digest([]byte("x"))}
	for _, row := range []struct {
		name  string
		words []string
		body  any
	}{
		{"render", []string{"brief", "render"}, api.TemplateRequest{Context: api.RoleContext{Level: 3, Role: "executor"}, Task: task, GrantSetID: "grants"}},
		{"start", []string{"brief", "start"}, api.BriefingRequest{Level: 2, Role: "executor"}},
		{"validate", []string{"org", "validate"}, api.OrgValidateRequest{Generation: 0}},
		{"bootstrap", []string{"org", "bootstrap"}, api.BootstrapRequest{OrgName: "org", SourceManifest: task}},
	} {
		t.Run(row.name, func(t *testing.T) {
			data, err := json.Marshal(row.body)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, row.name+".json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			args := append(append([]string{}, row.words...), "--config", "case-templates", "--request", path, "--idempotency-key", string(mutationKey(t)))
			exit := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
			var failure api.Error
			if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
				t.Fatal(err)
			}
			if exit != 2 || failure.Code != api.CodeInvalid || failure.Owner != "lb-v2-templates" || failure.Instead == "" || stdout.Len() != 0 {
				t.Fatalf("template file input missed its owned semantic validator: exit=%d failure=%+v", exit, failure)
			}
		})
	}
}

func TestServiceRenderGuards(t *testing.T) {
	t.Run("label", func(t *testing.T) {
		service, store, _, scope, request := component(t)
		scope.Actor = api.Actor{Kind: "service", ID: "lifecycle-service"}
		result, err := service.BriefRender(context.Background(), scope, request)
		if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 || len(store.reads) != 0 {
			t.Fatal("unlabelled service render retained a prompt")
		}
		errorCode(t, err, api.CodeForbidden)
	})
	for _, field := range []string{"foreign-life", "actor"} {
		t.Run(field, func(t *testing.T) {
			service, store, scope, request := lifecycleComponent(t, true)
			store.changeReceipt = func(receipt *api.MutationReceipt) {
				if field == "foreign-life" {
					receipt.Operation.LifeID = "foreign-life"
				} else {
					receipt.Actor = api.Actor{Kind: "service", ID: "another-service"}
				}
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 || len(store.reads) != 0 {
				t.Fatal("unbound service render retained a prompt")
			}
			errorCode(t, err, api.CodeForbidden)
		})
	}
}

func TestServiceReply(t *testing.T) {
	for _, name := range []string{"pending", "operation", "life", "completed"} {
		t.Run(name, func(t *testing.T) {
			service, store, scope, request := lifecycleComponent(t, true)
			operation := store.reservation.Operation
			switch name {
			case "operation":
				operation.ID = "foreign-operation"
			case "life":
				operation.LifeID = "foreign-life"
			case "completed":
				operation.Status = "succeeded"
			}
			data, err := json.Marshal(operation)
			if err != nil {
				t.Fatal(err)
			}
			store.reservation.Reply = &api.RPCReply{Result: data}
			result, err := service.BriefRender(context.Background(), scope, request)
			if name == "pending" {
				if err != nil || result.Markdown.ID == "" || len(store.retained) != 1 || store.retained[0].Intent.RequestedBy != store.reservation.Actor {
					t.Fatalf("active queued lifecycle could not retain its truthful prompt: %v", err)
				}
			} else {
				if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 {
					t.Fatal("foreign lifecycle reply retained a prompt")
				}
				errorCode(t, err, api.CodeIntegrity)
			}
		})
	}
}

func TestServiceHuman(t *testing.T) {
	service, store, scope, request := lifecycleComponent(t, false)
	requester := api.Actor{Kind: "human", ID: "original-human"}
	store.reservation.Actor = requester
	scope.Actor = api.Actor{Kind: "service", ID: "lifecycle-service"}
	serviceIdentity := scope.Actor
	store.lifecycleService = &serviceIdentity
	scope.Request.Proof = &api.ProofRef{ID: "human-proof", RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: "2030-01-01T00:10:00Z"}
	reframe(t, store, &scope)
	result, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || result.Markdown.ID == "" || len(store.retained) != 1 ||
		store.retained[0].Intent.RequestedBy != requester || store.retained[0].Intent.CauseOperationID != store.reservation.Operation.ID {
		t.Fatalf("human lifecycle requester lost its retained cause: %v", err)
	}
}

func seedVariant(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	switch name {
	case "missing":
		return nil
	case "eleven":
		parts := bytes.Split(data, []byte("[[blacklist]]"))
		if len(parts) != 13 {
			t.Fatal("workflow fixture does not have twelve entries")
		}
		return bytes.Join(parts[:len(parts)-1], []byte("[[blacklist]]"))
	case "route":
		changed := bytes.ReplaceAll(data, []byte("laneboss lane start / laneboss lane resume / laneboss lane turn"), []byte("ordinary unrelated route"))
		if bytes.Equal(changed, data) {
			t.Fatal("workflow fixture has no session route")
		}
		return changed
	}
	t.Fatal("unknown workflow fixture variant")
	return nil
}

func bindBootstrap(t *testing.T, store *memoryStore, scope *api.Scope, request api.BootstrapRequest) {
	t.Helper()
	params, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	proof := *scope.Request.Proof
	scope.Request.Params, scope.Request.Proof, scope.Request.RequestSHA256 = params, nil, ""
	scope.Request, err = client.PrepareRequest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	proof.RequestSHA256 = scope.Request.RequestSHA256
	scope.Request.Proof = &proof
	store.target.RequestSHA256 = scope.Request.RequestSHA256
	store.proof.Ref, store.proof.Target = proof, store.target
	store.reservation.Key.RequestSHA256 = scope.Request.RequestSHA256
	reframe(t, store, scope)
}

func TestBootstrapWorkflow(t *testing.T) {
	for _, name := range []string{"missing", "eleven", "route"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := bootstrapComponent(t)
			var manifest api.ObjectManifest
			if err := json.Unmarshal(store.blobs[request.SourceManifest.ID], &manifest); err != nil {
				t.Fatal(err)
			}
			entries := []api.ObjectEntry{}
			found := false
			for _, entry := range manifest.Entries {
				if entry.Path == templates.WorkflowPath {
					found = true
					data := seedVariant(t, name, store.blobs[entry.Content.ID])
					if data == nil {
						continue
					}
					ref := *entry.Content
					ref.ID, ref.Bytes, ref.SHA256 = "changed-workflow", int64(len(data)), digest(data)
					store.put(ref, data)
					entry.Content = &ref
				}
				entries = append(entries, entry)
			}
			if !found {
				t.Fatal("bootstrap fixture lacks its workflow source")
			}
			manifest.Entries = entries
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			request.SourceManifest.Bytes, request.SourceManifest.SHA256 = int64(len(data)), digest(data)
			store.put(request.SourceManifest, data)
			bindBootstrap(t, store, &scope, request)
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" || len(store.transactions) != 0 {
				t.Fatal("bootstrap accepted a missing or invalid workflow seed")
			}
			errorCode(t, err, api.CodeInvalid)
		})
	}
}

func TestOrgWorkflow(t *testing.T) {
	for _, name := range []string{"missing", "eleven", "route"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, _ := component(t)
			files := []api.ResourceFile{}
			for _, file := range store.snapshot.Sources {
				if file.Source.Path == templates.WorkflowPath {
					data := seedVariant(t, name, store.blobs[file.Content.ID])
					if data == nil {
						continue
					}
					file.Content.Bytes, file.Content.SHA256 = int64(len(data)), digest(data)
					file.Source.SHA256 = file.Content.SHA256
					store.put(file.Content, data)
				}
				files = append(files, file)
			}
			store.snapshot.Sources = files
			result, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation})
			if err == nil || result.Valid || store.writes != 0 {
				t.Fatal("org validation accepted a missing or invalid workflow seed")
			}
			errorCode(t, err, api.CodeInvalid)
		})
	}
}

func TestPromptObjectKey(t *testing.T) {
	service, store, _, scope, request := component(t)
	first, err := service.BriefRender(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	count := len(store.blobs)
	scope.Request.RequestID = mutationKey(t)
	again, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || again.Markdown != first.Markdown || len(store.blobs) != count {
		t.Fatal("identical render inputs allocated multiple prompt objects")
	}
	store.input.Lane.Run++
	next, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || next.Markdown.ID == first.Markdown.ID {
		t.Fatal("different runs shared a retained prompt identity")
	}
	scope.Actor.ID = "another-reader"
	other, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || other.Markdown.ID == next.Markdown.ID {
		t.Fatal("different owners shared a retained prompt identity")
	}
}
