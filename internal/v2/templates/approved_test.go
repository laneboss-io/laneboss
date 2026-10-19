package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestOriginalTaskBinding(t *testing.T) {
	service, store, _, scope, request := component(t)
	data := []byte("a visible task which was never assigned to this life")
	other := api.BlobRef{ID: "other-task", Class: "task", Bytes: int64(len(data)), SHA256: digest(data)}
	store.put(other, data)
	request.Task = other
	result, err := service.BriefRender(context.Background(), scope, request)
	if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 {
		t.Fatal("render accepted a visible but unassigned task")
	}
	errorCode(t, err, api.CodeConflict)
	// A start snapshot cannot substitute a different visible task either.
	store.input.Task, store.input.TaskBytes = other, data
	result, err = service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: scope.Actor.Level, Role: scope.Actor.Role})
	if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 {
		t.Fatal("start accepted a task outside the retained life assignment")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func TestOrgInventory(t *testing.T) {
	for _, name := range []string{"initial", "initial_nil", "later", "source", "derived"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, _ := component(t)
			generation := api.Generation(7)
			if name == "initial" || name == "initial_nil" {
				generation = 1
			}
			store.snapshot.Ref.Generation = generation
			for i := range store.snapshot.Sources {
				store.snapshot.Sources[i].Source.Generation = generation
				store.snapshot.Sources[i].RevisionGeneration = 1
			}
			file := store.snapshot.Derived[0]
			file.Source.Generation, file.RevisionGeneration = generation, 1
			if generation == 1 {
				store.snapshot.Derived = []api.ResourceFile{}
			} else {
				store.snapshot.Derived = []api.ResourceFile{file}
			}
			request := api.OrgValidateRequest{Generation: generation}
			result, err := service.OrgValidate(context.Background(), scope, request)
			if err != nil || !result.Valid || store.writes != 0 {
				t.Fatal("semantic org inventory was refused", err)
			}
			if name == "source" {
				store.snapshot.Sources[0].Kind = "file"
			} else if name == "derived" {
				store.snapshot.Derived[0].Kind = "prompt"
			} else if name == "initial" {
				store.snapshot.Derived = []api.ResourceFile{file}
			} else if name == "initial_nil" {
				store.snapshot.Derived = nil
			} else {
				store.snapshot.Derived = []api.ResourceFile{}
			}
			result, err = service.OrgValidate(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.Valid {
				t.Fatal("org validation bypassed the shared kind gate", err)
			}
		})
	}
}

func TestOrgBriefShape(t *testing.T) {
	for _, name := range []string{"render", "start"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			call := func() (api.Briefing, error) {
				if name == "render" {
					return service.BriefRender(context.Background(), scope, request)
				}
				return service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: scope.Actor.Level, Role: scope.Actor.Role})
			}
			if result, err := call(); err != nil || result.Markdown.ID == "" {
				t.Fatal("valid briefing inventory was refused", err)
			}
			store.snapshot.Derived = []api.ResourceFile{}
			result, err := call()
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || result.Markdown.ID != "" || len(store.retained) != 1 {
				t.Fatal("briefing accepted the initial derived exception", err)
			}
		})
	}
}

func TestOrgSelectors(t *testing.T) {
	for _, name := range []string{"validate", "render", "bootstrap"} {
		t.Run(name, func(t *testing.T) {
			if name == "bootstrap" {
				service, store, _, scope, request := bootstrapComponent(t)
				result, err := service.OrgBootstrap(context.Background(), scope, request)
				if len(store.orgRequests) != 0 {
					t.Fatal("bootstrap performed an org snapshot read")
				}
				if err != nil || result.ID == "" || result.Status != "pending" || len(store.transactions) != 1 {
					t.Fatal("bootstrap lost its actual pending publication", err)
				}
				if len(store.transactions[0].Compare) != 1 || store.transactions[0].Compare[0] != (api.Compare{Kind: api.CompareOrg, ID: store.target.TargetID, Generation: 0}) {
					t.Fatal("bootstrap lost its atomic absent-org fence")
				}
				return
			}
			service, store, _, scope, request := component(t)
			var err error
			if name == "validate" {
				_, err = service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: store.snapshot.Ref.Generation})
			} else {
				_, err = service.BriefRender(context.Background(), scope, request)
			}
			if err != nil {
				t.Fatal("valid org lookup was refused", err)
			}
			if len(store.orgRequests) != 1 || store.orgRequests[0] != (api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: store.snapshot.Ref.Generation}) {
				t.Fatal("org lookup omitted an exact selector")
			}
		})
	}
}

func TestOrgConfig(t *testing.T) {
	for _, name := range []string{"validate", "render", "lookup"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			if name == "validate" {
				result, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
				if err != nil || !result.Valid {
					t.Fatal("valid org validation failed", err)
				}
			} else if _, err := service.BriefRender(context.Background(), scope, request); err != nil {
				t.Fatal("valid org render failed", err)
			}
			lookups, retained := len(store.orgRequests), len(store.retained)
			sources, metadata, reads := store.sourceCalls, store.metadataCalls, len(store.reads)
			if name == "lookup" {
				// Keep the approved snapshot valid: a foreign provided selector must
				// refuse before lookup, rather than be replaced with the scope ID.
				store.selection.Snapshot.OrgID = "foreign-org"
			} else {
				store.changeSnapshot = func(snapshot *api.OrgSnapshot) { snapshot.Ref.OrgID = "foreign-org" }
			}
			var err error
			if name == "validate" {
				var result api.OrgValidation
				result, err = service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
				if result.Valid {
					t.Fatal("foreign org snapshot produced valid org validation")
				}
			} else {
				var result api.Briefing
				result, err = service.BriefRender(context.Background(), scope, request)
				if result.Markdown.ID != "" {
					t.Fatal("foreign org selection produced a prompt")
				}
			}
			wantCode := api.CodeIntegrity
			if name == "lookup" {
				wantCode = api.CodeConflict
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != wantCode || typed.Owner != "lb-v2-templates" {
				t.Fatalf("foreign org refusal differs from its exact typed fence: got %v; want %s", err, wantCode)
			}
			if name == "lookup" {
				if len(store.orgRequests) != lookups {
					t.Fatal("foreign provided org selector reached snapshot lookup")
				}
			} else {
				if len(store.orgRequests) != lookups+1 || store.orgRequests[lookups] != (api.OrgSnapshotRequest{OrgID: api.ID(scope.Config), Generation: 7}) {
					t.Fatal("foreign snapshot check lost its exact configuration selector")
				}
			}
			if len(store.retained) != retained || store.writes != 0 || store.sourceCalls != sources ||
				store.metadataCalls != metadata || len(store.reads) != reads {
				t.Fatal("foreign org refusal reached retained content or changed state")
			}
		})
	}
}

func TestApprovedSnapshotGuards(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*memoryStore)
		code   api.ErrorCode
	}{
		{"stale", func(s *memoryStore) { s.selection.Snapshot.Generation-- }, api.CodeConflict},
		{"config", func(s *memoryStore) { s.snapshot.Config = "another-config" }, api.CodeIntegrity},
		{"revision", func(s *memoryStore) { s.snapshot.Sources[0].RevisionGeneration = 8 }, api.CodeIntegrity},
		{"source-generation", func(s *memoryStore) { s.snapshot.Sources[0].Source.Generation-- }, api.CodeIntegrity},
		{"source-map", func(s *memoryStore) {
			s.changeSource = func(ref *api.RetainedSource) { ref.Content.ID = "wrong-content" }
		}, api.CodeIntegrity},
		{"hidden-local", func(s *memoryStore) { s.selection.LocalStatus, s.selection.Local = "absent", nil }, api.CodeIntegrity},
		{"local-error", func(s *memoryStore) { s.selection.LocalStatus = "unreadable" }, api.CodeIntegrity},
		{"input-task", func(s *memoryStore) {
			s.changeInput = func(input *api.BriefingInput) { input.Task = nil }
		}, api.CodeIntegrity},
	} {
		t.Run(row.name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			row.change(store)
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 || store.writes != 0 {
				t.Fatal("inconsistent approved snapshot produced a usable prompt")
			}
			errorCode(t, err, row.code)
		})
	}
}

func TestCommittedMetadataGuards(t *testing.T) {
	for _, row := range []struct {
		name   string
		change func(*api.ObjectMetadata)
	}{
		{"class", func(m *api.ObjectMetadata) { m.Ref.Class = "artifact" }},
		{"size", func(m *api.ObjectMetadata) { m.Ref.Bytes++ }},
		{"config", func(m *api.ObjectMetadata) { m.ACL.Config = "another-config" }},
		{"origin", func(m *api.ObjectMetadata) { m.Origin = "" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			store.changeMeta = row.change
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 {
				t.Fatal("caller blob labels overrode committed metadata")
			}
			errorCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestPromptRetentionFailure(t *testing.T) {
	service, store, _, scope, request := component(t)
	failure := &api.Error{Code: api.CodeUnavailable, Message: "fixture retention unavailable", Instead: "Restore fixture storage."}
	store.retainError = failure
	result, err := service.BriefRender(context.Background(), scope, request)
	if !errors.Is(err, failure) || result.Markdown.ID != "" || len(store.retained) != 0 {
		t.Fatal("retention failure became success or a different error")
	}
	store.retainError = nil
	store.changeRetain = func(ref *api.BlobRef) { ref.SHA256 = digest([]byte("another prompt")) }
	result, err = service.BriefRender(context.Background(), scope, request)
	if err == nil || result.Markdown.ID != "" {
		t.Fatal("mismatched retention receipt became a successful prompt")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func TestServiceOrgFallback(t *testing.T) {
	service, store, _, scope, request := component(t)
	store.selection.Local, store.selection.LocalStatus = nil, "absent"
	var sources []api.ResourceFile
	for _, source := range store.snapshot.Sources {
		if source.Source.Path != ".laneboss/L3/roles/executor.md" && source.Source.Path != ".laneboss/L3/roles/executor.toml" {
			sources = append(sources, source)
		}
	}
	store.snapshot.Sources = sources
	result, err := service.BriefRender(context.Background(), scope, request)
	if err != nil {
		t.Fatalf("service fallback rejected the approved org pair: %v", err)
	}
	if result.Template.ID != store.selection.Org.Prompt.Source.ID ||
		!bytes.Contains(store.blobs[result.Markdown.ID], asset(t, "org", "default.md")) {
		t.Fatal("service fallback did not use the explicit approved org pair")
	}
}

func TestHumanOverviewIsReadOnly(t *testing.T) {
	service, store, _, scope, _ := component(t)
	scope.Actor = api.Actor{Kind: "human", ID: "human-one"}
	store.changeInput = func(input *api.BriefingInput) {
		input.Mode, input.Lane, input.Task, input.GrantSet = "overview", nil, nil, nil
	}
	result, err := service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: 3, Role: "executor"})
	if err != nil {
		t.Fatal(err)
	}
	prompt := store.blobs[result.Markdown.ID]
	if store.writes != 0 || len(store.retained) != 1 || store.retained[0].Object.ACL.LifeID != "" ||
		bytes.Contains(prompt, []byte("## Assigned task")) || !bytes.Contains(prompt, []byte("human read-only overview")) {
		t.Fatal("human overview invented an assignment or started lifecycle work")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.Briefing
	if err := templates.DecodeJSON(encoded, &decoded); err != nil {
		t.Fatal("briefing response cannot cross the strict wire decoder")
	}
}

func TestOrgChecksUnselectedRole(t *testing.T) {
	service, store, _, scope, _ := component(t)
	data := []byte("# malformed unselected role\n")
	ref := source("unselected", ".laneboss/L4/roles/supervisor.md", data).Ref
	content := api.BlobRef{ID: "unselected-bytes", Class: "policy", SHA256: ref.SHA256, Bytes: int64(len(data))}
	store.put(content, data)
	store.snapshot.Sources = append(store.snapshot.Sources, api.ResourceFile{Source: ref, Content: content, Kind: "prompt", Mode: 0644, RevisionGeneration: 7})
	result, err := service.OrgValidate(context.Background(), scope, api.OrgValidateRequest{Generation: 7})
	if err == nil || result.Valid || store.writes != 0 {
		t.Fatal("org validation ignored an invalid unselected role pair")
	}
	errorCode(t, err, api.CodeInvalid)
}

func TestBlobExactEnd(t *testing.T) {
	data := []byte("retained bytes and an undeclared suffix")
	prefix := data[:8]
	ref := api.BlobRef{ID: "prefix-fixture", Class: "artifact", Bytes: int64(len(prefix)), SHA256: digest(prefix)}
	actual, err := templates.ReadVerifiedBlob(context.Background(), ref,
		func(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
			end := min(int(request.Offset)+request.Limit, len(data))
			part := data[int(request.Offset):end]
			return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: part, SHA256: digest(part)}, nil
		})
	if err == nil || actual != nil {
		t.Fatal("valid prefix hash hid undeclared object bytes")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func lifecycleComponent(t *testing.T, serviceActor bool) (*templates.Service, *memoryStore, api.Scope, api.TemplateRequest) {
	t.Helper()
	service, store, _, scope, request := component(t)
	requester := scope.Actor
	if serviceActor {
		requester = api.Actor{Kind: "lane", ID: "parent-actor", LifeID: store.input.Lane.ParentLifeID, Level: 5, Role: "supervisor"}
		scope.Actor = api.Actor{Kind: "service", ID: "lifecycle-service"}
		serviceIdentity := scope.Actor
		store.lifecycleService = &serviceIdentity
	}
	start := api.StartRequest{Lane: "fixture-child", Level: request.Context.Level, Role: request.Context.Role,
		Task: request.Task, Driver: api.DriverCodex, Model: "fixture-provider/fixture-model",
		ExpectedPolicyGeneration: store.input.Policy.Generation,
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
			Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	method, input := api.Method("lane.start"), any(start)
	if !serviceActor {
		method, input = "lane.resume", api.ResumeRequest{Target: api.LifeRef{LifeID: store.input.Lane.LifeID, Run: store.input.Lane.Run},
			ExpectedGeneration: store.input.Lane.Generation, Message: store.input.Task}
	}
	params, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request, err = client.PrepareRequest(api.Request{Config: scope.Config, Method: method, Params: params,
		IdempotencyKey: mutationKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	store.reservation = api.MutationReceipt{Config: scope.Config, Actor: requester,
		Key:       api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256},
		Operation: api.Operation{ID: "lifecycle-operation", LifeID: store.input.Lane.LifeID, Status: "pending"}}
	return service, store, scope, request
}

func TestLifecycleRenderReservation(t *testing.T) {
	service, store, scope, request := lifecycleComponent(t, true)
	result, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || result.Markdown.ID == "" || len(store.retained) != 1 {
		t.Fatalf("reserved lifecycle child could not render: %v", err)
	}
	intent := store.retained[0].Intent
	if intent.CauseOperationID != store.reservation.Operation.ID || intent.RequestedBy != store.reservation.Actor ||
		intent.Target.LifeID != store.input.Lane.LifeID || intent.CauseRequestID != scope.Request.RequestID {
		t.Fatal("lifecycle render lost its original operation or requester")
	}
	for _, field := range []string{"config", "key", "principal", "life"} {
		t.Run("receipt-"+field, func(t *testing.T) {
			// Actor equality remains a separate, strict rule for a direct caller.
			// The service's original requester is instead the authentic receipt actor.
			service, store, scope, request := lifecycleComponent(t, field == "config" || field == "key")
			if _, err := service.BriefRender(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			store.changeReceipt = func(receipt *api.MutationReceipt) {
				switch field {
				case "config":
					receipt.Config = "foreign-config"
				case "key":
					receipt.Key.IdempotencyKey = mutationKey(t)
				case "principal":
					receipt.Actor.ID = "foreign-service"
				case "life":
					receipt.Actor.LifeID = "foreign-life"
				}
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 1 {
				t.Fatal("foreign lifecycle receipt retained a child prompt")
			}
			errorCode(t, err, api.CodeIntegrity)
		})
	}
	store.changeReceipt = nil
	store.reservation.Operation.LifeID = "unrelated-life"
	result, err = service.BriefRender(context.Background(), scope, request)
	if err == nil || result.Markdown.ID != "" || len(store.retained) != 1 {
		t.Fatal("unbound lifecycle operation rendered another life’s prompt")
	}
	errorCode(t, err, api.CodeForbidden)
}
