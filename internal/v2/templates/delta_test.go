package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

func (s *memoryStore) PendingEffects(_ context.Context, request api.CursorRequest) ([]api.Effect, error) {
	return append([]api.Effect{}, s.planning[:min(len(s.planning), request.Limit)]...), nil
}

func (s *memoryStore) Effect(_ context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if s.lifecycleService == nil || scope.Actor != *s.lifecycleService || id != s.claim.Effect.ID {
		return api.EffectRecord{}, &api.Error{Code: api.CodeForbidden, Message: "fixture planning claim is outside its service", Instead: "Use the pinned fixture service and effect."}
	}
	return s.claim, nil
}

func (s *memoryStore) LaunchPlan(_ context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	s.planCalls++
	if s.lifecycleService == nil || scope.Actor != *s.lifecycleService || id != s.plan.Reservation.ID {
		return api.LaunchPlanRecord{}, &api.Error{Code: api.CodeNotFound, Message: "fixture launch reservation is absent", Instead: "Use the retained fixture reservation."}
	}
	return s.plan, nil
}

func TestPolicyLive(t *testing.T) {
	for _, refreshed := range []bool{false, true} {
		for _, start := range []bool{false, true} {
			service, store, _, scope, request := component(t)
			store.input.Lane.Run, store.input.Lane.State = 2, "running"
			store.input.Grants.PolicyGeneration, store.input.Lane.PolicyGeneration = 3, 3
			store.input.Policy.Generation, scope.PolicyGeneration = 4, 4
			if refreshed {
				store.input.Lane.PolicyGeneration = 4
			}
			var result api.Briefing
			var err error
			if start {
				result, err = service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: 3, Role: "executor"})
			} else {
				result, err = service.BriefRender(context.Background(), scope, request)
			}
			if err != nil || result.PolicyGeneration != 4 || result.Markdown.ID == "" || store.writes != 0 ||
				store.input.Grants.PolicyGeneration != 3 || !bytes.Contains(store.blobs[result.Markdown.ID], []byte("Policy generation: 4")) {
				t.Fatalf("live policy drift refused or rewrote historical grants: refreshed=%t start=%t err=%v", refreshed, start, err)
			}
		}
	}
}

func TestPolicyOrder(t *testing.T) {
	for _, name := range []string{"zero", "grant", "lane", "scope"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := component(t)
			store.input.Lane.Run, store.input.Lane.State = 2, "running"
			store.input.Grants.PolicyGeneration, store.input.Lane.PolicyGeneration = 3, 3
			store.input.Policy.Generation, scope.PolicyGeneration = 4, 4
			switch name {
			case "zero":
				store.input.Grants.PolicyGeneration = 0
			case "grant":
				store.input.Grants.PolicyGeneration = 4
			case "lane":
				store.input.Lane.PolicyGeneration = 5
			case "scope":
				scope.PolicyGeneration = 5
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 {
				t.Fatal("unordered policy generations retained a prompt")
			}
			errorCode(t, err, api.CodeConflict)
		})
	}
}

func TestPolicyLaunch(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		input := fixture(t)
		input.Lane.Run, input.Lane.State = 1, "preparing"
		input.Grants.PolicyGeneration, input.Lane.PolicyGeneration, input.Policy.Generation = 3, 3, 4
		if explicit {
			input.Lane.State, input.NewLaunch = "", true
		}
		document, err := templates.Render(input)
		if err == nil || len(document.Markdown) != 0 {
			t.Fatal("new launch accepted historical policy generations")
		}
		errorCode(t, err, api.CodeConflict)
	}
}

func planStartBody(task api.BlobRef, policy api.Generation) api.StartRequest {
	return api.StartRequest{Level: 3, Role: "executor", Task: task, Driver: api.DriverCodex,
		ExpectedPolicyGeneration: policy,
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
			Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
}

func planTurnBody(task api.BlobRef, target api.LifeRef, generation api.Generation) api.TurnRequest {
	return api.TurnRequest{Target: target, ExpectedGeneration: generation, MailIDs: []api.ID{}, IdleMessage: &task}
}

func TestPlanFrames(t *testing.T) {
	task := api.BlobRef{ID: "frame-task", Class: "task", Bytes: 1, SHA256: digest([]byte("x"))}
	for _, row := range []struct {
		name string
		body any
	}{
		{"start", planStartBody(task, 9)},
		{"turn", planTurnBody(task, api.LifeRef{LifeID: "frame-life", Run: 1}, 4)},
	} {
		t.Run(row.name, func(t *testing.T) {
			params, err := json.Marshal(row.body)
			if err != nil {
				t.Fatal(err)
			}
			method := api.Method("lane." + row.name)
			prepared, err := client.PrepareRequest(api.Request{Config: "case-templates", Method: method, Params: params, IdempotencyKey: mutationKey(t)})
			if err != nil || prepared.Method != method || !bytes.Equal(prepared.Params, params) || len(prepared.RequestSHA256) != 64 {
				t.Fatalf("launch fixture did not satisfy frozen request shape: %v", err)
			}
			var invalid map[string]any
			if err := json.Unmarshal(params, &invalid); err != nil {
				t.Fatal(err)
			}
			if row.name == "start" {
				invalid["grants"].(map[string]any)["resources"] = nil
			} else {
				invalid["mail_ids"] = nil
			}
			corrupt, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.PrepareRequest(api.Request{Config: "case-templates", Method: method, Params: corrupt, IdempotencyKey: mutationKey(t)})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
				t.Fatal("launch fixture accepted null required arrays")
			}
		})
	}
}

func planComponent(t *testing.T, mode string) (*templates.Service, *memoryStore, api.Scope, api.TemplateRequest) {
	t.Helper()
	_, store, policy, scope, request := component(t)
	scope.Actor, scope.Request = api.Actor{Kind: "service", ID: "lifecycle-service"}, api.Request{}
	serviceIdentity := scope.Actor
	store.lifecycleService = &serviceIdentity
	store.input.Lane.Run, store.input.Lane.Generation, store.input.Lane.State = 2, 5, "preparing"
	store.input.Lane.CancellationEpoch = 2
	data := []byte("# Active turn\nFollow-up bytes, separate from the original task.\n")
	store.input.Task = api.BlobRef{ID: "turn-task", Class: "task", Bytes: int64(len(data)), SHA256: digest(data)}
	store.input.TaskBytes, request.Task = data, store.input.Task
	store.put(request.Task, data)
	r := api.LaunchReservation{ID: "reservation-one", Config: scope.Config, Mode: mode, Level: 3, Role: "executor", Driver: api.DriverCodex,
		Authority: api.LaunchAuthority{Kind: "starter", ID: "previous-launch"}, Target: api.LifeRef{LifeID: store.input.Lane.LifeID, Run: 2},
		LaunchID: "next-launch", SpecID: "next-spec", GrantSetID: request.GrantSetID, Generation: 5, BaseGeneration: 4,
		CancellationEpoch: 2, PolicyGeneration: scope.PolicyGeneration, ParentLifeID: store.input.Lane.ParentLifeID,
		RootLifeID: store.input.Lane.RootLifeID, StarterChain: append([]api.ID{}, store.input.Lane.StarterChain...), StarterEventSeq: store.input.Lane.StarterEventSeq,
		OperationID: "plan-operation", RequestID: mutationKey(t), RequestSHA256: digest([]byte("retained continuation intent")),
		RequestedBy: api.Actor{Kind: "watchdog", ID: "watchdog-one"}, PreviousLaunchID: "previous-launch",
		OriginalRequest: api.BlobRef{ID: "original-request", Class: "launch_request", Bytes: 1, SHA256: digest([]byte("x"))}}
	if mode != "continue" {
		r.RequestedBy = api.Actor{Kind: "lane", ID: "parent-actor", LifeID: r.ParentLifeID, Level: 5, Role: "supervisor"}
		var body any = api.ResumeRequest{Target: api.LifeRef{LifeID: r.Target.LifeID, Run: 1}, ExpectedGeneration: 4, Message: request.Task}
		if mode == "start" || mode == "adopt" {
			r.Target.Run, r.Generation, r.BaseGeneration, r.PreviousLaunchID = 1, 1, 0, ""
			store.input.Lane.Run, store.input.Lane.Generation = 1, 1
			store.input.Lane.Task = request.Task
			body = planStartBody(request.Task, scope.PolicyGeneration)
		} else if mode == "turn" {
			body = planTurnBody(request.Task, api.LifeRef{LifeID: r.Target.LifeID, Run: 1}, 4)
		}
		params, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		scope.Request, err = client.PrepareRequest(api.Request{Config: scope.Config, Method: api.Method("lane." + mode), Params: params, IdempotencyKey: mutationKey(t)})
		if err != nil {
			t.Fatal(err)
		}
		r.RequestID, r.RequestSHA256 = scope.Request.RequestID, scope.Request.RequestSHA256
	}
	store.plan = api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	cause := &api.InternalIntent{ID: "plan-intent", Kind: api.InternalLaunchPlan, Config: scope.Config, Actor: scope.Actor,
		RequestedBy: r.RequestedBy, CauseRequestID: r.RequestID, CauseOperationID: r.OperationID, EffectID: "plan-effect", Target: r.Target, CancellationEpoch: r.CancellationEpoch}
	effect := api.Effect{ID: "plan-effect", OperationID: r.OperationID, Context: cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}
	store.planning = []api.Effect{effect}
	store.claim = api.EffectRecord{Effect: effect, Generation: 2, State: api.EffectClaimed, ClaimID: "claim-one", ClaimantID: scope.Actor.ID, ClaimExpiresAt: "2030-01-01T00:10:00Z"}
	request.Claim = api.PlanningClaim(r.ID, api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt})
	service, err := templates.New(templates.Dependencies{Store: store, Policy: policy, Clock: fixtureClock{now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.ValidateLaunchPlanRecord(store.plan); err != nil {
		t.Fatal(err)
	}
	return service, store, scope, request
}

func sourcePlan(t *testing.T, store *memoryStore) {
	t.Helper()
	r := store.plan.Reservation
	project := api.BlobRef{ID: "project-object", Class: "manifest", Bytes: 1, SHA256: digest([]byte("p"))}
	runtime := api.BlobRef{ID: "runtime-manifest", Class: "manifest", Bytes: 1, SHA256: digest([]byte("r"))}
	grants := store.input.Grants
	grants.ExpiresAt = "2030-01-01T00:10:00Z"
	grants.Data = append([]api.DataGrant{}, grants.Data...)
	grants.Data[0].SourceObjectID, grants.Data[0].SourceSHA256, grants.Data[0].HistoryScope = project.ID, project.SHA256, "tree"
	store.input.Grants = grants
	store.plan.Phase, store.plan.Generation = "sourced", 2
	store.plan.Inputs = &api.LaunchInputs{Grants: grants, Sources: api.LaunchSources{ReservationID: r.ID,
		Project: api.ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1, ProjectID: "project-one",
			GrantID: grants.Data[0].ID, Object: project, Base: strings.Repeat("a", 40), HistoryScope: "tree"},
		Runtime: api.LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: r.Driver,
			Executable: api.Executable{ID: "runtime-one", SHA256: digest([]byte("runtime")), Version: "fixture-v2"}, Manifest: runtime}}}
	if err := api.ValidateLaunchPlanRecord(store.plan); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRender(t *testing.T) {
	for _, mode := range []string{"start", "resume", "turn", "continue"} {
		t.Run(mode, func(t *testing.T) {
			for _, sourced := range []bool{false, true} {
				service, store, scope, request := planComponent(t, mode)
				if sourced {
					sourcePlan(t, store)
				}
				result, err := service.BriefRender(context.Background(), scope, request)
				if err != nil || result.Markdown.ID == "" || len(store.retained) != 1 || store.planCalls != 1 ||
					!bytes.HasSuffix(store.blobs[result.Markdown.ID], store.input.TaskBytes) || store.writes != 0 {
					t.Fatalf("reserved launch could not render its active task: sourced=%t err=%v", sourced, err)
				}
				intent, r := store.retained[0].Intent, store.plan.Reservation
				if intent.RequestedBy != r.RequestedBy || intent.CauseOperationID != r.OperationID || intent.CauseRequestID != r.RequestID || intent.Target != r.Target {
					t.Fatal("planned prompt lost its original continuation cause")
				}
			}
		})
	}
}

func TestPlanGuards(t *testing.T) {
	for _, name := range []string{"config", "target", "phase", "claim", "requester", "input"} {
		t.Run(name, func(t *testing.T) {
			service, store, scope, request := planComponent(t, "continue")
			switch name {
			case "config":
				store.plan.Reservation.Config = "foreign"
			case "target":
				store.plan.Reservation.Target.LifeID = "foreign-life"
			case "phase":
				store.plan.Phase, store.plan.Error = "failed", &api.Error{Code: api.CodeConflict, Owner: "fixture", Message: "failed plan", Instead: "Reconcile it."}
			case "claim":
				store.claim.ClaimExpiresAt = "2029-01-01T00:00:00Z"
			case "requester":
				store.plan.Reservation.RequestedBy.ID = "foreign-requester"
			case "input":
				store.input.Lane.Run++
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.retained) != 0 || name != "input" && len(store.inputRequests) != 0 {
				t.Fatal("invalid planning authority reached briefing inputs or retained a prompt")
			}
		})
	}
}

func TestPlanMatch(t *testing.T) {
	for _, field := range []string{"grants", "launch", "continue"} {
		t.Run(field, func(t *testing.T) {
			mode := "resume"
			if field == "continue" {
				mode = "continue"
			}
			service, store, scope, request := planComponent(t, mode)
			r := store.plan.Reservation
			if mode != "continue" {
				// A real receipt would permit the legacy route. A matched plan
				// mismatch must stop before that fallback can be attempted.
				store.reservation = api.MutationReceipt{Config: scope.Config, Actor: r.RequestedBy,
					Key:       api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256},
					Operation: api.Operation{ID: r.OperationID, LifeID: r.Target.LifeID, Status: "pending"}}
			}
			valid, err := service.BriefRender(context.Background(), scope, request)
			if err != nil || valid.Markdown.ID == "" || len(store.retained) != 1 || store.receiptCalls != 0 || store.planCalls != 1 {
				t.Fatalf("valid matched plan did not render before corruption: %v", err)
			}
			if field == "grants" {
				store.plan.Reservation.GrantSetID = "foreign-grants"
				store.claim.ClaimExpiresAt = "2029-01-01T00:00:00Z"
			} else {
				scope.LaunchID = "foreign-launch"
				store.plan.Phase, store.plan.Error = "failed", &api.Error{Code: api.CodeConflict, Owner: "fixture", Message: "failed plan", Instead: "Reconcile it."}
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "briefing launch reservation differs from its current causal effect" ||
				result.Markdown.ID != "" || len(store.retained) != 1 || len(store.inputRequests) != 1 || store.receiptCalls != 0 || store.planCalls != 2 {
				t.Fatalf("matched plan mismatch did not fail before fallback: field=%s err=%v", field, err)
			}
		})
	}
}

func TestServicePreflight(t *testing.T) {
	for _, name := range []string{"label", "missing", "digest"} {
		t.Run(name, func(t *testing.T) {
			service, store, scope, request := lifecycleComponent(t, true)
			switch name {
			case "label":
				scope.Request.Method = "brief.render"
			case "missing":
				scope.Request.IdempotencyKey = ""
			case "digest":
				scope.Request.RequestSHA256 = digest([]byte("foreign intent"))
			}
			result, err := service.BriefRender(context.Background(), scope, request)
			if err == nil || result.Markdown.ID != "" || len(store.inputRequests) != 0 || len(store.retained) != 0 {
				t.Fatal("service causal preconditions ran after briefing input selection")
			}
		})
	}
}

func TestTurnTask(t *testing.T) {
	service, store, _, scope, request := component(t)
	original := store.input.Lane.Task
	store.input.Lane.Run, store.input.Lane.State = 2, "running"
	data := []byte("# Current turn task\nExact continuation task bytes.\n")
	active := api.BlobRef{ID: "active-task", Class: "task", Bytes: int64(len(data)), SHA256: digest(data)}
	store.put(active, data)
	store.input.Task, store.input.TaskBytes, request.Task = active, data, active
	result, err := service.BriefRender(context.Background(), scope, request)
	if err != nil || result.Markdown.ID == "" || !bytes.HasSuffix(store.blobs[result.Markdown.ID], data) {
		t.Fatalf("active turn task was confused with original life task: %v", err)
	}
	_, err = service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: 3, Role: "executor"})
	errorCode(t, err, api.CodeIntegrity)
	store.changeInput = func(input *api.BriefingInput) { input.Task = &original }
	result, err = service.BriefStart(context.Background(), scope, api.BriefingRequest{Level: 3, Role: "executor"})
	if err != nil || result.Markdown.ID == "" || !bytes.HasSuffix(store.blobs[result.Markdown.ID], store.blobs[original.ID]) {
		t.Fatalf("start did not retain the original life task: %v", err)
	}
}

func markPresence(t *testing.T, store *memoryStore, scope *api.Scope, marked bool) {
	t.Helper()
	scope.Request.Proof.SimulatedPresence = marked
	store.proof.Ref, store.proof.SimulatedPresence = *scope.Request.Proof, marked
	store.reservation.SimulatedPresence = marked
	reframe(t, store, scope)
}

func TestBootPresence(t *testing.T) {
	for _, marked := range []bool{false, true} {
		service, store, human, scope, request := bootstrapComponent(t)
		markPresence(t, store, &scope, marked)
		operation, err := service.OrgBootstrap(context.Background(), scope, request)
		if err != nil || operation.ID == "" || operation.SimulatedPresence != marked || len(store.transactions) != 1 {
			t.Fatalf("bootstrap lost verified presence provenance: marked=%t err=%v", marked, err)
		}
		var queued api.Operation
		if err := json.Unmarshal(store.transactions[0].Reply.Result, &queued); err != nil {
			t.Fatal(err)
		}
		if queued.SimulatedPresence != marked || store.transactions[0].Guards[0].Proof.Proof.SimulatedPresence != marked {
			t.Fatal("bootstrap queued operation lost verified presence provenance")
		}
		replay, err := service.OrgBootstrap(context.Background(), scope, request)
		if err != nil || replay != operation || replay.SimulatedPresence != marked || len(store.transactions) != 1 || human.calls != 1 {
			t.Fatalf("bootstrap replay changed verified presence provenance: %v", err)
		}
	}
}

func TestBootPresenceGuard(t *testing.T) {
	for _, name := range []string{"verified", "receipt", "commit", "reply", "replay", "upgrade"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, scope, request := bootstrapComponent(t)
			markPresence(t, store, &scope, name != "receipt" && name != "upgrade" && name != "verified")
			code := api.CodeIntegrity
			switch name {
			case "verified":
				store.proof.SimulatedPresence = true
				code = api.CodeForbidden
			case "receipt":
				store.reservation.SimulatedPresence = true
				code = api.CodeForbidden
			case "commit":
				store.changeCommit = func(commit *api.Commit) { commit.Operation.SimulatedPresence = false }
			case "reply":
				store.changeCommit = func(commit *api.Commit) {
					operation := commit.Operation
					operation.SimulatedPresence = false
					data, err := json.Marshal(operation)
					if err != nil {
						t.Fatal(err)
					}
					commit.Reply = &api.RPCReply{Result: data}
				}
			case "replay", "upgrade":
				if _, err := service.OrgBootstrap(context.Background(), scope, request); err != nil {
					t.Fatal(err)
				}
				operation := store.reservation.Operation
				operation.SimulatedPresence = !operation.SimulatedPresence
				data, err := json.Marshal(operation)
				if err != nil {
					t.Fatal(err)
				}
				store.reservation.Reply = &api.RPCReply{Result: data}
			}
			operation, err := service.OrgBootstrap(context.Background(), scope, request)
			if err == nil || operation.ID != "" {
				t.Fatal("bootstrap accepted changed presence provenance")
			}
			errorCode(t, err, code)
			if (name == "verified" || name == "receipt") && len(store.transactions) != 0 {
				t.Fatal("invalid presence provenance reached the bootstrap transaction")
			}
		})
	}
}

func TestBootPresenceUnion(t *testing.T) {
	service, store, _, scope, request := bootstrapComponent(t)
	markPresence(t, store, &scope, false)
	store.reservation.Operation.SimulatedPresence = true
	operation, err := service.OrgBootstrap(context.Background(), scope, request)
	if err != nil || !operation.SimulatedPresence {
		t.Fatalf("bootstrap dropped earlier simulated authority: %v", err)
	}
	replay, err := service.OrgBootstrap(context.Background(), scope, request)
	if err != nil || !replay.SimulatedPresence || len(store.transactions) != 1 {
		t.Fatalf("bootstrap replay dropped combined presence provenance: %v", err)
	}
}
