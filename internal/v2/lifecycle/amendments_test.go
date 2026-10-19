package lifecycle

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixtureFrame struct {
	api.FrameContext
	raw []byte
}

func (frame *fixtureFrame) Bytes() []byte { return frame.raw }

func TestStopAtomicContext(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.State, lane.CancellationEpoch = "running", 7
	f.store.lanes[lane.LifeID] = lane
	request := api.StopRequest{Target: f.target, ExpectedGeneration: lane.Generation,
		Reason: f.blob("reason", "task", []byte("stop with durable context\n"))}
	scope := f.scope("lane.stop", request, f.parent)
	// scope already owns one actual dispatcher invocation. Replacing Frame
	// here creates a retry observer, even when its bytes are identical.
	raw := append([]byte{}, scope.Frame.Bytes()...)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	pending, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := f.service.ownsMutation(context.Background(), scope, key, pending)
	if err != nil || !owned {
		t.Fatalf("stop lost its registered invocation: %v", err)
	}
	operation, err := f.service.LaneStop(context.Background(), scope, request)
	if err != nil || operation.Status != "pending" || len(f.store.transactions) != 1 || f.store.awaitCalls != 0 {
		t.Fatalf("stop lost its durable pending operation: %v", err)
	}
	tx := f.store.transactions[0]
	if len(tx.Writes.Lanes) != 1 || tx.Writes.Lanes[0].State != "stopping" ||
		tx.Writes.Lanes[0].CancellationEpoch != lane.CancellationEpoch+1 ||
		f.store.lanes[lane.LifeID].CancellationEpoch != lane.CancellationEpoch+1 {
		t.Fatal("stop omitted durable cancellation epoch")
	}
	if len(tx.Guards) != 1 || tx.Guards[0].Cancellation == nil ||
		*tx.Guards[0].Cancellation != (api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}) {
		t.Fatal("stop omitted the atomic cancellation guard")
	}
	if len(tx.Effects) != 1 || tx.Effects[0].Context == nil {
		t.Fatal("stop omitted its causal effect context")
	}
	effect := tx.Effects[0]
	cause := effect.Context
	if cause.Kind != api.InternalLifecycleEffect || cause.Config != scope.Config ||
		cause.Actor.Kind != "service" || cause.RequestedBy != scope.Actor ||
		cause.CauseOperationID != operation.ID || cause.CauseRequestID != scope.Request.RequestID ||
		cause.EffectID != effect.ID || cause.Target != f.target ||
		cause.LogicalTurnID != lane.LogicalTurnID || cause.CancellationEpoch != lane.CancellationEpoch+1 {
		t.Fatal("stop lost the actual causal requester or epoch")
	}
	if !bytes.Equal(tx.RawRequest, raw) || tx.Reply == nil {
		t.Fatal("stop lost original frame bytes or typed reply")
	}
	var retained api.Operation
	if api.DecodeObject(tx.Reply.Result, &retained) != nil || retained.ID != operation.ID ||
		retained.Status != "pending" || f.launcher.stopped.Load() != 0 {
		t.Fatal("stop fabricated completion instead of retaining its pending reply")
	}
}

func TestHumanCommitGuard(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			review := fixtureReview(f)
			human := api.Actor{Kind: "human", ID: "reviewing-human"}
			review.Reviewer = human
			f.add("lane.reviewed", review, 2, "service", human)
			request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1,
				State: "accepted", Review: review}
			scope := f.prepareScope("lane.mark", request, human)
			if mode != "missing" {
				scope.Request.Proof = &api.ProofRef{ID: "proof", RequestSHA256: scope.Request.RequestSHA256}
			}
			scope = f.reserveScope(scope)
			if mode == "wrong-target" {
				f.store.targetHook = func(target api.HumanChallengeRequest) api.HumanChallengeRequest {
					target.TargetID = "another-life"
					return target
				}
			}
			_, err := f.service.LaneMark(context.Background(), scope, request)
			if mode != "valid" {
				want := api.CodeForbidden
				if mode == "wrong-target" {
					want = api.CodeIntegrity
				}
				if typed, ok := err.(*api.Error); !ok || typed.Code != want || len(f.store.transactions) != 0 {
					t.Fatalf("human proof barrier admitted missing or mismatched authority: %v", err)
				}
				return
			}
			if len(f.store.attempts) != 1 {
				t.Fatalf("confirmed human mark did not submit its guarded intent: %v", err)
			}
			tx := f.store.attempts[0]
			var proof *api.ProofUse
			for _, guard := range tx.Guards {
				if guard.Proof != nil {
					if proof != nil {
						t.Fatal("human mark duplicated its proof guard")
					}
					proof = guard.Proof
				}
			}
			if proof == nil || proof.Proof != *scope.Request.Proof || proof.Target.TargetID != f.target.LifeID ||
				proof.Target.Method != "lane.mark" || proof.Target.BaseGeneration != 1 ||
				proof.Target.RequestSHA256 != scope.Request.RequestSHA256 {
				t.Fatal("human mutation omitted its exact atomic proof guard")
			}
			if err != nil || len(f.store.transactions) != 1 {
				t.Fatalf("confirmed human mark could not commit: %v", err)
			}
		})
	}
}

func TestInputMetadataBinding(t *testing.T) {
	for _, mode := range []string{"class", "config"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			ref := f.blob("input", "task", []byte("retained task\n"))
			scope := f.scope("lane.check", f.target, f.parent)
			if data, err := f.service.readBlob(context.Background(), scope, ref); err != nil ||
				!bytes.Equal(data, f.store.blobs[ref.ID]) {
				t.Fatalf("committed input was not readable: %v", err)
			}
			if mode == "class" {
				ref.Class = "prompt"
			} else {
				metadata := f.store.metadata[ref.ID]
				metadata.ACL.Config = "unrelated"
				f.store.metadata[ref.ID] = metadata
			}
			reads := 0
			f.store.blobHook = func(chunk api.BlobChunk) (api.BlobChunk, error) {
				reads++
				return chunk, nil
			}
			_, err := f.service.readBlob(context.Background(), scope, ref)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || reads != 0 {
				t.Fatalf("forged object metadata was consumed: %v", err)
			}
		})
	}
}

func TestHistoryRequired(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.Session.HistoryID = ""
	f.store.lanes[lane.LifeID] = lane
	request := api.ResumeRequest{Target: f.target, ExpectedGeneration: lane.Generation,
		Message: f.blob("message", "task", []byte("continue\n")), Budget: f.budget}
	_, err := f.service.LaneResume(context.Background(), f.scope("lane.resume", request, f.parent), request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodePrerequisite {
		t.Fatalf("resume omitted retained private history identity: %v", err)
	}
}

func TestPolicyRoleBinding(t *testing.T) {
	f := newFixture(t)
	executor := api.Actor{Kind: "lane", ID: "executor", LifeID: f.child.LifeID, Level: f.child.Level, Role: f.child.Role}
	scope := f.scope("lane.check", f.target, executor)
	calls := 0
	forged := false
	f.store.briefingHook = func(actual api.Scope, input api.BriefingInput) api.BriefingInput {
		calls++
		if actual.Actor != scope.Actor || input.Lane == nil || input.Lane.LifeID != f.target.LifeID {
			t.Fatal("target policy lookup borrowed another principal")
		}
		if forged {
			input.Policy.Context = api.RoleContext{Level: f.parent.Level, Role: f.parent.Role}
		}
		return input
	}
	policy, err := f.service.policyForLane(context.Background(), scope, f.child)
	if err != nil || policy.Context.Level != f.child.Level || policy.Context.Role != f.child.Role {
		t.Fatalf("target role policy was not resolved: %v", err)
	}
	forged = true
	_, err = f.service.policyForLane(context.Background(), scope, f.child)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || calls != 2 {
		t.Fatalf("target policy accepted the requester's role: %v", err)
	}
	_, err = f.service.policyForLane(context.Background(), f.scope("lane.check", f.target, f.parent), f.child)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented || calls != 2 {
		t.Fatalf("parent policy crossed the own-life briefing boundary: %v", err)
	}
}

type fixtureReadView struct {
	snapshot api.ReadSnapshot
	closed   bool
}

func (view *fixtureReadView) Snapshot() api.ReadSnapshot { return view.snapshot }
func (view *fixtureReadView) Close() error {
	view.closed = true
	return nil
}

func TestBorrowedReadView(t *testing.T) {
	f := newFixture(t)
	initial := f.add("run.observed", f.launcher.observation, 2, "service", f.parent)
	request := api.EventTailRequest{LifeID: "child", Run: 2, Follow: true,
		Until: "lane.ended", DeadlineMS: 2000}
	scope := f.scope("event.tail", request, f.parent)
	view := &fixtureReadView{snapshot: api.ReadSnapshot{ID: "snapshot", Config: scope.Config, LastSeq: initial.Seq}}
	scope.ReadView = view
	page, err := f.service.EventTail(context.Background(), scope, request)
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("initial pinned snapshot was lost: %v", err)
	}
	stream, err := f.service.OpenEvents(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if stream.(*eventStream).scope.ReadView != nil || view.closed {
		t.Fatal("live stream retained or closed the borrowed read view")
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	selected := f.ended()
	frame, err := stream.Next(context.Background())
	if err != nil || frame.Event == nil || frame.Event.Seq != selected.Seq {
		t.Fatalf("live stream repeated its initial snapshot: %v", err)
	}
	end, err := stream.Next(context.Background())
	if err != nil || !end.End || end.Index != 2 {
		t.Fatalf("live stream lost its separate terminal frame: %v", err)
	}
}

func TestCheckReplyReplay(t *testing.T) {
	f := newFixture(t)
	f.ended()
	scope := f.scope("lane.check", f.target, f.parent)
	first, err := f.service.LaneCheck(context.Background(), scope, f.target)
	if err != nil {
		t.Fatal(err)
	}
	f.launcher.observation.State = "running"
	f.launcher.observation.ExitCode = nil
	scope.Request.RequestID, err = newID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.service.LaneCheck(context.Background(), scope, f.target)
	if err != nil || !reflect.DeepEqual(first, second) ||
		len(f.store.transactions) != 1 || f.launcher.observed.Load() != 1 {
		t.Fatalf("check retry re-observed instead of replaying its exact reply: %v", err)
	}
	f.identity.denied.Store(true)
	_, err = f.service.LaneCheck(context.Background(), scope, f.target)
	requireCode(t, err, api.CodeForbidden)
}

func TestUnknownReplyReplay(t *testing.T) {
	f := newFixture(t)
	f.ended()
	f.launcher.observation.State = "unknown"
	f.launcher.observation.ExitCode, f.launcher.observation.Survivors = nil, nil
	scope := f.scope("lane.check", f.target, f.parent)
	_, first := f.service.LaneCheck(context.Background(), scope, f.target)
	if typed, ok := first.(*api.Error); !ok || typed.Code != api.CodeContainmentUnknown {
		t.Fatalf("unknown check reply changed into success: %v", first)
	}
	if len(f.store.transactions) != 1 || f.store.transactions[0].Reply.Error != first {
		t.Fatal("unknown check reply differs from its durable error")
	}
	var ended api.RunEndEvent
	if err := api.DecodeObject(f.store.events[0].Payload, &ended); err != nil {
		t.Fatal(err)
	}
	f.launcher.observation = ended.Observation
	_, second := f.service.LaneCheck(context.Background(), scope, f.target)
	if second != first || len(f.store.transactions) != 1 || f.launcher.observed.Load() != 1 {
		t.Fatalf("unknown check reply was not replayed exactly: %v", second)
	}
}

func TestContinuationStaleEpoch(t *testing.T) {
	f := newFixture(t)
	request := fixtureContinuation(f)
	scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"},
		Source: "watchdog", PolicyGeneration: f.store.policy.Generation}
	_, err := f.service.Continue(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented {
		t.Fatalf("valid continuation did not reach the actual launch barrier: %v", err)
	}
	lane := f.child
	lane.CancellationEpoch = 1
	f.store.lanes[lane.LifeID] = lane
	_, err = f.service.Continue(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict {
		t.Fatalf("stale continuation epoch passed its cancellation gate: %v", err)
	}
	if len(f.store.transactions) != 0 || f.launcher.prepared.Load() != 0 ||
		f.service.deps.Credentials.(*fixtureCredentials).acquired.Load() != 0 {
		t.Fatal("stale continuation prepared another run")
	}
}

func TestRootTicketBinding(t *testing.T) {
	for _, mode := range []string{"valid", "redeemed", "expired", "role", "principal", "config", "endpoint"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			request := fixtureStart(f)
			request.RootTicketID = "ticket"
			ticket := api.Ticket{ID: "ticket", Level: request.Level, Role: request.Role,
				GrantSetID: "root-grants", ExpiresAt: "2031-01-01T00:00:00Z",
				PrincipalID: "root-human", Config: "example", EndpointGeneration: 1}
			switch mode {
			case "redeemed":
				ticket.Redeemed = true
			case "expired":
				ticket.ExpiresAt = "2029-01-01T00:00:00Z"
			case "role":
				ticket.Role = "another-role"
			case "principal":
				ticket.PrincipalID = "another-human"
			case "config":
				ticket.Config = "unrelated"
			case "endpoint":
				ticket.EndpointGeneration++
			}
			f.store.tickets[ticket.ID] = ticket
			human := api.Actor{Kind: "human", ID: "root-human"}
			_, err := f.service.LaneStart(context.Background(), f.scope("lane.start", request, human), request)
			want := api.CodeForbidden
			if mode == "valid" {
				want = api.CodeNotImplemented
			}
			if typed, ok := err.(*api.Error); !ok || typed.Code != want {
				t.Fatalf("root ticket scope or one-use check changed: %v", err)
			}
			if len(f.store.transactions) != 0 || f.store.tickets[ticket.ID] != ticket ||
				f.launcher.prepared.Load() != 0 || f.launcher.launched.Load() != 0 {
				t.Fatal("root ticket was consumed without a complete launch intent")
			}
		})
	}
}

type fixtureWatchdog struct{ api.Watchdog }

func TestProofBeforeReplay(t *testing.T) {
	f := newFixture(t)
	f.ended()
	review := fixtureReview(f)
	human := api.Actor{Kind: "human", ID: "reviewing-human"}
	review.Reviewer = human
	f.add("lane.reviewed", review, f.target.Run, "service", human)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: review}
	scope := f.prepareScope("lane.mark", request, human)
	scope.Request.Proof = &api.ProofRef{ID: "proof", RequestSHA256: scope.Request.RequestSHA256}
	scope = f.reserveScope(scope)
	if _, err := f.service.LaneMark(context.Background(), scope, request); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"empty-id", "digest", "lane"} {
		t.Run(mode, func(t *testing.T) {
			bad := scope
			proof := *scope.Request.Proof
			bad.Request.Proof = &proof
			want := api.CodeInvalid
			switch mode {
			case "empty-id":
				proof.ID = ""
			case "digest":
				proof.RequestSHA256 = digestOf([]byte("another operation"))
			case "lane":
				bad.Actor, want = f.parent, api.CodeForbidden
			}
			before := f.store.lookupCalls
			_, err := f.service.LaneMark(context.Background(), bad, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != want ||
				f.store.lookupCalls != before || len(f.store.transactions) != 1 {
				t.Fatalf("invalid proof reached receipt replay: %v", err)
			}
		})
	}
}

func TestReceiptBinding(t *testing.T) {
	f := newFixture(t)
	f.ended()
	review := fixtureReview(f)
	f.add("lane.reviewed", review, f.target.Run, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: 1, State: "accepted", Review: review}
	scope := f.scope("lane.mark", request, f.parent)
	first, err := f.service.LaneMark(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey,
		RequestSHA256: scope.Request.RequestSHA256}
	retained, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil || retained.Config != scope.Config || retained.Actor != scope.Actor || retained.Key != key {
		t.Fatalf("receipt fixture lost the original request binding: %v", err)
	}
	for _, mode := range []string{"config", "principal", "life", "kind", "method", "key", "digest"} {
		t.Run(mode, func(t *testing.T) {
			foreign := retained
			switch mode {
			case "config":
				foreign.Config = "unrelated"
			case "principal":
				foreign.Actor.ID = "another-principal"
			case "life":
				foreign.Actor.LifeID = "another-life"
			case "kind":
				foreign.Actor.Kind = "worker"
			case "method":
				foreign.Key.Method = "lane.stop"
			case "key":
				foreign.Key.IdempotencyKey = "another-key"
			case "digest":
				foreign.Key.RequestSHA256 = digestOf([]byte("different request"))
			}
			f.store.lookupOverride = &foreign
			_, err := f.service.LaneMark(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(f.store.transactions) != 1 {
				t.Fatalf("foreign lifecycle receipt was replayed: %v", err)
			}
			f.store.lookupOverride = nil
		})
	}
	t.Run("before-await", func(t *testing.T) {
		foreign := retained
		foreign.Config, foreign.Reply = "unrelated", nil
		f.store.lookupOverride, f.store.awaitOverride = &foreign, &retained
		before := f.store.awaitCalls
		_, err := f.service.LaneMark(context.Background(), scope, request)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || f.store.awaitCalls != before {
			t.Fatalf("foreign pending receipt reached await: %v", err)
		}
	})
	t.Run("after-await", func(t *testing.T) {
		pending, foreign := retained, retained
		pending.Reply, foreign.Actor.ID = nil, "another-principal"
		f.store.lookupOverride, f.store.awaitOverride = &pending, &foreign
		_, err := f.service.LaneMark(context.Background(), scope, request)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
			t.Fatalf("foreign awaited receipt was replayed: %v", err)
		}
	})
	f.store.lookupOverride, f.store.awaitOverride = nil, nil
	replayed, err := f.service.LaneMark(context.Background(), scope, request)
	if err != nil || replayed != first || len(f.store.transactions) != 1 {
		t.Fatalf("binding checks changed the original lifecycle reply: %v", err)
	}
}

func TestReleaseEventEvidence(t *testing.T) {
	for _, mode := range []string{"valid", "nonzero", "unknown", "target", "operation"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			zero := uint64(0)
			release := api.ReleaseReceipt{ID: "release", LeaseID: "lease", ContainmentID: "containment",
				Backend: "linux-bwrap-landlock", OperationID: "release-operation", EffectID: "release-effect",
				Quiescence: f.launcher.observation, LiveConnections: &zero, QueuedJobs: &zero, WritableExports: &zero,
				ObservedAt: "2030-01-02T03:04:05Z"}
			switch mode {
			case "nonzero":
				nonzero := uint64(1)
				release.WritableExports = &nonzero
			case "unknown":
				release.LiveConnections = nil
			case "target":
				release.Quiescence.Handle.Target.LifeID = "another-life"
			}
			event := f.add("helper.released", release, f.target.Run, "service", f.parent)
			event.OperationID = release.OperationID
			if mode == "operation" {
				event.OperationID = "another-operation"
			}
			request := api.EventTailRequest{LifeID: f.target.LifeID, Run: f.target.Run}
			selected, err := selectedEvent(f.scope("event.tail", request, f.parent), f.child, request, event)
			if mode == "valid" {
				if err != nil || !selected {
					t.Fatalf("correlated helper receipt was not readable: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || selected {
				t.Fatalf("unmeasured release was delivered: %v", err)
			}
		})
	}
}

func TestRootTicketClass(t *testing.T) {
	for _, mode := range []string{"human-on-lane", "lane-on-human", "worker", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			request := fixtureStart(f)
			request.RootTicketID = "ticket"
			f.store.tickets[request.RootTicketID] = api.Ticket{ID: request.RootTicketID,
				Level: request.Level, Role: request.Role, GrantSetID: "root-grants", ExpiresAt: "2031-01-01T00:00:00Z",
				PrincipalID: "root-human", Config: "example", EndpointGeneration: 1}
			human := api.Actor{Kind: "human", ID: "root-human"}
			scope := f.scope("lane.start", request, human)
			connection := scope.Connection.(*fixtureConnection)
			switch mode {
			case "human-on-lane":
				connection.binding.Class = api.EndpointLane
			case "lane-on-human":
				scope.Actor = f.parent
			case "worker":
				connection.binding.Class = api.EndpointWorker
				scope.Actor.Kind = "worker"
			case "stale":
				connection.binding.EndpointGeneration++
			}
			_, err := f.service.LaneStart(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeForbidden || f.store.ticketReads != 0 {
				t.Fatalf("ticket lookup crossed its human endpoint binding: %v", err)
			}
		})
	}
}

func TestLaneCounterBounds(t *testing.T) {
	for _, field := range []string{"epoch", "failures", "retries"} {
		t.Run(field, func(t *testing.T) {
			f := newFixture(t)
			scope := f.scope("lane.status", f.target, f.parent)
			if _, err := f.service.LaneStatus(context.Background(), scope, f.target); err != nil {
				t.Fatalf("valid lifecycle counters became unavailable: %v", err)
			}
			lane := f.child
			switch field {
			case "epoch":
				lane.CancellationEpoch = api.Generation(maxInteger + 1)
			case "failures":
				lane.Counters.Failures = maxInteger + 1
			case "retries":
				lane.Counters.Retries = maxInteger + 1
			}
			f.store.lanes[lane.LifeID] = lane
			_, err := f.service.LaneStatus(context.Background(), scope, f.target)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("unsafe lifecycle counter was exposed: %v", err)
			}
		})
	}
}

func TestWatchdogBinding(t *testing.T) {
	f := newFixture(t)
	var missing *fixtureWatchdog
	requireCode(t, f.service.BindWatchdog(missing), api.CodePrerequisite)
	first, second := &fixtureWatchdog{}, &fixtureWatchdog{}
	if err := f.service.BindWatchdog(first); err != nil || f.service.watchdog != first {
		t.Fatalf("watchdog dependency was not bound: %v", err)
	}
	if err := f.service.BindWatchdog(second); err == nil || f.service.watchdog != first {
		t.Fatal("watchdog binding replaced a live runtime dependency")
	} else {
		requireCode(t, err, api.CodeConflict)
	}
}
