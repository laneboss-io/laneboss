package service

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type reviewControlPort interface {
	ResolveReview(context.Context, api.Scope, api.LifeRef) (api.ReviewSubject, []string, error)
	PrepareReview(context.Context, api.Scope, api.ReviewRequest, api.Generation, api.ID, api.Sequence) (api.ReviewVerifyRequest, error)
}

// Transport, snapshot and policy are explicit component boundaries. This
// tests the coordinator's authentic selector checks, not a native launch.
type reviewContextState struct {
	*unusedStore
	lane     api.Lane
	subject  api.ReviewSubject
	capture  api.CaptureState
	end      api.Event
	objects  map[api.ID][]byte
	metadata map[api.ID]api.ObjectMetadata
	reads    int
}

func (f *reviewContextState) BeginRead(_ context.Context, scope api.Scope) (api.ReadView, error) {
	return receiptView{snapshot: api.ReadSnapshot{ID: "review-view", Config: scope.Config, LastSeq: 12}}, nil
}
func (f *reviewContextState) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	if scope.ReadView == nil || target != f.subject.Target {
		return api.Lane{}, serviceError(api.CodeIntegrity, "review lost its pinned selector")
	}
	f.reads++
	return f.lane, nil
}
func (f *reviewContextState) Events(_ context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	if scope.ReadView == nil || request.LifeID != f.subject.Target.LifeID || request.Run != f.subject.Target.Run {
		return api.EventPage{}, serviceError(api.CodeIntegrity, "review events are not pinned")
	}
	return api.EventPage{Events: []api.Event{f.end}, Complete: true}, nil
}
func (f *reviewContextState) CaptureState(_ context.Context, scope api.Scope, id api.ID) (api.CaptureState, error) {
	if scope.ReadView == nil || id != f.capture.Binding.ID {
		return api.CaptureState{}, serviceError(api.CodeIntegrity, "review capture is not pinned")
	}
	return f.capture, nil
}
func (f *reviewContextState) ReviewSnapshot(_ context.Context, _ api.Scope, target api.LifeRef) (api.ReviewSubject, error) {
	if target != f.subject.Target {
		return api.ReviewSubject{}, serviceError(api.CodeNotFound, "review snapshot is absent")
	}
	return f.subject, nil
}
func (*reviewContextState) ReserveReviewWorker(context.Context, api.Scope, api.ReviewRequest, api.ReviewSubject, []string) (api.WorkerLease, error) {
	return api.WorkerLease{}, serviceError(api.CodePrerequisite, "component native reservation is deliberately unopened")
}
func (*reviewContextState) AwaitReviewResult(context.Context, api.Scope, api.WorkerLease) (api.BlobRef, error) {
	return api.BlobRef{}, serviceError(api.CodePrerequisite, "component native execution is deliberately unopened")
}
func (f *reviewContextState) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	m, ok := f.metadata[id]
	if !ok {
		return api.ObjectMetadata{}, serviceError(api.CodeNotFound, "review fixture object is absent")
	}
	return m, nil
}
func (f *reviewContextState) Blob(_ context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	raw, ok := f.objects[request.ObjectID]
	if !ok || request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit < 1 {
		return api.BlobChunk{}, serviceError(api.CodeNotFound, "review fixture range is absent")
	}
	data := raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: digestBytes(data)}, nil
}

type reviewPolicyFixture struct {
	api.HelperControl
	names []string
}

func (f *reviewPolicyFixture) RequiredReviewChecks(_ context.Context, scope api.Scope, _ api.LifeRef) ([]string, error) {
	if scope.Actor.Kind != "service" || scope.Request.Method != "" || scope.Connection != nil {
		return nil, serviceError(api.CodeForbidden, "review policy requires the installed service")
	}
	return append([]string{}, f.names...), nil
}

func reviewContextFixture(t *testing.T) (*Server, *reviewContextState, api.Scope) {
	t.Helper()
	host := fixtureServer(t)
	host.verified, host.bound, host.controller = true, true, fixtureID(t)
	a, b := net.Pipe()
	connection, err := newConnection(a, host.deps.Binding, host.deps.Clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	auth := host.deps.Authenticator.(*authFixture)
	auth.scope.Actor.Level, auth.scope.Actor.Role = 5, "supervisor"
	scope, err := auth.Authenticate(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	target := api.LifeRef{LifeID: "review-subject", Run: 3}
	refInput := api.BlobRef{ID: "candidate-input", Class: "manifest", SHA256: digestBytes(nil), Bytes: 0}
	scope.Request = requestFor(t, "lane.review", api.ReviewRequest{Target: target, Diff: refInput,
		Checks: []api.BlobRef{refInput}, RecordInventory: refInput, RefusalResolution: []api.ID{}})
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame, scope.Source = sessionDispatchFrame{raw: raw}, "cli"
	objects := map[api.ID][]byte{"frozen-snapshot": []byte("{\"schema\":\"laneboss.objects.v2\",\"entries\":[]}\n")}
	ref := api.BlobRef{ID: "frozen-snapshot", Class: "manifest", Bytes: int64(len(objects["frozen-snapshot"])), SHA256: digestBytes(objects["frozen-snapshot"])}
	subject := api.ReviewSubject{Target: target, LaunchID: "subject-launch", Generation: 5, EndEventID: "end-event", EndSeq: 9,
		Snapshot: ref, SessionID: "subject-session", InventorySeq: 12, CaptureBindingID: "capture-binding",
		Streams: []api.CaptureStreamBinding{{ID: "stdout", PipeID: "stdout-pipe", Stream: "stdout"}, {ID: "stderr", PipeID: "stderr-pipe", Stream: "stderr"}}, RefusalIDs: []api.ID{}}
	zero, exit := uint64(0), 0
	payload, err := json.Marshal(api.RunEndEvent{Reason: "exit", Observation: api.ProcessObservation{Handle: api.ProcessHandle{ID: subject.LaunchID, Target: target},
		State: "exited", Survivors: &zero, ExitCode: &exit, ObservedAt: "2030-01-01T00:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	state := &reviewContextState{unusedStore: &unusedStore{}, subject: subject, objects: objects,
		lane:     api.Lane{LifeID: target.LifeID, Run: target.Run, LaunchID: subject.LaunchID, Generation: subject.Generation, State: "verifying", Session: api.Session{ID: subject.SessionID}},
		end:      api.Event{ID: subject.EndEventID, Config: scope.Config, Seq: subject.EndSeq, Kind: "lane.ended", LifeID: target.LifeID, Run: target.Run, Origin: "service", Payload: payload},
		metadata: map[api.ID]api.ObjectMetadata{ref.ID: {Ref: ref, Origin: "service", SourceOperationID: "freeze-operation", ACL: api.ObjectACL{Config: scope.Config, LifeID: target.LifeID, Owner: api.Actor{Kind: "service", ID: host.controller}}}}}
	state.capture = api.CaptureState{Binding: api.CaptureBinding{ID: subject.CaptureBindingID, Config: scope.Config, Target: target, LaunchID: subject.LaunchID,
		Status: "registered", Streams: subject.Streams}, Generation: 1, LastSeq: 12,
		Positions: []api.CapturePosition{{StreamID: "stdout", EOF: true}, {StreamID: "stderr", EOF: true}}}
	host.deps.Store = state
	host.runtime.Helper = &reviewPolicyFixture{names: []string{"unit"}}
	return host, state, scope
}

func TestInstalledReviewContext(t *testing.T) {
	for _, mode := range []string{"valid", "snapshot-run", "snapshot-end", "snapshot-generation", "inventory-seq", "capture", "capture-eof", "end-origin", "end-survivor", "artifact", "actor", "frame", "requirements"} {
		t.Run(mode, func(t *testing.T) {
			host, state, scope := reviewContextFixture(t)
			control, ok := any(host).(reviewControlPort)
			if !ok {
				t.Fatal("installed review control is missing")
			}
			switch mode {
			case "snapshot-run":
				state.subject.Target.Run++
			case "snapshot-end":
				state.subject.EndEventID = "foreign-end"
			case "snapshot-generation":
				state.subject.Generation++
			case "inventory-seq":
				state.subject.InventorySeq++
			case "capture":
				state.capture.Binding.LaunchID = "foreign-launch"
			case "capture-eof":
				state.capture.Positions[0].EOF = false
			case "end-origin":
				state.end.Origin = "observation"
			case "end-survivor":
				one := uint64(1)
				var end api.RunEndEvent
				if err := json.Unmarshal(state.end.Payload, &end); err != nil {
					t.Fatal(err)
				}
				end.Observation.Survivors = &one
				var err error
				state.end.Payload, err = json.Marshal(end)
				if err != nil {
					t.Fatal(err)
				}
			case "artifact":
				state.objects[state.subject.Snapshot.ID][0] ^= 1
			case "actor":
				scope.Actor.ID = "foreign-actor"
			case "frame":
				scope.Frame = nil
			case "requirements":
				host.runtime.Helper.(*reviewPolicyFixture).names = nil
			}
			target := api.LifeRef{LifeID: state.lane.LifeID, Run: state.lane.Run}
			actual, names, err := control.ResolveReview(context.Background(), scope, target)
			if mode == "valid" {
				if err != nil || !reflect.DeepEqual(actual, state.subject) || !reflect.DeepEqual(names, []string{"unit"}) || state.reads == 0 {
					t.Fatalf("installed review did not resolve actual pinned context: %v", err)
				}
			} else if err == nil || actual.Target.LifeID != "" || len(names) != 0 {
				t.Fatalf("invalid installed review context escaped: %s: %v", mode, err)
			}
		})
	}
}

var _ reviewjob.Source = (*reviewContextState)(nil)
