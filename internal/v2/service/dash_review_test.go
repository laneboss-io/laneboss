package service

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type dashReviewState struct {
	*reviewContextState
	framed   int
	prepared int
}

func (f *dashReviewState) Lane(context.Context, api.Scope, api.LifeRef) (api.Lane, error) {
	return f.lane, nil
}
func (f *dashReviewState) CaptureState(context.Context, api.Scope, api.ID) (api.CaptureState, error) {
	return f.capture, nil
}
func (f *dashReviewState) Events(context.Context, api.Scope, api.EventTailRequest) (api.EventPage, error) {
	return api.EventPage{Events: []api.Event{f.end}, Complete: true}, nil
}
func (f *dashReviewState) LaunchBinding(context.Context, api.ID) (api.LaunchBindingRequest, error) {
	return api.LaunchBindingRequest{Recovery: &api.LaunchRecovery{PlanID: "actual-plan", Capture: f.capture.Binding}}, nil
}
func (f *dashReviewState) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	plan := api.LaunchPlanRecord{Inputs: &api.LaunchInputs{}}
	plan.Inputs.Sources.Project.Object = f.subject.Snapshot
	return plan, nil
}
func (f *dashReviewState) FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error) {
	f.framed++
	return []api.CaptureRecord{}, nil
}
func (f *dashReviewState) ReviewSnapshot(ctx context.Context, scope api.Scope, target api.LifeRef) (api.ReviewSubject, error) {
	if f.framed != 1 {
		return api.ReviewSubject{}, serviceError(api.CodeIntegrity, "freeze preceded framing")
	}
	f.prepared++
	return f.reviewContextState.ReviewSnapshot(ctx, scope, target)
}
func (f *dashReviewState) RetainObject(_ context.Context, _ api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	o := request.Object
	f.objects[o.ObjectKey] = append([]byte{}, o.Bytes...)
	ref := api.BlobRef{ID: o.ObjectKey, Class: o.Class, Bytes: int64(len(o.Bytes)), SHA256: digestBytes(o.Bytes)}
	f.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: o.Origin, ACL: o.ACL, SourceOperationID: request.Intent.CauseOperationID}
	return ref, nil
}

func TestDashboardEntryReviewPlan(t *testing.T) {
	_, original, _ := reviewContextFixture(t)
	host, conn, actor := dashboardTransportFixture(t)
	host.verified, host.bound, host.controller = true, true, "actual-controller"
	state := &dashReviewState{reviewContextState: original}
	state.lane.Session.Driver = api.DriverClaudock
	state.capture.Binding.OperationID, state.capture.Binding.RequestID = "actual-run-op", "actual-run-request"
	host.deps.Store, host.runtime.Helper = state, &reviewPolicyFixture{names: []string{"unit"}}
	request := DashboardEntryRequest{Protocol: DashboardEntryProtocol, Action: "review-inputs", Target: &state.subject.Target}
	if _, err := host.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request); err == nil {
		t.Fatal("native preparation accepted no human read authority")
	}
	now := host.deps.Clock.Now()
	if err := conn.BindReadAuthority(api.ReadAuthority{Generation: 1, SessionID: "actual-session", CredentialID: "actual-credential",
		PrincipalID: actor.ID, ConnectionID: conn.ID(), Config: host.options.Config, EndpointGeneration: 1,
		IdleExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(now.Add(2 * time.Minute).Format(time.RFC3339Nano))}); err != nil {
		t.Fatal(err)
	}
	value, err := host.dashboardEntryCall(context.Background(), conn, entryFrame(t, conn, request), request)
	if err != nil {
		t.Fatal(err)
	}
	prepared := value.(dashboardReviewInputs)
	if !reflect.DeepEqual(prepared.Subject, original.subject) {
		t.Fatal("review inputs selected another native subject")
	}
	if state.prepared != 1 || state.framed != 1 || len(prepared.Missing) != 1 || prepared.Missing[0] != "unit" || len(prepared.Request.Checks) != 0 {
		t.Fatal("review preparation invented a test or skipped its actual producer")
	}
	var diff map[string]any
	if json.Unmarshal(state.objects[prepared.Request.Diff.ID], &diff) != nil || diff["schema"] != "laneboss.review-diff.v2" || prepared.Request.RecordInventory.ID == "" {
		t.Fatal("review preparation did not retain actual candidate bytes")
	}
}

func TestDashboardEntryReviewDiff(t *testing.T) {
	content := api.BlobRef{ID: "source-object", Class: "artifact", SHA256: digestBytes([]byte(t.Name())), Bytes: int64(len(t.Name()))}
	other := content
	other.ID = "separate-object"
	base := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "actual.txt", Kind: "file", Mode: 0444, Content: &content}}}
	current := api.ObjectManifest{Schema: base.Schema, Entries: []api.ObjectEntry{{Path: "work/actual.txt", Kind: "file", Mode: 0444, Content: &other}}}
	diff := dashboardTreeDiff(base, current, content.SHA256, other.SHA256)
	if len(diff.Changes) != 0 {
		t.Fatal("review diff mistook object identity for changed content")
	}
	current.Entries[0].Mode = 0644
	diff = dashboardTreeDiff(base, current, content.SHA256, other.SHA256)
	if len(diff.Changes) != 1 || diff.Changes[0].Path != "actual.txt" || diff.Changes[0].Before.Mode == diff.Changes[0].After.Mode {
		t.Fatal("review diff omitted an actual permission change")
	}
}

func TestDashboardEntryReviewEmpty(t *testing.T) {
	host, state, _ := reviewContextFixture(t)
	state.objects["empty-artifact"] = []byte{}
	ref := api.BlobRef{ID: "empty-artifact", Class: "artifact", SHA256: digestBytes(nil)}
	if raw, err := host.dashboardReviewObject(context.Background(), api.Scope{}, ref); err != nil || len(raw) != 0 {
		t.Fatal("empty frozen content was not read from its actual object")
	}
	ref.SHA256 = digestBytes([]byte("other"))
	if _, err := host.dashboardReviewObject(context.Background(), api.Scope{}, ref); err == nil {
		t.Fatal("empty frozen content accepted a different digest")
	}
}

func TestDashboardEntryToolCoverage(t *testing.T) {
	host, state, _ := reviewContextFixture(t)
	session := api.Session{VendorID: "actual-vendor", LogicalCWD: "/work/main"}
	frames := []api.CaptureRecord{}
	appendFrame := func(id string, value any) {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		ref := api.BlobRef{ID: api.ID(id), Class: "capture", SHA256: digestBytes(raw), Bytes: int64(len(raw))}
		state.objects[ref.ID] = raw
		frames = append(frames, api.CaptureRecord{Target: state.subject.Target, Primary: true, Coverage: "complete", Data: ref})
	}
	appendFrame("init-frame", map[string]any{"type": "system", "subtype": "init", "session_id": session.VendorID, "cwd": session.LogicalCWD})
	appendFrame("use-frame", map[string]any{"type": "assistant", "session_id": session.VendorID, "message": map[string]any{"content": []any{map[string]any{"type": "tool_use", "id": "actual-tool", "name": "installed_cli"}}}})
	result := map[string]any{"type": "tool_result", "tool_use_id": "actual-tool"}
	appendFrame("result-frame", map[string]any{"type": "user", "session_id": session.VendorID, "message": map[string]any{"content": []any{result}}})
	appendFrame("end-frame", map[string]any{"type": "result", "session_id": session.VendorID, "is_error": false})
	coverage, err := host.dashboardToolCoverage(context.Background(), api.Scope{}, state.subject.Target, session, frames)
	if err != nil || coverage != api.CoverageComplete {
		t.Fatal("actual paired provider capture was not complete", err)
	}
	result["tool_use_id"] = "foreign-tool"
	frames = frames[:2]
	appendFrame("foreign-result", map[string]any{"type": "user", "session_id": session.VendorID, "message": map[string]any{"content": []any{result}}})
	appendFrame("another-end", map[string]any{"type": "result", "session_id": session.VendorID, "is_error": false})
	coverage, err = host.dashboardToolCoverage(context.Background(), api.Scope{}, state.subject.Target, session, frames)
	if err != nil || coverage != api.CoveragePartial {
		t.Fatal("unpaired provider tool result became complete coverage", err)
	}
}
