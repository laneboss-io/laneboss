//go:build linux && laneboss_root_canary && laneboss_gate_integration

package service

import (
	"context"
	"os"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// ExerciseAgentOwnerNativeCanary runs the real helper prepare/open/reconcile
// exchange and then uses the real store writer to publish lane.started. The
// fixture supplies only immutable plan metadata; helper IPC, native gate,
// permit consumption, process observation and journal ordering are measured.
func ExerciseAgentOwnerNativeCanary(t *testing.T, exchange func(string, any, any) error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("agent open canary writer must remain unprivileged")
	}
	ctx := context.Background()
	var identity struct {
		UID    uint32
		Config string
	}
	if err := exchange("identity", api.Empty{}, &identity); err != nil {
		t.Fatal(err)
	}
	f := fx.New(t, identity.Config)
	f.Reserve(t)
	f.Source(t)
	f.CaptureSetup = func(binding api.CaptureBinding) api.CaptureBinding {
		var actual api.CaptureBinding
		if err := exchange("capture", binding, &actual); err != nil {
			t.Fatal("native capture setup failed", err)
		}
		return actual
	}
	f.BuildPlanForIdentity(t, true, identity.UID, identity.UID)
	f.Spec(t)
	f.PrepareJob(t)
	policy, err := f.State.Policy(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	input := struct {
		Plan       api.LaunchPlan
		Handoff    api.PreparedSpecHandoff
		Prepared   api.PreparedLaunch
		Request    api.HelperLaunchRequest
		Allocation api.HelperLeaseRequest
		Worker     api.WorkerLease
		Policy     api.EffectivePolicy
	}{f.Plan, *f.Record.Handoff, f.Prepared, *f.PreparedClaim.Record.Effect.HelperPrepare, f.Allocation, f.WorkerLease, policy}
	if err := exchange("prepare", input, &f.Prepared); err != nil {
		t.Fatal("native helper prepare failed", err)
	}
	f.Bind(t)
	before, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil || before.Phase != "bound" {
		t.Fatal("native canary did not retain the bound phase before open", err)
	}
	var opened api.LaunchReconciliation
	if err := exchange("open", f.Binding, &opened); err != nil {
		t.Fatal("native helper open failed", err)
	}
	if opened.Process == nil || opened.ConsumedPermit == nil || opened.Observation.State != "running" {
		t.Fatal("native helper open lacked its measured process and consumed permit")
	}
	f.Process = *opened.Process
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, opened); err != nil {
		t.Fatal("native process reconciliation was not retained", err)
	}
	f.Lane.Generation++
	f.Lane.State, f.Lane.Containment = "running", "running"
	record := f.Record
	record.Generation++
	record.Phase = "opened"
	template := api.TemplateRef{ID: fx.ID(t), SourceSHA256: fx.Digest([]byte("native-template")), Generation: 1, RenderedSHA256: f.Plan.Runner.Prompt.SHA256}
	started := api.LaunchEvent{Task: f.Lane.Task, LaunchID: f.Reservation.LaunchID, Lane: f.Lane, GrantSetID: f.Reservation.GrantSetID,
		GrantsSHA256: f.Plan.Inputs.Grants.SHA256, PolicyGeneration: f.Reservation.PolicyGeneration, PromptTemplate: template,
		TaskSHA256: f.Lane.Task.SHA256, Prompt: f.Plan.Runner.Prompt, BoundaryBackend: f.Plan.Inputs.Sources.Runtime.Backend,
		EndpointGeneration: f.Plan.Lease.EndpointGeneration, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, SecretGrantIDs: []api.ID{}, SecretSourceVersions: []string{}, InjectionOutcome: f.Plan.Injection.Outcome,
		Trigger: api.Trigger{Kind: f.Reservation.Mode, MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}}
	f.Transition(t, record, api.StateWrites{Lanes: []api.Lane{f.Lane}}, []api.Event{f.Event(t, "lane.started", started)}, api.InternalHelperOpen, f.Claim.Record.Effect.ID)
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation, Status: "succeeded", LaunchPlan: &f.Plan, Process: &f.Process}); err != nil {
		t.Fatal("opened parent completion failed", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: f.Reservation.Target.LifeID, Run: f.Reservation.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	var observed, startedSeq api.Sequence
	for _, event := range page.Events {
		switch event.Kind {
		case "run.observed":
			observed = event.Seq
		case "lane.started":
			startedSeq = event.Seq
		}
	}
	if observed == 0 || startedSeq == 0 || observed >= startedSeq {
		t.Fatal("lane.started was published before measured open reconciliation", observed, startedSeq)
	}
	var ended api.LaunchReconciliation
	if err := exchange("end", api.Empty{}, &ended); err != nil {
		t.Fatal("native canary process did not end", err)
	}
	if ended.Observation.ExitCode == nil || *ended.Observation.ExitCode != 0 || ended.Observation.Signal != nil {
		t.Fatal("native canary did not measure a successful exit")
	}
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, ended); err != nil {
		t.Fatal(err)
	}
	retained, err := f.State.LaunchPlan(ctx, f.Execution, f.Reservation.ID)
	if err != nil || retained.Phase != "opened" || retained.Plan == nil || !reflect.DeepEqual(*retained.Plan, f.Plan) {
		t.Fatal("native open canary changed its retained opened plan", err)
	}
	t.Log("real helper prepare, committed bind, open permit consumption, measured reconciliation, and lane.started ordering passed")
}
