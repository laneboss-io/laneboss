package dataworker

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type reviewResultView struct{ config string }

func (v reviewResultView) Snapshot() api.ReadSnapshot {
	return api.ReadSnapshot{ID: "review-result-view", Config: v.config}
}
func (reviewResultView) Close() error { return nil }

type reviewResultState struct {
	api.StateStore
	job    ReviewJob
	ports  *archivePorts
	lease  api.WorkerLease
	effect api.EffectRecord
	output api.BlobRef
	mode   string
}

func (f *reviewResultState) BeginRead(_ context.Context, scope api.Scope) (api.ReadView, error) {
	return reviewResultView{scope.Config}, nil
}
func (f *reviewResultState) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	if id != f.lease.ID {
		return api.WorkerLease{}, api.NotImplemented("component", "foreign review lease")
	}
	return f.lease, nil
}
func (f *reviewResultState) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	if id != f.lease.EffectID {
		return api.EffectRecord{}, api.NotImplemented("component", "foreign review effect")
	}
	return f.effect, nil
}
func (f *reviewResultState) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	if id != f.job.Principal.Record.ID {
		return api.LaunchRecord{}, api.NotImplemented("component", "foreign worker identity")
	}
	record := f.job.Principal.Record
	if f.mode == "identity" {
		record.Target.Run++
	}
	return record, nil
}
func (f *reviewResultState) Blob(ctx context.Context, _ api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	return f.ports.read(ctx, request)
}
func (f *reviewResultState) ObjectMetadata(_ context.Context, _ api.Scope, id api.ID) (api.ObjectMetadata, error) {
	ref, origin := f.lease.Input, "service"
	if id == f.output.ID {
		ref, origin = f.output, "worker"
	}
	if id != ref.ID {
		return api.ObjectMetadata{}, api.NotImplemented("component", "unselected metadata")
	}
	return api.ObjectMetadata{Ref: ref, Origin: origin, SourceOperationID: f.lease.OperationID,
		ACL: api.ObjectACL{Config: f.job.Scope.Config, Owner: api.Actor{Kind: "service", ID: "review-coordinator"},
			LifeID: f.lease.Target.LifeID, Audience: "private", Generation: 1}}, nil
}

type reviewResultControl struct {
	api.MaterializationControl
	state *reviewResultState
	calls int
}

// Native observation is a component boundary. The result body itself comes
// from running the real fixed verifier over the actual retained object bytes.
func (c *reviewResultControl) WithReviewResult(ctx context.Context, caller api.Scope, prepared api.ReviewVerifyRequest, consume func(api.Scope, api.BlobRef) error) error {
	c.calls++
	f := c.state
	if caller.Actor != f.job.Principal.Claim.Record.Effect.Context.RequestedBy || caller.Request.Method != "lane.review" || prepared.Lease.ID != f.lease.ID {
		return &api.Error{Code: api.CodeForbidden, Message: "component original reviewer differs"}
	}
	ack, err := RunReview(ctx, f.job)
	if err != nil {
		return err
	}
	f.output = ack.Result
	f.ports.objects[ack.Result.ID] = append([]byte{}, f.ports.result...)
	f.lease.Generation++
	zero, exit := uint64(0), 0
	f.effect.State, f.effect.Generation = api.EffectCompleted, f.effect.Generation+1
	f.effect.Outcome = &api.EffectOutcome{EffectID: f.lease.EffectID, ClaimID: f.effect.ClaimID,
		ExpectedGeneration: f.effect.Generation - 1, Status: "succeeded", Output: &f.output,
		Observation: &api.ProcessObservation{Handle: api.ProcessHandle{ID: f.job.Principal.Record.ID, Target: f.lease.Target,
			ContainmentID: f.job.Principal.Record.ContainmentID, Generation: f.job.Principal.Record.ProcessGeneration},
			State: "exited", Survivors: &zero, ExitCode: &exit, ObservedAt: api.Timestamp(f.job.Clock.Now().UTC().Format(time.RFC3339Nano))}}
	switch f.mode {
	case "survivors":
		one := uint64(1)
		f.effect.Outcome.Observation.Survivors = &one
	case "effect":
		f.effect.Effect.OperationID = "foreign-operation"
	case "plan":
		f.effect.Effect.Worker.Input.ID = "foreign-input"
	case "lease":
		f.lease.RuntimeManifest.ID = "foreign-runtime"
	case "lease-generation":
		f.lease.Generation++
	case "output-hash":
		f.ports.objects[f.output.ID][0] ^= 1
	case "worker-kind":
		f.lease.Kind = "archive"
	case "input":
		f.ports.objects[f.lease.Input.ID][0] ^= 1
	}
	return consume(api.Scope{Config: f.job.Scope.Config, Actor: api.Actor{Kind: "service", ID: "review-coordinator"}}, f.output)
}

func TestReviewMeasuredResult(t *testing.T) {
	for _, mode := range []string{"valid", "partial", "output-hash", "survivors", "identity", "input", "effect", "worker-kind", "plan", "lease", "lease-generation"} {
		t.Run(mode, func(t *testing.T) {
			workerMode := "valid"
			if mode == "partial" {
				workerMode = "partial"
			}
			job, ports := reviewWorkerFixture(t, workerMode)
			var input reviewjob.Input
			if err := api.DecodeObject(ports.input.Bytes, &input); err != nil {
				t.Fatal(err)
			}
			state := &reviewResultState{job: job, ports: ports, lease: job.Principal.Lease, effect: job.Principal.Claim.Record, mode: mode}
			control := &reviewResultControl{state: state}
			service, _, _ := workerFixture(t)
			service.deps.Config, service.deps.Store, service.deps.Controls, service.deps.Clock = job.Scope.Config, state, control, job.Clock
			raw, err := json.Marshal(input.Request)
			if err != nil {
				t.Fatal(err)
			}
			caller := api.Scope{Config: job.Scope.Config, Actor: job.Principal.Claim.Record.Effect.Context.RequestedBy,
				Request: api.Request{Config: job.Scope.Config, Method: "lane.review", Params: raw}}
			prepared := api.ReviewVerifyRequest{Lease: job.Principal.Lease, Request: input.Request,
				ExpectedGeneration: input.Subject.Generation, EndEventID: input.Subject.EndEventID, EndSeq: input.Subject.EndSeq}
			evidence, err := service.VerifyReview(context.Background(), caller, prepared)
			if mode != "valid" && mode != "partial" {
				if err == nil || !reflect.ValueOf(evidence).IsZero() {
					t.Fatalf("unmeasured review result escaped: %s: %v", mode, err)
				}
				return
			}
			if err != nil || control.calls != 1 || !reflect.DeepEqual(evidence.Subject, input.Subject) ||
				manifest.Hash(ports.result) != state.output.SHA256 {
				t.Fatalf("review did not consume its actual verifier output: %s: %v", mode, err)
			}
			want := api.CoverageComplete
			if mode == "partial" {
				want = api.CoveragePartial
			}
			if evidence.Coverage != want {
				t.Fatalf("review changed measured coverage: %s", mode)
			}
		})
	}
}
