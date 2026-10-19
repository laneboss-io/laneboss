package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type childSubmitState struct {
	api.StateStore
	subject     api.ReviewSubject
	reservation testjob.Reservation
	transaction api.Transaction
	calls       int
	drains      int
	stop        error
}

func (f *childSubmitState) Lane(context.Context, api.Scope, api.LifeRef) (api.Lane, error) {
	return api.Lane{LaunchID: "actual-launch"}, nil
}
func (f *childSubmitState) LaunchBinding(context.Context, api.ID) (api.LaunchBindingRequest, error) {
	return api.LaunchBindingRequest{Recovery: &api.LaunchRecovery{Capture: api.CaptureBinding{ID: "actual-capture", Target: f.subject.Target,
		Streams: []api.CaptureStreamBinding{{ID: "actual-out", Stream: "stdout"}, {ID: "actual-err", Stream: "stderr"}}}}}, nil
}
func (f *childSubmitState) CaptureState(context.Context, api.Scope, api.ID) (api.CaptureState, error) {
	f.drains++
	return api.CaptureState{Positions: []api.CapturePosition{{StreamID: "actual-out", EOF: true}, {StreamID: "actual-err", EOF: f.drains > 1}}}, nil
}

func (f *childSubmitState) ReviewSnapshot(context.Context, api.Scope, api.LifeRef) (api.ReviewSubject, error) {
	return f.subject, nil
}
func (*childSubmitState) ReserveReviewWorker(context.Context, api.Scope, api.ReviewRequest, api.ReviewSubject, []string) (api.WorkerLease, error) {
	return api.WorkerLease{}, errors.New("TestChild called the export verifier")
}
func (*childSubmitState) AwaitReviewResult(context.Context, api.Scope, api.WorkerLease) (api.BlobRef, error) {
	return api.BlobRef{}, errors.New("TestChild awaited an export result")
}
func (f *childSubmitState) StageChildTest(context.Context, api.Scope, api.TestChildRequest, api.GrantSet, api.ReviewSubject) (testjob.Reservation, error) {
	return f.reservation, nil
}
func (f *childSubmitState) Transact(_ context.Context, input api.Transaction) (api.Commit, error) {
	f.calls++
	f.transaction = input
	return api.Commit{}, f.stop
}

func childCaller(t *testing.T) (*Server, api.Scope, api.TestChildRequest) {
	t.Helper()
	host, conn, actor := dashboardTransportFixture(t)
	host.verified, host.bound, host.controller = true, true, "test-controller"
	ref := api.BlobRef{ID: "actual-candidate", Class: "manifest", Bytes: 2, SHA256: digestBytes([]byte("{}"))}
	request := api.TestChildRequest{Child: api.LifeRef{LifeID: "actual-child", Run: 2}, Candidate: ref, TestPlan: ref,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 32 << 20, Processes: 4, DiskBytes: 1 << 20, Currency: "USD"}}
	params, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	input := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: host.options.Config, Method: "grants.test-child",
		RequestID: "actual-request-correlation", IdempotencyKey: "actual-idempotency-key", Params: params}
	input.RequestSHA256, err = api.RequestDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Proof = &api.ProofRef{ID: "actual-proof", RequestSHA256: input.RequestSHA256, ExpiresAt: "2030-01-01T01:00:00Z"}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return host, api.Scope{Config: host.options.Config, Actor: actor, EndpointGeneration: 1, PolicyGeneration: 1, Connection: conn,
		Request: input, Frame: dashboardNativeFrame{raw: raw, conn: conn}}, request
}

func TestNativeChildSubmit(t *testing.T) {
	host, caller, request := childCaller(t)
	stop := api.NotImplemented("component", "stop after examining the actual atomic transaction")
	lease := api.WorkerLease{ID: "actual-lease", Kind: "test", Target: request.Child, OperationID: "actual-operation", EffectID: "actual-effect"}
	state := &childSubmitState{subject: api.ReviewSubject{Target: request.Child}, stop: stop, reservation: testjob.Reservation{
		Job: archivejob.Job{Lease: lease, Intent: archivejob.Intent{OperationID: lease.OperationID}}, Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID}}}
	host.deps.Store = state
	guard := api.TransactionGuard{Proof: &api.ProofUse{Proof: *caller.Request.Proof, Target: api.HumanChallengeRequest{Method: caller.Request.Method, TargetID: request.Child.LifeID}}}
	_, err := host.SubmitChildTest(context.Background(), testjob.Call{Scope: caller, Guards: []api.TransactionGuard{guard}}, request, api.GrantSet{})
	if !errors.Is(err, stop) || state.calls != 1 {
		t.Fatal("TestChild did not reach its exact atomic writer boundary", err)
	}
	tx := state.transaction
	if !reflect.DeepEqual(tx.Guards, []api.TransactionGuard{guard}) || !bytes.Equal(tx.RawRequest, caller.Frame.Bytes()) || tx.Scope.Actor != caller.Actor || tx.Scope.Connection != caller.Connection ||
		!reflect.DeepEqual(tx.Writes.WorkerLeases, []api.WorkerLease{lease}) || !reflect.DeepEqual(tx.Effects, []api.Effect{state.reservation.Effect}) {
		t.Fatal("TestChild detached its proof, native request or worker effect from atomic admission")
	}
}

func TestNativeChildMissingGuard(t *testing.T) {
	host, caller, request := childCaller(t)
	_, err := host.SubmitChildTest(context.Background(), testjob.Call{Scope: caller}, request, api.GrantSet{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "TestChild lost its atomic human proof guard" {
		t.Fatal("TestChild accepted a missing atomic human guard", err)
	}
}

func TestNativeChildFrame(t *testing.T) {
	host, caller, request := childCaller(t)
	caller.Request.RequestID = "changed-correlation"
	if _, err := host.testCaller(context.Background(), caller, request); err == nil {
		t.Fatal("TestChild accepted a different native frame")
	}
}

func TestNativeChildActor(t *testing.T) {
	host, caller, request := childCaller(t)
	host.deps.Authenticator.(*authFixture).scope.Actor.ID = "another-human"
	if _, err := host.testCaller(context.Background(), caller, request); err == nil {
		t.Fatal("TestChild accepted a replaced native actor")
	}
}

func TestNativeChildCaptureWait(t *testing.T) {
	host, caller, request := childCaller(t)
	state := &childSubmitState{subject: api.ReviewSubject{Target: request.Child}}
	host.deps.Store = state
	if err := host.awaitTestCapture(context.Background(), caller, request.Child); err != nil {
		t.Fatal(err)
	}
	if state.drains != 2 {
		t.Fatal("TestChild froze before every primary EOF was observed")
	}
}
