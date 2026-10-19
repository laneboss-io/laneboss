//go:build linux

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The helper and native peer here are explicit component doubles. Digests and
// receipts come from retained variable input/output bytes through the store;
// no component result claims a native copy, confinement or installed E2E.
type dataHelperFixture struct {
	api.HelperControl
	d                                    *fx.DataFixture
	t                                    *testing.T
	badRegistration                      bool
	foreignObservation                   bool
	running                              bool
	handoffErr                           error
	locks, unlocks                       int
	registers, prepares, opens, measures int
}

type dataHandoffFixtureKey struct{}

func (h *dataHelperFixture) WithWorkerLaunch(ctx context.Context, prepared api.PreparedLaunch, open func(context.Context) error) error {
	h.locks++
	defer func() { h.unlocks++ }()
	if prepared != h.d.Prepared {
		return serviceError(api.CodeIntegrity, "component handoff changed its native prepared gate")
	}
	if h.handoffErr != nil {
		return h.handoffErr
	}
	return open(context.WithValue(ctx, dataHandoffFixtureKey{}, prepared.ID))
}

func (h *dataHelperFixture) check(ctx context.Context, q api.StorageProjectionRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	selected := q.Claim
	q.Claim = api.LaunchClaim{} // Compare stable identity separately from live authority.
	if q != projectionRequest(h.d.Stage) {
		return serviceError(api.CodeIntegrity, "component helper received a foreign selector")
	}
	current, err := h.d.F.State.Effect(ctx, h.d.F.Execution, selected.EffectID)
	if err != nil {
		return err
	}
	return api.CheckPlanningClaim(current, selected, h.d.F.Deps.Config, h.d.F.Deps.Clock.Now())
}
func (h *dataHelperFixture) OpenLaunchDataStorage(ctx context.Context, q api.StorageProjectionRequest) (api.StorageProjection, error) {
	return h.d.Projection, h.check(ctx, q)
}
func (h *dataHelperFixture) DataWorkerLease(ctx context.Context, q api.StorageProjectionRequest) (api.HelperLease, error) {
	return h.d.Allocation, h.check(ctx, q)
}
func (h *dataHelperFixture) RegisterDataWorker(ctx context.Context, q api.StorageProjectionRequest, handoff api.PreparedSpecHandoff, endpoint api.InstalledBinding) (api.PreparedSpecReceipt, error) {
	h.registers++
	if err := h.check(ctx, q); err != nil {
		return api.PreparedSpecReceipt{}, err
	}
	expected := h.d.Endpoint
	for _, entry := range []struct {
		path string
		id   *uint32
	}{{"/proc/sys/kernel/overflowuid", &expected.MappedServiceUID}, {"/proc/sys/kernel/overflowgid", &expected.MappedServiceGID}} {
		raw, err := os.ReadFile(entry.path)
		if err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil {
			return api.PreparedSpecReceipt{}, err
		}
		*entry.id = uint32(value)
	}
	if !reflect.DeepEqual(endpoint, expected) || handoff.Spec.Worker == nil || handoff.Spec.Kind != "worker" || handoff.Spec.Materialization.GrantSetID != handoff.Spec.Grants.ID {
		return api.PreparedSpecReceipt{}, serviceError(api.CodeIntegrity, "component helper received another worker seal")
	}
	h.d.Endpoint = endpoint
	h.d.Handoff = handoff
	receipt := api.PreparedSpecReceipt{SpecID: handoff.Spec.ID, Config: handoff.Config, Target: handoff.Spec.Target, LeaseID: handoff.Spec.UIDLeaseID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: handoff.Spec.RuntimeManifest, OperationID: handoff.OperationID}
	if h.badRegistration {
		receipt.Config = "foreign-config"
	}
	return receipt, nil
}
func (h *dataHelperFixture) PrepareDataWorker(ctx context.Context, q api.StorageProjectionRequest) (api.PreparedLaunch, error) {
	h.prepares++
	if err := h.check(ctx, q); err != nil {
		return api.PreparedLaunch{}, err
	}
	if h.d.Prepared.ID == "" {
		h.d.Prepared = api.PreparedLaunch{ID: fx.ID(h.t), SpecSHA256: h.d.Handoff.SpecSHA256, Target: h.d.Stage.Reservation.Target, ContainmentID: h.d.Allocation.ContainmentID, ProcessGeneration: "component-boot:" + string(fx.ID(h.t)), EndpointGeneration: h.d.Allocation.EndpointGeneration, GateID: fx.ID(h.t)}
	}
	return h.d.Prepared, nil
}
func (h *dataHelperFixture) OpenDataWorker(ctx context.Context, q api.StorageProjectionRequest, request api.HelperOpenRequest) (api.ProcessHandle, error) {
	h.opens++
	if ctx.Value(dataHandoffFixtureKey{}) != request.Prepared.ID {
		return api.ProcessHandle{}, serviceError(api.CodeContainmentUnknown, "component worker open lost its enclosing native guard")
	}
	if err := h.check(ctx, q); err != nil {
		return api.ProcessHandle{}, err
	}
	binding, err := h.d.F.State.LaunchBinding(ctx, h.d.Stage.WorkerLaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if request.Prepared != binding.Prepared || request.Permit.RecordSHA256 != binding.Identity.RecordSHA256 || request.Permit.CommittedSeq != binding.Identity.CommittedSeq {
		return api.ProcessHandle{}, serviceError(api.CodeIntegrity, "component helper received an uncommitted permit")
	}
	h.d.Binding = binding
	return api.ProcessHandle{ID: binding.Record.ID, Target: binding.Record.Target, ContainmentID: binding.Record.ContainmentID, Generation: binding.Record.ProcessGeneration}, nil
}
func (h *dataHelperFixture) observation() api.ProcessObservation {
	zero, survivors := 0, uint64(0)
	observation := api.ProcessObservation{Handle: h.d.Stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if h.running {
		observation.State, observation.ExitCode = "running", nil
		*observation.Survivors = 1
	}
	return observation
}
func (h *dataHelperFixture) ObserveDataWorker(ctx context.Context, q api.StorageProjectionRequest) (api.ProcessObservation, error) {
	if err := h.check(ctx, q); err != nil {
		return api.ProcessObservation{}, err
	}
	observation := h.observation()
	if h.foreignObservation {
		observation.Handle.ID = fx.ID(h.t)
	}
	return observation, nil
}
func (h *dataHelperFixture) MeasureDataWorker(ctx context.Context, q api.StorageProjectionRequest, receipt api.WorkerResultReceipt) (api.LaunchDataResult, error) {
	h.measures++
	if err := h.check(ctx, q); err != nil {
		return api.LaunchDataResult{}, err
	}
	chunk, err := h.d.F.State.Blob(ctx, h.d.F.Execution, api.BlobReadRequest{ObjectID: receipt.Result.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	if fx.Digest(chunk.Data) != receipt.Result.SHA256 {
		return api.LaunchDataResult{}, serviceError(api.CodeIntegrity, "component measurement lost actual acknowledged bytes")
	}
	var data api.LaunchData
	if err := api.DecodeObject(chunk.Data, &data); err != nil {
		return api.LaunchDataResult{}, err
	}
	manifest, err := h.d.F.State.Blob(ctx, h.d.F.Execution, api.BlobReadRequest{ObjectID: data.Materialization.Manifest.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	return api.LaunchDataResult{StageID: q.StageID, WorkerLeaseID: q.WorkerLeaseID, EffectID: h.d.Stage.Worker.EffectID, OperationID: h.d.Stage.Reservation.OperationID, InputSHA256: h.d.Stage.Worker.Input.SHA256, Data: data, Manifest: data.Materialization.Manifest, ReadBackSHA256: fx.Digest(manifest.Data), Observation: h.observation(), ResultReceipt: receipt}, nil
}

type dataAuthFixture struct {
	*authFixture
	d *fx.DataFixture
}

func (a *dataAuthFixture) Authenticate(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	return a.retainedWorkerScope(ctx, c)
}

func (a *dataAuthFixture) CurrentConnectionScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	if c == nil || c.Peer() == nil {
		return api.Scope{}, serviceError(api.CodeUnauthenticated, "data recheck requires its existing peer")
	}
	if err := c.Peer().Alive(ctx); err != nil {
		return api.Scope{}, err
	}
	return a.retainedWorkerScope(ctx, c)
}

func (a *dataAuthFixture) retainedWorkerScope(ctx context.Context, c api.ConnectionContext) (api.Scope, error) {
	r, err := a.d.F.State.Launch(ctx, c.Binding().LaunchID)
	if err != nil {
		return api.Scope{}, err
	}
	return api.Scope{Config: r.Config, Actor: r.Actor, LaunchID: r.ID, EndpointGeneration: r.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, Connection: c}, nil
}
func (a *dataAuthFixture) BindLaunch(ctx context.Context, binding api.LaunchBindingRequest) (api.LaunchPermit, error) {
	if ctx.Value(dataHandoffFixtureKey{}) != binding.Prepared.ID {
		return api.LaunchPermit{}, serviceError(api.CodeContainmentUnknown, "component identity borrow lost its enclosing native guard")
	}
	actual, err := a.d.F.State.LaunchBinding(ctx, binding.Record.ID)
	if err != nil {
		return api.LaunchPermit{}, err
	}
	if !reflect.DeepEqual(actual, binding) {
		return api.LaunchPermit{}, serviceError(api.CodeIntegrity, "component identity received a changed binding")
	}
	return api.LaunchPermit{LaunchID: actual.Record.ID, PreparedID: actual.Prepared.ID, RecordSHA256: actual.Identity.RecordSHA256, CommittedSeq: actual.Identity.CommittedSeq}, nil
}

func dataServer(t *testing.T, d *fx.DataFixture) (*Server, *dataHelperFixture) {
	t.Helper()
	s := launchServer(t, d.F)
	s.deps.Binding = d.HostBinding()
	h := &dataHelperFixture{d: d, t: t}
	s.runtime.Helper = h
	s.deps.Authenticator = &dataAuthFixture{authFixture: &authFixture{}, d: d}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, h
}

func frameWorker(t *testing.T, d *fx.DataFixture, method api.WorkerOperation, params any) api.Scope {
	t.Helper()
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: d.F.Deps.Config, Method: api.Method(method), RequestID: fx.ID(t), IdempotencyKey: fx.ID(t), Params: fx.JSON(t, params)}
	var err error
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	scope := d.Worker
	scope.Frame = &fx.Frame{Raw: fx.JSON(t, request)}
	return scope
}

func requireDataRefusal(t *testing.T, err error, message string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != message {
		t.Fatal("materialization service control reached an unrelated refusal", err)
	}
}

// Reorder actual retained records only. Claims, bytes and validation still
// come from the real store; no generated ID or scheduler timing chooses the case.
type dataOrderStore struct {
	*store.Service
	parentFirst bool
}

func (s *dataOrderStore) DispatchEffects(ctx context.Context) ([]api.EffectRecord, error) {
	records, err := s.Service.DispatchEffects(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		left, right := records[i].Effect.PlanLaunch != nil, records[j].Effect.PlanLaunch != nil
		if s.parentFirst {
			return left && !right
		}
		return !left && right
	})
	return records, nil
}

func TestDataStageDispatch(t *testing.T) {
	for _, order := range []string{"parent_first", "child_first"} {
		t.Run(order, func(t *testing.T) {
			d := datafx.NewData(t)
			s, h := dataServer(t, d)
			ordered := &dataOrderStore{Service: d.F.State, parentFirst: order == "parent_first"}
			s.deps.Store = ordered
			stage, err := s.MaterializationStage(context.Background(), d.Request)
			if err != nil {
				t.Fatal("materialization dispatch failed", err)
			}
			d.Stage = stage
			records, err := ordered.DispatchEffects(context.Background())
			if err != nil || len(records) != 2 {
				t.Fatal("materialization retry requires both real live claims", err)
			}
			want := []api.ID{stage.ParentEffectID, stage.Worker.EffectID}
			if !ordered.parentFirst {
				want[0], want[1] = want[1], want[0]
			}
			for i, record := range records {
				if record.Effect.ID != want[i] || record.ClaimID == "" || record.Outcome != nil {
					t.Fatal("materialization retry did not retain the selected claim order")
				}
			}
			again, err := s.MaterializationStage(context.Background(), d.Request)
			if err != nil || !reflect.DeepEqual(stage, again) || h.registers != 1 || h.prepares != 1 || h.opens != 1 || h.locks != 1 || h.unlocks != 1 {
				t.Fatal("materialization dispatch repeated a retained launch", err)
			}
		})
	}
}

func TestDataHandoffRefusal(t *testing.T) {
	d := datafx.NewData(t)
	s, h := dataServer(t, d)
	sentinel := serviceError(api.CodeContainmentUnknown, "native worker handoff unavailable")
	h.handoffErr = sentinel
	stage, err := s.MaterializationStage(context.Background(), d.Request)
	if !errors.Is(err, sentinel) || stage.Process.ID != "" || h.opens != 0 || h.locks != 1 || h.unlocks != 1 {
		t.Fatal("materialization lost the native guard refusal or executed beyond it", err)
	}
}

func TestDataParentClaim(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	f, ctx := d.F, context.Background()
	if _, err := f.State.CompleteEffect(ctx, f.Execution, api.EffectOutcome{
		EffectID: f.Claim.Record.Effect.ID, ClaimID: f.Claim.ClaimID, ExpectedGeneration: f.Claim.Record.Generation,
		Status: "failed", Error: &api.Error{Code: api.CodeConflict, Message: "component planning owner stopped"},
	}); err != nil {
		t.Fatal("materialization parent completion setup failed", err)
	}
	s, h := dataServer(t, d)
	// The child remains current and can authorize a generic input read. It
	// cannot replace the completed planning claim, even for an opened replay.
	if _, err := s.Plan(ctx, d.Request.ReservationID); err != nil {
		t.Fatal("materialization child lost its generic read claim", err)
	}
	_, err := s.MaterializationStage(ctx, d.Request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "launch input lookup has no current original stage claim" || h.registers != 0 || h.prepares != 0 || h.opens != 0 {
		t.Fatal("materialization child replaced a completed planning claim", err)
	}
}

func TestDataRegistrationPin(t *testing.T) {
	d := datafx.NewData(t)
	s, h := dataServer(t, d)
	h.badRegistration = true
	if _, err := s.MaterializationStage(context.Background(), d.Request); err == nil {
		t.Fatal("materialization accepted a foreign registration receipt")
	} else {
		requireDataRefusal(t, err, "materialization helper registration changed its sealed spec")
	}
}

func TestAwaitDataProcess(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, h := dataServer(t, d)
	_, raw := d.Result(t)
	if _, err := d.F.State.WorkerResult(context.Background(), d.Worker, d.Submission(raw)); err != nil {
		t.Fatal(err)
	}
	h.foreignObservation = true
	if _, err := s.AwaitMaterialization(context.Background(), d.Stage.ID); err == nil {
		t.Fatal("materialization await accepted another observed process")
	} else {
		requireDataRefusal(t, err, "materialization observed another process")
	}
}

func TestAwaitDataResult(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, h := dataServer(t, d)
	_, raw := d.Result(t)
	if _, err := d.F.State.WorkerResult(context.Background(), d.Worker, d.Submission(raw)); err != nil {
		t.Fatal(err)
	}
	result, err := s.AwaitMaterialization(context.Background(), d.Stage.ID)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.AwaitMaterialization(context.Background(), d.Stage.ID)
	if err != nil || !reflect.DeepEqual(result, replay) || h.measures != 1 {
		t.Fatal("materialization wait did not replay its measured completion", err)
	}
}

func TestAwaitDataCancellation(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, h := dataServer(t, d)
	h.running = true
	assertOriginal := func() {
		t.Helper()
		f := d.F
		receipt, err := f.State.LookupReceipt(context.Background(), f.Human, api.RequestKey{Method: f.Human.Request.Method, IdempotencyKey: f.Human.Request.IdempotencyKey, RequestSHA256: f.Human.Request.RequestSHA256})
		if err != nil || !bytes.Equal(receipt.RawRequest, f.Raw) {
			t.Fatal("materialization expiry fixture changed its original receipt bytes", err)
		}
		original, err := s.Original(context.Background(), f.Reservation.OriginalRequest)
		if err != nil || !bytes.Equal(original, receipt.RawRequest) {
			t.Fatal("materialization expiry lost exact retained launch input", err)
		}
	}
	assertOriginal()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := s.AwaitMaterialization(ctx, d.Stage.ID)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeDeadline {
		t.Fatal("materialization expiry did not return a typed deadline", err)
	}
	assertOriginal()
	ctx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	_, err = s.AwaitMaterialization(ctx, d.Stage.ID)
	if !errors.As(err, &typed) || typed.Code != api.CodeCancelled {
		t.Fatal("materialization cancellation did not remain typed", err)
	}
	assertOriginal()
}

func TestWorkerIngressFrame(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, _ := dataServer(t, d)
	request := api.WorkerInputRequest{LeaseID: d.Stage.Worker.ID}
	scope := frameWorker(t, d, api.WorkerInputRead, request)
	scope.Actor = d.F.Human.Actor
	actual, err := s.WorkerInput(context.Background(), scope, request)
	if err != nil || actual.LeaseID != d.Stage.Worker.ID {
		t.Fatal("worker ingress trusted supplied scope labels", err)
	}
	framed := frameWorker(t, d, api.WorkerInputRead, api.WorkerInputRequest{LeaseID: fx.ID(t)})
	if _, err := s.WorkerInput(context.Background(), framed, request); err == nil {
		t.Fatal("worker ingress accepted changed framed inputs")
	} else {
		requireDataRefusal(t, err, "worker parameters differ from their authenticated frame")
	}
}

func TestWorkerResultIngress(t *testing.T) {
	d := datafx.NewData(t)
	d.Open(t)
	s, _ := dataServer(t, d)
	_, raw := d.Result(t)
	request := d.Submission(raw)
	scope := frameWorker(t, d, api.WorkerResultAppend, request)
	first, err := s.WorkerResult(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.WorkerResult(context.Background(), scope, request)
	if err != nil || first != again || first.Result.SHA256 != fx.Digest(raw) {
		t.Fatal("worker result ingress lost its one exact receipt", err)
	}
	var data api.LaunchData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	data.Target.Run++
	request.Result, err = api.CanonicalJSON(fx.JSON(t, data))
	if err != nil {
		t.Fatal(err)
	}
	scope = frameWorker(t, d, api.WorkerResultAppend, request)
	if _, err := s.WorkerResult(context.Background(), scope, request); err == nil {
		t.Fatal("worker ingress replay accepted changed result bytes")
	}
}
