//go:build linux

package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func fixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOwnedFailureDoesNotHalt(t *testing.T) {
	ownedFailureDoesNotHalt(t, false, false)
}

func TestOwnedFailureDiagnosticDoesNotHalt(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "changed"}[corrupt], func(t *testing.T) {
			ownedFailureDoesNotHalt(t, true, corrupt)
		})
	}
}

type missingOwnedDeadline struct {
	*reconcileFenceStore
	effect, missing api.ID
	calls           int
	corrupt         bool
}

func (s *missingOwnedDeadline) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	record, err := s.reconcileFenceStore.Effect(ctx, scope, id)
	if err == nil && id == s.effect && s.corrupt && record.Outcome != nil && record.Outcome.Error != nil {
		record.Outcome.Error.Message += " changed after persistence"
	}
	return record, err
}

func (s *missingOwnedDeadline) OwnedEffectDeadline(ctx context.Context, scope api.Scope, id api.ID) (api.Timestamp, error) {
	if id != s.effect {
		return "", serviceError(api.CodeIntegrity, "component received another owned effect")
	}
	s.calls++
	_, err := s.Service.ObjectMetadata(ctx, scope, s.missing)
	if api.ErrorComponent(err) != "store_object" {
		return "", serviceError(api.CodeIntegrity, "component did not reach the real missing object diagnostic")
	}
	return "", err
}

func ownedFailureDoesNotHalt(t *testing.T, diagnostic, corrupt bool) {
	t.Helper()
	host, state, scope, ctx, active := reconcileFixture(t, "", nil)
	next, err := state.Service.Effect(context.Background(), scope, state.next)
	if err != nil {
		t.Fatal(err)
	}
	target := next.Effect.Context.Target
	lane, err := state.Service.Lane(context.Background(), scope, target)
	if err != nil {
		t.Fatal(err)
	}
	clean := api.CleanRequest{Target: target, ExpectedGeneration: lane.Generation, ArchiveReceiptID: fixtureID(t)}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: scope.Config, Method: "lane.clean", RequestID: fixtureID(t), IdempotencyKey: fixtureID(t), Params: fixtureJSON(t, clean)}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	caller := scope
	caller.Request = request
	receipt, _, err := state.Service.ReserveMutation(context.Background(), api.RequestReservation{Scope: caller, RawRequest: fixtureJSON(t, request), Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	cause := api.InternalIntent{ID: fixtureID(t), Kind: api.InternalLifecycleEffect, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor, CauseOperationID: receipt.Operation.ID, CauseRequestID: request.RequestID, EffectID: fixtureID(t), Target: target, CancellationEpoch: lane.CancellationEpoch}
	effect := api.Effect{ID: cause.EffectID, OperationID: receipt.Operation.ID, Context: &cause, Clean: &clean}
	if _, err := state.Service.Transact(context.Background(), api.Transaction{Scope: caller, Effects: []api.Effect{effect}, Reply: &api.RPCReply{Result: fixtureJSON(t, receipt.Operation)}}); err != nil {
		t.Fatal("owned refusal outbox fixture failed", err)
	}
	state.blocked = effect.ID
	want := api.CodeNotImplemented
	var missing *missingOwnedDeadline
	if diagnostic {
		missing = &missingOwnedDeadline{reconcileFenceStore: state, effect: effect.ID, missing: fixtureID(t), corrupt: corrupt}
		host.deps.Store = missing
		want = api.CodeNotFound
	}
	host.reconcileLoop(ctx)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("owned failure halted the reconciler before the next real effect")
	}
	failed, err := state.Service.Effect(context.Background(), scope, effect.ID)
	if err != nil || failed.State != api.EffectFailed || failed.Outcome == nil || failed.Outcome.Error == nil || failed.Outcome.Error.Code != want {
		t.Fatal("missing collector was not recorded as an owned terminal refusal", err)
	}
	if !*active {
		var refusal *api.Error
		if corrupt && errors.As(host.fault, &refusal) && refusal.Code == api.CodeIntegrity && refusal.Message == "owned effect returned before its atomic verified completion" && missing.calls == 1 {
			return
		}
		t.Fatal("owned failure stopped processing unrelated effects", host.fault)
	}
	if corrupt {
		t.Fatal("owned readback accepted a changed public error message")
	}
	if diagnostic && missing.calls != 1 {
		t.Fatal("owned failure did not consume its real missing-object input exactly once")
	}
}

type installedCollector struct{ api.DataWorker }

func (installedCollector) CollectCleanup(context.Context, api.CleanupJob) (api.CleanupReceipt, error) {
	return api.CleanupReceipt{}, api.NotImplemented("lb-v2-grants", "fixture collector must not run without native storage")
}
func TestCleanupRequiresNativePorts(t *testing.T) {
	host, state, _, _, _ := reconcileFixture(t, "", nil)
	runtime := host.runtime
	runtime.Store = state.Service
	runtime.Worker = installedCollector{}
	err := supportsEffect(runtime, api.Effect{Clean: &api.CleanRequest{}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodeNotImplemented {
		t.Fatal("cleanup dispatch accepted nil native collection ports", err)
	}
}
