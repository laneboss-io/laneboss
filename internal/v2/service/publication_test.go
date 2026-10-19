package service

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// These ports isolate coordinator dispatch only. Store publication tests use
// actual SQLite, canonical files, pointer swaps and independent readback.
type publicationRouteStore struct {
	api.StateStore
	lease   api.EffectLease
	input   api.PublishChangeRequest
	pending api.MutationReceipt
}

func (s *publicationRouteStore) Effect(ctx context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if ctx.Err() != nil {
		return api.EffectRecord{}, ctx.Err()
	}
	if id != s.lease.Record.Effect.ID || scope.Actor.ID != s.lease.Record.ClaimantID {
		return api.EffectRecord{}, serviceError(api.CodeForbidden, "foreign route fixture claim")
	}
	return s.lease.Record, nil
}
func (s *publicationRouteStore) ChangePublication(ctx context.Context, scope api.Scope, lease api.EffectLease) (api.PublishChangeRequest, api.MutationReceipt, error) {
	if ctx.Err() != nil || !reflect.DeepEqual(lease, s.lease) {
		return api.PublishChangeRequest{}, api.MutationReceipt{}, serviceError(api.CodeConflict, "stale route fixture claim")
	}
	return s.input, s.pending, nil
}

type publicationRoutePublisher struct {
	api.OrgPublisher
	fresh, recovered int
}

func (p *publicationRoutePublisher) PublishChange(ctx context.Context, scope api.Scope, input api.PublishChangeRequest) (api.ChangeReceipt, error) {
	p.fresh++
	return routePublication(ctx, input)
}
func (p *publicationRoutePublisher) ReconcileChange(ctx context.Context, scope api.Scope, input api.PublishChangeRequest) (api.ChangeReceipt, error) {
	p.recovered++
	return routePublication(ctx, input)
}
func routePublication(ctx context.Context, input api.PublishChangeRequest) (api.ChangeReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.ChangeReceipt{}, err
	}
	return api.ChangeReceipt{ID: input.Lease.Record.Effect.OperationID, ChangeID: input.ChangeID, ApprovalID: input.ApprovalID, OldGeneration: input.BaseGeneration, NewGeneration: input.BaseGeneration + 1, ManifestSHA256: input.ManifestSHA256, AppliedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}, nil
}

func TestPublicationEffectCoordinator(t *testing.T) {
	for _, mode := range []string{"fresh", "recovery", "stale", "missing_publisher"} {
		t.Run(mode, func(t *testing.T) {
			id := func() api.ID {
				value, err := wire.NewID()
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			config, actor := "publication-case", api.Actor{Kind: "lane", ID: id(), LifeID: id(), Level: 6, Role: "supervisor"}
			apply := api.ChangeApplyRequest{ChangeID: id(), ApprovalID: id(), ExpectedGeneration: 1}
			params, err := json.Marshal(apply)
			if err != nil {
				t.Fatal(err)
			}
			request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: config, Method: "org.change.apply", RequestID: id(), IdempotencyKey: id(), Params: params}
			request.RequestSHA256, err = api.RequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			op, effectID, claimant, claim := id(), id(), id(), id()
			effect := api.Effect{ID: effectID, OperationID: op, ApplyChange: &apply, Context: &api.InternalIntent{ID: id(), Config: config, Kind: api.InternalOrgPublish, Actor: api.Actor{Kind: "service", ID: id()}, RequestedBy: actor, CauseRequestID: request.RequestID, CauseOperationID: op, EffectID: effectID, Target: api.LifeRef{LifeID: actor.LifeID, Run: 1}}}
			generation := api.Generation(2)
			if mode == "recovery" {
				generation++
			}
			expires := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
			lease := api.EffectLease{Record: api.EffectRecord{Effect: effect, Generation: generation, State: api.EffectClaimed, ClaimID: claim, ClaimantID: claimant, ClaimExpiresAt: expires}, ClaimID: claim, ExpiresAt: expires}
			key := api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
			pending := api.MutationReceipt{Config: config, Actor: actor, Key: key, Operation: api.Operation{ID: op, Status: "pending"}, RawRequest: raw, Deferred: &api.DeferredReply{Key: key, OperationID: op, EffectID: effectID}}
			state := &publicationRouteStore{lease: lease, pending: pending, input: api.PublishChangeRequest{Lease: lease, ChangeID: apply.ChangeID, ApprovalID: apply.ApprovalID, BaseGeneration: 1, ManifestSHA256: api.Digest(strings.Repeat("a", 64)), Renderer: api.Executable{ID: id(), SHA256: api.Digest(strings.Repeat("b", 64)), Version: "route-component"}}}
			publisher := &publicationRoutePublisher{}
			host := &Server{deps: Dependencies{Store: state, Clock: fixtureClock{}}, runtime: api.RuntimeServices{Store: state, Publisher: publisher}}
			if mode == "missing_publisher" {
				host.runtime.Publisher = nil
			}
			if mode == "stale" {
				state.lease.Record.Generation++
			}
			outcome, err := host.runEffect(context.Background(), api.Scope{Config: config, Actor: api.Actor{Kind: "service", ID: claimant}}, lease)
			if mode == "stale" || mode == "missing_publisher" {
				if err == nil || publisher.fresh+publisher.recovered != 0 {
					t.Fatal("invalid publication reached a publisher")
				}
				return
			}
			if err != nil {
				t.Fatal("publication effect did not reach its owning coordinator", err)
			}
			if err := api.ValidateDeferredCompletion(pending, lease, outcome); err != nil {
				t.Fatal("coordinator lost original deferred request binding", err)
			}
			if mode == "fresh" && (publisher.fresh != 1 || publisher.recovered != 0) || mode == "recovery" && (publisher.recovered != 1 || publisher.fresh != 0) {
				t.Fatal("recovery executed a new publication path")
			}
		})
	}
}
