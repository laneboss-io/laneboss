package identity

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type fixtureInvalidator struct {
	call func(context.Context, api.LaunchRevocation) (api.TransportInvalidationReceipt, error)
}

func (f *fixtureInvalidator) InvalidateLaunch(ctx context.Context, r api.LaunchRevocation) (api.TransportInvalidationReceipt, error) {
	return f.call(ctx, r)
}

func TestRevocationConsumerFixture(t *testing.T) {
	for _, rule := range []string{"valid", "record", "event", "unknown", "survivor", "operation", "error", "changed", "record-drift", "unbound"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			store.record.Revoked = true
			if rule == "record" {
				store.record.Revoked = false
			}
			cause := api.InternalIntent{ID: "revocation-cause", Kind: api.InternalLifecycleEffect, Config: store.record.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"},
				RequestedBy: api.Actor{Kind: "human", ID: "human"}, Target: store.record.Target, CauseOperationID: "revocation-operation", CauseRequestID: "revocation-request", CancellationEpoch: 2}
			revocation := api.LaunchRevocation{Record: store.record, RecordSHA256: launchBlob(t, "record", "manifest", store.record).SHA256, Cause: cause, EventID: "revocation-event", CommittedSeq: 12}
			store.revocation = &revocation
			store.events = &api.EventPage{Complete: true, Events: []api.Event{{Schema: api.SchemaVersion, ID: revocation.EventID, Seq: revocation.CommittedSeq, Kind: "identity.revoked", Config: store.record.Config,
				Actor: cause.Actor, RequestedBy: cause.RequestedBy, LifeID: store.record.Target.LifeID, Run: store.record.Target.Run, RequestID: cause.CauseRequestID, OperationID: cause.CauseOperationID, Payload: launchJSON(t, store.record)}}}
			if rule == "event" {
				store.events.Events[0].Actor.ID = "foreign-service"
			}
			calls := 0
			sentinel := api.NotImplemented("lb-v2-service", "fixture transport unavailable")
			invalidator := &fixtureInvalidator{call: func(ctx context.Context, r api.LaunchRevocation) (api.TransportInvalidationReceipt, error) {
				calls++
				if rule == "error" {
					return api.TransportInvalidationReceipt{}, sentinel
				}
				zero, deliveries := uint64(0), uint64(0)
				receipt := api.TransportInvalidationReceipt{LaunchID: r.Record.ID, RevocationEventID: r.EventID, OperationID: r.Cause.CauseOperationID,
					RemainingConnections: &zero, RemainingDeliveries: &deliveries, CompletedAt: timestamp(s.deps.Clock.Now())}
				switch rule {
				case "unknown":
					receipt.RemainingConnections = nil
				case "survivor":
					deliveries = 1
				case "operation":
					receipt.OperationID = "foreign-operation"
				case "changed":
					store.revocation.Cause.CauseRequestID = "new-request"
				case "record-drift":
					store.record.Revoked = false
				}
				return receipt, nil
			}}
			if rule != "unbound" {
				if err := s.BindConnections(invalidator); err != nil {
					t.Fatal(err)
				}
			}
			err := s.RevokeLaunch(context.Background(), store.record.ID)
			if rule == "record" && calls != 0 {
				t.Fatal("fixture check: invalid revocation reached transport")
			}
			switch rule {
			case "record", "unknown", "survivor", "operation":
				fixtureCode(t, err, api.CodeInvalid)
				return
			case "event":
				fixtureCode(t, err, api.CodeIntegrity)
				return
			case "error":
				if !errors.Is(err, sentinel) {
					t.Fatal("fixture check: invalidation failure was replaced")
				}
				return
			case "changed", "record-drift":
				fixtureCode(t, err, api.CodeConflict)
				return
			case "unbound":
				fixtureCode(t, err, api.CodeNotImplemented)
				return
			}
			if err != nil || calls != 1 || store.transaction != nil || store.eventQuery.Since != revocation.CommittedSeq-1 || !store.record.Revoked {
				t.Fatalf("fixture check: committed revocation was not invalidated: %v", err)
			}
		})
	}
}

func TestInvalidatorBindingFixture(t *testing.T) {
	s, _, _ := serviceFixture(t)
	fixtureCode(t, s.BindConnections(nil), api.CodePrerequisite)
	provider := &fixtureInvalidator{call: func(ctx context.Context, r api.LaunchRevocation) (api.TransportInvalidationReceipt, error) {
		return api.TransportInvalidationReceipt{}, api.NotImplemented("lb-v2-service", "unused fixture invalidator")
	}}
	if err := s.BindConnections(provider); err != nil {
		t.Fatal(err)
	}
	fixtureCode(t, s.BindConnections(provider), api.CodeConflict)
}
