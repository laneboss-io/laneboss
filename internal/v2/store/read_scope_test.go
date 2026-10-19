//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Assertions and enrollment are component inputs. Reads and reservations use
// the real store; no read-session authority is available to hide a bad proof.
func proofReadFixture(t *testing.T) (*Service, api.Scope, api.VerifiedHumanProof, api.LifeRef) {
	t.Helper()
	s, scope, session := sessionFixture(t)
	scope.Connection.(*scopeConnection).authority = nil
	target := api.LifeRef{LifeID: testID(t), Run: 1}
	lane := api.Lane{LifeID: target.LifeID, Run: target.Run, Generation: 1, State: "verifying"}
	fixtureProjection(t, s, "lane", lane.LifeID, lane.Generation, lane)
	scope.Request = testRequest(t, "lane.check", target)
	scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
	authorization, err := s.authorizationTarget(context.Background(), s.db, scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	proof := api.VerifiedHumanProof{Config: scope.Config, PrincipalID: scope.Actor.ID, CredentialID: session.CredentialID,
		EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, Target: authorization,
		Ref: api.ProofRef{ID: testID(t), RequestSHA256: scope.Request.RequestSHA256,
			ExpiresAt: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(timeFormat))}}
	fixtureProjection(t, s, "proof", proof.Ref.ID, 1, proof)
	scope.Request.Proof = &proof.Ref
	scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
	return s, scope, proof, target
}

func TestProofEventRead(t *testing.T) {
	for _, mode := range []string{"own", "another_human", "lane", "different_life"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, proof, target := proofReadFixture(t)
			ctx := context.Background()
			other := api.LifeRef{LifeID: testID(t), Run: 1}
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			want := testID(t)
			for i, selected := range []api.LifeRef{target, other, {LifeID: target.LifeID, Run: 2}} {
				id := testID(t)
				if i == 0 {
					id = want
				}
				payload := api.ProofUseReceipt{ProofID: proof.Ref.ID, CredentialID: proof.CredentialID, NonceID: testID(t), OperationID: testID(t), UsedAt: archStamp()}
				event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "human.proof.used", Actor: scope.Actor, RequestedBy: scope.Actor,
					OperationID: payload.OperationID, RequestID: scope.Request.RequestID, LifeID: selected.LifeID, Run: selected.Run, Origin: "service", Payload: archJSON(t, payload)}
				if _, err := appendPrivateEvent(ctx, tx, event, archStamp()); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			query := api.EventTailRequest{LifeID: target.LifeID, Run: target.Run}
			control, err := s.Events(ctx, scope, query)
			if err != nil || len(control.Events) != 1 || control.Events[0].ID != want {
				t.Fatal("own proof did not read exactly its life and run", err)
			}
			switch mode {
			case "own":
				return
			case "another_human":
				var enrollment api.HumanEnrollment
				if err := storedProjection(ctx, s.db, "enrollment", scope.Actor.ID, &enrollment); err != nil {
					t.Fatal(err)
				}
				scope.Actor.ID = testID(t)
				enrollment.PrincipalID = scope.Actor.ID
				fixtureProjection(t, s, "enrollment", scope.Actor.ID, enrollment.Generation, enrollment)
			case "lane":
				scope.Actor = api.Actor{Kind: "lane", ID: testID(t), LifeID: target.LifeID, Level: 3, Role: "executor"}
				scope.Connection, scope.Frame, scope.LaunchID = nil, nil, testID(t)
				grant := api.GrantSet{ID: testID(t), LifeID: target.LifeID, Generation: 1}
				fixtureProjection(t, s, "grants", grant.ID, 1, grant)
				// Match changeFixture's protected launch setup. Its complete
				// record includes the native and grant pins required by Decode.
				_, identity := identityIntent(t)
				launch := identity.Record
				launch.ID, launch.Config, launch.Actor = scope.LaunchID, scope.Config, scope.Actor
				launch.Target, launch.RootLifeID = target, target.LifeID
				launch.EndpointGeneration, launch.GrantSetID = scope.EndpointGeneration, grant.ID
				fixtureProjection(t, s, "launch", launch.ID, 1, launch)
			case "different_life":
				query.LifeID = other.LifeID
			}
			page, err := s.Events(ctx, scope, query)
			if len(page.Events) != 0 {
				t.Fatal("foreign proof exposed a protected event")
			}
			if mode == "lane" {
				if err != nil {
					t.Fatal("lane missed the ordinary event visibility path", err)
				}
				return
			}
			expectCode(t, err, api.CodeUnauthenticated)
		})
	}
}

func TestProofReadMethod(t *testing.T) {
	s, scope, proof, target := proofReadFixture(t)
	ctx := context.Background()
	if _, err := s.Lane(ctx, scope, target); err != nil {
		t.Fatal("human mutation proof read control failed", err)
	}
	scope.Request = testRequest(t, "lane.status", target)
	authorization, err := s.authorizationTarget(ctx, s.db, scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	proof.Ref.RequestSHA256, proof.Target = scope.Request.RequestSHA256, authorization
	fixtureProjection(t, s, "proof", proof.Ref.ID, 2, proof)
	scope.Request.Proof = &proof.Ref
	scope.Frame = &archFrame{raw: archJSON(t, scope.Request)}
	// This proof matches even the read request exactly. Only mutations may
	// borrow proof authority; public reads require an actual read session.
	lane, err := s.Lane(ctx, scope, target)
	expectCode(t, err, api.CodeUnauthenticated)
	if lane.LifeID != "" {
		t.Fatal("non-mutation proof returned lane state")
	}
}

func reserveReadOp(t *testing.T, s *Service, scope api.Scope) api.ID {
	t.Helper()
	raw := archJSON(t, scope.Request)
	scope.Frame = &archFrame{raw: raw}
	receipt, won, err := s.ReserveMutation(context.Background(), api.RequestReservation{Scope: scope, RawRequest: raw,
		Deadline: api.Timestamp(s.deps.Clock.Now().Add(time.Minute).UTC().Format(timeFormat))})
	if err != nil || !won {
		t.Fatal("proof read reservation control failed", err)
	}
	return receipt.Operation.ID
}

func TestConsumedByOwnOperation(t *testing.T) {
	for _, mode := range []string{"own", "another_actor", "another_request"} {
		t.Run(mode, func(t *testing.T) {
			s, scope, proof, target := proofReadFixture(t)
			ctx := context.Background()
			own := reserveReadOp(t, s, scope)
			proof.ConsumedBy = own
			fixtureProjection(t, s, "proof", proof.Ref.ID, 2, proof)
			if lane, err := s.Lane(ctx, scope, target); err != nil || lane.LifeID != target.LifeID {
				t.Fatal("consumed proof lost its own operation read", err)
			}
			if mode == "own" {
				return
			}
			foreign := scope
			foreign.Request.Proof = nil
			if mode == "another_actor" {
				foreign.Actor.ID = testID(t)
			} else {
				foreign.Request = testRequest(t, "lane.check", target)
			}
			proof.ConsumedBy = reserveReadOp(t, s, foreign)
			if proof.ConsumedBy == own {
				t.Fatal("foreign reservation reused the original operation")
			}
			fixtureProjection(t, s, "proof", proof.Ref.ID, 3, proof)
			lane, err := s.Lane(ctx, scope, target)
			expectCode(t, err, api.CodeUnauthenticated)
			if lane.LifeID != "" || !strings.Contains(err.Error(), "(consumed)") {
				t.Fatal("foreign consumer missed the exact-operation refusal", err)
			}
		})
	}
}
