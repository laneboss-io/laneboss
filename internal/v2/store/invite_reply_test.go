//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestInviteReplyFences(t *testing.T) {
	for _, action := range []string{"invite", "approve", "reject", "revoke"} {
		t.Run(action, func(t *testing.T) {
			s, owner, _ := sessionFixture(t)
			request := api.HumanAccessRequest{Action: "invite", Role: "human"}
			if action != "invite" {
				_, pending := inviteRegister(t, s, inviteNew(t, s, owner))
				request = api.HumanAccessRequest{Action: action, InviteID: pending.ID, Fingerprint: pending.Fingerprint, ExpectedGeneration: pending.Generation}
				if action == "revoke" {
					active := inviteDecision(t, s, owner, pending, "approve")
					request = api.HumanAccessRequest{Action: action, PrincipalID: active.PrincipalID, ExpectedGeneration: active.EnrollmentGeneration}
				}
			}
			scope := inviteScope(t, s, owner, request)
			value, err := inviteCommit(t, s, scope, request)
			if err != nil {
				t.Fatal("projection reply positive control did not commit", err)
			}
			receipt, err := s.LookupReceipt(context.Background(), scope, requestKey(scope.Request))
			if err != nil || receipt.Reply == nil {
				t.Fatal("actual operation receipt is missing", err)
			}
			for _, mode := range []string{"control", "actor", "endpoint", "configuration", "proof", "operation", "projection", "token", "generation"} {
				t.Run(mode, func(t *testing.T) {
					input := api.Transaction{Scope: scope, Reply: &api.RPCReply{Result: enrollmentJSON(t, value)}}
					operation := receipt.Operation
					changed := value
					switch mode {
					case "actor":
						input.Scope.Actor.ID = testID(t)
					case "endpoint":
						input.Scope.EndpointGeneration++
					case "configuration":
						input.Scope.Config = "other-config"
					case "proof":
						input.Scope.Request.Proof = nil
					case "operation":
						operation.ID = testID(t)
					case "projection":
						changed.ID = testID(t)
					case "token":
						changed.Token += "changed"
					case "generation":
						changed.Generation++
					}
					input.Reply.Result = enrollmentJSON(t, changed)
					tx, err := s.db.BeginTx(context.Background(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					reply, err := s.finalReply(context.Background(), tx, input, operation)
					if mode == "control" {
						if err != nil || reply == nil || !wire.SameJSON(reply.Result, receipt.Reply.Result) {
							t.Fatal("actual projection reply changed its durable result", err)
						}
					} else if err == nil || reply != nil {
						t.Fatal("reply correlation accepted "+mode, err)
					}
				})
			}
		})
	}
}

type stagedHuman struct {
	*scopeConnection
	bound api.HumanStaging
}

func (c *stagedHuman) HumanStaging(context.Context) (api.HumanStaging, error) { return c.bound, nil }

func TestInviteStagingPrincipal(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	install, pending := inviteRegister(t, s, inviteNew(t, s, owner))
	reader := inviteReader(t, s, install.Enrollment)
	native := reader.Connection.(*scopeConnection)
	native.authority = nil
	bound := &stagedHuman{scopeConnection: native, bound: api.HumanStaging{
		Frame: &archFrame{raw: []byte(`{"native":"opening frame"}`)}, PrincipalID: install.Enrollment.PrincipalID}}
	reader.Connection = bound
	staging := reader
	staging.Actor.ID = ""
	_, err := s.Enrollment(context.Background(), staging)
	expectCode(t, err, api.CodeUnauthenticated)
	inviteDecision(t, s, owner, pending, "approve")
	actual, err := s.Enrollment(context.Background(), staging)
	if err != nil || actual.PrincipalID != install.Enrollment.PrincipalID {
		t.Fatal("native opening lost its authenticated principal", err)
	}
	chunk, err := s.Blob(context.Background(), reader, api.BlobReadRequest{ObjectID: install.CeremonyEvidence.ID, Limit: 20})
	expectCode(t, err, api.CodeUnauthenticated)
	if len(chunk.Data) != 0 {
		t.Fatal("native staging principal granted a content read", err)
	}
	r := api.HumanAccessRequest{Action: "revoke", PrincipalID: actual.PrincipalID, ExpectedGeneration: actual.Generation}
	if _, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r); err != nil {
		t.Fatal(err)
	}
	_, err = s.Enrollment(context.Background(), staging)
	expectCode(t, err, api.CodeUnauthenticated)
}
