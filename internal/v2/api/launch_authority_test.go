package api

import (
	"encoding/json"
	"testing"
)

func reservationRequestFixture(t *testing.T, human, retained bool) (Scope, LaunchReservationRequest) {
	t.Helper()
	p := launchFixture(t)
	grants := GrantRequest{Resources: []ResourceDelegation{}, Data: []DataGrantRequest{}, Secrets: []SecretDelegation{},
		Profiles: []ProfileDelegation{}, Network: []NetworkDelegation{}, Channels: []ChannelDelegation{}}
	start := StartRequest{Lane: "child", ProjectID: "project-one", Level: 5, Role: "supervisor", Driver: DriverCodex,
		Task: launchFixtureBlob("task", "task"), Grants: grants, ProfileGrantID: "profile-grant", Model: "fixture-model",
		Budget: p.Budget, ExpectedPolicyGeneration: 3}
	scope := Scope{Config: "demo", PolicyGeneration: 3, EndpointGeneration: 8,
		Actor: Actor{Kind: "lane", ID: "parent-principal", LifeID: "parent-life", Level: 6, Role: "supervisor"}, LaunchID: "parent-launch"}
	request := LaunchReservationRequest{OperationID: "operation-one"}
	if human {
		scope.Actor = Actor{Kind: "human", ID: "human-one"}
		start.RootTicketID = "root-ticket"
		request.Guards = []TransactionGuard{{Ticket: &TicketUse{TicketID: start.RootTicketID, PrincipalID: scope.Actor.ID,
			Config: scope.Config, EndpointGeneration: scope.EndpointGeneration, Level: start.Level, Role: start.Role, GrantSetID: "root-grants"}}}
	}
	var body any = start
	method := Method("lane.start")
	if retained {
		method = "lane.resume"
		body = ResumeRequest{Target: p.Reservation.Target, ExpectedGeneration: 1, Message: launchFixtureBlob("message", "prompt"), Budget: p.Budget}
		request.Guards = []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: p.Reservation.Target.LifeID, Epoch: 1}}}
	}
	params, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request = Request{Protocol: Protocol, Schema: SchemaVersion, Config: scope.Config, Method: method,
		RequestID: "frame-one", IdempotencyKey: "key-one", Params: params}
	scope.Request.RequestSHA256, err = RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	if retained && human {
		ref := ProofRef{ID: "human-proof", RequestSHA256: scope.Request.RequestSHA256}
		scope.Request.Proof = &ref
		request.Guards = append(request.Guards, TransactionGuard{Proof: &ProofUse{Proof: ref,
			Target: HumanChallengeRequest{Method: method, TargetID: p.Reservation.Target.LifeID, RequestSHA256: ref.RequestSHA256, BaseGeneration: 1}}})
	}
	return scope, request
}

func TestReserveAuthority(t *testing.T) {
	for _, human := range []bool{false, true} {
		for _, retained := range []bool{false, true} {
			scope, request := reservationRequestFixture(t, human, retained)
			if err := ValidateLaunchReservationRequest(scope, request); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, fault := range []string{"root_ticket", "principal", "endpoint", "lane_proof", "lane_ticket", "epoch", "human_proof"} {
		t.Run(fault, func(t *testing.T) {
			scope, request := reservationRequestFixture(t, true, false)
			switch fault {
			case "root_ticket":
				request.Guards = nil
			case "principal":
				request.Guards[0].Ticket.PrincipalID = "foreign-human"
			case "endpoint":
				request.Guards[0].Ticket.EndpointGeneration++
			case "lane_proof":
				scope, request = reservationRequestFixture(t, false, false)
				scope.Request.Proof = &ProofRef{ID: "borrowed-proof", RequestSHA256: scope.Request.RequestSHA256}
				request.Guards = []TransactionGuard{{Proof: &ProofUse{Proof: *scope.Request.Proof}}}
			case "lane_ticket":
				scope, request = reservationRequestFixture(t, false, false)
				request.Guards = []TransactionGuard{{Ticket: &TicketUse{TicketID: "borrowed-ticket"}}}
			case "epoch":
				scope, request = reservationRequestFixture(t, false, true)
				request.Guards = nil
			case "human_proof":
				scope, request = reservationRequestFixture(t, true, true)
				request.Guards = request.Guards[:1]
			}
			requireLaunchInvalid(t, ValidateLaunchReservationRequest(scope, request), "reservation authority gate was bypassed")
		})
	}
}

func TestReserveRecord(t *testing.T) {
	for _, fault := range []string{"root_ticket", "lane_proof", "child_level"} {
		t.Run(fault, func(t *testing.T) {
			r := launchFixture(t).Reservation
			if fault == "root_ticket" {
				r.Authority.Kind = "starter"
			} else {
				r.RequestedBy = Actor{Kind: "lane", ID: "parent-principal", LifeID: "parent-life", Level: 6, Role: "supervisor"}
				r.ParentLifeID, r.RootLifeID, r.StarterChain, r.StarterEventSeq = "parent-life", "parent-life", []ID{"parent-life"}, 5
				r.Authority = LaunchAuthority{Kind: "starter", ID: "parent-launch"}
				if fault == "lane_proof" {
					r.Authority.Kind = "proof"
				} else {
					r.Level = 6
				}
			}
			requireLaunchInvalid(t, ValidateLaunchReservation(r), "reservation retained invalid authority")
		})
	}
}

func TestReservedRolePins(t *testing.T) {
	for _, fault := range []string{"level", "role"} {
		t.Run(fault, func(t *testing.T) {
			p := launchFixture(t)
			b := launchFixtureBinding(t, p)
			if fault == "level" {
				b.Record.Actor.Level = 3
			} else {
				b.Record.Actor.Role = "executor"
			}
			// The record remains correctly hashed. The reservation pin decides.
			_, b.Identity.RecordSHA256 = launchFixtureHash(t, b.Record)
			requireLaunchInvalid(t, ValidateLaunchBindingPlan(b, p), "bound record changed reserved role")
		})
	}
	t.Run("driver", func(t *testing.T) {
		p := launchFixture(t)
		p.Reservation.Driver = DriverClaudock
		requireLaunchInvalid(t, ValidateLaunchPlan(p), "plan changed reserved driver")
	})
}
