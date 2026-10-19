package guidance

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Structural connection fixture only. Native peer verification, expiry and
// revocation belong to the transport/store; this fixture exercises their port.
type readConnection struct {
	api.ConnectionContext
	id        api.ID
	binding   api.InstalledBinding
	authority api.ReadAuthority
	failure   error
	reads     int
}

func (connection *readConnection) ID() api.ID                    { return connection.id }
func (connection *readConnection) Binding() api.InstalledBinding { return connection.binding }
func (connection *readConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	connection.reads++
	return connection.authority, connection.failure
}

func humanScope() (api.Scope, *readConnection) {
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	connection := &readConnection{id: "connection-a",
		binding: api.InstalledBinding{Class: api.EndpointHuman, Config: "example", EndpointGeneration: 4},
		authority: api.ReadAuthority{ConnectionID: "connection-a", SessionID: "session-a", PrincipalID: "human-a",
			CredentialID: "credential-a", Config: "example", EndpointGeneration: 4, IdleExpiresAt: expires, ExpiresAt: expires}}
	return api.Scope{Config: "example", PolicyGeneration: 3, EndpointGeneration: 4,
		Actor: api.Actor{Kind: "human", ID: "human-a"}, Connection: connection,
		Request: api.Request{Method: "guidance.select", Config: "example", RequestID: "human-request", IdempotencyKey: "human-key", RequestSHA256: digestBytes([]byte("human fixture request"))}}, connection
}

func TestSelectSelfAuthority(t *testing.T) {
	changes := map[string]func(*api.Scope){
		"other-life": func(scope *api.Scope) { scope.Actor.LifeID = "other-life" },
		"ancestor": func(scope *api.Scope) {
			scope.Actor.LifeID = "parent-life"
			scope.Actor.Level = 6
			scope.Actor.Role = "owner"
			scope.Source = "human"
		},
		"worker":         func(scope *api.Scope) { scope.Actor.Kind = "worker" },
		"proof":          func(scope *api.Scope) { scope.Request.Proof = &api.ProofRef{} },
		"read-authority": func(scope *api.Scope) { scope.ReadAuthority = &api.ReadAuthority{} },
		"method":         func(scope *api.Scope) { scope.Request.Method = "lane.status" },
		"config":         func(scope *api.Scope) { scope.Request.Config = "other" },
		"run": func(scope *api.Scope) {
			target := guidanceRequest().Target
			target.Run++
			scope.Connection = &readConnection{binding: api.InstalledBinding{Class: api.EndpointLane, Config: scope.Config, Target: &target}}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			service, store, judge, scope := serviceFixture(t)
			change(&scope)
			_, err := service.GuidanceSelect(context.Background(), scope, guidanceRequest())
			if store.laneCalls != 0 || store.policyCalls != 0 || store.reservationCalls != 0 || store.transactions != 0 || judge.fitCalls != 0 {
				t.Fatal("self authority failure reached a store read or judge")
			}
			assertCode(t, err, api.CodeForbidden)
		})
	}
}

func TestStageSelfAuthority(t *testing.T) {
	for _, mode := range []string{"single", "batches"} {
		for _, defect := range []string{"life", "config", "worker"} {
			t.Run(mode+"/"+defect, func(t *testing.T) {
				request, scope := stageRequest(), stageScope()
				switch defect {
				case "life":
					request.Context.Target.LifeID = "child-life"
					scope.Actor.Level = 6
				case "config":
					request.Context.Config = "other"
				case "worker":
					scope.Actor.Kind = "worker"
				}
				probe := &judgeProbe{fit: fixtureFit}
				var err error
				if mode == "single" {
					_, err = stage(probe).evaluateCandidates(context.Background(), scope, request, stagePolicy())
				} else {
					_, err = stage(probe).evaluateBatches(context.Background(), scope, request, stagePolicy())
				}
				if probe.fitCalls != 0 || probe.evalCalls != 0 {
					t.Fatal("foreign judge context reached fit or inference")
				}
				assertCode(t, err, api.CodeForbidden)
			})
		}
	}
}

func TestHumanSessionReplay(t *testing.T) {
	service, store, judge, _, request, retained := retainedFixture(t)
	scope, connection := humanScope()
	scope = scopeForGuidance(t, scope, request)
	actual, err := service.GuidanceSelect(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(actual, retained) {
		t.Fatalf("bound human session could not replay: %v", err)
	}
	transaction := store.lastTransaction
	if connection.reads != 2 || transaction.Scope.ReadAuthority == nil ||
		*transaction.Scope.ReadAuthority != connection.authority || transaction.Scope.Request.Proof != nil ||
		len(transaction.Guards) != 0 || store.transactions != 1 || judge.fitCalls != 0 || judge.evalCalls != 0 {
		t.Fatal("human replay omitted live read authority or consumed an operation proof")
	}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		t.Fatal(err)
	}
}

func TestHumanReplayAuthority(t *testing.T) {
	for _, defect := range []string{"missing", "unbound", "foreign", "closed", "session", "proof"} {
		t.Run(defect, func(t *testing.T) {
			service, store, _, _, request, _ := retainedFixture(t)
			scope, connection := humanScope()
			authority := connection.authority
			scope.ReadAuthority = &authority
			switch defect {
			case "missing":
				scope.Connection = nil
			case "unbound":
				connection.authority.SessionID = ""
			case "foreign":
				authority.ConnectionID = "other-connection"
			case "closed":
				connection.failure = forbidden("structural fixture connection is closed")
			case "session":
				authority.SessionID = "old-session"
			case "proof":
				scope.Request.Proof = &api.ProofRef{}
			}
			_, err := service.GuidanceSelect(context.Background(), scope, request)
			if store.laneCalls != 0 || store.reservationCalls != 0 || store.transactions != 0 {
				t.Fatal("invalid human session reached a retained read or replay")
			}
			assertCode(t, err, api.CodeForbidden)
		})
	}
}

func TestReplayRechecksLiveSession(t *testing.T) {
	service, store, _, _, request, retained := retainedFixture(t)
	scope, connection := humanScope()
	authority := connection.authority
	scope.ReadAuthority = &authority
	connection.failure = forbidden("structural fixture session revoked before seal")
	_, err := service.sealReplay(context.Background(), scope, request.Target, retained)
	if connection.reads != 1 || store.reservationCalls != 0 || store.transactions != 0 {
		t.Fatal("replay trusted stale authority without a live session check")
	}
	assertCode(t, err, api.CodeForbidden)
}
