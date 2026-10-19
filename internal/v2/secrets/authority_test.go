package secrets

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReadWindowContract(t *testing.T) {
	if readIdleLimit != 5*time.Minute || readAbsoluteLimit != 30*time.Minute {
		t.Fatal("published secret read windows drifted")
	}
	for _, name := range []string{"exact", "idle-over", "absolute-over"} {
		t.Run(name, func(t *testing.T) {
			s, _, _, clock := serviceFixture(t)
			scope := scopeFixture("secret.key")
			authority := &scope.Connection.(*connectionFixture).authority
			idle, absolute := clock.now.Add(5*time.Minute), clock.now.Add(30*time.Minute)
			if name == "idle-over" {
				idle = idle.Add(time.Nanosecond)
			}
			if name == "absolute-over" {
				absolute = absolute.Add(time.Nanosecond)
			}
			authority.IdleExpiresAt = api.Timestamp(idle.Format(time.RFC3339Nano))
			authority.ExpiresAt = api.Timestamp(absolute.Format(time.RFC3339Nano))
			key, err := s.SecretKey(context.Background(), scope, api.Empty{})
			if name == "exact" {
				if err != nil || key.ID == "" {
					t.Fatal("exact published read windows were refused")
				}
			} else {
				stageCode(t, err, api.CodeUnauthenticated)
			}
		})
	}
}

func TestProofPreflight(t *testing.T) {
	for _, name := range []string{"id", "digest", "expired", "malformed"} {
		t.Run(name, func(t *testing.T) {
			s, _, human, clock := serviceFixture(t)
			request := api.SecretImportRequest{Name: "canary", Version: "one", SealedUploadID: "stage-a"}
			scope := withInput(scopeFixture("secret.import"), request)
			proof := api.ProofRef{ID: "proof-a", RequestSHA256: scope.Request.RequestSHA256,
				ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
			switch name {
			case "id":
				proof.ID = "*"
			case "digest":
				proof.RequestSHA256 = digestFixture("different intent")
			case "expired":
				proof.ExpiresAt = api.Timestamp(clock.now.Format(time.RFC3339Nano))
			case "malformed":
				proof.ExpiresAt = "invalid"
			}
			scope.Request.Proof = &proof
			scope = framedScope(scope)
			_, err := s.SecretImport(context.Background(), scope, request)
			stageCode(t, err, api.CodeForbidden)
			if human.checked != 0 {
				t.Fatal("invalid proof reached the human verifier")
			}
		})
	}
}

func TestReadsRejectProof(t *testing.T) {
	for _, method := range []api.Method{"secret.key", "secret.stage", "secret.list"} {
		t.Run(string(method), func(t *testing.T) {
			s, _, _, clock := serviceFixture(t)
			scope := scopeFixture(method)
			scope.Request.Proof = &api.ProofRef{ID: "proof-a", RequestSHA256: scope.Request.RequestSHA256,
				ExpiresAt: api.Timestamp(clock.now.Add(time.Minute).Format(time.RFC3339Nano))}
			scope = framedScope(scope)
			var err error
			switch method {
			case "secret.key":
				_, err = s.SecretKey(context.Background(), scope, api.Empty{})
			case "secret.stage":
				_, err = s.SecretStage(context.Background(), scope, api.SecretStageRequest{})
			case "secret.list":
				_, err = s.SecretList(context.Background(), scope, api.Empty{})
			}
			stageCode(t, err, api.CodeInvalid)
		})
	}
}

func TestStageInjectedClock(t *testing.T) {
	_, key, value := stageFixture(t)
	clock := &clockFixture{now: time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)}
	key.ExpiresAt = api.Timestamp(clock.now.Add(time.Second).Format(time.RFC3339Nano))
	if _, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: value}, clock); err != nil {
		t.Fatal("sealed upload ignored the injected clock")
	}
	clock.now = clock.now.Add(time.Second)
	_, err := SealStage("stage-case", key, "canary", "one", api.SecretMaterial{Bytes: value}, clock)
	stageCode(t, err, api.CodeForbidden)
}

func TestInstalledInputs(t *testing.T) {
	s, _, _, _ := serviceFixture(t)
	deps := s.deps
	deps.Config = ""
	_, err := New(deps)
	stageCode(t, err, api.CodePrerequisite)
	deps = s.deps
	deps.ServiceScope = api.Scope{}
	derived, err := New(deps)
	if err != nil || derived.deps.ServiceScope.Config != deps.Config ||
		derived.deps.ServiceScope.Actor.Kind != "service" || derived.deps.ServiceScope.Actor.ID != "secrets" {
		t.Fatal("installed secret service lookup scope was not derived")
	}
	deps.ServiceScope = api.Scope{Config: "other-case", Actor: api.Actor{Kind: "service", ID: "service-a"}}
	_, err = New(deps)
	stageCode(t, err, api.CodeInvalid)
}
