package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPlanClaimState(t *testing.T) {
	c := newLaunchCase(t, "helper")
	var effect api.EffectRecord
	if c.store.read("effect.json", &effect) != nil {
		t.Fatal("cannot read retained plan state control")
	}
	effect.State = "running"
	if c.store.save("effect.json", effect) != nil {
		t.Fatal("cannot retain legacy effect state control")
	}
	_, err := c.acquire(context.Background(), c.target, c.grant)
	stageCode(t, err, api.CodeConflict)
}

func TestRetrySourceRevocation(t *testing.T) {
	for _, operation := range []string{"acquire", "inject"} {
		t.Run(operation, func(t *testing.T) {
			c := newLaunchCase(t, "helper")
			_, err := c.acquire(context.Background(), c.target, c.grant)
			if err != nil {
				t.Fatal("cannot prepare source retry revocation control")
			}
			if err := c.backend.Revoke(context.Background(), api.SecretInfo{Name: c.profile.Source.Name, Version: c.profile.Source.Version, SourceHandle: c.profile.Source.SourceHandle, KeyID: "key-a"}); err != nil {
				t.Fatal("cannot revoke actual source retry control")
			}
			if operation == "acquire" {
				_, err = c.acquire(context.Background(), c.target, c.grant)
			} else {
				_, err = c.inject(context.Background(), c.target, []api.SecretGrant{})
			}
			stageCode(t, err, api.CodeForbidden)
		})
	}
}

func TestRetainedPolicyAdvance(t *testing.T) {
	c, request, _ := eligibilityCase(t)
	c.store.policy.Generation++
	c.store.lane.PolicyGeneration = c.store.policy.Generation
	result, err := c.service.Eligibility(context.Background(), request)
	if err != nil || !result.Compatible {
		t.Fatal("retained credential selection rejected an approved live policy advance")
	}
}

func TestActorStageCap(t *testing.T) {
	s, _, _, clock := serviceFixture(t)
	scope := scopeFixture("secret.key")
	key, err := s.SecretKey(context.Background(), scope, api.Empty{})
	if err != nil {
		t.Fatal("cannot establish actual actor staging key")
	}
	for i := 0; i < 9; i++ {
		request, err := SealStage("service-case", key, fmt.Sprintf("stage-%d", i), "one", api.SecretMaterial{Bytes: syntheticBytes(t, 31)}, clock)
		if err != nil {
			t.Fatal("cannot seal actual actor staging input")
		}
		stage := scope
		stage.Request.Method, stage.Request.IdempotencyKey = "secret.stage", api.ID(fmt.Sprintf("stage-key-%d", i))
		stage = withInput(stage, request)
		_, err = s.SecretStage(context.Background(), stage, request)
		if i < 8 {
			if err != nil {
				t.Fatal("actor staging bound refused an authorized slot early")
			}
		} else {
			stageCode(t, err, api.CodeBudget)
		}
	}
}

func TestHistoryWalkBound(t *testing.T) {
	s, _, state, _, _ := mutationFixture(t)
	ctx := context.Background()
	scope := scopeFixture("secret.import")
	const chunkBytes = 512 << 10
	padding := strings.Repeat("x", chunkBytes-len(`{"padding":""}`))
	payload, err := json.Marshal(map[string]string{"padding": padding})
	if err != nil || len(payload) != chunkBytes || !json.Valid(payload) {
		t.Fatal("cannot prepare exact bounded history payload")
	}
	for index := 0; index < 16; index++ {
		state.events = append(state.events, api.Event{Config: scope.Config, Seq: api.Sequence(index + 1), Kind: "lane.status", Payload: payload})
	}
	// A config-only scope must still fail authorization before replay. The old
	// bound fixture stopped here and never reached its budget assertion.
	_, _, err = s.heads(ctx, api.Scope{Config: scope.Config}, []api.SecretInfo{})
	stageCode(t, err, api.CodeForbidden)
	heads, known, err := s.heads(ctx, scope, []api.SecretInfo{})
	if err != nil || len(heads) != 0 || len(known) != 0 {
		t.Fatal("history at the exact byte bound was refused or changed metadata")
	}
	expanded, err := json.Marshal(map[string]string{"padding": padding + "x"})
	if err != nil || len(expanded) != chunkBytes+1 || !json.Valid(expanded) {
		t.Fatal("cannot prepare the one-byte history overflow")
	}
	state.events[len(state.events)-1].Payload = expanded
	_, _, err = s.heads(ctx, scope, []api.SecretInfo{})
	stageCode(t, err, api.CodeBudget)
}
