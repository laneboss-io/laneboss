package admin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaneDoctorCache(t *testing.T) {
	s := &Service{deps: Dependencies{Config: "admin-case"}, binding: testBinding()}
	scope := api.Scope{Config: "admin-case", EndpointGeneration: 1,
		Actor: api.Actor{Kind: "lane", ID: "actor-a", LifeID: "life-a", Level: 3, Role: "executor"}}
	result, err := s.Doctor(context.Background(), scope, api.Empty{})
	if err != nil || result.Ready || len(result.Capabilities) != 1 || result.Capabilities[0].Name != "doctor.cached_health" {
		t.Fatal("acceptance: lane drove root probe")
	}
	s.health = &api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion, Ready: true,
		Capabilities: []api.Capability{{Name: "observed", Available: true}}}
	s.healthAt = time.Now()
	result, err = s.Doctor(context.Background(), scope, api.Empty{})
	if err != nil || !result.Ready || result.Capabilities[0].Name != "observed" {
		t.Fatal("lane did not receive current observed health")
	}
	result.Capabilities[0].Available = false
	if !s.health.Capabilities[0].Available {
		t.Fatal("caller mutated the cached health")
	}
}

func TestStrictCaseAndSurrogate(t *testing.T) {
	for _, input := range []string{`{"kind":"human","id":"actor","ROLE":"x"}`,
		`{"kind":"human","id":"actor","role":"a","ROLE":"b"}`,
		`{"kind":"human","id":"actor","role":"\ud800"}`} {
		var actor api.Actor
		if err := decodeStrict([]byte(input), &actor); err == nil {
			t.Fatal("acceptance: ambiguous actor JSON")
		}
	}
	for _, actor := range []api.Actor{{Kind: "lane", ID: "a", LifeID: "life", Level: 2, Role: "executor"},
		{Kind: "human", ID: "h", LifeID: "life"}, {Kind: "worker", ID: "w", Level: 3}} {
		if validActor(actor) {
			t.Fatal("actor metadata widened authority")
		}
	}
	encoded, err := json.Marshal(testAllocation())
	if err != nil {
		t.Fatal(err)
	}
	var request api.HelperLeaseRequest
	if err := decodeStrict(encoded, &request); err != nil {
		t.Fatal(err)
	}
}
