package admin

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestDoctorInput(t *testing.T) {
	for _, raw := range []string{`{}`, " \n { \t } \r\n"} {
		if err := ValidateDoctorInput(json.RawMessage(raw)); err != nil {
			t.Fatalf("empty doctor object refused: %v", err)
		}
	}
	registry := &recordedRegistry{}
	if err := (&Service{}).Register(registry); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"field":     `{"path":"ignored"}`,
		"duplicate": `{"path":1,"path":2}`,
		"null":      `null`,
		"array":     `[]`,
		"trailing":  `{} {}`,
		"empty":     ``,
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateDoctorInput(json.RawMessage(raw))
			if err == nil {
				t.Fatal("acceptance: nonempty doctor input accepted")
			}
			requireCode(t, err, api.CodeInvalid)
			_, err = registry.methods["doctor"](context.Background(), api.Scope{}, json.RawMessage(raw))
			requireCode(t, err, api.CodeInvalid)
		})
	}
}

func TestDoctorReadiness(t *testing.T) {
	result := api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: identity.Version, ArtifactSHA256: testDigest("doctor"), Ready: false,
		Capabilities: []api.Capability{{Name: "helper.prepare", Available: false, Reason: "missing gate"}}}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDoctorHealth(data)
	if err != nil || parsed.Ready {
		t.Fatalf("unready control: %v", err)
	}
	result.Ready = true
	data, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseDoctorHealth(data)
	if err == nil {
		t.Fatal("acceptance: doctor false readiness")
	}
	requireCode(t, err, api.CodeIntegrity)
	result.Capabilities[0].Available = true
	data, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseDoctorHealth(data)
	if err != nil || !parsed.Ready {
		t.Fatalf("ready control: %v", err)
	}
}

func TestDoctorResultShape(t *testing.T) {
	result := api.Health{Protocol: api.Protocol, Schema: api.SchemaVersion,
		ServiceVersion: identity.Version, ArtifactSHA256: testDigest("doctor"), Ready: false,
		Capabilities: []api.Capability{{Name: "gate", Available: false, Reason: "missing"}}}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	delete(members, "ready")
	missing, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDoctorHealth(missing); err == nil {
		t.Fatal("acceptance: missing ready accepted")
	}
	duplicate := append(append([]byte{}, data[:len(data)-1]...), []byte(`,"ready":false}`)...)
	if _, err := ParseDoctorHealth(duplicate); err == nil {
		t.Fatal("acceptance: duplicate ready accepted")
	}
	result.Capabilities = append(result.Capabilities, result.Capabilities[0])
	data, err = json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDoctorHealth(data); err == nil {
		t.Fatal("acceptance: duplicate capability accepted")
	}
}
