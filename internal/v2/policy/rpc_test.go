package policy

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type testRegistry struct {
	api.Registrar
	handlers map[api.Method]api.Handler
}

func (r *testRegistry) Register(method api.Method, handler api.Handler) error {
	if _, duplicate := r.handlers[method]; duplicate {
		return conflict("duplicate fixture handler")
	}
	r.handlers[method] = handler
	return nil
}

func TestRPCShapeAndRegistration(t *testing.T) {
	f := newFixture(t, sourceRule("publish"))
	registry := &testRegistry{handlers: map[api.Method]api.Handler{}}
	if err := f.service.Register(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.handlers) != 4 {
		t.Fatal("module did not register exactly its frozen methods")
	}
	for _, method := range []api.Method{"policy.get", "policy.evaluate", "config.read", "config.validate"} {
		if registry.handlers[method] == nil {
			t.Fatalf("missing method %s", method)
		}
	}
	for _, raw := range []string{
		`{}`, `{"life_id":null}`, `{"life_id":"","role":"supervisor"}`,
		`{"life_id":"","life_id":"other"}`, `{"life_id":""} {}`,
		`{"LIFE_ID":""}`, `[]`,
	} {
		_, err := registry.handlers["policy.get"](context.Background(), f.scope, []byte(raw))
		wantCode(t, err, api.CodeInvalid)
	}
	raw, err := registry.handlers["policy.get"](context.Background(), f.scope, []byte(`{"life_id":""}`))
	if err != nil || strings.Contains(string(raw), ":null") {
		t.Fatalf("valid policy response failed or emitted null arrays: %s, %v", raw, err)
	}
	_, err = registry.handlers["config.validate"](context.Background(), f.scope, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, f.service.Register(registry), api.CodeConflict)
}

func TestConfigProjectionAndLimits(t *testing.T) {
	f := newFixture(t, sourceRule("publish"))
	addUnselectedSource(f)
	f.scope.Request.Method = "config.read"
	result, err := f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: "path"})
	if err != nil {
		t.Fatal(err)
	}
	var projection api.ConfigProjection
	if err := api.DecodeObject(f.store.uploads[result.Projection.ID].data, &projection); err != nil ||
		projection.Schema != "laneboss.config-view.v2" || projection.Config != f.scope.Config || projection.View != "path" ||
		!reflect.DeepEqual(projection.Sources, f.store.policy.Sources) || projection.Binding != nil {
		t.Fatal("configuration projection lost policy content/provenance")
	}
	if !reflect.ValueOf(f.store.lastTx).IsZero() {
		t.Fatal("configuration read submitted a public state transaction")
	}
	other := api.RoleContext{Level: 6, Role: "supervisor"}
	_, err = f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: "path", Context: &other})
	wantCode(t, err, api.CodeForbidden)
	_, err = f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: "unknown"})
	wantCode(t, err, api.CodeInvalid)
	for _, view := range []string{"show", "settings", "roles", "plugins", "channels"} {
		_, err := f.service.ConfigRead(context.Background(), f.scope, api.ConfigReadRequest{View: view})
		wantCode(t, err, api.CodePrerequisite)
		if err.(*api.Error).Owner != "lb-v2-policy" || err.(*api.Error).Instead == "" {
			t.Fatal("missing canonical source did not retain its approval prerequisite")
		}
	}
	valid, err := f.service.ConfigValidate(context.Background(), f.scope, api.Empty{})
	if err != nil || !valid.Valid || valid.Problems == nil || len(valid.Problems) != 0 {
		t.Fatal("valid policy control failed")
	}
	f.service.deps.ValidateSources = nil
	_, err = f.service.ConfigValidate(context.Background(), f.scope, api.Empty{})
	wantCode(t, err, api.CodeNotImplemented)
	f.store.policy.Rules[0].Band = "allow"
	valid, err = f.service.ConfigValidate(context.Background(), f.scope, api.Empty{})
	if err != nil || valid.Valid || len(valid.Problems) == 0 {
		t.Fatal("invalid policy returned successful validation")
	}
}
