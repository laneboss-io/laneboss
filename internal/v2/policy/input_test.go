package policy

import (
	"context"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReadInputSemantics(t *testing.T) {
	for _, life := range []api.ID{"", "life-a"} {
		if err := ValidateGetInput(api.PolicyGetRequest{LifeID: life}); err != nil {
			t.Fatalf("valid policy life input refused: %v", err)
		}
	}
	f := newFixture(t)
	f.store.policyErr = api.NotImplemented("fixture", "read input must precede store")
	for _, life := range []api.ID{"bad.id", api.ID(strings.Repeat("x", 129))} {
		request := api.PolicyGetRequest{LifeID: life}
		expected := ValidateGetInput(request)
		wantCode(t, expected, api.CodeInvalid)
		_, actual := f.service.PolicyGet(context.Background(), f.scope, request)
		wantCode(t, actual, api.CodeInvalid)
		if actual.(*api.Error).Owner != "lb-v2-policy" || actual.Error() != expected.Error() {
			t.Fatal("service policy-get input differs from shared validator")
		}
	}
	for _, view := range []string{"path", "list", "show", "settings", "roles", "plugins", "channels"} {
		request := api.ConfigReadRequest{View: view, Context: &api.RoleContext{Level: 3, Role: "executor"}}
		if err := ValidateConfigReadInput(request); err != nil {
			t.Fatalf("valid configuration view refused: %v", err)
		}
	}
	for _, request := range []api.ConfigReadRequest{
		{View: ""}, {View: "unknown"}, {View: "config"}, {View: "read"},
		{View: "path", Context: &api.RoleContext{Level: 2, Role: "executor"}},
		{View: "path", Context: &api.RoleContext{Level: 7, Role: "executor"}},
		{View: "path", Context: &api.RoleContext{Level: 3, Role: "bad.role"}},
		{View: "path", Context: &api.RoleContext{Level: 3, Role: "executor", InstanceID: "bad.id"}},
	} {
		expected := ValidateConfigReadInput(request)
		wantCode(t, expected, api.CodeInvalid)
		_, actual := f.service.ConfigRead(context.Background(), f.scope, request)
		wantCode(t, actual, api.CodeInvalid)
		if actual.(*api.Error).Owner != "lb-v2-policy" || actual.Error() != expected.Error() {
			t.Fatal("service config-read input differs from shared validator")
		}
	}
}

func TestEmptyConfigInput(t *testing.T) {
	f := newFixture(t)
	registry := &testRegistry{handlers: map[api.Method]api.Handler{}}
	if err := f.service.Register(registry); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{"empty", `{}`, true},
		{"whitespace", " \n { } \n", true},
		{"extra-field", `{"unexpected":true}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"duplicate", `{"x":1,"x":2}`, false},
		{"trailing", `{} {}`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := ValidateConfigValidateInput([]byte(row.raw))
			if !row.valid {
				wantCode(t, err, api.CodeInvalid)
			} else if err != nil {
				t.Fatalf("empty object validator refused valid bytes: %v", err)
			}
			result, err := registry.handlers["config.validate"](context.Background(), f.scope, []byte(row.raw))
			if !row.valid {
				wantCode(t, err, api.CodeInvalid)
				return
			}
			var validation api.OrgValidation
			if err != nil || api.DecodeObject(result, &validation) != nil || !validation.Valid {
				t.Fatalf("valid empty input did not reach service validation: %v", err)
			}
		})
	}
}
