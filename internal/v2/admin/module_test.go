package admin

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type recordedRegistry struct {
	methods map[api.Method]api.Handler
	failure error
}

func (r *recordedRegistry) Register(method api.Method, handler api.Handler) error {
	if r.failure != nil {
		return r.failure
	}
	if r.methods == nil {
		r.methods = map[api.Method]api.Handler{}
	}
	r.methods[method] = handler
	return nil
}

func (r *recordedRegistry) RegisterStream(api.Method, api.StreamHandler) error {
	return failure(api.CodeInvalid, "doctor cannot register a stream")
}

func TestDoctorRegistration(t *testing.T) {
	service := &Service{deps: Dependencies{Config: "admin-case"}}
	registry := &recordedRegistry{failure: failure(api.CodeConflict, "duplicate method")}
	requireCode(t, service.Register(registry), api.CodeConflict)
	registry.failure = nil
	if err := service.Register(registry); err != nil {
		t.Fatal(err)
	}
	if len(registry.methods) != 1 || registry.methods["doctor"] == nil {
		t.Fatal("admin registered a missing or extra public RPC")
	}
	handler := registry.methods["doctor"]
	scope := api.Scope{Config: "other-config", Actor: api.Actor{Kind: "lane", ID: "actor"}}
	_, err := handler(context.Background(), scope, json.RawMessage(`{}`))
	requireCode(t, err, api.CodeForbidden)
	_, err = handler(context.Background(), scope, json.RawMessage(`{"path":"/root"}`))
	requireCode(t, err, api.CodeInvalid)
}
