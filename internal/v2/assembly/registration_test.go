package assembly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// These fixtures exercise registration only. They do not replace an installed
// transport, authenticate a peer or perform a store transaction.
type registrationFixture struct {
	owner      string
	omit       api.Method
	omitStream api.Method
	failure    error
	calls      *int
}

func (m registrationFixture) Register(r api.Registrar) error {
	for _, method := range fixtureMethods(m.owner) {
		if method == m.omit {
			continue
		}
		if err := r.Register(method, func(_ context.Context, _ api.Scope, raw json.RawMessage) (json.RawMessage, error) {
			if m.calls != nil {
				(*m.calls)++
			}
			return append(json.RawMessage(nil), raw...), nil
		}); err != nil {
			return err
		}
		if fixtureStream(method) && method != m.omitStream {
			if err := r.RegisterStream(method, func(context.Context, api.Scope, json.RawMessage) (api.EventStream, error) {
				return nil, api.NotImplemented(m.owner, "fixture stream")
			}); err != nil {
				return err
			}
		}
	}
	return m.failure
}

type ignoresRegistrationFailure struct{}

func (ignoresRegistrationFailure) Register(r api.Registrar) error {
	// Intentionally broken module: a refused registration must remain fatal
	// even when its Register implementation discards the returned error.
	_ = r.Register("unknown.method", func(context.Context, api.Scope, json.RawMessage) (json.RawMessage, error) {
		return nil, errors.New("unreachable fixture")
	})
	return nil
}

func TestRegistrationCannotHideRefusal(t *testing.T) {
	modules := fixtureModules()
	modules[0].module = ignoresRegistrationFailure{}
	target := captureRoutes()
	err := registerModules(target, modules)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity {
		t.Fatal("discarded refusal was not fatal")
	}
	if len(target.handlers) != 0 || len(target.streams) != 0 {
		t.Fatal("refused graph reached transport")
	}
}

func fixtureMethods(owner string) []api.Method {
	var methods []api.Method
	for method, spec := range api.Methods {
		if owner == "" || spec.Owner == owner {
			methods = append(methods, method)
		}
	}
	sort.Slice(methods, func(i, j int) bool { return methods[i] < methods[j] })
	return methods
}

func fixtureStream(method api.Method) bool {
	return method == "event.tail" || method == "lane.attach"
}

func fixtureModules() []ownedModule {
	owners := map[string]bool{}
	for _, spec := range api.Methods {
		owners[spec.Owner] = true
	}
	var names []string
	for owner := range owners {
		names = append(names, owner)
	}
	sort.Strings(names)
	var modules []ownedModule
	for _, owner := range names {
		modules = append(modules, ownedModule{owner, registrationFixture{owner: owner}})
	}
	return modules
}

type captureRegistrar struct {
	handlers map[api.Method]api.Handler
	streams  map[api.Method]api.StreamHandler
}

func captureRoutes() *captureRegistrar {
	return &captureRegistrar{handlers: map[api.Method]api.Handler{}, streams: map[api.Method]api.StreamHandler{}}
}

func (r *captureRegistrar) Register(method api.Method, handler api.Handler) error {
	if r.handlers[method] != nil {
		return errors.New("duplicate fixture handler")
	}
	r.handlers[method] = handler
	return nil
}

func (r *captureRegistrar) RegisterStream(method api.Method, handler api.StreamHandler) error {
	if r.streams[method] != nil {
		return errors.New("duplicate fixture stream")
	}
	r.streams[method] = handler
	return nil
}

func TestCompleteRegistration(t *testing.T) {
	target := captureRoutes()
	if err := registerModules(target, fixtureModules()); err != nil {
		t.Fatal(err)
	}
	if len(target.handlers) != len(api.Methods) || len(target.streams) != 2 {
		t.Fatal("catalog coverage differs")
	}
	for method, handler := range target.handlers {
		raw := json.RawMessage(`{"method":"` + string(method) + `"}`)
		result, err := handler(context.Background(), api.Scope{}, raw)
		if err != nil || !bytes.Equal(result, raw) {
			t.Fatal("ready handler was replaced", method)
		}
	}
}

func TestRegistrationTargetFailure(t *testing.T) {
	sentinel := errors.New("transport registration failed")
	target := &testRegistrar{failure: sentinel}
	if err := registerModules(target, fixtureModules()); !errors.Is(err, sentinel) {
		t.Fatal("target failure was swallowed")
	}
}

func TestRegistrationRejectsBadModules(t *testing.T) {
	for _, code := range []api.ErrorCode{api.CodeForbidden, api.CodeIntegrity, api.CodeUnavailable} {
		t.Run(string(code), func(t *testing.T) {
			modules := fixtureModules()
			sentinel := &api.Error{Code: code, Owner: modules[0].owner, Message: "fixture failure"}
			modules[0].module = registrationFixture{owner: modules[0].owner, failure: sentinel}
			target := captureRoutes()
			if err := registerModules(target, modules); !errors.Is(err, sentinel) {
				t.Fatal("module failure was swallowed")
			}
			if len(target.handlers) != 0 || len(target.streams) != 0 {
				t.Fatal("failed graph reached transport")
			}
		})
	}
	for _, name := range []string{"unknown", "duplicate", "omitted", "wrong error owner"} {
		t.Run(name, func(t *testing.T) {
			modules := fixtureModules()
			switch name {
			case "unknown":
				modules[0].owner = "unknown-owner"
			case "duplicate":
				modules = append(modules, modules[0])
			case "omitted":
				modules = modules[1:]
			case "wrong error owner":
				modules[0].module = registrationFixture{owner: modules[0].owner,
					failure: api.NotImplemented("another-owner", "fixture")}
			}
			if err := registerModules(captureRoutes(), modules); err == nil {
				t.Fatal("invalid graph was accepted")
			}
		})
	}
}
