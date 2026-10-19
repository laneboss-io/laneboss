//go:build laneboss_partial

package assembly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPartialRefusesEveryUnreadyRPC(t *testing.T) {
	for index, entry := range fixtureModules() {
		for _, kind := range []string{"nil", "typed nil", "incomplete", "stub"} {
			t.Run(entry.owner+"/"+kind, func(t *testing.T) {
				modules := fixtureModules()
				calls := 0
				switch kind {
				case "nil":
					modules[index].module = nil
				case "typed nil":
					modules[index].module = (*registrationFixture)(nil)
				case "incomplete":
					modules[index].module = registrationFixture{owner: entry.owner,
						omit: fixtureMethods(entry.owner)[0], calls: &calls}
				case "stub":
					modules[index].module = registrationFixture{owner: entry.owner, calls: &calls,
						failure: api.NotImplemented(entry.owner, "fixture")}
				}
				target := captureRoutes()
				if err := registerModules(target, modules); err != nil {
					t.Fatal(err)
				}
				if len(target.streams) != 2 {
					t.Fatal("partial stream catalog has a hole")
				}
				for method, spec := range api.Methods {
					handler := target.handlers[method]
					if handler == nil {
						t.Fatal("partial catalog has a hole", method)
					}
					raw := json.RawMessage(`{"method":"` + string(method) + `"}`)
					result, err := handler(context.Background(), api.Scope{}, raw)
					if spec.Owner == entry.owner {
						assertOwnerRefusal(t, err, entry.owner, method)
						if len(result) != 0 {
							t.Fatal("unready RPC returned result bytes")
						}
					} else if err != nil || !bytes.Equal(result, raw) {
						t.Fatal("ready owner handler changed", method)
					}
				}
				for method, stream := range target.streams {
					if api.Methods[method].Owner != entry.owner {
						continue
					}
					result, err := stream(context.Background(), api.Scope{}, nil)
					assertOwnerRefusal(t, err, entry.owner, method)
					if result != nil {
						t.Fatal("unready stream returned a producer")
					}
				}
				if calls != 0 {
					t.Fatal("unready module executed a handler")
				}
			})
		}
	}
}

func assertOwnerRefusal(t *testing.T, err error, owner string, method api.Method) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != owner ||
		typed.Message != api.NotImplemented(owner, string(method)).Message {
		t.Fatal("wrong partial owner refusal", method, err)
	}
}

func TestPartialReplacesOwnerWithoutStream(t *testing.T) {
	for _, missing := range []api.Method{"event.tail", "lane.attach"} {
		modules := fixtureModules()
		owner := api.Methods[missing].Owner
		for index, entry := range modules {
			if entry.owner == owner {
				modules[index].module = registrationFixture{owner: owner, omitStream: missing}
			}
		}
		target := captureRoutes()
		if err := registerModules(target, modules); err != nil {
			t.Fatal(err)
		}
		for _, method := range fixtureMethods(owner) {
			_, err := target.handlers[method](context.Background(), api.Scope{}, nil)
			assertOwnerRefusal(t, err, owner, method)
		}
		for _, method := range []api.Method{"event.tail", "lane.attach"} {
			producer, err := target.streams[method](context.Background(), api.Scope{}, nil)
			assertOwnerRefusal(t, err, owner, method)
			if producer != nil {
				t.Fatal("missing stream gained a producer")
			}
		}
	}
}
