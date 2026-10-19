//go:build !laneboss_partial

package assembly

import (
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReleaseRejectsMissingHandlers(t *testing.T) {
	for index, entry := range fixtureModules() {
		for _, kind := range []string{"nil", "typed nil", "incomplete", "stub"} {
			t.Run(entry.owner+"/"+kind, func(t *testing.T) {
				modules := fixtureModules()
				switch kind {
				case "nil":
					modules[index].module = nil
				case "typed nil":
					modules[index].module = (*registrationFixture)(nil)
				case "incomplete":
					modules[index].module = registrationFixture{owner: entry.owner, omit: fixtureMethods(entry.owner)[0]}
				case "stub":
					modules[index].module = registrationFixture{owner: entry.owner,
						failure: api.NotImplemented(entry.owner, "fixture")}
				}
				target := captureRoutes()
				err := registerModules(target, modules)
				var typed *api.Error
				prefix := "required RPC handler is missing: "
				if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented ||
					typed.Owner != entry.owner || !strings.HasPrefix(typed.Message, prefix) {
					t.Fatal("missing owner did not stop release", err)
				}
				if len(target.handlers) != 0 || len(target.streams) != 0 {
					t.Fatal("incomplete release reached transport")
				}
			})
		}
	}
}

func TestReleaseRejectsMissingStreams(t *testing.T) {
	for _, method := range []api.Method{"event.tail", "lane.attach"} {
		modules := fixtureModules()
		for index, entry := range modules {
			if entry.owner == api.Methods[method].Owner {
				modules[index].module = registrationFixture{owner: entry.owner, omitStream: method}
			}
		}
		err := registerModules(captureRoutes(), modules)
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != api.Methods[method].Owner {
			t.Fatal("missing stream did not stop release")
		}
	}
}
