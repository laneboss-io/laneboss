package assembly

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/approval"
	"laneboss.io/laneboss/internal/v2/dashboard"
	"laneboss.io/laneboss/internal/v2/distribution"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/judge"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/messaging"
	"laneboss.io/laneboss/internal/v2/migration"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/records"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/service"
	"laneboss.io/laneboss/internal/v2/templates"
)

func TestDraftFourRealRegistrations(t *testing.T) {
	// Registration does not execute these services or assert that
	// their installed dependencies work. Bypass the partial registry fallback
	// so a module reverting to a Register stub cannot pass this audit.
	core, err := lifecycle.New(lifecycle.Dependencies{
		Store: &struct{ api.StateStore }{}, Identity: &struct{ api.Authenticator }{}, Clock: wallClock{},
	})
	if err != nil {
		t.Fatal("lifecycle registration fixture could not initialize", err)
	}
	modules := []ownedModule{
		{"lb-v2-service", &service.Service{}}, {"lb-v2-identity", &identity.Service{}},
		{"lb-v2-admin", &admin.Service{}}, {"lb-v2-grants", &grants.Service{}},
		{"lb-v2-secrets", &secrets.Service{}}, {"lb-v2-judge", &judge.Service{}},
		{"lb-v2-policy", &policy.Service{}}, {"lb-v2-guidance", &guidance.Service{}},
		{"lb-v2-lifecycle", core},
		{"lb-v2-messaging", &messaging.Service{}}, {"lb-v2-approval", &approval.Service{}},
		{"lb-v2-integrate", &records.Service{}},
		{"lb-v2-templates", &templates.Service{}}, {"lb-v2-dashboard", &dashboard.Service{}},
		{"lb-v2-migration", &migration.Service{}}, {"lb-v2-packaging", &distribution.Service{}},
	}
	for _, entry := range modules {
		t.Run(entry.owner, func(t *testing.T) {
			target := captureRoutes()
			registry := &catalogRegistrar{target: target, owner: entry.owner,
				seen: map[api.Method]bool{}, streams: map[api.Method]bool{}}
			if err := entry.module.Register(registry); err != nil {
				t.Fatal("real module registration failed", err)
			}
			for method, spec := range api.Methods {
				if spec.Owner != entry.owner {
					continue
				}
				if target.handlers[method] == nil || fixtureStream(method) && target.streams[method] == nil {
					t.Fatal("real module catalog is incomplete")
				}
			}
		})
	}
}
