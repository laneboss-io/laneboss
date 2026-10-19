package grants

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func TestAPIKeyRoot(t *testing.T) {
	f, b, _, input := rootProfileCase(t)
	grant := input.Profiles[0]
	var profile bstate.Profile
	if err := b.native.WithBroker(context.Background(), func(j bstate.Journal) error {
		return j.Read("profile", grant.ProfileID, &profile)
	}); err != nil {
		t.Fatal(err)
	}
	profile.Mode = "claude-api-key"
	if err := rootProfile(profile, grant, f.scope.Config, f.clock.Now()); err != nil {
		t.Fatal("API key root enrollment refused", err)
	}
	profile.Driver, grant.Driver = api.DriverCodex, api.DriverCodex
	if err := rootProfile(profile, grant, f.scope.Config, f.clock.Now()); err == nil {
		t.Fatal("API key enrollment accepted a foreign driver")
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_OTHER", "CLAUDOCK_OTHER", "CODEX_OTHER", "OPENAI_API_KEY"} {
		if err := manifest.SecretTarget("env", name); err == nil {
			t.Fatal("reserved vendor task target accepted")
		}
	}
}
