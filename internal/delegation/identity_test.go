package delegation

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/settings"
)

func TestMissingStarterUsesIdentityGate(t *testing.T) {
	t.Setenv("LANEBOSS_FAULTS", "")
	// A nil configuration makes any attempted state or org resolution invalid.
	// The missing-identity gate must return before either can be consulted.
	err := Bind(nil, "", settings.Empty())
	if err == nil || strings.Split(err.Error(), "\n")[0] != "the caller has no recorded identity" {
		t.Fatalf("identity must be checked before delegation state: %v", err)
	}
	if !strings.Contains(err.Error(), "Instead: run laneboss start --role") {
		t.Fatal("the missing-identity refusal lost its registration route")
	}
}
