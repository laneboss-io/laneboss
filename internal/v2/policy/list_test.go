package policy

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPolicyListText(t *testing.T) {
	f := newFixture(t, sourceRule("publish"))
	empty := testSource("empty-role")
	f.store.policy.Sources = append(f.store.policy.Sources, empty)
	f.seal(t)
	projection, err := f.service.PolicyGet(context.Background(), f.scope, api.PolicyGetRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := RenderBlacklist(&output, f.scope.Config, projection); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		projection.Rules[0].Text, projection.Rules[0].Instead,
		projection.Rules[0].Source.Path, empty.Path,
		"OS/service boundaries:", "laneboss doctor --config fixture",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("rule list omitted actual words or provenance: %s", expected)
		}
	}
	if len(f.judge.fits) != 0 || len(f.judge.requests) != 0 {
		t.Fatal("rule listing invoked inference")
	}
}
