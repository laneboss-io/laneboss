package ticket

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFullInstanceScopeHandoff(t *testing.T) {
	s, _ := newTestStore(t)
	scope := Scope{Config: strings.Repeat("c", 32), Level: 4, Role: "L4." + strings.Repeat("r", 93)}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	if len(raw) != 180 {
		t.Fatal("the maximum canonical instance scope did not survive issuance")
	}
	path := filepath.Join(t.TempDir(), "handoff")
	if err := os.WriteFile(path, []byte(raw+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadFile(path)
	if err != nil || read != raw {
		t.Fatal("a valid complete instance scope did not survive the private handoff")
	}
	if err := s.Consume(context.Background(), scope, read); err != nil {
		t.Fatal("the complete persisted instance scope could not be redeemed")
	}
}

func TestPolicyChangeCarriesExactScope(t *testing.T) {
	issued := Scope{Config: "example", Level: 4, Role: "reviewer"}
	current := Scope{Config: "example", Level: 3, Role: "reviewer"}
	for _, change := range []PolicyChange{
		{Issued: issued, Current: &current},
		{Issued: issued, State: "removed"},
		{Issued: issued, State: "unavailable"},
	} {
		if !change.Valid() {
			t.Fatal("a real current-policy refusal did not validate")
		}
		encoded, err := json.Marshal(change)
		if err != nil {
			t.Fatal(err)
		}
		var received PolicyChange
		if err := json.Unmarshal(encoded, &received); err != nil {
			t.Fatal(err)
		}
		before := (&Refusal{Reason: PolicyChanged, Policy: &change}).Error()
		after := (&Refusal{Reason: PolicyChanged, Policy: &received}).Error()
		if before != after || !strings.HasPrefix(after, "the registration policy changed: issued example L4 reviewer; current ") || !strings.Contains(after, "new ticket for the current scope") {
			t.Fatal("the authenticated response lost the exact policy scope or recovery")
		}
	}
	wrong := current
	wrong.Config = "other"
	if (&PolicyChange{Issued: issued, Current: &wrong}).Valid() {
		t.Fatal("a current scope from another configuration was accepted")
	}
	wrong = issued
	if (&PolicyChange{Issued: issued, Current: &wrong}).Valid() {
		t.Fatal("an unchanged scope was represented as a policy demotion")
	}
}
