package caller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

type absentServiceProbe struct{ registrations int }

func (*absentServiceProbe) Configured(string) bool { return false }
func (p *absentServiceProbe) Register(context.Context, ticket.Scope, string) error {
	p.registrations++
	return errors.New("an invalid configuration reached registration")
}

func TestMalformedServiceNeverLegacy(t *testing.T) {
	c := isolatedConfig(t)
	probe := &absentServiceProbe{}
	if RequiresTicket(c, probe) {
		t.Fatal("the absent-service control unexpectedly requires a ticket")
	}
	for _, value := range []any{
		true, "enabled", []any{}, nil,
		map[string]any{"runtime_root": ""},
		map[string]any{"runtime_root": "relative"},
		map[string]any{"runtime_root": false},
		map[string]any{"runtime_roo": "/tmp/unused"},
	} {
		c.Data["identity_service"] = value
		if !RequiresTicket(c, probe) {
			t.Fatal("MalformedService: a present invalid service selected legacy registration")
		}
		err := RegisterRoleWithTicket(context.Background(), c, "mini-a", 4, "", probe)
		var invalid *config.Error
		if !errors.As(err, &invalid) || invalid.Code != 2 || invalid.Prefix != "invalid configuration" {
			t.Fatal("an invalid service was not refused before caller registration")
		}
		if probe.registrations != 0 {
			t.Fatal("an invalid service reached the registrar")
		}
		for _, directory := range []string{"sessions", "roles"} {
			if _, err := os.Stat(filepath.Join(c.StateDir, directory)); !os.IsNotExist(err) {
				t.Fatal("an invalid service wrote legacy identity state")
			}
		}
	}
	c.Data["identity_service"] = map[string]any{}
	if !RequiresTicket(c, probe) {
		t.Fatal("an empty service table failed to select its documented default root")
	}
	delete(c.Data, "identity_service")
	if RequiresTicket(c, probe) {
		t.Fatal("the absent-service control changed after invalid selections")
	}
}
