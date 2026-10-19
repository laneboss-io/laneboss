package secrets

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func TestAPIKeyProfile(t *testing.T) {
	c := newLaunchCase(t, "claude-api-key", api.DriverClaudock)
	ctx := context.Background()
	var profile bstate.Profile
	if err := c.backend.WithBroker(ctx, func(j bstate.Journal) error {
		return j.Read("profile", c.profile.ID, &profile)
	}); err != nil || profile.Mode != "claude-api-key" {
		t.Fatal("API key enrollment lost its encrypted kind", err)
	}
	slot, err := c.acquire(ctx, c.target, c.grant)
	if err != nil || slot.Mode != "claude-api-key" {
		t.Fatal("API key enrollment lost its selected slot kind", err)
	}
	saved := readCaseSlot(t, c, slot.ID)
	defer clear(saved.Material)
	if saved.Credential != slot || !bytes.Equal(saved.Material, c.material) {
		t.Fatal("API key keystore slot changed its enrolled material")
	}
	entries, err := os.ReadDir(c.backendDirectory())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(c.backendDirectory(), entry.Name()))
		if err != nil || bytes.Contains(data, c.material) {
			t.Fatal("API key material escaped the encrypted keystore")
		}
	}
	profile.Driver = api.DriverCodex
	if err := c.service.validateEnrollment(profile); err == nil {
		t.Fatal("API key enrollment accepted a foreign driver")
	}
}
