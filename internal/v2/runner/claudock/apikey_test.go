package claudock

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAPIKeyValidator(t *testing.T) {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	key := []byte("sk-ant-" + hex.EncodeToString(entropy[:]))
	clear(entropy[:])
	defer clear(key)
	validator := APIKeyValidator{}
	if err := validator.ValidateAPIKeyCredential("profile", "login", key); err != nil {
		t.Fatal("bounded printable API key was refused", err)
	}
	for name, material := range map[string][]byte{
		"empty": nil, "prefix-only": []byte("sk-ant-"), "foreign-prefix": []byte("other-"),
		"newline": append(bytes.Clone(key), '\n'), "carriage-return": append(bytes.Clone(key), '\r'),
		"space": append(bytes.Clone(key), ' '), "nul": append(bytes.Clone(key), 0),
		"unicode": append(bytes.Clone(key), 0xc3, 0xa9), "delete": append(bytes.Clone(key), 127),
		"over-bound": append([]byte("sk-ant-"), bytes.Repeat([]byte{'x'}, MaxAPIKeyBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			defer clear(material)
			if err := validator.ValidateAPIKeyCredential("profile", "login", material); err == nil {
				t.Fatal("API key shape negative control was accepted")
			}
		})
	}
	if err := validator.ValidateAPIKeyCredential("", "login", key); err == nil {
		t.Fatal("API key validator accepted an absent profile")
	}
	if err := validator.ValidateAPIKeyCredential("profile", "", key); err == nil {
		t.Fatal("API key validator accepted an absent login")
	}
}

func TestAPIKeyPlan(t *testing.T) {
	f := runnerReady(t, nil)
	f.request.Slot.Mode = "claude-api-key"
	f.sourceLaunch(t, "start")
	wrapper, vendor := f.service.deps.Executable, f.service.deps.Claude
	f.service.deps.VerifyMode = func(_ context.Context, actualWrapper, actualVendor api.Executable, mode string) error {
		if actualWrapper != wrapper || actualVendor != vendor || mode != "claude-api-key" {
			return failure(api.CodeForbidden, "API key fixture compatibility identity differs")
		}
		return nil
	}
	plan, err := f.service.Start(context.Background(), f.request)
	if err != nil {
		t.Fatal("actual runner refused the API key slot", err)
	}
	if !reflect.DeepEqual(plan.EnvironmentNames, []string{"ANTHROPIC_API_KEY"}) || plan.Slot != f.request.Slot ||
		len(plan.Argv) < 3 || plan.Argv[1] != "run" || plan.Argv[2] != KeyProfile {
		t.Fatal("API key runner changed its slot, vendor command or single environment name")
	}
	var registry struct {
		Version  int `json:"version"`
		Profiles []struct {
			Command string `json:"command"`
			Kind    string `json:"authKind"`
			Managed bool   `json:"managed"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(get(t, filepath.Join(f.home.path, ".config/claudock/profiles.json")), &registry); err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, p := range registry.Profiles {
		if p.Kind == "apiKey" && p.Managed && p.Command == "claude-"+KeyProfile {
			keys++
		}
	}
	if keys != 1 || registry.Version != 2 || len(registry.Profiles) != 2 {
		t.Fatal("API key mode lacks its one managed key profile and required default")
	}
	for _, mode := range []string{"claudock-helper", "claudock-api"} {
		request := f.request
		request.Slot.Mode = mode
		if _, err := f.service.Start(context.Background(), request); err == nil {
			t.Fatal("API key support enabled an unimplemented mode")
		}
	}
}
