package lane

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestStartSettingsModelFlagDiagnostic(t *testing.T) {
	cases := []struct{ name, model string }{
		{"family-alias", "deepseek-flash"},
		{"provider-alias", "provider/current"},
		{"unsafe-character", "model-1;extra"},
		{"control-character", "model-1\nextra"},
		{"too-long", "m1" + strings.Repeat("x", 127)},
		{"invalid-utf8", "model-1" + string([]byte{0xff})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &configuration{data: object{}}
			_, snapshot, err := c.startSettings(arguments{values: map[string]string{"model": tc.model}})
			if snapshot != nil {
				t.Fatal("an invalid model must not resolve a launch snapshot")
			}
			var p *problem
			if !errors.As(err, &p) || p.code != 2 || p.prefix != "refused" {
				t.Fatal("an invalid model must produce a typed CLI refusal")
			}
			var output bytes.Buffer
			p.write(&output)
			want := "refused: --model must be a full model name that includes its version, not a family alias\n"
			if output.String() != want {
				t.Fatalf("the established model-flag diagnostic changed: %s", output.String())
			}
			if strings.Contains(output.String(), tc.model) {
				t.Fatal("a rejected model value must be withheld")
			}
		})
	}
}

func TestStartSettingsModelScreen(t *testing.T) {
	// Synthetic detector input, never a credential read from the environment.
	model := "sk-7" + strings.Repeat("b", 30) + ";invalid"
	c := &configuration{data: object{}}
	_, snapshot, err := c.startSettings(arguments{values: map[string]string{"model": model}})
	if snapshot != nil || err == nil {
		t.Fatal("credential-shaped model input must refuse before resolving settings")
	}
	if !strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "--model") {
		t.Fatal("credential screening must precede the model-flag diagnostic")
	}
	if strings.Contains(err.Error(), model) {
		t.Fatal("credential-shaped model input must be withheld")
	}
}

func TestStartSettingsFullModelFlags(t *testing.T) {
	for _, model := range []string{"deepseek-v4.1-flash", "provider/model-2:variant+stable@current[slot]", "m1" + strings.Repeat("x", 126)} {
		c := &configuration{data: object{}}
		a, snapshot, err := c.startSettings(arguments{values: map[string]string{"model": model}})
		if err != nil {
			t.Fatalf("a valid full model must resolve: %s", err)
		}
		if snapshot == nil || a.get("model") != model || snapshot.Values["model"] != model || snapshot.Overrides["model"] != model {
			t.Fatal("full model names must remain unchanged in arguments and typed settings")
		}
	}
}

func TestStartSettingsTypedValidation(t *testing.T) {
	cases := []struct {
		name, key string
		values    map[string]string
		sets      []string
	}{
		{"runner-flag", "runner", map[string]string{"runner": "InvalidRunner"}, nil},
		{"effort-flag", "effort", map[string]string{"effort": "INVALID"}, nil},
		{"account-flag", "account", map[string]string{"account": "invalid account"}, nil},
		{"model-set", "model", map[string]string{}, []string{`model="provider-alias"`}},
		{"budget-set", "budget_minutes", map[string]string{}, []string{"budget_minutes=true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &configuration{data: object{}}
			_, snapshot, err := c.startSettings(arguments{values: tc.values, sets: tc.sets})
			if snapshot != nil || err == nil || err.Error() != "settings."+tc.key+": invalid type or value" {
				t.Fatal("typed settings validation must still reject invalid launch flags and --set values")
			}
		})
	}
}
