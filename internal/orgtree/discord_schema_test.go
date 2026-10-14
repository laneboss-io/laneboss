package orgtree

import (
	"path/filepath"
	"testing"
)

// Run on the disposable Linux box. The acceptance prep first runs this test
// against a copy with the old top-level whitelist, requiring the positive case
// to fail, and then against the actual source tree.
func TestOrgDiscordServiceSchema(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"schema_version": int64(1), "name": "demo", "company": "demo", "owner_channel": "owner",
			"levels":       []any{int64(3), int64(4), int64(5)},
			"secret_store": map[string]any{"kind": "keychain", "path": "acceptance/demo"},
			"defaults":     map[string]any{"level": int64(3), "role": "executor"},
		}
	}
	root := filepath.Join(t.TempDir(), "demo")
	valid := map[string]any{"guild_id": "123456789012345678", "token_secret": "DISCORD_BOT_TOKEN", "owner_id": "234567890123456789"}
	for _, field := range []string{"schema_version", "name", "company", "levels", "owner_channel", "secret_store", "defaults"} {
		t.Run("required_org_"+field, func(t *testing.T) {
			org := base()
			delete(org, field)
			if len(checkOrg(org, "org.toml", root)) == 0 {
				t.Fatal("required Python org-schema field was accepted missing")
			}
		})
	}
	for _, field := range []string{"kind", "path"} {
		t.Run("required_secret_store_"+field, func(t *testing.T) {
			org := base()
			delete(org["secret_store"].(map[string]any), field)
			if len(checkOrg(org, "org.toml", root)) == 0 {
				t.Fatal("required Python secret-store field was accepted missing")
			}
		})
	}
	t.Run("secret_store_service_remains_unknown", func(t *testing.T) {
		org := base()
		org["secret_store"].(map[string]any)["service"] = "example-service"
		if len(checkOrg(org, "org.toml", root)) == 0 {
			t.Fatal("secret-store schema diverged from Python's kind/path whitelist")
		}
	})
	t.Run("accepts_discord", func(t *testing.T) {
		org := base()
		org["services"] = map[string]any{"discord": valid}
		if problems := checkOrg(org, "org.toml", root); len(problems) != 0 {
			t.Fatalf("valid Discord service rejected: %v", problems)
		}
	})
	t.Run("optional_service", func(t *testing.T) {
		if problems := checkOrg(base(), "org.toml", root); len(problems) != 0 {
			t.Fatalf("org without Discord rejected: %v", problems)
		}
	})
	t.Run("owner_is_optional", func(t *testing.T) {
		org := base()
		org["services"] = map[string]any{"discord": map[string]any{"guild_id": valid["guild_id"], "token_secret": valid["token_secret"]}}
		if problems := checkOrg(org, "org.toml", root); len(problems) != 0 {
			t.Fatalf("optional owner was required: %v", problems)
		}
	})
	t.Run("unknown_service_keys_as_python", func(t *testing.T) {
		org := base()
		org["services"] = map[string]any{"another-service": map[string]any{}, "discord": map[string]any{
			"guild_id": valid["guild_id"], "token_secret": valid["token_secret"], "extra": true,
		}}
		if problems := checkOrg(org, "org.toml", root); len(problems) != 0 {
			t.Fatalf("Python-compatible extra service settings rejected: %v", problems)
		}
	})
	for _, field := range []string{"guild_id", "token_secret"} {
		t.Run("missing_"+field, func(t *testing.T) {
			entry := map[string]any{}
			for k, v := range valid {
				if k != field {
					entry[k] = v
				}
			}
			org := base()
			org["services"] = map[string]any{"discord": entry}
			if len(checkOrg(org, "org.toml", root)) == 0 {
				t.Fatal("missing required Discord field accepted")
			}
		})
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"wrong_table", "discord"},
		{"wrong_discord_table", map[string]any{"discord": "not a table"}},
		{"zero_guild", map[string]any{"discord": map[string]any{"guild_id": "0", "token_secret": "BOT"}}},
		{"oversize_guild", map[string]any{"discord": map[string]any{"guild_id": "123456789012345678901", "token_secret": "BOT"}}},
		{"numeric_id", map[string]any{"discord": map[string]any{"guild_id": int64(123), "token_secret": "BOT"}}},
		{"zero_owner", map[string]any{"discord": map[string]any{"guild_id": "123", "token_secret": "BOT", "owner_id": "0"}}},
		{"literal_token", map[string]any{"discord": map[string]any{"guild_id": "123", "token_secret": "not a secret name"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := base()
			org["services"] = tc.value
			if len(checkOrg(org, "org.toml", root)) == 0 {
				t.Fatal("malformed Discord service accepted")
			}
		})
	}
}
