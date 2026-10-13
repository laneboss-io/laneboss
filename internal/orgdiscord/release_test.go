//go:build !laneboss_faults

package orgdiscord

import "testing"

func TestReleaseIgnoresDiscordBaseOverride(t *testing.T) {
	for _, value := range []string{"", "not-a-url", "http://127.0.0.1:1/api/v10"} {
		t.Setenv("LANEBOSS_TEST_DISCORD_BASE_URL", value)
		base, err := apiBase()
		if err != nil || base != "https://discord.com/api/v10" {
			t.Fatal("release routing used the test override")
		}
	}
}
