package report

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/eventstore"
)

func TestDiscordLegacyText(t *testing.T) {
	body := []byte("Actual report bytes for " + t.Name())
	marked := discordText(eventstore.Object{"legacy_relationship": true}, body)
	if marked != "[legacy_relationship: true]\n\n"+string(body) {
		t.Fatal("the Discord representation lost the marker or original report text")
	}
	for _, value := range []any{nil, false, "true"} {
		plain := discordText(eventstore.Object{"legacy_relationship": value}, body)
		if plain != string(body) || strings.Contains(plain, "legacy_relationship") {
			t.Fatal("an unmarked report acquired a Discord legacy label")
		}
	}
}
