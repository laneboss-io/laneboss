package credentialtext

import (
	"strings"
	"testing"
)

func TestCredentialShapes(t *testing.T) {
	for name, text := range map[string]string{
		"assignment":    "api_key = \"" + "synthetic9" + strings.Repeat("q", 20) + "\"",
		"authorization": "Authorization: Bearer " + strings.Repeat("a", 20),
		"url":           "https://" + "user:synthetic9" + "@example.invalid/path",
	} {
		t.Run(name, func(t *testing.T) {
			if !HasCredential(text) {
				t.Fatal("credential shape was not withheld")
			}
		})
	}
	for _, text := range []string{"SERVICE_KEY", "api_key = SERVICE_KEY", "A plain observation about the build."} {
		if HasCredential(text) {
			t.Fatal("names-only or ordinary text was withheld")
		}
	}
}
