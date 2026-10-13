package laneturns

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestBearerUnicodeWhitespace(t *testing.T) {
	for _, whitespace := range []string{"\u00a0", "\u0085", "\u2003", "\u202f", "\u001c", "\v"} {
		token := fmt.Sprintf("%x", sha256.Sum256([]byte(t.Name()+whitespace)))
		for prefix, expected := range map[string]string{"Bearer": "bearer-token", "Authorization:" + whitespace + "Bearer": "authorization-header"} {
			if rule, _ := findCredential(prefix + whitespace + token); rule != expected {
				t.Fatal("Unicode whitespace escaped the credential detector")
			}
		}
	}
}
