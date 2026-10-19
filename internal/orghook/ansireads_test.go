package orghook

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestANSIReadBackstop(t *testing.T) {
	root := t.TempDir()
	name := "protected.fixture"
	for _, level := range []int{3, 4, 5, 6} {
		inst := &instance{home: filepath.Join(root, ".laneboss"), level: level, secretNames: []string{name}}
		rules := []rule{{data: map[string]any{"kind": "secret-read", "names": []any{"{secret_names}"}}}}
		for _, escape := range []string{"hex", "octal", "unicode"} {
			encoded := ""
			for _, character := range name {
				switch escape {
				case "hex":
					encoded += fmt.Sprintf("\\x%02x", character)
				case "octal":
					encoded += fmt.Sprintf("\\%03o", character)
				case "unicode":
					encoded += fmt.Sprintf("\\u%04x", character)
				}
			}
			word := "'" + root + "/'$'" + encoded + "'"
			for _, script := range []string{"cat " + word, "head -n 1 " + word, "cat < " + word} {
				reason, err := ansiSecretReadRefusal(inst, script, root, rules)
				if err != nil || !strings.HasPrefix(reason, "org hook fails closed: ANSI-C shell quoting cannot be inspected\n") {
					t.Fatalf("a decoded protected read must refuse at level %d (%s): %q %v", level, escape, reason, err)
				}
			}
			for _, script := range []string{"echo " + word, "cat '" + root + "/'$'public\\x2etxt'", "cat '" + root + "/'$'prefix'public.txt"} {
				if reason, err := ansiSecretReadRefusal(inst, script, root, rules); reason != "" || err != nil {
					t.Fatalf("ordinary encoded data must remain R26-allowed: %q %v", reason, err)
				}
			}
		}
	}
	if decoded, ok := decodeANSICWord("plain"); ok || decoded != "" {
		t.Fatal("a non-ANSI word must not report a decoded value")
	}
}

func TestANSIInspectionGaps(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "protected.fixture")
	public := filepath.Join(root, "public.txt")
	inst := &instance{home: filepath.Join(root, ".laneboss"), level: 3, secretNames: []string{filepath.Base(secret)}}
	rules := []rule{{data: map[string]any{"kind": "secret-read", "names": []any{"{secret_names}"}}}}
	quote := func(text string) string { return "'" + strings.ReplaceAll(text, "'", "'\"'\"'") + "'" }
	ansi := func(text string) string {
		var encoded strings.Builder
		encoded.WriteString("$'")
		for _, value := range []byte(text) {
			fmt.Fprintf(&encoded, "\\x%02x", value)
		}
		encoded.WriteByte('\'')
		return encoded.String()
	}
	nested := func(body string, depth int) string {
		for count := 0; count < depth; count++ {
			body = "sh -c " + quote(body)
		}
		return body
	}
	body := ansi("cat \"$INPUT\" " + quote(secret))
	echo := ansi("echo \"$INPUT\" " + quote(secret))
	cases := []struct{ name, canary, control string }{
		{"inspection", "cat \"$INPUT\" " + ansi(secret), "echo \"$INPUT\" " + ansi(secret)},
		{"depth", nested("cat "+ansi(secret), 5), nested("echo "+ansi(secret), 5)},
		{"body", "bash -c " + body, "bash -c " + echo},
		{"eval", "eval " + body, "eval " + echo},
		{"alias", "alias inspect_read=" + body + "; inspect_read", "alias inspect_read=" + echo + "; inspect_read"},
	}
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			for _, control := range []string{row.control, "cat " + ansi(public), nested("cat "+ansi(public), 2)} {
				if reason, err := ansiSecretReadRefusal(inst, control, root, rules); err != nil || reason != "" {
					t.Fatalf("the encoded public/echo control must remain allowed: %q %v", reason, err)
				}
			}
			reason, err := ansiSecretReadRefusal(inst, row.canary, root, rules)
			if err != nil || !strings.HasPrefix(reason, "org hook fails closed: ANSI-C shell quoting cannot be inspected\n") {
				t.Fatalf("the encoded read gap must refuse with the contract reason: %q %v", reason, err)
			}
		})
	}
	word := quote(root+"/") + "$''" + ansi(filepath.Base(secret))
	tokens, err := lexShell("cat " + word)
	if err != nil || len(tokens) != 2 || !tokens[1].ansiC || tokens[1].decoded != secret {
		t.Fatal("the lexer must supply only complete ANSI-C fragments and retain adjacent decoded bytes")
	}
	if _, err := lexShell("cat $'unterminated"); err == nil {
		t.Fatal("an unclosed fragment must fail before the ANSI-C decoder is called")
	}
}
