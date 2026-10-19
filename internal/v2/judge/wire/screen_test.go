package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func credentialPositions() map[string]string {
	credential := "Bearer " + strings.Repeat("a1", 16)
	padding := strings.Repeat("界", 90000)
	return map[string]string{
		"alone":  credential,
		"prefix": credential + padding,
		"middle": padding[:len(padding)/2] + credential + padding[len(padding)/2:],
		"suffix": padding + credential,
	}
}

func TestCredentialStringPositions(t *testing.T) {
	for name, text := range credentialPositions() {
		t.Run(name, func(t *testing.T) {
			if !secretText(text) || !Sensitive(text, "") {
				t.Fatal("credential position escaped")
			}
			if name != "alone" && len(text) <= api.MaxJudgeBytes {
				t.Fatal("long canary was shortened")
			}
		})
	}
	for _, credential := range []string{
		"Bearer " + strings.Repeat("a1", 16),
		"ghp_" + strings.Repeat("a1", 15),
		"AKIA" + strings.Repeat("A1", 8),
		"Authorization: Bearer " + strings.Repeat("b2", 16),
	} {
		for _, adjacent := range []string{"界", "Z", "_", "\x1b"} {
			if !secretText(adjacent + credential + adjacent) {
				t.Fatal("adjacent text hid credential")
			}
		}
	}
	if !secretText("token=\nfake-value-1") || !secretText("界token=\nfake-value-1") {
		t.Fatal("line break hid credential value")
	}
	for _, benign := range []string{"build project", "Bearer short", "ghp_short",
		"AKIAshort", "token=$EXAMPLE_KEY", "token: redacted"} {
		if secretText(benign) || Sensitive(benign, "") {
			t.Fatal("benign control was withheld")
		}
	}
}

func TestOutgoingFieldCoverage(t *testing.T) {
	fields := []string{"rule", "command", "context-key", "context-value",
		"instructions", "true-criteria", "false-criteria", "criteria-key",
		"decision", "task", "argv", "path"}
	for _, field := range fields {
		for position, text := range credentialPositions() {
			t.Run(field+"/"+position, func(t *testing.T) {
				original, _, err := Payload(request())
				if err != nil {
					t.Fatal(err)
				}
				if err := screenOutgoing(original, ""); err != nil {
					t.Fatal("clean body did not pass")
				}
				var root map[string]any
				if err := json.Unmarshal(original, &root); err != nil {
					t.Fatal(err)
				}
				state := root["state"].(map[string]any)
				command := state["commands"].([]any)[0].(map[string]any)
				context := state["context"].(map[string]any)
				question := root["questions"].(map[string]any)["rule-a"].(map[string]any)
				criteria := question["criteria"].(map[string]any)
				switch field {
				case "rule":
					state["rules"].([]any)[0].(map[string]any)["text"] = text
				case "command":
					command["command"] = text
				case "context-key":
					context[text] = "ordinary data"
				case "context-value":
					context["cwd"] = text
				case "instructions":
					question["instructions"] = text
				case "true-criteria":
					criteria["true"] = text
				case "false-criteria":
					criteria["false"] = text
				case "criteria-key":
					criteria[text] = "ordinary data"
				case "decision":
					state["decisions"] = []any{map[string]any{"text": text}}
				case "task":
					state["task"] = text
				case "argv":
					command["argv"] = []any{text}
				case "path":
					command["declared_paths"] = []any{text}
				}
				body, err := json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				var typed *api.Error
				err = screenOutgoing(body, "")
				if !errors.As(err, &typed) || typed.Code != api.CodeUnscored ||
					typed.Message != "credential-shaped input withheld" {
					t.Fatal("outgoing field escaped screen")
				}
			})
		}
	}
}

func TestNestedJSONCredentialScreen(t *testing.T) {
	credential := "Bearer " + strings.Repeat("a1", 16)
	var escaped strings.Builder
	for _, character := range credential {
		fmt.Fprintf(&escaped, `\u%04x`, character)
	}
	objects := []any{
		map[string]any{"context": map[string]any{credential: "data"}},
		map[string]any{"context": []any{map[string]any{"note": credential}}},
		map[string]any{"task": `{"note":"` + escaped.String() + `"}`},
		map[string]any{"task": `["` + escaped.String() + `"]`},
	}
	for _, object := range objects {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if screenOutgoing(raw, "") == nil {
			t.Fatal("nested JSON hid credential")
		}
	}
	clean, err := json.Marshal(map[string]any{"task": `{"token":"$EXAMPLE_KEY"}`})
	if err != nil || screenOutgoing(clean, "") != nil {
		t.Fatal("JSON reference was withheld")
	}
}

func TestSplitCredentialFields(t *testing.T) {
	fragment := strings.Repeat("a1", 16)
	for _, object := range []any{
		map[string]any{"context": map[string]any{"a": "Bear", "b": "er " + fragment}},
		map[string]any{"context": map[string]any{"Bear": "er " + fragment}},
		map[string]any{"argv": []any{"Bearer", fragment}},
		map[string]any{"argv": []any{"Bear", "er ", fragment}},
	} {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("Bearer "+fragment)) {
			t.Fatal("split control was not split")
		}
		if screenOutgoing(raw, "") == nil {
			t.Fatal("split credential escaped")
		}
	}
	for _, object := range []any{
		map[string]any{"argv": []any{"build", "project"}},
		map[string]any{"argv": []any{"token=$EXAMPLE_KEY", "data"}},
		map[string]any{"a": "token: redacted", "b": "params"},
	} {
		clean, err := json.Marshal(object)
		if err != nil || screenOutgoing(clean, "") != nil {
			t.Fatal("clean fields were withheld")
		}
	}
}
