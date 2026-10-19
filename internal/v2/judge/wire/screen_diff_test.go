package wire

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

const normalScreenRows = 2048
const longScreenRows = 16384
const screenSeed = 0x7328683

var screenEvidence = flag.String("judge-screen-evidence", "", "private differential evidence directory")

// The named assignment extensions. caller-join is proved separately by the
// independent ownership oracle below. Assignment classification uses only
// the frozen assignment grammar and independent suffix parsing. It never
// calls production's screen/region/tail helpers or changes the oracle verdict.
// quote-tail: a quoted placeholder/empty value with a glued bare suffix.
// spaced-tail: the same form after whitespace following the assignment.
// reference-tail: a complete angle/brace reference with a glued bare suffix.
// Each can otherwise disguise a literal value as an empty/redacted reference.
func namedScreenExtra(value any) string {
	switch value := value.(type) {
	case string:
		for _, match := range fix1Assignment.FindAllStringIndex(value, -1) {
			raw := value[match[1]:]
			text := strings.TrimLeftFunc(raw, fix1TextSpace)
			if text == "" {
				continue
			}
			end, name := 0, ""
			if strings.ContainsRune("\"'`", rune(text[0])) {
				if at := strings.IndexByte(text[1:], text[0]); at >= 0 {
					end, name = at+2, "quote-tail"
					if len(raw) != len(text) {
						name = "spaced-tail"
					}
				}
			} else if text[0] == '<' || text[0] == '{' {
				closing := byte('}')
				if text[0] == '<' {
					closing = '>'
				}
				if at := strings.IndexByte(text, closing); at >= 0 {
					end = at + 1
					if end < len(text) && text[end] == '}' {
						end++
					}
					if fix1Reference.MatchString(text[:end]) {
						name = "reference-tail"
					}
				}
			}
			if name != "" && end < len(text) {
				r, _ := utf8.DecodeRuneInString(text[end:])
				if !fix1TextSpace(r) && !strings.ContainsRune(",;)}]", r) {
					return name
				}
			}
		}
		trimmed := strings.TrimSpace(value)
		if len(trimmed) != 0 && strings.ContainsRune("{[\"", rune(trimmed[0])) && json.Valid([]byte(trimmed)) {
			var decoded any
			if err := json.Unmarshal([]byte(trimmed), &decoded); err == nil {
				return namedScreenExtra(decoded)
			}
		}
	case []any:
		for _, child := range value {
			if name := namedScreenExtra(child); name != "" {
				return name
			}
		}
	case map[string]any:
		for key, child := range value {
			if name := namedScreenExtra(key); name != "" {
				return name
			}
			if name := namedScreenExtra(child); name != "" {
				return name
			}
		}
	}
	return ""
}

// A reference-only omission requires an independent caller projection with no
// hit. Removing only the listed service fields must remove the reference hit;
// the previous per-string/per-list test could excuse a real caller-only split.
func namedScreenOmission(root map[string]any, key string) string {
	caller, excluded := frozenCallerScreen(root, key)
	if !fix1Sensitive(root, key) || caller || len(excluded) == 0 {
		return ""
	}
	return "structured-join"
}

type screenFixture struct{ name, text, benign string }

func screenFixtures() []screenFixture {
	a := func(n int) string { return strings.Repeat("a", n) }
	return []screenFixture{
		{"private", "-----" + "BEGIN RSA PRIVATE KEY" + "-----", "PRIVATE KEY reference"},
		{"authorization", "Authorization: Basic " + a(8), "Authorization: Basic short"},
		{"bearer", "Bearer " + a(16), "Bearer short"},
		{"github", "ghp_" + a(30), "ghp_short"},
		{"github-pat", "github_pat_" + a(30), "github_pat_short"},
		{"gitlab", "glpat-" + a(20), "glpat-short"},
		{"slack", "xoxb-" + a(10), "xoxb-short"},
		{"discord", "M" + a(23) + "." + a(6) + "." + a(27), "M.short.value"},
		{"telegram", "12345678:AA" + a(33), "12345678:AAshort"},
		{"aws", "AKIA" + strings.Repeat("A1", 8), "AKIAshort"},
		{"google", "AIza" + a(35), "AIzashort"},
		{"oauth", "ya29." + a(20), "ya29.short"},
		{"openai", "sk-" + a(1000) + "1", "sk-reference"},
		{"stripe", "sk_live_" + a(16), "sk_live_short"},
		{"npm", "npm_" + a(36), "npm_short"},
		{"pypi", "pypi-" + a(50), "pypi-short"},
		{"huggingface", "hf_" + a(30), "hf_short"},
		{"pa", "pa-" + a(1000) + "1", "pa-reference"},
		{"jwt", "eyJ" + a(8) + ".eyJ" + a(8) + "." + a(8), "eyJ.short.value"},
		{"url", "https://user:fake-value-1" + "@" + "host.invalid", "https://host.invalid/path"},
		{"discord-hook", "discord.com/api/" + "webhooks/12345/abcdef", "discord.com/api/reference"},
		{"slack-hook", "hooks.slack.com/services/" + "TAAAAA/BAAAAA/abcdef", "hooks.slack.com/reference"},
		{"slack-workflow", "hooks.slack.com/workflows/" + "TAAAAA/AAAAAA/12345/abcdef", "workflow reference"},
		{"slack-trigger", "hooks.slack.com/triggers/" + "TAAAAA/12345/abcdef", "trigger reference"},
		{"script", "script.google.com/macros/s/" + a(10), "script.google.com/reference"},
		{"script-id", "AKfycb" + a(40), "AKfycbshort"},
		{"encoded-hook", "discord.com%2Fapi%2F" + "webhooks%2F12345%2Fabcdef", "encoded reference"},
		{"unicode-auth", "Authorİzatİon: Basİc " + a(8), "unicode reference"},
		{"assignment", "token=fake-value-1", "token=$EXAMPLE_KEY"},
		{"wide-bearer", "Bearer" + strings.Repeat(" ", 513) + a(16), "Bearer" + strings.Repeat(" ", 513) + "short"},
		{"wide-auth", "proxy-authorization" + strings.Repeat(" ", 1025) + ": Basic " + a(8), "authorization reference"},
	}
}

func generatedScreenValue(text string, mode, script, padding, split int) any {
	neighbour := []string{"Z", "界", "A界ıİ_"}[script]
	pad := strings.Repeat(neighbour, padding)
	split = min(max(split, 1), len(text)-1)
	// Split only at rune boundaries; every actual decoded string stays UTF-8.
	for split > 0 && text[split]&0xc0 == 0x80 {
		split--
	}
	switch mode {
	case 0:
		return text
	case 1:
		return text + pad
	case 2:
		return pad + text + pad
	case 3:
		return pad + text
	case 4:
		body, _ := json.Marshal(map[string]any{"note": text})
		return string(body)
	case 5:
		return []any{pad, text[:split], text[split:]}
	case 6:
		return map[string]any{"a": pad, "b": text[:split], "c": text[split:]}
	case 7:
		return map[string]any{text[:split]: text[split:]}
	case 8:
		body, _ := json.Marshal([]any{map[string]any{text: pad}})
		return string(body)
	case 9:
		quote := []string{"", "\"", "'", "`"}[(padding+script)%4]
		value := "token=" + quote + strings.Repeat(" \t", padding) + text + quote
		return []any{value, "ordinary data"}
	case 10:
		return text[:split] + strings.Repeat(" ", padding) + text[split:]
	default:
		var escaped strings.Builder
		for _, code := range utf16.Encode([]rune(text)) {
			fmt.Fprintf(&escaped, `\u%04x`, code)
		}
		return `{"` + escaped.String() + `":"ordinary"}`
	}
}

func generatedScreenRoot(t *testing.T, value any) map[string]any {
	t.Helper()
	r := request()
	switch value := value.(type) {
	case string:
		r.Command.Command = []byte(value)
		r.Command.RawSHA256 = Digest(r.Command.Command)
	case []any:
		stringsOnly := true
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				stringsOnly = false
				break
			}
			r.Command.Argv = append(r.Command.Argv, text)
		}
		if !stringsOnly {
			r.Command.Argv = []string{}
			var err error
			r.Task, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
	default:
		var err error
		r.Task, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, _, err := Payload(r)
	if err != nil {
		t.Fatal(err)
	}
	root, err := typesafe.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	state := root["state"].(map[string]any)
	command := state["commands"].([]any)[0].(map[string]any)
	if command["command"] != string(r.Command.Command) || state["task"] != string(r.Task) {
		t.Fatal("generated payload lost input")
	}
	argv := command["argv"].([]any)
	if len(argv) != len(r.Command.Argv) {
		t.Fatal("generated argv lost input")
	}
	for i, text := range r.Command.Argv {
		if argv[i] != text {
			t.Fatal("generated argv changed bytes")
		}
	}
	return root
}

func screenLedger(t *testing.T, label string) *os.File {
	t.Helper()
	var output *os.File
	if *screenEvidence != "" {
		if !filepath.IsAbs(*screenEvidence) {
			t.Fatal("evidence path must be absolute")
		}
		if err := os.MkdirAll(*screenEvidence, 0700); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(*screenEvidence)
		if err != nil {
			t.Fatal(err)
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || owner.Uid != uint32(os.Geteuid()) {
			t.Fatal("evidence directory is not private")
		}
		output, err = os.OpenFile(filepath.Join(*screenEvidence, label+".jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := output.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return output
}

func runScreenDifferential(t *testing.T, rows int, label string) {
	t.Helper()
	output := screenLedger(t, label)
	count, allowed, detected, cappedCount := 0, 0, 0, 0
	extras := map[string]int{}
	omissions := map[string]int{}
	check := func(name string, root map[string]any, key string, allowCap bool) {
		t.Helper()
		body, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		want := fix1Sensitive(root, key)
		caller, excluded := frozenCallerScreen(root, key)
		extra := namedScreenExtra(root)
		if extra == "" && !want && caller {
			extra = "caller-join"
		}
		err = screenOutgoing(body, key)
		got, capped := err != nil, false
		if err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeUnscored {
				t.Fatalf("screen gate failed: %s", name)
			}
			capped = typed.Message == ScreenCapReason
			if !capped && typed.Message != "credential-shaped input withheld" {
				t.Fatalf("screen reason changed: %s", name)
			}
		}
		omission := ""
		if want && !got {
			omission = namedScreenOmission(root, key)
		}
		count++
		if output != nil {
			row := struct {
				Case       int      `json:"case"`
				Name       string   `json:"name"`
				Body       []byte   `json:"body"`
				Key        string   `json:"key"`
				Reference  bool     `json:"reference"`
				Production bool     `json:"production"`
				Capped     bool     `json:"capped"`
				Extra      string   `json:"extra,omitempty"`
				Omission   string   `json:"omission,omitempty"`
				Caller     bool     `json:"caller"`
				Excluded   []string `json:"excluded_paths,omitempty"`
			}{count, name, body, key, want, got, capped, extra, omission, caller, excluded}
			if err := json.NewEncoder(output).Encode(row); err != nil {
				t.Fatal(err)
			}
		}
		if want && !got && omission == "" {
			t.Fatalf("reference credential escaped: %s", name)
		}
		if caller && !got {
			t.Fatalf("caller credential escaped: %s", name)
		}
		if omission != "" {
			omissions[omission]++
		}
		if got && !want && !capped && extra == "" {
			t.Fatalf("extra non-cap detection: %s", name)
		}
		if extra != "" && !got {
			t.Fatalf("named assignment extra escaped: %s", name)
		}
		if got && !want && !capped {
			extras[extra]++
		}
		if capped {
			_, exhausted := requestScreenResult(root, key)
			if !allowCap || len(body) <= MaxScreenInputBytes && !exhausted {
				t.Fatalf("unproved screening cap: %s", name)
			}
			cappedCount++
		} else if got {
			detected++
		} else {
			allowed++
		}
	}
	fixtures := screenFixtures()
	for _, fixture := range benignScreenRequests() {
		body, _, err := Payload(fixture.request)
		if err != nil {
			t.Fatal(err)
		}
		root, err := typesafe.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		if fix1Sensitive(root, "") != fixture.reference {
			t.Fatalf("benign reference verdict changed: %s", fixture.name)
		}
		check("benign-"+fixture.name, root, "", false)
		if err := screenOutgoing(body, ""); err != nil {
			t.Fatalf("benign structured input withheld: %s", fixture.name)
		}
	}
	// Every frozen signature must have a real matching fixture, including the
	// two digit-bearing shapes whose digit is deliberately far past 512 bytes.
	for _, rule := range fix1CredentialShapes {
		covered := false
		for _, f := range fixtures {
			for _, at := range rule.re.FindAllStringIndex(f.text, -1) {
				if !rule.digit || strings.ContainsAny(f.text[at[0]:at[1]], "0123456789") {
					covered = true
				}
			}
		}
		if !covered {
			t.Fatal("reference shape lacks a fixture")
		}
	}
	rng := rand.New(rand.NewSource(screenSeed))
	var modes [12]int
	var scripts [3]int
	var quotes [4]int
	for i := range rows {
		f := fixtures[i%len(fixtures)]
		phase := i / len(fixtures)
		mode, script := phase%12, phase/12%3
		padding := []int{0, 1, 513, 1025}[rng.Intn(4)]
		if mode == 9 {
			padding = []int{0, 1, 513, 1025}[i%4]
			quotes[(padding+script)%4]++
		}
		modes[mode]++
		scripts[script]++
		for j, text := range []string{f.text, f.benign} {
			split := 1 + rng.Intn(len(text)-1)
			value := generatedScreenValue(text, mode, script, padding, split)
			check(fmt.Sprintf("generated-%d-%d-%s", i, j, f.name), generatedScreenRoot(t, value), "", false)
		}
	}
	for _, n := range modes {
		if n == 0 {
			t.Fatal("missing generated position")
		}
	}
	for _, n := range scripts {
		if n == 0 {
			t.Fatal("missing generated script")
		}
	}
	for _, n := range quotes {
		if n == 0 {
			t.Fatal("missing generated quote")
		}
	}
	for _, fixture := range callerFixtures() {
		check("caller-"+fixture.name, callerRoot(t, fixture.request), "", false)
	}
	for i, root := range unknownCallerRoots(t) {
		check(fmt.Sprintf("unknown-caller-%d", i), root, "", false)
	}
	for _, values := range []map[string]string{assignmentCanaries(), assignmentExtensionControls()} {
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			check(name, map[string]any{"state": values[name]}, "", false)
		}
	}
	wide := wideFragmentCanaries()
	names := make([]string, 0, len(wide))
	for name := range wide {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		check(name, map[string]any{"state": wide[name]}, "", false)
	}
	fragment := strings.Repeat("a1", 16)
	for i, value := range []any{
		map[string]any{"a": "Bear", "b": "er " + fragment},
		map[string]any{"Bear": "er " + fragment},
		[]any{"Bearer", fragment}, []any{"Bear", "er ", fragment},
	} {
		check(fmt.Sprintf("fix1-split-%d", i), map[string]any{"state": value}, "", false)
	}
	for i, text := range []string{"ordinary project data", "Bearer short", "ghp_short", "AKIAshort",
		"token=$EXAMPLE_KEY", "token: redacted", "token=fn(token: redacted )"} {
		root := map[string]any{"state": text}
		if fix1Sensitive(root, "") {
			t.Fatal("clean control is not clean")
		}
		check(fmt.Sprintf("clean-%d", i), root, "", false)
	}
	// Six paired edge cases per serialized-input, judge-byte, depth, node and
	// supplied-key cap. Oversize is withheld with a distinct cap reason.
	for _, limit := range []int{MaxScreenInputBytes, api.MaxJudgeBytes} {
		for _, delta := range []int{-1, 0, 1} {
			for _, poison := range []bool{false, true} {
				root := map[string]any{"state": ""}
				empty, _ := json.Marshal(root)
				n := limit + delta - len(empty)
				text := strings.Repeat("q", n)
				if poison {
					text = text[:n-len("Bearer "+fragment)] + "Bearer " + fragment
				}
				root["state"] = text
				check(fmt.Sprintf("bytes-%d-%d-%t", limit, delta, poison), root, "", true)
			}
		}
	}
	for _, delta := range []int{-1, 0, 1} {
		for _, poison := range []bool{false, true} {
			var deep any = "ordinary"
			if poison {
				deep = "Bearer " + fragment
			}
			for range MaxScreenDepth + delta - 1 {
				deep = []any{deep}
			}
			check(fmt.Sprintf("depth-%d-%t", delta, poison), map[string]any{"state": deep}, "", true)
			nodes := make([]any, MaxScreenNodes-3+delta)
			if poison {
				nodes[len(nodes)-1] = "Bearer " + fragment
			}
			check(fmt.Sprintf("nodes-%d-%t", delta, poison), map[string]any{"state": nodes}, "", true)
			key := strings.Repeat("k", maxScreenKeyBytes+delta)
			var value any = "ordinary"
			if poison {
				value = []any{key[:len(key)/2], key[len(key)/2:]}
			}
			check(fmt.Sprintf("key-%d-%t", delta, poison), map[string]any{"state": value}, key, true)
		}
	}
	if count != 2*rows+54+len(benignScreenRequests())+len(callerFixtures())+len(unknownCallerRoots(t)) || allowed < rows/4 || detected < rows/4 || cappedCount == 0 || omissions["structured-join"] == 0 {
		t.Fatal("differential coverage changed")
	}
	for _, name := range []string{"quote-tail", "spaced-tail", "reference-tail", "caller-join"} {
		if extras[name] == 0 {
			t.Fatalf("named extra lacks coverage: %s", name)
		}
	}
	t.Logf("seed=%d cases=%d allowed=%d detected=%d capped=%d", screenSeed, count, allowed, detected, cappedCount)
	t.Logf("named extras=%v", extras)
	t.Logf("named omissions=%v", omissions)
}

func TestScreenDifferential(t *testing.T) {
	runScreenDifferential(t, normalScreenRows, "normal")
}
