package dashboard

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"testing"
)

// The shortcut panel's rows in page order: the key cap, then what it does.
var shortcutRows = [][2]string{
	{"/", "Find an agent"},
	{"g o", "Go to the live org"},
	{"g a", "Go to analytics"},
	{"g d", "Go to decisions"},
	{"?", "Show this list"},
	{"Esc", "Close this list"},
}

// between returns the text from the first start up to the next end, or "".
func between(text, start, end string) string {
	i := strings.Index(text, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(text[i:], end)
	if j < 0 {
		return ""
	}
	return text[i : i+j]
}

// checkShortcuts is the whole claim: the header carries no shortcut hint (gone
// from its text, not merely hidden), the keys are still wired, and "?" lists
// them in a panel whose copy is in the one message table in both languages.
func checkShortcuts(document string, table map[string]map[string]string) error {
	header := between(document, `<div class="watch-controls">`, `<section id="now"`)
	if header == "" {
		return fmt.Errorf("the header controls were not found")
	}
	if strings.Contains(header, "<kbd") || strings.Contains(header, "shortcut") {
		return fmt.Errorf("the header still carries the shortcut hint")
	}
	for _, old := range []string{"search ·", "org ·", "analytics ·"} {
		if strings.Contains(document, old) {
			return fmt.Errorf("the old hint text %q is still in the page", old)
		}
	}
	for _, wired := range []string{
		`event.key==='?'`, `shortcutPanel.showModal()`, `byId('shortcut-close')`,
		`byId('agent-search').focus()`, `{o:'org-live',a:'analytics',d:'decisions'}`,
	} {
		if !strings.Contains(document, wired) {
			return fmt.Errorf("the shortcut handler lost %s", wired)
		}
	}
	panel := between(document, `<dialog id="shortcut-panel"`, `</dialog>`)
	if panel == "" {
		return fmt.Errorf("the shortcut panel is missing")
	}
	at := 0
	for _, row := range shortcutRows {
		for _, key := range row {
			i := strings.Index(panel[at:], `data-msg="`+html.EscapeString(key)+`"`)
			if i < 0 {
				return fmt.Errorf("the shortcut panel lacks %q in order", key)
			}
			at += i + 1
		}
	}
	if rest := strings.TrimSpace(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(panel, "")); rest != "" {
		return fmt.Errorf("panel text %q is outside the message table", rest)
	}
	han := regexp.MustCompile(`\p{Han}`)
	for _, match := range regexp.MustCompile(`data-msg="([^"]*)"`).FindAllStringSubmatch(panel, -1) {
		key := html.UnescapeString(match[1])
		row, ok := table[key]
		if !ok || row["en"] != key {
			return fmt.Errorf("panel text %q is not in the message table", key)
		}
		if len(key) > 3 && !han.MatchString(row["zh-TW"]) {
			return fmt.Errorf("panel text %q has no zh-TW translation", key)
		}
	}
	return nil
}

func copyTable(table map[string]map[string]string) map[string]map[string]string {
	result := map[string]map[string]string{}
	for key, row := range table {
		result[key] = map[string]string{"en": row["en"], "zh-TW": row["zh-TW"]}
	}
	return result
}

func TestShortcutPanel(t *testing.T) {
	var table map[string]map[string]string
	if err := json.Unmarshal([]byte(localeData), &table); err != nil {
		t.Fatal(err)
	}
	document := experiencePage()
	if err := checkShortcuts(document, table); err != nil {
		t.Fatal(err)
	}
	// Each control breaks one part of the claim and must be rejected by the same
	// check that accepts the real page.
	actions := `<div class="watch-actions">`
	controls := map[string]string{
		"the old hint back in the header":   strings.Replace(document, actions, actions+`<span class="shortcut-hint"><kbd>/</kbd> search · <kbd>g o</kbd> org ·</span>`, 1),
		"the hint only hidden with a style": strings.Replace(document, actions, actions+`<span class="shortcut-hint" style="display:none"><kbd>/</kbd> x</span>`, 1),
		"the question mark case removed":    strings.Replace(document, `event.key==='?'`, `event.key==='none'`, 1),
		"the panel removed":                 strings.Replace(document, `<dialog id="shortcut-panel"`, `<dialog id="other-panel"`, 1),
		"the g then key map removed":        strings.Replace(document, `{o:'org-live',a:'analytics',d:'decisions'}`, `{}`, -1),
	}
	for name, mutated := range controls {
		if mutated == document {
			t.Fatalf("control %q did not change the page", name)
		}
		if err := checkShortcuts(mutated, table); err == nil {
			t.Fatalf("control %q was accepted", name)
		}
	}
	untranslated := copyTable(table)
	untranslated["Show this list"]["zh-TW"] = "Show this list"
	if err := checkShortcuts(document, untranslated); err == nil {
		t.Fatal("an untranslated panel row was accepted")
	}
	missing := copyTable(table)
	delete(missing, "Go to analytics")
	if err := checkShortcuts(document, missing); err == nil {
		t.Fatal("a panel row missing from the message table was accepted")
	}
}
