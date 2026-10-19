package dashboard

import (
	_ "embed"
	"encoding/json"
	"html"
	"regexp"
	"strings"
)

// One table supplies all interface copy. English literals in the renderer are
// message keys; recorded strings are explicitly marked and never translated.
//
//go:embed locale.json
var localeData string

//go:embed locale.js
var localeScript string

var htmlText = regexp.MustCompile(`>([^<>]+)<`)
var htmlOption = regexp.MustCompile(`<option([^>]*)>([^<]+)</option>`)

func localizeShell(document string) string {
	var messages map[string]map[string]string
	if err := json.Unmarshal([]byte(localeData), &messages); err != nil {
		panic("invalid dashboard message table")
	}
	encoded, err := json.Marshal(messages)
	if err != nil {
		panic("invalid dashboard message table")
	}
	document = strings.Replace(document, "/* MESSAGE_TABLE */", string(encoded), 1)
	before, script, found := strings.Cut(document, "<script>")
	if !found {
		return document
	}
	before = strings.Replace(before, "<title>Laneboss · Org overview</title>", `<title data-msg="Laneboss · Org overview"></title>`, 1)
	before = htmlOption.ReplaceAllStringFunc(before, func(match string) string {
		parts := htmlOption.FindStringSubmatch(match)
		key := html.UnescapeString(strings.TrimSpace(parts[2]))
		if _, ok := messages[key]; !ok {
			return match
		}
		return `<option` + parts[1] + ` data-msg="` + html.EscapeString(key) + `"></option>`
	})
	before = htmlText.ReplaceAllStringFunc(before, func(match string) string {
		text := strings.TrimSpace(match[1 : len(match)-1])
		key := html.UnescapeString(text)
		if _, ok := messages[key]; !ok {
			return match
		}
		return `><span data-msg="` + html.EscapeString(key) + `"></span><`
	})
	return before + "<script>" + script
}
