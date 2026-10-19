// Package v2 embeds the inert human dashboard web assets owned by lb-v2-dashboard.
package v2

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"html"
	"strings"
)

//go:embed index.html
var indexHTML string

//go:embed styles.css
var stylesCSS string

//go:embed app.js
var appJS string

//go:embed locale.json
var localeJSON string

//go:embed enrollment.html
var enrollmentHTML string

//go:embed enrollment.js
var enrollmentJS string

var dashboardScript = strings.Replace(appJS, "/* LOCALE */", strings.TrimSpace(localeJSON), 1)

func scriptHash(script string) string {
	digest := sha256.Sum256([]byte(script))
	return "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
}

// ScriptSources authenticates the exact bytes between the embedded script tags.
func ScriptSources() string {
	return scriptSources
}

var scriptSources = scriptHash("\n"+dashboardScript+"\n") + " " + scriptHash("\n"+enrollmentJS+"\n")

func EnrollmentPage() []byte {
	doc := strings.Replace(enrollmentHTML, "/* STYLES */", strings.TrimSpace(stylesCSS), 1)
	return []byte(strings.Replace(doc, "/* ENROLLMENT */", enrollmentJS, 1))
}

// Page returns the self-contained human dashboard HTML document with no external network dependencies.
func Page() []byte {
	doc := strings.Replace(indexHTML, "/* STYLES */", strings.TrimSpace(stylesCSS), 1)
	doc = strings.Replace(doc, "/* SCRIPT */", dashboardScript, 1)
	return []byte(doc)
}

// InertText escapes arbitrary untrusted text so stored HTML or script tags are rendered strictly as inert text.
func InertText(raw string) string {
	return html.EscapeString(raw)
}
