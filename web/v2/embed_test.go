package v2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestScriptCSP(t *testing.T) {
	for _, page := range [][]byte{Page(), EnrollmentPage()} {
		parts := strings.Split(string(page), "<script>")
		if len(parts) != 2 {
			t.Fatal("embedded page has an unexpected script inventory")
		}
		script, _, ok := strings.Cut(parts[1], "</script>")
		if !ok {
			t.Fatal("embedded page has an unterminated script")
		}
		digest := sha256.Sum256([]byte(script))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'"
		if !strings.Contains(ScriptSources(), want) || strings.Contains(ScriptSources(), "unsafe-inline") {
			t.Fatal("CSP did not authenticate exact embedded script bytes")
		}
	}
	if !bytes.Contains(EnrollmentPage(), []byte("navigator.credentials.create")) || bytes.Contains(EnrollmentPage(), []byte("attestation_marker")) {
		t.Fatal("real-device enrollment page lost WebAuthn or added a software marker")
	}
}

func TestPageAndInertText(t *testing.T) {
	doc := Page()
	if len(doc) == 0 {
		t.Fatal("Page returned empty document")
	}
	if !bytes.Contains(bytes.ToLower(doc), []byte("<!doctype html>")) {
		t.Fatal("Page is missing doctype")
	}
	for _, forbidden := range []string{"/* STYLES */", "/* SCRIPT */", "/* LOCALE */", "innerHTML", "outerHTML", "document.write"} {
		if bytes.Contains(doc, []byte(forbidden)) {
			t.Fatalf("Page contains forbidden token %q", forbidden)
		}
	}
	for _, panelID := range []string{
		"bootstrap-handoff",
		"bootstrap-nonce",
		"tree-panel",
		"lifecycle-panel",
		"raw-panel",
		"decisions-panel",
		"refusals-panel",
		"plugins-panel",
		"resources-panel",
		"approvals-panel",
		"shortcut-panel",
	} {
		if !bytes.Contains(doc, []byte(panelID)) {
			t.Fatalf("Page is missing panel %q", panelID)
		}
	}
	if !bytes.Contains(doc, []byte("Copy this nonce into the native sign-in command")) {
		t.Fatal("Page is missing the native nonce handoff")
	}

	raw := `<script>window.__xss=1</script><img src=x onerror="alert(1)">`
	escaped := InertText(raw)
	if strings.Contains(escaped, "<script>") || strings.Contains(escaped, "<img") {
		t.Fatalf("InertText did not escape HTML tags: %s", escaped)
	}
}
