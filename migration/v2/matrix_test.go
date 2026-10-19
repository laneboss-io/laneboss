package v2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompatibilityMatrix(t *testing.T) {
	m, err := Matrix()
	if err != nil {
		t.Fatal(err)
	}
	if m.Schema != "laneboss.migration-matrix.v2" || m.TargetSchema != 2 {
		t.Fatalf("unexpected matrix metadata: %+v", m)
	}
	if !SupportedSourceVersion("0.7.0") || !SupportedSourceVersion("1.0.0-candidate") || SupportedSourceVersion("9.9.9") {
		t.Fatal("unexpected source version support")
	}
	for _, proto := range []string{"1.1.0", "1.2.0", "1.3.0"} {
		if !SupportedSourceProtocol(proto) {
			t.Fatalf("expected protocol %s to be supported", proto)
		}
	}
	if SupportedSourceProtocol("2.0.0") {
		t.Fatal("unexpected 2.0.0 source protocol")
	}
	if len(MatrixSHA256()) != 64 {
		t.Fatal("invalid matrix digest length")
	}
}

func TestAdversarialInventory(t *testing.T) {
	path := filepath.Join("..", "..", "e2e-rows", "adversarial-additions.json")
	inv, raw, err := LoadAdversarialAdditions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.IDs) != 16 || inv.Bytes != int64(len(raw)) || len(inv.SHA256) != 64 {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
	// Corrupt one ID and verify rejection.
	bad := strings.Replace(string(raw), "must-ansic-redirect", "forged-ansic-id", 1)
	if _, err := VerifyAdversarialAdditions([]byte(bad)); err == nil {
		t.Fatal("expected tampered adversarial-additions to fail verification")
	}
	_ = os.DevNull
}

func TestCheck050Incompatibilities(t *testing.T) {
	cfg := []byte(`schema_version = 1
name = "demo"
owner_channel = "owner"
[turns]
idle_seconds = 60
[runners.agent]
command = ["claudock", "{session}"]
resume = ["claudock", "{session}"]
prompt = "stdin"
stream = true
`)
	events := []map[string]any{
		{
			"seq":  1,
			"kind": "lane.started",
			"payload": map[string]any{
				"session_id": "12345678-1234-4234-8234-123456789abc",
				"mail":       []any{},
			},
		},
		{
			"seq":     2,
			"kind":    "lane.adopted",
			"payload": map[string]any{},
		},
		{
			"seq":     3,
			"kind":    "lane.ended",
			"payload": map[string]any{"prompt": map[string]any{"state": "written"}},
		},
		{
			"seq":     4,
			"kind":    "lane.mailed",
			"payload": map[string]any{"legacy_relationship": true},
		},
	}
	projs := []map[string]any{
		{
			"lane":  "demo-1",
			"state": "waiting",
			"mail":  map[string]any{"turn_based": true},
		},
	}
	reasons, err := Check050Compatibility(cfg, events, projs)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(reasons, ",")
	for _, want := range []string{
		"config.toml:turns",
		"config.toml:owner_channel",
		"config.toml:runners.agent.prompt",
		"config.toml:runners.agent.stream",
		"config.toml:runners.agent.command:{session}",
		"event:1:lane.started.session_id",
		"event:1:lane.started.mail",
		"event:2:kind:lane.adopted",
		"event:3:lane.ended.prompt",
		"event:4:kind:lane.mailed",
		"event:4:lane.mailed.legacy_relationship",
		"projection:demo-1:mail",
		"projection:demo-1:state:waiting",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing expected 0.5.0 incompatibility %q in %v", want, reasons)
		}
	}
}
