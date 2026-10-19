//go:build linux || darwin

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

func TestReuseScannerPaths(t *testing.T) {
	for _, kind := range []string{"key", "last8", "name", "link", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			material, inputs := reuseScanFixture(t)
			path := filepath.Join(inputs.Evidence, "nested", "retained file\nentry")
			if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
				t.Fatal("cannot create path control")
			}
			plant := material.Bytes
			if kind == "last8" {
				plant = plant[len(plant)-8:]
			}
			if kind == "name" {
				path = filepath.Join(filepath.Dir(path), string(material.Bytes))
				plant = []byte("ordinary retained bytes")
			}
			if kind == "link" {
				if os.Symlink(string(material.Bytes), path) != nil {
					t.Fatal("cannot plant link control")
				}
			} else if os.WriteFile(path, plant, 0600) != nil {
				t.Fatal("cannot plant path control")
			}
			if kind == "unreadable" {
				if os.Chmod(path, 0000) != nil {
					t.Fatal("cannot make unreadable path control")
				}
				t.Cleanup(func() {
					if os.Chmod(path, 0600) != nil {
						t.Error("cannot collect unreadable path control")
					}
				})
			}
			result := ScanAPIKeyReleaseInputs(context.Background(), material, inputs)
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal("cannot encode path result")
			}
			var paths [9]struct {
				Path           string `json:"path"`
				UnreadablePath string `json:"unreadable_path"`
			}
			if json.Unmarshal(encoded, &paths) != nil {
				t.Fatal("cannot read path result")
			}
			found := paths[5].Path
			if kind == "unreadable" {
				found = paths[5].UnreadablePath
				if !result[5].Unreadable || result[5].Key || result[5].Last8 {
					t.Fatal("unreadable control was confused with a material match")
				}
			}
			if found == "" || kind != "name" && found != path {
				t.Fatal("release scan omitted the exact finding path")
			}
			if kind == "name" && !strings.HasPrefix(found, filepath.Dir(path)+string(os.PathSeparator)) {
				t.Fatal("redaction lost the safe parent path")
			}
			if !strings.Contains(result.Line(), strconv.Quote(found)) || strings.Count(result.Line(), "\n") != 1 {
				t.Fatal("journal omitted or failed to quote the finding path")
			}
			if bytes.Contains(encoded, material.Bytes[len(material.Bytes)-8:]) || strings.Contains(result.Line(), string(material.Bytes[len(material.Bytes)-8:])) {
				t.Fatal("finding path exposed credential material")
			}
		})
	}
}

func TestReuseScannerNativePaths(t *testing.T) {
	material, inputs := reuseScanFixture(t)
	clean := ScanAPIKeyReleaseInputs(context.Background(), material, inputs)
	raw, err := json.Marshal(clean)
	if err != nil {
		t.Fatal("cannot encode native path control")
	}
	var rows [9]map[string]any
	if json.Unmarshal(raw, &rows) != nil {
		t.Fatal("cannot read native path control")
	}
	rows[5]["key"], rows[5]["last8"], rows[5]["unreadable"] = true, true, true
	rows[5]["path"] = "/evidence/" + string(material.Bytes)
	rows[5]["unreadable_path"] = "/evidence/" + string(material.Bytes[len(material.Bytes)-8:])
	raw, err = json.Marshal(rows)
	if err != nil {
		t.Fatal("cannot encode native path metadata")
	}
	defer clear(raw)
	var scan APIKeyScanResult
	if json.Unmarshal(raw, &scan) != nil {
		t.Fatal("cannot decode native path metadata")
	}
	a := api.CredentialProjectionAuthority{ID: "path-authority", Request: api.CredentialProjectionRequest{
		Prepared: api.PreparedLaunch{Target: api.LifeRef{LifeID: "path-life", Run: 1}}}}
	native := &rscan.NativeReleaseScan{Authority: a, Scan: scan,
		Cause: api.InternalIntent{Kind: api.InternalHelperRelease, Target: a.Request.Prepared.Target}}
	ctx := rscan.WithNativeReleaseScan(context.Background(), native)
	result, err := rscan.ReadNativeReleaseScan(ctx, a, material)
	if err != nil || result.Clean() || !strings.Contains(result.Line(), "/evidence/") {
		t.Fatal("native scan lost its finding or safe parent path")
	}
	encoded, err := json.Marshal(result)
	if err != nil || bytes.Contains(encoded, material.Bytes[len(material.Bytes)-8:]) || strings.Contains(result.Line(), string(material.Bytes[len(material.Bytes)-8:])) {
		t.Fatal("native scan serialized material in a finding path")
	}
}
