package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

// The Python producer's JSON must cross the same input decoder as run().
// Keep its nested objects raw until DecodeObject: marshaling Go grant structs
// first would silently supply the missing fields this regression must catch.
func TestGrantsBootBundle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out := grantsBoot(t, ctx)
	validateGrantsInitial(t, ctx, out)
	t.Log("GREEN: actual grants boot passed installer initial validation")
}

// The producer/decoder/assembly proof also runs in the unprivileged queue.
// The original root-only test above still owns protected installer validation.
func TestGrantsBootProfiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	grantsBoot(t, ctx)
}

func grantsBoot(t *testing.T, ctx context.Context) output {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "python3", "-B",
		filepath.Join(root, "e2e", "v2", "cases", "grants", "boot_bundle_input.py"), t.TempDir())
	command.Dir = root
	var stderr bytes.Buffer
	command.Stderr = &stderr
	raw, err := command.Output()
	if err != nil {
		t.Fatalf("actual grants boot failed: %v; stderr=%s", err, stderr.Bytes())
	}
	var extra map[string]json.RawMessage
	if err := json.Unmarshal(raw, &extra); err != nil {
		t.Fatal("boot bundle JSON:", err)
	}
	base, err := json.Marshal(bundleTestInput(t))
	if err != nil {
		t.Fatal(err)
	}
	var full map[string]json.RawMessage
	if err := json.Unmarshal(base, &full); err != nil {
		t.Fatal(err)
	}
	for name, value := range extra {
		switch name {
		case "sources":
			var sources, additional []json.RawMessage
			if err := json.Unmarshal(full[name], &sources); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(value, &additional); err != nil {
				t.Fatal(err)
			}
			full[name], err = json.Marshal(append(sources, additional...))
			if err != nil {
				t.Fatal(err)
			}
		case "documents", "contexts", "projects", "root_grants", "budget":
			full[name] = value
		default:
			t.Fatal("unsupported boot bundle field:", name)
		}
	}
	raw, err = json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var in input
	if err := api.DecodeObject(raw, &in); err != nil {
		t.Fatal("boot bundle decoder:", err)
	}
	if in.RootGrants == nil || len(in.RootGrants.Resources) != 0 || len(in.RootGrants.Secrets) != 0 || len(in.RootGrants.Data) != 2 {
		t.Fatal("boot bundle lost the actual fixture grants")
	}
	// Two ordinary lifecycle fixtures plus independent successful grants seats.
	// The lifecycle Codex seat is later used only by the running-stop control.
	wantProfiles := map[api.ID]api.Driver{
		"serve-profile-claudock-cli": "claudock-cli",
		"serve-profile-codex":        "codex",
		"grants-profile-parent":      "codex",
		"grants-profile-child":       "codex",
	}
	if len(in.RootGrants.Profiles) != len(wantProfiles) {
		t.Fatalf("boot bundle has %d profiles; want the four isolated seats", len(in.RootGrants.Profiles))
	}
	for _, profile := range in.RootGrants.Profiles {
		driver, found := wantProfiles[profile.ProfileID]
		if !found || profile.Driver != driver || profile.Provider != "serve-fixture" || profile.Paid || !profile.Delegate {
			t.Fatalf("boot bundle profile differs from isolated design: %+v", profile)
		}
		delete(wantProfiles, profile.ProfileID)
	}
	if len(wantProfiles) != 0 {
		t.Fatal("boot bundle lost isolated profiles:", wantProfiles)
	}
	out, err := assemble(in)
	if err != nil {
		t.Fatal("assemble actual grants boot:", err)
	}
	var published api.RootGrantManifest
	found := false
	for _, doc := range out.Documents {
		if doc.Ref != out.Initial.Profiles {
			continue
		}
		if doc.Ref != ref(doc.Ref.ID, doc.Ref.Class, doc.Data) {
			t.Fatal("published root grants differ from their actual bytes")
		}
		if err := api.DecodeObject(doc.Data, &published); err != nil {
			t.Fatal("published root grants JSON:", err)
		}
		found = true
	}
	if !found || len(published.Data) != len(in.RootGrants.Data)+1 || published.Data[0].SourceObjectID != "serve-project" || published.Data[0].Destination != "/work/main" {
		t.Fatal("assembled root lost the baseline workspace or case data")
	}
	published.Data = published.Data[1:]
	if !reflect.DeepEqual(published, *in.RootGrants) {
		t.Fatal("assembled root changed the producer's grant fields")
	}
	t.Logf("GREEN: actual boot JSON %s passed the bundle decoder and assembly", digest(raw))
	return out
}

// Use the installer's root-only validator and its actual protected file reader.
// Runtime bytes are the same inert unit fixture used by bundleTestInput; no
// service, worker, enrollment or model request is started by this test.
func validateGrantsInitial(t *testing.T, ctx context.Context, out output) {
	t.Helper()
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("installer initial validation requires the authorized disposable Linux root observer")
	}
	stage, err := os.MkdirTemp("/opt", "lb-v2-case-grants-initial-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stage); err != nil {
			t.Error(err)
		}
	})
	objects := filepath.Join(stage, "initial-objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0444); err != nil {
			t.Fatal(err)
		}
	}
	contents := map[api.ID][]byte{"laneboss": []byte(bundleTestBinary)}
	for _, doc := range out.Documents {
		if _, exists := contents[doc.Ref.ID]; exists {
			t.Fatal("initial fixture repeated an object:", doc.Ref.ID)
		}
		contents[doc.Ref.ID] = doc.Data
	}
	for _, selected := range out.Initial.Objects {
		raw, found := contents[selected.ID]
		if !found || selected != ref(selected.ID, selected.Class, raw) {
			t.Fatal("initial fixture lacks the actual selected bytes:", selected.ID)
		}
		write(filepath.Join(objects, string(selected.ID)), raw)
	}
	manifestPath, refPath := filepath.Join(stage, "initial.json"), filepath.Join(stage, "initial-ref.json")
	write(manifestPath, out.Raw)
	request, err := json.Marshal(admin.InitialRequest{Manifest: out.Ref})
	if err != nil {
		t.Fatal(err)
	}
	write(refPath, request)
	var receipt bytes.Buffer
	if err := admin.RunInitialValidation(ctx, out.Initial.Config,
		[]string{"--validate-initial", manifestPath, "--initial-ref", refPath}, &receipt); err != nil {
		t.Fatal("admin initial validation:", err)
	}
	var result struct {
		Valid    bool        `json:"valid"`
		Manifest api.BlobRef `json:"manifest"`
		ID       api.ID      `json:"id"`
	}
	if err := api.DecodeObject(receipt.Bytes(), &result); err != nil {
		t.Fatal("admin initial validation receipt:", err)
	}
	if !result.Valid || result.Manifest != out.Ref || result.ID != out.Initial.ID {
		t.Fatal("admin initial validation did not confirm the exact boot publication")
	}
}
