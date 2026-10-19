package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Use the same Python builders as enroll_root and the wire decoder used by the
// installed client's RPC path. Decode exact file bytes before any Go marshal
// can add fields or repair an ID. The synthetic imported handle is only an
// input-format fixture; this test starts no service or enrollment operation.
func TestGrantsEnrollmentInputs(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-B",
		filepath.Join(root, "e2e", "v2", "cases", "grants", "boot_bundle_input.py"), directory, "--enrollment")
	command.Dir = root
	var stderr bytes.Buffer
	command.Stderr = &stderr
	exported, err := command.Output()
	if err != nil {
		t.Fatalf("actual enrollment producer failed: %v; stderr=%s", err, stderr.Bytes())
	}
	// Base64 is just a lossless envelope around the producer's retained files.
	var requests map[string][]byte
	if err := json.Unmarshal(exported, &requests); err != nil || len(requests) != 2 {
		t.Fatal("enrollment producer lost its two exact request files:", err)
	}
	importedRaw, err := os.ReadFile(filepath.Join(directory, "enrollment-import-fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var imported struct {
		SourceHandle api.ID `json:"source_handle"`
		Name         string `json:"name"`
		Version      string `json:"version"`
	}
	if err := wire.Decode(importedRaw, &imported); err != nil {
		t.Fatal("declared synthetic import fixture:", err)
	}
	for _, family := range []string{"resource", "secret"} {
		t.Run(family, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(directory, family+"-enrollment.json"))
			if err != nil || !bytes.Equal(raw, requests[family]) {
				t.Fatal("enrollment producer changed its exact request file:", err)
			}
			// Keep the actual input bytes in the cloud transcript even when a
			// RED control fails and Go later removes the temporary directory.
			t.Logf("enrollment input sha256=%s bytes_base64=%s", digest(raw), base64.StdEncoding.EncodeToString(raw))
			var proposal api.CapabilityEnrollmentRequest
			if err := wire.Decode(raw, &proposal); err != nil {
				t.Fatal("enrollment CLI decoder:", err)
			}
			if family == "resource" && (proposal.Resource == nil || proposal.Secret != nil) ||
				family == "secret" && (proposal.Secret == nil || proposal.Resource != nil) {
				t.Fatal("enrollment producer changed its capability family")
			}
			if proposal.Secret != nil && (proposal.Secret.SourceHandle != imported.SourceHandle ||
				proposal.Secret.Name != imported.Name || proposal.Secret.Version != imported.Version) {
				t.Fatal("secret enrollment changed the imported source selection")
			}
			if err := manifest.EnrollmentInput(proposal); err != nil {
				t.Fatal("enrollment semantic validator:", err)
			}
			key, err := client.NewRequestID()
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := client.PrepareRequest(api.Request{Config: "case-grants", Method: "grants.enroll",
				Params: raw, IdempotencyKey: key})
			if err != nil {
				t.Fatal("enrollment CLI request preparation:", err)
			}
			if !bytes.Equal(prepared.Params, raw) {
				t.Fatal("enrollment preparation changed the producer's bytes")
			}
			if err := wire.ValidateRequest(prepared); err != nil {
				t.Fatal("enrollment RPC decoder:", err)
			}
			t.Log("GREEN: actual enrollment input passed CLI preparation, wire decoding and semantic validation")
		})
	}
}
