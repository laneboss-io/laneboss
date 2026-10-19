package approval_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

func TestCLIFileInputs(t *testing.T) {
	ref := api.BlobRef{ID: "source-one", SHA256: api.Digest(strings.Repeat("1", 64)), Bytes: 3, Class: "artifact"}
	propose := api.ChangeProposeRequest{OrgID: "org-one", BaseGeneration: 7, Reason: ref,
		Files: []api.ResourceDelta{{Path: "scripts/demo.sh", Action: "add", Mode: 0755, After: &ref}}}
	badPropose := propose
	badPropose.BaseGeneration = 0
	get := api.ChangeGetRequest{ChangeID: "change-one"}
	badGet := get
	badGet.ChangeID = "bad/id"
	approve := api.ChangeApproveRequest{ChangeID: get.ChangeID, ManifestSHA256: ref.SHA256, BaseGeneration: 7}
	badApprove := approve
	badApprove.BaseGeneration = 0
	apply := api.ChangeApplyRequest{ChangeID: get.ChangeID, ApprovalID: "approval-one", ExpectedGeneration: 7}
	badApply := apply
	badApply.ExpectedGeneration = 0
	for _, row := range []struct {
		name           string
		valid, invalid any
		message        string
	}{
		{"propose", propose, badPropose, "proposal requires org, current base and retained reason"},
		{"get", get, badGet, "a valid change ID is required"},
		{"approve", approve, badApprove, "approval requires change ID, exact manifest and base"},
		{"apply", apply, badApply, "application requires change ID, approval ID and base"},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, sample := range []struct {
				name string
				body any
			}{{"invalid", row.invalid}, {"valid", row.valid}} {
				t.Run(sample.name, func(t *testing.T) {
					directory := approvalPrivateDir(t)
					requestFile := filepath.Join(directory, "request.json")
					approvalWriteJSON(t, requestFile, sample.body)
					args := []string{"org", "change", row.name, "--config", approvalTestConfig(),
						"--request", requestFile, "--binding", filepath.Join(directory, "missing-binding.json")}
					if sample.name == "invalid" {
						// Any proof, metadata or binding work would produce a
						// different error before the owning semantic refusal.
						args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"),
							"--request-id", "short", "--idempotency-key", "short")
						failure := assertCLIInvalid(t, args)
						if failure.Message != row.message {
							t.Fatalf("common approval file did not reach its semantic validator: %s", failure.Message)
						}
						return
					}
					args = append(args, "--request-id", strings.Repeat("r", 32),
						"--idempotency-key", strings.Repeat("k", 32))
					if row.name == "approve" {
						raw, err := os.ReadFile(requestFile)
						if err != nil {
							t.Fatal(err)
						}
						intent, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
							Config: approvalTestConfig(), Method: "org.change.approve", Params: raw})
						if err != nil {
							t.Fatal(err)
						}
						proofFile := filepath.Join(directory, "proof.json")
						approvalWriteJSON(t, proofFile, api.ProofRef{ID: "fixture-proof", RequestSHA256: intent,
							ExpiresAt: api.Timestamp(time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano))})
						args = append(args, "--proof", proofFile)
					}
					var stdout, stderr bytes.Buffer
					exit := cli.Run(args, strings.NewReader(""), &stdout, &stderr)
					var failure api.Error
					if err := json.Unmarshal(stderr.Bytes(), &failure); err != nil {
						t.Fatalf("valid file transport refusal was not typed JSON: %v", err)
					}
					if exit != 69 || stdout.Len() != 0 || failure.Owner == "lb-v2-approval" || failure.Code == api.CodeInvalid {
						t.Fatalf("valid approval file did not reach transport: exit=%d code=%s owner=%s", exit, failure.Code, failure.Owner)
					}
					// An isolated port may be unimplemented; the composed client
					// must reject this deliberately absent protected binding.
					switch failure.Code {
					case api.CodeNotImplemented, api.CodePrerequisite:
					default:
						t.Fatalf("valid file reached an unexpected boundary: %s", failure.Code)
					}
				})
			}
		})
	}
}

func approvalWriteJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
