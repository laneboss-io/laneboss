package grants_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestCLIRejectsAmbiguousInput(t *testing.T) {
	for _, arguments := range [][]string{
		{"grants", "get"},
		{"grants", "get", "--config", "case-grants"},
		{"grants", "get", "--config", "case-grants", "--request", "a", "--request", "b"},
		{"grants", "get", "--config", "case-grants", "--state", "anything"},
	} {
		var stdout, stderr bytes.Buffer
		code := cli.Run(arguments, bytes.NewReader(nil), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 {
			t.Fatal("invalid CLI input produced success")
		}
		var typed api.Error
		if err := json.Unmarshal(stderr.Bytes(), &typed); err != nil || typed.Code != api.CodeInvalid {
			t.Fatal("CLI lost the typed error", err)
		}
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "request.json")
	input := []byte(`{"grant_set_id":"x","grant_set_id":"y"}`)
	if err := os.WriteFile(file, input, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"grants", "get", "--config", "case-grants", "--request", file},
		bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 {
		t.Fatal("duplicate JSON key was not rejected locally")
	}
	actual, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(input, actual) {
		t.Fatal("CLI altered its exact input bytes", err)
	}
}

func TestCLIFileValidators(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	config := os.Getenv("LANEBOSS_CONFIG")
	if config == "" {
		config = "case-grants"
	}
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "manifest", SHA256: manifest.Hash([]byte("input")), Bytes: 5, Class: "manifest"}
	budget := api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 2, DiskBytes: 8192, Currency: "USD"}
	root := api.RootGrantRequest{Manifest: ref, Budget: budget}
	badRoot := root
	badRoot.Manifest.Class = "artifact"
	enrollment := api.CapabilityEnrollmentRequest{Resource: &api.ResourceEnrollment{Provider: "gcp", Regions: []string{"region-a"},
		ImageIDs: []string{"image-a"}, MachineTypes: []string{"small"}, MaxActive: 1, ExpiresAt: "2099-01-01T00:00:00Z"}}
	validate := api.GrantValidateRequest{ParentLifeID: "parent", ChildLevel: 3, ExpectedPolicyGeneration: 1,
		Requested: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{},
			Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	badValidate := validate
	badValidate.Requested.Data = []api.DataGrantRequest{{ParentGrantID: "data", RelativePath: "../private",
		Access: "ro", Delivery: "copy", Destination: "/work/main", ExpiresAt: "2099-01-01T00:00:00Z"}}
	revoke := api.GrantRevokeRequest{GrantSetID: "child-set", ExpectedGeneration: 1, Reason: ref}
	revoke.Reason.Class = "report"
	badRevoke := revoke
	badRevoke.ExpectedGeneration = 0
	child := api.TestChildRequest{Child: api.LifeRef{LifeID: "child", Run: 1}, Candidate: ref, TestPlan: ref, Budget: budget}
	child.Candidate.ID, child.TestPlan.ID = "candidate", "test-plan"
	badChild := child
	badChild.Child.Run = 0
	for _, item := range []struct {
		name           string
		valid, invalid any
	}{
		{"root", root, badRoot},
		{"enroll", enrollment, api.CapabilityEnrollmentRequest{}},
		{"validate", validate, badValidate},
		{"get", api.GrantGetRequest{GrantSetID: "child-set"}, api.GrantGetRequest{GrantSetID: ""}},
		{"revoke", revoke, badRevoke},
		{"test-child", child, badChild},
	} {
		t.Run(item.name, func(t *testing.T) {
			for _, form := range []string{"request", "positional"} {
				t.Run(form, func(t *testing.T) {
					for _, valid := range []bool{false, true} {
						name, body := "invalid", item.invalid
						if valid {
							name, body = "valid", item.valid
						}
						t.Run(name, func(t *testing.T) {
							raw, err := json.Marshal(body)
							if err != nil {
								t.Fatal(err)
							}
							file := filepath.Join(directory, item.name+"-"+form+"-"+name+".json")
							if err := os.WriteFile(file, raw, 0600); err != nil {
								t.Fatal(err)
							}
							args := []string{"grants", item.name, "--config", config,
								"--binding", filepath.Join(directory, "missing-binding.json")}
							if form == "request" {
								args = append(args, "--request", file)
							} else {
								args = append(args, file)
							}
							if valid {
								args = append(args, "--request-id", string(requestID), "--idempotency-key", string(key))
							} else {
								// Semantic refusal must precede a proof read, missing
								// mutation key, invalid request ID and binding lookup.
								args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"), "--request-id", "bad")
							}
							var stdout, stderr bytes.Buffer
							code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
							var typed api.Error
							if err := json.Unmarshal(stderr.Bytes(), &typed); err != nil {
								t.Fatal("CLI did not return a typed error", err)
							}
							if !valid {
								if code != 2 || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-grants" || stdout.Len() != 0 {
									t.Fatalf("grant file validator boundary failed: invalid input: exit=%d code=%s owner=%s", code, typed.Code, typed.Owner)
								}
							} else {
								// Both the isolated client stub and the combined real
								// client must get beyond this feature's validator.
								transport := typed.Code == api.CodeNotImplemented || typed.Code == api.CodePrerequisite || typed.Code == api.CodeUnavailable
								if code != 69 || typed.Owner == "lb-v2-grants" || typed.Code == api.CodeInvalid || !transport || stdout.Len() != 0 {
									t.Fatalf("grant file validator boundary failed: valid input: exit=%d code=%s owner=%s", code, typed.Code, typed.Owner)
								}
							}
							actual, err := os.ReadFile(file)
							if err != nil || !bytes.Equal(raw, actual) {
								t.Fatal("CLI altered its exact request bytes", err)
							}
						})
					}
				})
			}
		})
	}
}
