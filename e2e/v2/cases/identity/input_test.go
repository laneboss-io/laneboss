package identitycase

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

func TestCLIFileValidationFixture(t *testing.T) {
	challenge := api.HumanChallengeRequest{Method: "ticket.issue", TargetID: "root",
		RequestSHA256: api.Digest(strings.Repeat("a", 64)), BaseGeneration: 1}
	badChallenge := challenge
	badChallenge.Method = "health"
	confirm := api.HumanConfirmRequest{ChallengeID: "challenge", CredentialID: "credential", ClientDataJSON: []byte("{}"),
		AuthenticatorData: make([]byte, 37), Signature: []byte{1}}
	badConfirm := confirm
	badConfirm.AuthenticatorData = make([]byte, 36)
	ticket := api.TicketIssueRequest{Level: 6, Role: "supervisor", GrantSetID: "root-grants",
		ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
	badTicket := ticket
	badTicket.Level = 2
	for _, row := range []struct {
		name     string
		command  []string
		valid    any
		invalid  any
		semantic bool
	}{
		{"self", []string{"identity", "self"}, api.Empty{}, map[string]bool{"unexpected": true}, false},
		{"session", []string{"human", "session"}, api.HumanSessionRequest{}, map[string]bool{"unexpected": true}, false},
		{"challenge", []string{"human", "challenge"}, challenge, badChallenge, true},
		{"confirm", []string{"human", "confirm"}, confirm, badConfirm, true},
		{"ticket", []string{"ticket", "issue"}, ticket, badTicket, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			for _, phase := range []string{"invalid", "transport"} {
				t.Run(phase, func(t *testing.T) {
					directory := identityPrivateDir(t)
					input := row.valid
					if phase == "invalid" {
						input = row.invalid
					}
					raw, err := json.Marshal(input)
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(directory, "request.json")
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					args := append(append([]string{}, row.command...), "--config", "fixture", "--request", path,
						"--binding", filepath.Join(directory, "missing-binding.json"))
					if phase == "invalid" {
						// Both later inputs are deliberately absent: the body must
						// fail before proof loading, key preparation or transport.
						args = append(args, "--proof", filepath.Join(directory, "missing-proof.json"))
					} else {
						args = append(args, "--idempotency-key", strings.Repeat("k", 32))
					}
					var stdout, stderr bytes.Buffer
					code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr)
					var failure api.Error
					if stdout.Len() != 0 || json.Unmarshal(stderr.Bytes(), &failure) != nil {
						t.Fatal("fixture check: file preflight returned no typed refusal")
					}
					if phase == "invalid" {
						if code != 2 || failure.Code != api.CodeInvalid || row.semantic && failure.Owner != "lb-v2-identity" {
							t.Fatal("fixture check: invalid file bypassed identity preflight")
						}
						return
					}
					// An uninstalled binding stops the real client; the isolated
					// tree may instead stop at its still-unimplemented transport.
					// Neither outcome is an installed RPC success.
					accepted := failure.Code == api.CodePrerequisite || failure.Code == api.CodeNotImplemented
					if code != 69 || !accepted || failure.Owner == "lb-v2-identity" || failure.Code == api.CodeInvalid {
						t.Fatal("fixture check: valid file did not reach installed transport")
					}
				})
			}
		})
	}
}
