package approval

import (
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestProposeResult(t *testing.T) {
	f := newFixture(t)
	request := f.request
	result := f.store.change
	if err := ValidateProposeResult(request, result); err != nil {
		t.Fatalf("matching proposed result refused: %v", err)
	}
	for name, edit := range map[string]func(*api.ChangeRequest){
		"org": func(c *api.ChangeRequest) {
			c.OrgID = "other-org"
			c.SourceSnapshot.OrgID = c.OrgID
		},
		"base": func(c *api.ChangeRequest) {
			c.BaseGeneration++
			c.SourceSnapshot.Generation = c.BaseGeneration
		},
		"reason": func(c *api.ChangeRequest) { c.Reason = testRef("other-reason", []byte("another reason")) },
		"mode":   func(c *api.ChangeRequest) { c.Files[0].Mode = 0600 },
		"bytes": func(c *api.ChangeRequest) {
			ref := testRef("other-source", []byte("different source bytes\n"))
			c.Files[0].After = &ref
		},
		"extra": func(c *api.ChangeRequest) {
			ref := testRef("extra-source", []byte("additional source\n"))
			c.Files = append(c.Files, api.ResourceDelta{Path: "tools/unrequested.txt", Action: "add", Mode: 0644, After: &ref})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := cloneChange(result)
			if err != nil {
				t.Fatal(err)
			}
			edit(&candidate)
			rehash(t, &candidate)
			// Each changed result is internally hash-consistent; only its
			// relationship to the original request must reject it.
			if err := ValidateChange(candidate); err != nil {
				t.Fatalf("result fixture is not internally valid: %v", err)
			}
			codeIs(t, ValidateProposeResult(request, candidate), api.CodeIntegrity)
		})
	}
	before, err := cloneChange(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateProposeResult(request, result); err != nil || !reflect.DeepEqual(before, result) {
		t.Fatalf("result validation mutated a retained change: %v", err)
	}
}

func TestGetResult(t *testing.T) {
	f := newFixture(t)
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	if err := ValidateGetResult(request, f.store.change); err != nil {
		t.Fatalf("matching read result refused: %v", err)
	}
	candidate := f.store.change
	candidate.ID = "another-change"
	codeIs(t, ValidateGetResult(request, candidate), api.CodeIntegrity)
}

func TestApproveResult(t *testing.T) {
	f := newFixture(t)
	request := api.ChangeApproveRequest{ChangeID: f.store.change.ID,
		ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: f.store.change.BaseGeneration}
	result := testApproval(f.store.change)
	if err := ValidateApproveResult(request, result); err != nil {
		t.Fatalf("matching approval result refused: %v", err)
	}
	for name, edit := range map[string]func(*api.ChangeApproval){
		"change": func(a *api.ChangeApproval) { a.ChangeID = "other-change" },
		"hash":   func(a *api.ChangeApproval) { a.ManifestSHA256 = testDigest([]byte("other manifest")) },
		"base":   func(a *api.ChangeApproval) { a.BaseGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := result
			edit(&candidate)
			if err := ValidateApproval(candidate); err != nil {
				t.Fatalf("approval fixture is not internally valid: %v", err)
			}
			codeIs(t, ValidateApproveResult(request, candidate), api.CodeIntegrity)
		})
	}
}

func TestApplyResult(t *testing.T) {
	f := newFixture(t)
	request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
	result := api.ChangeReceipt{ID: "receipt-one", ChangeID: request.ChangeID, ApprovalID: request.ApprovalID,
		OldGeneration: 7, NewGeneration: 8, ManifestSHA256: f.store.change.ManifestSHA256,
		AppliedAt: "2026-10-15T09:01:00Z"}
	if err := ValidateApplyResult(request, result); err != nil {
		t.Fatalf("matching application result refused: %v", err)
	}
	for name, edit := range map[string]func(*api.ChangeReceipt){
		"change":   func(r *api.ChangeReceipt) { r.ChangeID = "other-change" },
		"approval": func(r *api.ChangeReceipt) { r.ApprovalID = "other-approval" },
		"base":     func(r *api.ChangeReceipt) { r.OldGeneration++; r.NewGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := result
			edit(&candidate)
			if err := ValidateReceipt(candidate); err != nil {
				t.Fatalf("receipt fixture is not internally valid: %v", err)
			}
			codeIs(t, ValidateApplyResult(request, candidate), api.CodeIntegrity)
		})
	}
}

func TestProofRef(t *testing.T) {
	intent := testDigest([]byte("approval intent"))
	proof := api.ProofRef{ID: "proof-one", RequestSHA256: intent, ExpiresAt: "2020-01-01T00:00:00Z"}
	// Shape validation must not claim freshness or invalidate completed replay.
	if err := ValidateProofRef(proof, intent); err != nil {
		t.Fatalf("canonical proof reference refused before server replay: %v", err)
	}
	for name, edit := range map[string]func(*api.ProofRef){
		"id":       func(p *api.ProofRef) { p.ID = "invalid/proof" },
		"intent":   func(p *api.ProofRef) { p.RequestSHA256 = testDigest([]byte("other intent")) },
		"time":     func(p *api.ProofRef) { p.ExpiresAt = "not-a-time" },
		"timezone": func(p *api.ProofRef) { p.ExpiresAt = "2020-01-01T00:00:00+00:00" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proof
			edit(&candidate)
			codeIs(t, ValidateProofRef(candidate, intent), api.CodeInvalid)
		})
	}
}
