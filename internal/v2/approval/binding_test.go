package approval

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func testApproval(change api.ChangeRequest) api.ChangeApproval {
	return api.ChangeApproval{ID: "approval-one", ChangeID: change.ID,
		RequesterLifeID: change.Requester.LifeID, ApproverKeyID: "key-one", NonceID: "nonce-one",
		ManifestSHA256: change.ManifestSHA256, BaseGeneration: change.BaseGeneration,
		ApprovedAt: "2026-10-15T09:00:00Z", ExpiresAt: "2026-10-15T09:10:00Z"}
}

func rehash(t *testing.T, change *api.ChangeRequest) {
	t.Helper()
	var err error
	change.ManifestSHA256, err = ManifestDigest(*change)
	if err != nil {
		t.Fatal(err)
	}
}

func withDerived(t *testing.T) api.ChangeRequest {
	t.Helper()
	f := newFixture(t)
	change, err := cloneChange(f.store.change)
	if err != nil {
		t.Fatal(err)
	}
	ref := testRef("derived-one", []byte("generated settings\n"))
	change.Derived = []api.ResourceDelta{{Path: "generated/settings.txt", Action: "add", Mode: 0644, After: &ref}}
	rehash(t, &change)
	return change
}

func TestRenderedBinding(t *testing.T) {
	staged := withDerived(t)
	input, err := cloneChange(staged)
	if err != nil {
		t.Fatal(err)
	}
	input.Derived = []api.ResourceDelta{}
	input.ManifestSHA256 = ""
	input.Diff = api.BlobRef{}
	if err := ValidateRenderedChange(input, staged); err != nil {
		t.Fatalf("first render could not retain computed outputs: %v", err)
	}
	for name, edit := range map[string]func(*api.ChangeRequest){
		"identity": func(c *api.ChangeRequest) { c.ID = "different-change" },
		"org": func(c *api.ChangeRequest) {
			c.OrgID = "different-org"
			c.SourceSnapshot.OrgID = c.OrgID
		},
		"requester": func(c *api.ChangeRequest) { c.Requester.LifeID = "different-life" },
		"base": func(c *api.ChangeRequest) {
			c.BaseGeneration++
			c.SourceSnapshot.Generation = c.BaseGeneration
		},
		"created":  func(c *api.ChangeRequest) { c.CreatedAt = "2026-10-15T08:00:01Z" },
		"expires":  func(c *api.ChangeRequest) { c.ExpiresAt = "2026-10-16T07:59:59Z" },
		"status":   func(c *api.ChangeRequest) { c.Status = "approved" },
		"renderer": func(c *api.ChangeRequest) { c.Renderer.SHA256 = testDigest([]byte("another executable")) },
		"sources":  func(c *api.ChangeRequest) { c.Files[0].Mode = 0600 },
		"config":   func(c *api.ChangeRequest) { c.Config = "other-config" },
		"reason":   func(c *api.ChangeRequest) { c.Reason = testRef("other-reason", []byte("another reason")) },
		"snapshot": func(c *api.ChangeRequest) { c.SourceSnapshot.ManifestSHA256 = testDigest([]byte("other inventory")) },
		"ownership": func(c *api.ChangeRequest) {
			c.OwnershipManifest = testClassRef("other-owner", []byte("another ownership"), "manifest")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, err := cloneChange(staged)
			if err != nil {
				t.Fatal(err)
			}
			edit(&candidate)
			rehash(t, &candidate)
			codeIs(t, ValidateRenderedChange(input, candidate), api.CodeIntegrity)
		})
	}
}

func TestRevalidationEffects(t *testing.T) {
	staged := withDerived(t)
	staged.Derived[0].Action = "replace"
	staged.Derived[0].BeforeSHA256 = testDigest([]byte("previous settings\n"))
	rehash(t, &staged)
	freshRender := func() api.ChangeRequest {
		candidate, err := cloneChange(staged)
		if err != nil {
			t.Fatal(err)
		}
		candidate.Derived[0].After.ID = "fresh-derived"
		candidate.Diff.ID = "fresh-diff"
		rehash(t, &candidate)
		return candidate
	}
	t.Run("fresh_ids", func(t *testing.T) {
		candidate := freshRender()
		if candidate.ManifestSHA256 == staged.ManifestSHA256 ||
			candidate.Derived[0].After.ID == staged.Derived[0].After.ID || candidate.Diff.ID == staged.Diff.ID {
			t.Fatal("fresh-reference fixture did not change its retained identities")
		}
		if err := ValidateRevalidation(staged, candidate); err != nil {
			t.Fatalf("byte-identical fresh IDs were refused: %v", err)
		}
	})
	for name, edit := range map[string]func(*api.ChangeRequest){
		"extra": func(c *api.ChangeRequest) {
			ref := testRef("extra-output", []byte("unreviewed note\n"))
			c.Derived = append(c.Derived, api.ResourceDelta{Path: "generated/unreviewed.txt", Action: "add", Mode: 0644, After: &ref})
		},
		"bytes": func(c *api.ChangeRequest) {
			ref := testRef("changed-output", []byte("different generated settings\n"))
			c.Derived[0].After = &ref
		},
		"path":   func(c *api.ChangeRequest) { c.Derived[0].Path = "generated/renamed.txt" },
		"mode":   func(c *api.ChangeRequest) { c.Derived[0].Mode = 0755 },
		"before": func(c *api.ChangeRequest) { c.Derived[0].BeforeSHA256 = testDigest([]byte("another preimage")) },
		"action": func(c *api.ChangeRequest) {
			c.Derived[0].Action, c.Derived[0].After = "delete", nil
		},
		"after_size":  func(c *api.ChangeRequest) { c.Derived[0].After.Bytes++ },
		"after_class": func(c *api.ChangeRequest) { c.Derived[0].After.Class = "report" },
		"diff":        func(c *api.ChangeRequest) { c.Diff = testRef("changed-diff", []byte("different review text\n")) },
		"diff_size":   func(c *api.ChangeRequest) { c.Diff.Bytes++ },
		"diff_class":  func(c *api.ChangeRequest) { c.Diff.Class = "report" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := freshRender()
			edit(&candidate)
			rehash(t, &candidate)
			codeIs(t, ValidateRevalidation(staged, candidate), api.CodeConflict)
		})
	}
	t.Run("hidden_hash", func(t *testing.T) {
		candidate := freshRender()
		candidate.Derived[0].Mode = 0755
		codeIs(t, ValidateRevalidation(staged, candidate), api.CodeIntegrity)
	})
}

func TestApprovalBinding(t *testing.T) {
	change := withDerived(t)
	approval := testApproval(change)
	now := time.Date(2026, 10, 15, 9, 1, 0, 0, time.UTC)
	if err := ValidateApprovalBinding(now, change, approval); err != nil {
		t.Fatalf("matching receipt metadata refused: %v", err)
	}
	for name, edit := range map[string]func(*api.ChangeApproval){
		"change":    func(a *api.ChangeApproval) { a.ChangeID = "other-change" },
		"requester": func(a *api.ChangeApproval) { a.RequesterLifeID = "other-life" },
		"hash":      func(a *api.ChangeApproval) { a.ManifestSHA256 = testDigest([]byte("unreviewed manifest")) },
		"base":      func(a *api.ChangeApproval) { a.BaseGeneration++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := approval
			edit(&candidate)
			codeIs(t, ValidateApprovalBinding(now, change, candidate), api.CodeConflict)
		})
	}
	t.Run("expired", func(t *testing.T) {
		expired := now.Add(9 * time.Minute)
		codeIs(t, ValidateApprovalBinding(expired, change, approval), api.CodeForbidden)
	})
	t.Run("future", func(t *testing.T) {
		before := now.Add(-2 * time.Minute)
		codeIs(t, ValidateApprovalBinding(before, change, approval), api.CodeForbidden)
	})
	t.Run("outlives_stage", func(t *testing.T) {
		candidate := change
		candidate.ExpiresAt = "2026-10-15T09:05:00Z"
		codeIs(t, ValidateApprovalBinding(now, candidate, approval), api.CodeIntegrity)
	})
	t.Run("before_stage", func(t *testing.T) {
		candidate := change
		candidate.CreatedAt = "2026-10-15T09:00:30Z"
		codeIs(t, ValidateApprovalBinding(now, candidate, approval), api.CodeIntegrity)
	})
	t.Run("missing_clock", func(t *testing.T) {
		codeIs(t, ValidateApprovalBinding(time.Time{}, change, approval), api.CodeInvalid)
	})
}

func TestPolicyHumanRequired(t *testing.T) {
	for _, name := range []string{"lane", "missing", "wrong_intent"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.store.change.Files[0].Path = "shared/config/approval-policy.toml"
			rehash(t, &f.store.change)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID,
				ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: f.store.change.BaseGeneration}
			scope := f.bound("org.change.approve", request, true)
			switch name {
			case "lane":
				scope.Actor, scope.LaunchID = f.scope.Actor, f.scope.LaunchID
			case "missing":
				scope.Request.Proof = nil
			case "wrong_intent":
				scope.Request.Proof.RequestSHA256 = testDigest([]byte("previous policy approval"))
			}
			_, err := f.service.OrgChangeApprove(context.Background(), scope, request)
			codeIs(t, err, api.CodeForbidden)
			f.noEffects()
		})
	}
}
