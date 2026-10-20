package dashboard

import (
	"encoding/json"
	"net/http"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Receipts and the verified human connection are component inputs. The real
// HTTP view and projection consume findings from the production generator;
// frozen-tree verification is exercised by the dataworker and store tests.
func TestDashReviewFindingsCoverage(t *testing.T) {
	for _, test := range []struct {
		name, coverage, path, kind string
	}{
		{"fake-complete", api.CoverageComplete, "internal/cache_test.go", "fake_only_diff"},
		{"fake-partial", api.CoveragePartial, "internal/cache_test.go", "fake_only_diff"},
		{"empty-complete", api.CoverageComplete, "", "empty_diff"},
		{"empty-partial", api.CoveragePartial, "", "empty_diff"},
		{"trusted-complete", api.CoverageComplete, "internal/cache.go", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, service := draft4Fixture(t)
			_, _, token := h.establishVerifiedScope(t, service, "cfg-dash")
			h.lanes["life-reviewed"] = api.Lane{LifeID: "life-reviewed", Level: 3, Run: 1}
			h.appendEvent(api.Event{Kind: "policy.evaluated", Origin: "service", LifeID: "life-reviewed", Run: 1,
				Payload: reviewJSON(t, api.PolicyDecision{ID: "coverage-policy", AuditComplete: true,
					Rules: []api.RuleDecision{{RuleID: "production-rule", Result: "warn"}}})})
			diff := reviewjob.Diff{Changes: []reviewjob.Change{}}
			if test.path != "" {
				diff.Changes = append(diff.Changes, reviewjob.Change{Path: test.path})
			}
			findings := reviewjob.DiffFindings(diff, []api.ReviewCheckFact{{Name: "unit", ExitCode: 0}})
			evidence := &api.ReviewEvidence{Coverage: test.coverage, Inventory: api.ReviewInventory{ToolCoverage: api.CoverageComplete},
				Findings: findings, Untrusted: len(findings) != 0}
			h.appendEvent(api.Event{Kind: "lane.reviewed", Origin: "service", LifeID: "life-reviewed", Run: 1,
				Payload: reviewJSON(t, api.ReviewReceipt{ID: "review-result", Coverage: test.coverage, Evidence: evidence})})
			response := reviewRead(t, service, token, "/api/v2/refusals?life_id=life-reviewed&run=1&limit=10")
			if response.Code != http.StatusOK {
				t.Fatalf("review coverage HTTP view failed: %d %s", response.Code, response.Body.String())
			}
			var view api.RefusalView
			if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			buckets := map[api.ID]api.RefusalCount{}
			for _, count := range view.Counts {
				buckets[count.RuleID] = count
			}
			policy, ok := buckets["production-rule"]
			if !ok || policy.UnknownCoverage != (test.kind != "") {
				t.Fatalf("review trust did not reach the coverage column: %+v", view.Counts)
			}
			if test.kind == "" {
				if len(view.Counts) != 1 {
					t.Fatalf("trusted production review acquired a warning: %+v", view.Counts)
				}
				return
			}
			finding, ok := buckets[api.ID(test.kind)]
			if !ok || finding.Warned != 1 || !finding.UnknownCoverage || finding.Refused != 0 || finding.Level != 3 {
				t.Fatalf("finding kind disappeared from the dashboard warning/coverage row: %+v", view.Counts)
			}
		})
	}
}
