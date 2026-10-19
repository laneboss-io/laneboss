package boxgcp

import (
	"strings"
	"testing"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/boxcore"
)

// TestClassify rejects missing error patterns, wrong precedence and unsafe details.
func TestClassify(t *testing.T) {
	cases := []struct {
		name, text, code string
		kind             boxcore.ErrorKind
	}{
		{"capacity-code", "zone_resource_pool_exhausted", "ZONE_RESOURCE_POOL_EXHAUSTED", boxcore.KindCapacity},
		{"capacity-text", "does not have enough resources available", "", boxcore.KindCapacity},
		{"unavailable", "is currently unavailable in the zone", "", boxcore.KindCapacity},
		{"quota-code", "QUOTA_EXCEEDED", "QUOTA_EXCEEDED", boxcore.KindQuota},
		{"quota-text", "Quota 'demo limit' exceeded", "", boxcore.KindQuota},
		{"denied-code", "permission_denied", "PERMISSION_DENIED", boxcore.KindDenied},
		{"required", "Required 'demo' permission", "", boxcore.KindDenied},
		{"permission", "does not have permission", "", boxcore.KindDenied},
		{"http-denied", "HTTPError 403", "", boxcore.KindDenied},
		{"impersonation", "Failed to impersonate", "", boxcore.KindDenied},
		{"token", "iam.serviceAccounts.getAccessToken", "", boxcore.KindDenied},
		{"scopes", "insufficient authentication scopes", "", boxcore.KindDenied},
		{"gone-text", "box was not found", "", boxcore.KindNotFound},
		{"gone-http", "HTTPError 404", "", boxcore.KindNotFound},
		{"gone-code", "notFound", "", boxcore.KindNotFound},
		{"unknown", "demo failure", "", boxcore.KindOther},
		{"capacity-first", "PERMISSION_DENIED QUOTA_EXCEEDED " + "ZONE_RESOURCE_POOL_EXHAUSTED", "ZONE_RESOURCE_POOL_EXHAUSTED", boxcore.KindCapacity},
		{"quota-first", "PERMISSION_DENIED Quota 'demo' exceeded", "PERMISSION_DENIED", boxcore.KindQuota},
		{"denied-first", "notFound Failed to impersonate", "", boxcore.KindDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify("probe", tc.text)
			if got.Kind != tc.kind || got.Code != tc.code || got.Op != "probe" || got.Detail != tc.text {
				t.Fatal("classification, code, operation or stderr-only detail is wrong")
			}
			if strings.Contains(got.Detail, "gcloud compute") {
				t.Fatal("detail includes argv that was not in stderr")
			}
		})
	}
	got := classify("probe", " \nline one\nline two\r ")
	if got.Detail != "line one line two" {
		t.Fatal("detail was not trimmed and flattened")
	}
	got = classify("probe", strings.Repeat("界", 301))
	if utf8.RuneCountInString(got.Detail) != 300 || !utf8.ValidString(got.Detail) {
		t.Fatal("detail limit is not 300 complete characters")
	}
}
