package admin

import (
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Protocol time-boundary inputs; native removal and journal publication are
// separately covered by TestCleanupNative/measured on the disposable host.
func TestCleanupMeasured(t *testing.T) {
	for _, mode := range []string{"future", "malformed", "expired-at-result"} {
		t.Run(mode, func(t *testing.T) {
			original, current, journal := cleanupClaimFixture(t)
			result := *journal.Removal
			if err := validateMeasuredCleanup(original, result, time.Now()); err != nil {
				t.Fatalf("acceptance: measured cleanup incorrectly used publication time: %v", err)
			}
			now := time.Now()
			result.ClaimID = current.Claim.ClaimID
			switch mode {
			case "future":
				future := now.Add(time.Minute)
				result.After.ObservedAt = api.Timestamp(future.UTC().Format(time.RFC3339Nano))
				if err := api.ValidateWorkspaceRemoval(current, result, future); err != nil {
					t.Fatal("future fixture has a competing receipt refusal")
				}
			case "malformed":
				result.After.ObservedAt = "invalid"
			case "expired-at-result":
				current = original
				result.ClaimID = current.Claim.ClaimID
				result.After.ObservedAt = api.Timestamp(now.Add(-time.Second).UTC().Format(time.RFC3339Nano))
			}
			err := validateMeasuredCleanup(current, result, now)
			var typed *api.Error
			if err == nil || mode != "expired-at-result" && (!errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "cleanup result time is invalid or in the future") {
				t.Fatal("acceptance: measured cleanup accepted an unproven result time")
			}
		})
	}
}
