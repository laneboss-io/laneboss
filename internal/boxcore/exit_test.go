package boxcore

import "testing"

func TestExitName(t *testing.T) {
	cases := []struct {
		code int
		num  int
		name string
	}{
		{ExitOK, 0, "ok"},
		{ExitFailed, 1, "failed"},
		{ExitUsage, 2, "usage"},
		{ExitNoCandidate, 3, "no-candidate"},
		{ExitNotRecorded, 4, "not-recorded"},
		{ExitNotRegistered, 5, "not-registered"},
		{ExitDryDenied, 6, "dry-denied"},
		{ExitDryUnexpected, 7, "dry-unexpected"},
		{ExitAccess, 10, "access"},
		{ExitHarvest, 11, "harvest"},
		{ExitPreempted, 12, "preempted"},
		{ExitTimeout, 13, "timeout"},
		{ExitCostCap, 14, "cost-cap"},
		{ExitEndPending, 15, "end-pending"},
		{ExitInternal, 70, "internal"},
	}
	seen := make(map[int]bool)
	for _, tc := range cases {
		if seen[tc.code] {
			t.Fatalf("duplicate exit constant %d", tc.code)
		}
		seen[tc.code] = true
		t.Run(tc.name, func(t *testing.T) {
			if tc.code != tc.num {
				t.Fatalf("exit code = %d, want %d", tc.code, tc.num)
			}
			if got := ExitName(tc.code); got != tc.name {
				t.Fatalf("ExitName = %q, want %q", got, tc.name)
			}
		})
	}
	t.Run("unknown", func(t *testing.T) {
		if got := ExitName(99); got != "unknown" {
			t.Fatalf("ExitName(99) = %q", got)
		}
	})
}
