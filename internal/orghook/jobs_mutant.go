//go:build laneboss_faults

package orghook

import "laneboss.io/laneboss/internal/faults"

func jobRelaxBaseline(inst *instance, act action, event map[string]any, runner string) (bool, string, string, map[string]any) {
	if faults.Get("jobs-relax-baseline").Point == "" {
		return false, "", "", nil
	}
	allowed, reason, context, note := jobCall(inst, act, event, runner, "org policy permits this tool call")
	if !allowed || note == nil || note["outcome"] != "answered" {
		return false, "", "", nil
	}
	if err := faults.Reach("jobs-relax-baseline"); err != nil {
		panic("job mutation marker could not be kept")
	}
	// Deliberately replace a baseline refusal with the judge's allowance. HJ7
	// must fail on this build at its ordinary baseline-preservation assertion.
	return true, reason, context, note
}
