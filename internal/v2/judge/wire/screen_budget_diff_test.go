package wire

import (
	"encoding/json"
	"strings"
	"testing"
)

// Nine component-boundary comparisons complement the full-request corpus:
// view capacity, remaining shared work, and remaining assignment inspection.
func TestScreenBudgetDifferential(t *testing.T) {
	count := 0
	output := screenLedger(t, "budget-edges")
	record := func(kind, text string, remaining int, hit, capped bool) {
		if output == nil {
			return
		}
		row := struct {
			Kind      string `json:"kind"`
			Text      []byte `json:"text"`
			Remaining int    `json:"remaining"`
			Withheld  bool   `json:"withheld"`
			Capped    bool   `json:"capped"`
		}{kind, []byte(text), remaining, hit, capped}
		if err := json.NewEncoder(output).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	for _, delta := range []int{-1, 0, 1} {
		text := strings.Repeat("q", ScreenWindowBytes+delta)
		if fix1Sensitive(text, "") {
			t.Fatal("view control is not benign")
		}
		s := newScreen("")
		hit := s.appendBytes(&s.views[0], text) || s.finish()
		record("view", text, ScreenWindowBytes, hit, s.exhausted)
		if hit != (delta > 0) || hit != s.exhausted {
			t.Fatal("view cap differential changed")
		}
		count++

		text = "ordinary project data"
		if fix1Sensitive(text, "") {
			t.Fatal("work control is not benign")
		}
		s = newScreen("")
		if !s.spend(MaxScreenWorkBytes - len(text) - delta) {
			t.Fatal("work edge setup failed")
		}
		hit = s.text(text)
		record("work", text, len(text)+delta, hit, s.exhausted)
		if hit != (delta < 0) || hit != s.exhausted {
			t.Fatal("work cap differential changed")
		}
		count++

		text = "token=redacted "
		if fix1SecretText(text) {
			t.Fatal("assignment control is not benign")
		}
		limit := maxAssignmentWorkFactor*len(text) + 32
		measured := &assignmentWork{left: limit}
		if visitAssignments(text, literalValue, measured) || measured.capped {
			t.Fatal("assignment edge setup failed")
		}
		spent := limit - measured.left
		if spent < 1 {
			t.Fatal("assignment work was not charged")
		}
		w := &assignmentWork{left: spent + delta}
		hit = visitAssignments(text, literalValue, w)
		record("assignment", text, spent+delta, hit, w.capped)
		if hit != (delta < 0) || hit != w.capped {
			t.Fatal("assignment cap differential changed")
		}
		count++
	}
	if count != 9 {
		t.Fatal("budget edge coverage changed")
	}
	t.Logf("component differential cases=%d", count)
}

func TestAssignmentOverlapBudget(t *testing.T) {
	output := screenLedger(t, "overlap")
	text := strings.Repeat("token=call(", 500) + "redacted"
	if fix1SecretText(text) {
		t.Fatal("nested code reference is not benign")
	}
	spent := 0
	hit, capped := screenText(text, func(n int) bool { spent += n; return true })
	if output != nil {
		if err := json.NewEncoder(output).Encode(map[string]any{"text": []byte(text), "spent": spent, "withheld": hit, "capped": capped}); err != nil {
			t.Fatal(err)
		}
	}
	if !hit || !capped || spent > maxAssignmentWorkFactor*len(text)+32 {
		t.Fatal("overlap exceeded linear work bound")
	}
	if secretText(strings.Repeat("token=redacted ", 500)) {
		t.Fatal("disjoint reference was withheld")
	}
}
