package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type shortEffectJournal struct{}

func (shortEffectJournal) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestHelperReasonInDeferredJournal(t *testing.T) {
	private := string(fixtureID(t))
	cause := api.WithHelperReason(&api.Error{Code: api.CodeContainmentUnknown, Message: private, Owner: private}, "storage_parent")
	var journal bytes.Buffer
	if err := (&effectAttempt{kind: "PlanLaunch"}).writeTo(&journal, "deferred", "run_"+effectReason(cause)); err != nil {
		t.Fatal(err)
	}
	var entry map[string]string
	if json.Unmarshal(journal.Bytes(), &entry) != nil || entry["reason"] != "run_containment_unknown_"+"dependency_storage_parent" || bytes.Contains(journal.Bytes(), []byte(private)) {
		t.Fatal("deferred effect lost the helper check or exposed a value")
	}
	attempt := &effectAttempt{kind: "PlanLaunch"}
	ctx := api.WithHelperReasonObserver(context.Background(), attempt.observeHelperReason)
	// A missing prior data job is a normal helper query result which planning
	// can recover from. Its check must not label a later, different refusal.
	missing := &api.Error{Code: api.CodeNotFound, Owner: "lb-v2-admin", Message: private}
	api.ObserveHelperReason(ctx, missing, "operation")
	api.ObserveHelperReason(ctx, cause, "storage_parent")
	api.ObserveHelperReason(ctx, cause, "launch_sources")
	api.ObserveHelperReason(ctx, cause, private)
	var original *api.Error
	if !errors.As(cause, &original) || attempt.errorReason(original) != "containment_unknown_"+"dependency_storage_parent" {
		t.Fatal("helper check disappeared when lifecycle normalized the typed refusal")
	}
	copy := *original
	copy.Retryable = true
	if attempt.errorReason(&copy) != "containment_unknown_"+"dependency_storage_parent" || attempt.errorReason(missing) != "not_found_admin_operation" ||
		attempt.errorReason(&api.Error{Code: api.CodeConflict}) != "conflict_dependency" {
		t.Fatal("helper check crossed an unrelated refusal or disappeared on retryability normalization")
	}
	terminal := &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-admin"}
	if terminalPlanRefusal(terminal) != terminal || !transientPlanAttempt(original) {
		t.Fatal("helper journaling changed the refusal decision")
	}
}

func TestEffectJournalContainsOnlyFixedWords(t *testing.T) {
	private := string(fixtureID(t))
	for _, code := range []api.ErrorCode{api.CodeNotImplemented, api.ErrorCode(private)} {
		cause := &api.Error{Code: code, Message: private, Instead: private, Owner: private, OperationID: api.ID(private)}
		effect := api.Effect{ID: api.ID(private), OperationID: api.ID(private), PlanLaunch: &api.LaunchPlanEffect{ReservationID: api.ID(private)}}
		attempt := effectAttempt{kind: effectKind(effect)}
		var journal bytes.Buffer
		if err := attempt.writeTo(&journal, "deferred", "run_"+effectReason(cause)); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(journal.Bytes(), []byte(private)) || bytes.Count(journal.Bytes(), []byte{'\n'}) != 1 {
			t.Fatal("effect journal exposed a value or broke its single-line record")
		}
		var entry map[string]string
		if err := json.Unmarshal(journal.Bytes(), &entry); err != nil || len(entry) != 4 || entry["event"] != "effect_attempt" || entry["kind"] != "PlanLaunch" || entry["outcome"] != "deferred" {
			t.Fatal("effect journal lost its bounded fields", err)
		}
		want := "run_not_implemented"
		if code != api.CodeNotImplemented {
			want = "run_dependency_failure"
		}
		if entry["reason"] != want {
			t.Fatal("effect journal did not classify the actual reason")
		}
	}
	if err := (&effectAttempt{kind: "PlanLaunch"}).writeTo(shortEffectJournal{}, "started", "claim"); err == nil {
		t.Fatal("short effect journal write was accepted")
	}
}

func TestPlanAttemptFailureClassification(t *testing.T) {
	integrity := serviceError(api.CodeIntegrity, "component immutable bytes changed")
	transient := serviceError(api.CodeUnavailable, "component port unavailable")
	for _, cause := range []error{integrity, errors.Join(transient, integrity), fmt.Errorf("component wrapped: %w", errors.Join(context.Canceled, integrity))} {
		if transientPlanAttempt(cause) || terminalPlanRefusal(cause) != nil {
			t.Fatal("plan attempt classification hid an integrity failure")
		}
	}
	if !transientPlanAttempt(transient) || !transientPlanAttempt(context.DeadlineExceeded) {
		t.Fatal("plan attempt lost its transient claim-recovery path")
	}
	refusal := api.NotImplemented("lb-v2-grants", "component required port")
	if transientPlanAttempt(refusal) || terminalPlanRefusal(refusal) != refusal || terminalPlanRefusal(errors.Join(refusal, integrity)) != nil {
		t.Fatal("missing port became retryable or hid a joined failure")
	}
}

func TestEffectJournalRefusingComponent(t *testing.T) {
	private := string(fixtureID(t))
	original := &api.Error{Code: api.CodeUnauthenticated, Owner: private, Message: private, Instead: private, OperationID: api.ID(private)}
	for _, row := range []struct{ component, want string }{
		{"store_read_view", "unauthenticated_store_read_view"},
		{"lifecycle_authorize", "unauthenticated_lifecycle_authorize"},
		{private, "unauthenticated_dependency"},
	} {
		cause := api.WithErrorComponent(original, row.component)
		if effectReason(cause) != row.want || api.ErrorComponent(original) != "dependency" {
			t.Fatal("refusal component was lost or mutated its shared cause")
		}
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(cause)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("private diagnostic changed the public error envelope", err)
		}
		var journal bytes.Buffer
		attempt := effectAttempt{kind: "PlanLaunch"}
		if err := attempt.writeTo(&journal, "fault", "run_"+effectReason(cause)); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(journal.Bytes(), []byte(private)) {
			t.Fatal("refusal component journal exposed an arbitrary value")
		}
	}
}

func TestPlanningMissingComponentJournal(t *testing.T) {
	private := string(fixtureID(t))
	for _, row := range []struct{ component, want string }{
		{"store_read_view", "not_found_store_read_view"},
		{private, "not_found_dependency"},
	} {
		original := &api.Error{Code: api.CodeNotFound, Owner: private, Message: private, OperationID: api.ID(private)}
		cause := api.WithErrorComponent(original, row.component)
		attempt := effectAttempt{kind: "PlanLaunch"}
		attempt.completed(api.EffectOutcome{Status: "failed", Error: cause})
		var journal bytes.Buffer
		if err := attempt.writeTo(&journal, attempt.outcome, attempt.reason); err != nil {
			t.Fatal(err)
		}
		var entry map[string]string
		if json.Unmarshal(journal.Bytes(), &entry) != nil || entry["reason"] != "run_"+row.want || bytes.Contains(journal.Bytes(), []byte(private)) {
			t.Fatal("planning not_found lost its fixed component or exposed a private value")
		}
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(cause)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("planning diagnostic changed the public error", err)
		}
	}
}
