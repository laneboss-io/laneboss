package service

import (
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type retainedStageFixture struct {
	error
	stage string
}

func (e retainedStageFixture) Unwrap() error               { return e.error }
func (e retainedStageFixture) RetainedLaunchStage() string { return e.stage }

func TestRetainedCaptureRetryStops(t *testing.T) {
	host := fixtureServer(t)
	now := host.deps.Clock.Now()
	retries := make(effectRetries)
	id, other := fixtureID(t), fixtureID(t)
	refusal := &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: string(fixtureID(t))}
	attempt := &effectAttempt{server: host, kind: "PlanLaunch"}
	attempt.observeHelperReason(refusal, "capture_retained_failure")
	retained := retainedStageFixture{error: refusal, stage: "capture"}
	if result := attempt.deferEffect("run", retained, id, retries); result != attemptNext {
		t.Fatal("retained capture failure stopped unrelated reconciliation")
	}
	if retries.ready(id, now.Add(24*time.Hour)) || !retries.ready(other, now) || host.fault != nil {
		t.Fatal("immutable capture failure remained in an automatic retry loop")
	}
	if attempt.outcome != "held" {
		t.Fatal("stopped capture replay was journaled as a progressing wait")
	}
	transient := &api.Error{Code: api.CodeUnavailable, Retryable: true, Message: string(fixtureID(t))}
	ordinary := &effectAttempt{server: host, kind: "PlanLaunch"}
	if result := ordinary.deferEffect("run", transient, other, retries); result != attemptNext || retries.ready(other, now) || !retries.ready(other, now.Add(time.Minute)) {
		t.Fatal("ordinary transient refusal lost its bounded retry path")
	}
	for _, cause := range []error{refusal, retainedStageFixture{error: refusal, stage: "runner"}, errors.Join(retained, serviceError(api.CodeIntegrity, "actual mixed failure"))} {
		attempt := &effectAttempt{server: host, kind: "PlanLaunch"}
		attempt.deferEffect("run", cause, other, retries)
		if !retries.ready(other, now.Add(24*time.Hour)) || attempt.outcome == "held" {
			t.Fatal("capture hold crossed an ordinary, foreign-stage or mixed failure")
		}
	}
}
