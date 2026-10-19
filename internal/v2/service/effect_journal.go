package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type effectAttempt struct {
	server          *Server
	kind            string
	outcome, reason string
	// detail: the error's fixed message (owner R191-R192 usable-by-noon diagnosis; review after noon).
	detail        string
	ranFor        time.Duration
	helperMu      sync.Mutex
	helperReasons map[api.Error]string
}

func (a *effectAttempt) observeHelperReason(cause error, reason string) {
	if !api.ValidHelperReason(reason) {
		return
	}
	key, ok := helperRefusalKey(cause)
	if !ok {
		return
	}
	a.helperMu.Lock()
	defer a.helperMu.Unlock()
	if a.helperReasons == nil {
		a.helperReasons = make(map[api.Error]string)
	}
	if a.helperReasons[key] == "" {
		a.helperReasons[key] = reason
	}
}

// Lifecycle can copy the same refusal while promoting Retryable after a
// joined transient cause. All other error fields, including its private
// component, remain its identity. The key never enters a journal or state.
func helperRefusalKey(cause error) (api.Error, bool) {
	var typed *api.Error
	if !errors.As(cause, &typed) || typed == nil {
		return api.Error{}, false
	}
	key := *typed
	key.Retryable = false
	return key, true
}

func (a *effectAttempt) errorReason(err error) string {
	reason := effectReason(err)
	if api.HelperReason(err) == "" {
		key, ok := helperRefusalKey(err)
		if !ok {
			return reason
		}
		a.helperMu.Lock()
		defer a.helperMu.Unlock()
		if check := a.helperReasons[key]; api.ValidHelperReason(check) {
			reason += "_" + check
		}
	}
	return reason
}

// Started and final records are each one line. Their closed vocabulary contains
// no IDs, payloads, paths, error messages or other caller-controlled values.
func (a *effectAttempt) write(outcome, reason string) error {
	return a.writeTo(os.Stderr, outcome, reason)
}

func (a *effectAttempt) writeTo(writer io.Writer, outcome, reason string) error {
	data, err := json.Marshal(struct {
		Event   string `json:"event"`
		Kind    string `json:"kind"`
		Outcome string `json:"outcome"`
		Reason  string `json:"reason"`
		Detail  string `json:"detail,omitempty"`
	}{"effect_attempt", a.kind, outcome, reason, a.detail})
	if err != nil {
		return serviceError(api.CodeIntegrity, "cannot encode effect attempt journal")
	}
	data = append(data, '\n')
	n, err := writer.Write(data)
	if err != nil || n != len(data) {
		return serviceError(api.CodeIntegrity, "cannot retain effect attempt journal")
	}
	return nil
}

func (a *effectAttempt) fault(stage string, err error) attemptResult {
	a.outcome, a.reason = "fault", stage+"_"+a.errorReason(err)
	a.detail = errorDetail(err)
	a.server.recordFault(err)
	return attemptStop
}

func (a *effectAttempt) deferEffect(stage string, err error, id api.ID, retries effectRetries) attemptResult {
	a.outcome, a.reason = "deferred", stage+"_"+a.errorReason(err)
	a.detail = errorDetail(err)
	if a.kind == "PlanLaunch" && retainedCaptureFailure(err) {
		// The immutable result cannot progress through another claim. Keep
		// its resources and error for review without stopping other effects.
		// This is local to this reconciler lifetime, not a forged completion
		// or a durable replacement/recovery decision.
		a.outcome = "held"
		retries.hold(id)
		return attemptNext
	}
	retries.refused(id, a.server.deps.Clock.Now())
	return attemptNext
}

func retainedCaptureFailure(cause error) bool {
	switch typed := cause.(type) {
	case interface{ RetainedLaunchStage() string }:
		return typed.RetainedLaunchStage() == "capture"
	case interface{ Unwrap() error }:
		return retainedCaptureFailure(typed.Unwrap())
	}
	// A joined failure may also contain a real storage/integrity error.
	// A retained-stage marker must never hide that independent failure.
	return false
}

func (a *effectAttempt) completed(outcome api.EffectOutcome) {
	a.outcome, a.reason = "completed", "verified_completion"
	if outcome.Status == "failed" {
		a.outcome, a.reason = "failed", "run_"+a.errorReason(outcome.Error)
		a.detail = errorDetail(outcome.Error)
	}
}

func effectReason(err error) string {
	var typed *api.Error
	if errors.As(err, &typed) && typed != nil {
		if reason := api.HelperReason(err); reason != "" {
			copy := *typed
			return effectReason(&copy) + "_" + reason
		}
		if typed.Code == api.CodeInvalid || typed.Code == api.CodeUnauthenticated || typed.Code == api.CodeNotFound || typed.Code == api.CodeContainmentUnknown ||
			typed.Code == api.CodeDeadline || typed.Code == api.CodeUnavailable || typed.Code == api.CodeConflict {
			return string(typed.Code) + "_" + api.ErrorComponent(err)
		}
		switch typed.Code {
		case api.CodeUnauthenticated, api.CodeForbidden, api.CodeConflict, api.CodeIdempotencyConflict, api.CodeIntegrity, api.CodeUnavailable, api.CodeContainmentUnknown,
			api.CodeDeadline, api.CodeCancelled, api.CodeNotImplemented, api.CodePrerequisite, api.CodeUnsupported,
			api.CodeInvalid, api.CodeNotFound, api.CodeVersion, api.CodeBudget, api.CodeUnscored, api.CodeCursorExpired:
			return string(typed.Code)
		}
	}
	return "dependency_failure"
}

func effectKind(effect api.Effect) string {
	switch {
	case effect.PlanLaunch != nil:
		return "PlanLaunch"
	case effect.Launch != nil:
		return "Launch"
	case effect.Stop != nil:
		return "Stop"
	case effect.Deliver != nil:
		return "Deliver"
	case effect.HelperAllocate != nil:
		return "HelperAllocate"
	case effect.HelperPrepare != nil:
		return "HelperPrepare"
	case effect.HelperRelease != nil:
		return "HelperRelease"
	case effect.HelperAbort != nil:
		return "HelperAbort"
	case effect.Worker != nil:
		return "Worker"
	case effect.Channel != nil:
		return "Channel"
	case effect.Clean != nil:
		return "Clean"
	case effect.Swap != nil:
		return "Swap"
	case effect.ApplyChange != nil:
		return "ApplyChange"
	case effect.Migration != nil:
		return "Migration"
	case effect.Upgrade != nil:
		return "Upgrade"
	case effect.Rebuild != nil:
		return "Rebuild"
	case effect.Bootstrap != nil:
		return "Bootstrap"
	default:
		return "Unknown"
	}
}

// longToken matches identifiers, keys and paths (24 or more token bytes); errorDetail never journals them.
var longToken = regexp.MustCompile(`[A-Za-z0-9_+/=.:-]{24,}`)

// errorDetail returns a typed error's fixed message, capped, for the journal (diagnosis only).
func errorDetail(err error) string {
	var typed *api.Error
	if !errors.As(err, &typed) || typed == nil {
		return ""
	}
	message := longToken.ReplaceAllString(typed.Message, "<redacted>")
	if len(message) > 160 {
		message = message[:160]
	}
	return message
}

// failureClass names a failure for the journal even when it is untyped, with how long the effect ran.
func failureClass(err error, ran time.Duration) string {
	detail := errorDetail(err)
	switch {
	case detail != "":
	case errors.Is(err, context.DeadlineExceeded):
		detail = "claim deadline exceeded"
	case errors.Is(err, context.Canceled):
		detail = "cancelled"
	default:
		detail = "untyped failure"
	}
	return fmt.Sprintf("%s (ran %d ms)", detail, ran.Milliseconds())
}
