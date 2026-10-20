package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

var errHelperJournal = errors.New("helper request journal failed")

// helperSlowTurn is the wait or hold above which one helper turn is journaled (box 110 diagnosis).
const helperSlowTurn = 250 * time.Millisecond

type helperRequestTrace struct {
	method  string
	check   string
	timing  io.Writer
	stageAt time.Time
	stages  []helperStageTiming
	match   *uidMatch
	nonce   api.ID
	lease   api.ID
	life    api.ID
	run     api.RunNumber
	launch  api.ID
	caller  int
}

// These are native comparison facts for a refused UID scan, never authority,
// command lines, paths or caller-supplied process descriptions.
type uidMatch struct {
	UID     uint32 `json:"uid"`
	PID     int    `json:"pid"`
	TID     int    `json:"tid"`
	Start   string `json:"start_time,omitempty"`
	LifeID  api.ID `json:"life_id,omitempty"`
	LeaseID api.ID `json:"lease_id,omitempty"`
}

// Only a validated retained helper record supplies these selectors. They are
// diagnostics, never request authority and never include credential contents.
func helperLaneIDs(ctx context.Context, record leaseRecord) {
	trace, _ := ctx.Value(helperTimingKey{}).(*helperRequestTrace)
	if trace == nil || record.Spec == nil {
		return
	}
	spec := record.Spec.Handoff.Spec
	trace.lease, trace.life, trace.run, trace.launch = record.Lease.ID, spec.Target.LifeID, spec.Target.Run, spec.LaunchID
}

type helperStageTiming struct {
	stage string
	wait  time.Duration
	hold  time.Duration
}

type helperTimingKey struct{}

func (t *helperRequestTrace) stage(stage string) {
	if !t.stageAt.IsZero() {
		t.stages = append(t.stages, helperStageTiming{t.check, 0, time.Since(t.stageAt)})
	}
	t.check, t.stageAt = stage, time.Now()
}

func (t *helperRequestTrace) finishTiming() {
	if t.method != "containment_live" {
		return
	}
	t.stage(t.check)
	for _, elapsed := range t.stages {
		if elapsed.wait < helperSlowTurn && elapsed.hold < helperSlowTurn {
			continue
		}
		journalHelperTurn(t.timing, t.method, elapsed.stage, elapsed.wait, elapsed.hold)
	}
}

func helperStage(ctx context.Context, stage string) func() {
	trace, _ := ctx.Value(helperTimingKey{}).(*helperRequestTrace)
	if trace == nil || trace.method != "containment_live" {
		return func() {}
	}
	start := time.Now()
	return func() { trace.stages = append(trace.stages, helperStageTiming{stage, 0, time.Since(start)}) }
}

func helperLockTiming(ctx context.Context, stage string, wait, hold time.Duration) {
	trace, _ := ctx.Value(helperTimingKey{}).(*helperRequestTrace)
	if trace != nil && trace.method == "containment_live" {
		trace.stages = append(trace.stages, helperStageTiming{stage, wait, hold})
	}
}

// Timing is diagnostic only: its write cannot replace an operation's result
// or change the existing refusal journal policy. No request selectors escape.
func journalHelperTurn(writer io.Writer, operation, stage string, wait, hold time.Duration) {
	if writer == nil {
		return
	}
	data, err := json.Marshal(struct {
		Event     string `json:"event"`
		Operation string `json:"operation"`
		Stage     string `json:"stage"`
		WaitMS    int64  `json:"wait_ms"`
		HoldMS    int64  `json:"hold_ms"`
	}{"helper_timing", helperTimingMethod(operation), stage, wait.Milliseconds(), hold.Milliseconds()})
	if err == nil {
		_, _ = writer.Write(append(data, '\n'))
	}
}

func helperTimingMethod(method string) string {
	switch method {
	case "credential_peer_verify", "credential_projection_source", "credential_projection_observe",
		"credential_projection_observe_id", "credential_gate_observe":
		return method
	}
	return helperMethod(method)
}

func helperCheck(resultErr *error, reason string) {
	*resultErr = api.WithHelperReason(*resultErr, reason)
}

func helperContextCheck(ctx context.Context, resultErr *error, reason string) {
	helperCheck(resultErr, reason)
	if *resultErr != nil {
		api.ObserveHelperReason(ctx, *resultErr, api.HelperReason(*resultErr))
	}
	*resultErr = api.WithoutHelperReason(*resultErr)
}

func helperMethod(method string) string {
	switch method {
	case "judge_lease", "judge_register", "judge_prepare", "judge_open", "judge_observe", "judge_collect":
		return method
	case "channel_lease", "channel_register", "channel_prepare", "channel_reconcile", "channel_collect":
		return method
	case "claudock_bootstrap", "claudock_home":
		return method
	case "review_freeze", "review_check", "review_bytes", "review_lease", "review_register", "review_prepare", "review_open", "review_observe", "review_reconcile", "review_retire":
		return method
	case "restore_begin", "restore_chunk", "restore_stage", "restore_publish", "restore_abort", "restore_roots", "archive_freeze", "archive_check", "archive_bytes", "archive_lease", "archive_register", "archive_prepare", "archive_open", "archive_observe", "archive_reconcile", "archive_retire",
		"cleanup_resolve", "cleanup_inspect", "cleanup_remove", "cleanup_journal", "cleanup_read",
		"data_open", "data_query", "data_selector", "data_lease", "data_register", "data_prepare", "data_gate", "data_observe", "data_measure", "data_revoke", "data_collect", "data_native",
		"resolve_runtime", "open_gate", "observe_gate", "stop_gate", "reconcile_gate", "register_capture", "reconcile_capture", "allocate_launch", "resolve_storage",
		"allocate", "prepare", "credential_bind", "credential_binding", "register_spec", "abort", "containment", "containment_live", "containment_revoke", "release",
		"runner_prompt", "isolation_evidence", "probe", "admin_enrollment", "worker_launch", "plan_cleanup_native_read", "credential_withdrawal_observe":
		return method
	}
	return "unknown"
}

func (t *helperRequestTrace) write(writer io.Writer, cause error) error {
	if cause == nil {
		switch t.method {
		case "data_open", "data_prepare", "data_gate", "containment_live", "open_gate":
		default:
			return nil
		}
	}
	code := api.CodeUnavailable
	if cause == nil {
		code = api.ErrorCode("ok")
	}
	var typed *api.Error
	if errors.As(cause, &typed) && typed != nil {
		switch typed.Code {
		case api.CodeInvalid, api.CodeUnauthenticated, api.CodeForbidden, api.CodeNotFound, api.CodeConflict, api.CodeIdempotencyConflict,
			api.CodeVersion, api.CodeUnavailable, api.CodePrerequisite, api.CodeUnsupported, api.CodeIntegrity, api.CodeBudget,
			api.CodeUnscored, api.CodeCursorExpired, api.CodeContainmentUnknown, api.CodeCancelled, api.CodeDeadline, api.CodeNotImplemented,
			CodeArchiveLiveWriter, CodeCleanupUnmerged:
			code = typed.Code
		default:
			code = api.CodeIntegrity
		}
	}
	reason := api.HelperReason(cause)
	if reason == "" {
		reason = t.check
	}
	if !api.ValidHelperReason(reason) {
		reason = "operation"
	}
	// An archive worker refusal also journals its fixed message: the outer effect reports only the later
	// retirement refusal, which hides which archive check failed (item 1 diagnosis, box 90). Archive
	// refusals are fixed strings from the archive code, never credential or lane bytes.
	detail := ""
	if typed != nil && strings.HasPrefix(t.method, "archive_") {
		detail = typed.Message
	}
	match := t.match
	if reason != "uid_survivor" {
		match = nil
	}
	lease, life := t.lease, t.life
	var requestLease, requestLife api.ID
	if match != nil {
		// The flat IDs belong to the measured UID owner. Preserve a distinct
		// retained request target without letting it hide that observation.
		if lease != match.LeaseID {
			requestLease = lease
		}
		if life != match.LifeID {
			requestLife = life
		}
		lease, life = match.LeaseID, match.LifeID
	}
	data, err := json.Marshal(struct {
		Event  string        `json:"event"`
		Method string        `json:"method"`
		Code   api.ErrorCode `json:"code"`
		Reason string        `json:"reason"`
		Detail string        `json:"detail,omitempty"`
		*uidMatch
		Nonce        api.ID        `json:"helper_nonce,omitempty"`
		Lease        api.ID        `json:"lease_id,omitempty"`
		Life         api.ID        `json:"life_id,omitempty"`
		Run          api.RunNumber `json:"run,omitempty"`
		Launch       api.ID        `json:"launch_id,omitempty"`
		Caller       int           `json:"caller_pid,omitempty"`
		RequestLease api.ID        `json:"request_lease_id,omitempty"`
		RequestLife  api.ID        `json:"request_life_id,omitempty"`
	}{
		Event: "helper_request", Method: helperMethod(t.method), Code: code, Reason: reason,
		Detail: detail, uidMatch: match, Nonce: t.nonce, Lease: lease, Life: life,
		Run: t.run, Launch: t.launch, Caller: t.caller,
		RequestLease: requestLease, RequestLife: requestLife,
	})
	if err != nil {
		return errors.Join(errHelperJournal, err)
	}
	data = append(data, '\n')
	n, err := writer.Write(data)
	if err != nil || n != len(data) {
		return errors.Join(errHelperJournal, err)
	}
	return nil
}
