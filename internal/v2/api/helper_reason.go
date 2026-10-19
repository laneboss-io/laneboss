package api

import (
	"context"
	"encoding/json"
	"errors"
)

type helperReasonContextKey struct{}

// The observer is process-local diagnostics. It never travels in a request,
// changes an Error's dynamic type, or survives in an authority/state record.
func WithHelperReasonObserver(ctx context.Context, observer func(error, string)) context.Context {
	return context.WithValue(ctx, helperReasonContextKey{}, observer)
}

func ObserveHelperReason(ctx context.Context, cause error, reason string) {
	if !ValidHelperReason(reason) {
		return
	}
	if observer, ok := ctx.Value(helperReasonContextKey{}).(func(error, string)); ok && observer != nil {
		observer(cause, reason)
	}
}

func WithoutHelperReason(cause error) error {
	for {
		tagged, ok := cause.(*helperReasonError)
		if !ok || tagged == nil {
			return cause
		}
		cause = tagged.cause
	}
}

// Helper reasons are diagnostics, never authority or caller-selected values.
// The private helper envelope carries them separately from the public Error.
func ValidHelperReason(reason string) bool {
	switch reason {
	case "plan_entry", "plan_claim", "plan_record", "plan_original", "plan_sources", "plan_allocation", "plan_materialize", "plan_runner", "plan_capture", "plan_validate", "plan_verify", "plan_seal", "plan_recovery",
		"pv_reservation", "pv_inputs", "pv_lease", "pv_storage", "pv_material", "pv_receipt", "pv_runner", "pv_loop", "pv_credentials", "pv_capture", "pv_cap_policy", "pv_cap_rule", "pv_cap_binding",
		"plan_slot_mode", "plan_retain", "plan_events", "plan_publish",
		"effect_claim", "effect_support", "plan_policy", "agent_stage", "cred_bind",
		"agent_record", "agent_prepare", "agent_bind", "agent_child_done", "agent_bound_child", "agent_binding", "agent_binding_plan", "agent_recover", "agent_open", "agent_observe", "agent_measure", "agent_publish",
		"agent_input", "agent_endpoint", "agent_bind_tx", "agent_bind_read", "agent_open_tx",
		"linux_spec", "linux_handoff", "linux_original", "linux_plan", "linux_register", "linux_runtime", "linux_prepare_cause", "linux_prepare", "linux_prepared_tuple",
		"plan_profile", "plan_prompt", "plan_credential_slot", "plan_injection", "plan_runner_call",
		"transport_window", "caller_identity", "caller_lifetime", "caller_containment", "caller_privileges", "caller_executable",
		"planning_dispatch", "planning_wait", "materialization_context", "materialization_parent", "materialization_claim", "materialization_inputs", "materialization_grants", "materialization_sources", "materialization_owner",
		"materialization_storage", "materialization_allocation", "materialization_seal", "materialization_handoff", "materialization_endpoint", "materialization_register", "materialization_prepare", "materialization_bind", "materialization_open",
		"materialization_process", "materialization_result", "materialization_receipt", "materialization_deadline", "materialization_child_claim", "materialization_exit_status", "materialization_exit_code", "materialization_signal", "materialization_survivors", "materialization_wait",
		"request_frame", "request_decode", "request_binding", "caller_role", "installation", "cancellation", "operation_input", "operation",
		"peer_lifetime", "response_encode", "reply_transport", "connection_close", "call_context", "call_identity", "call_binding", "call_socket",
		"call_peer", "call_encode", "call_write", "reply_decode", "reply_binding", "reply_result",
		"launch_authority", "launch_sources", "launch_allocation", "lease_allocation", "lease_activation", "lease_records", "lease_save",
		"lease_read", "lease_write", "lease_duplicate", "lease_recovery_transition", "lease_recovery_owner", "lease_recovery_identity",
		"lease_archive", "lease_capture_drain", "lease_cleanup", "lease_credentials", "lease_projection_alias", "lease_network", "lease_gate", "lease_launch",
		"lease_identity", "lease_phase", "lease_abort_state", "lease_abort_receipt", "lease_allocation_history", "lease_spec_state", "lease_spec",
		"lease_release_state", "lease_receipt_state", "lease_release", "lease_receipt", "lease_data_identity", "lease_data_job", "lease_capture_identity",
		"lease_data_registration", "lease_data_lease", "lease_data_parent", "lease_data_state", "lease_data_evidence", "lease_data_allocation",
		"lease_data_storage", "lease_data_seal", "lease_data_stage", "lease_data_result", "lease_data_collection", "lease_data_gate",
		"allocation_enrollment", "uid_scan", "uid_inventory", "uid_threads", "uid_status", "uid_shape", "uid_survivor", "cgroup_open", "cgroup_read", "cgroup_write", "cgroup_population", "cgroup_limits",
		"capture_registration", "capture_boot", "capture_phase", "capture_storage_missing", "capture_storage_unready",
		"capture_supervisor", "capture_uid", "capture_cgroup", "capture_runtime", "capture_spool", "capture_gate", "capture_publish", "capture_retained_failure",
		"prompt_input", "bootstrap_lifetime", "gate_observation",
		"active_lease", "storage_root", "storage_parent", "storage_directory", "storage_inode", "storage_mappings", "spec_registration", "gate_prepare", "runtime_enrollment", "data_retry":
		return true
	}
	return false
}

type helperReasonError struct {
	cause  error
	reason string
}

func (e *helperReasonError) Error() string {
	return e.cause.Error()
}
func (e *helperReasonError) Unwrap() error {
	return e.cause
}
func (e *helperReasonError) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.cause)
}

// WithHelperReason retains the original refusal, including joined causes, and
// keeps the first (deepest) named check. It never mutates a shared Error.
func WithHelperReason(cause error, reason string) error {
	if cause == nil || !ValidHelperReason(reason) || HelperReason(cause) != "" {
		return cause
	}
	return &helperReasonError{cause: cause, reason: reason}
}

func HelperReason(cause error) string {
	var tagged *helperReasonError
	if errors.As(cause, &tagged) && tagged != nil && ValidHelperReason(tagged.reason) {
		return tagged.reason
	}
	return ""
}
