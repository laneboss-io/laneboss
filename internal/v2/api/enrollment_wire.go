package api

import (
	"encoding/json"
	"errors"
)

// These are the existing administrator helper's private wire fields, shared
// by its client, installed service listener and store's exact-frame check.
// They are not public RPC methods and convey no authority without native IPC.
const AdminEnrollmentProtocol = "laneboss.admin-enrollment.v2"

type AdminEnrollmentFrame struct {
	Protocol       string          `json:"protocol"`
	Revision       string          `json:"contract_revision"`
	Config         string          `json:"config"`
	Generation     Generation      `json:"generation"`
	ArtifactSHA256 Digest          `json:"artifact_sha256"`
	Nonce          ID              `json:"nonce"`
	Method         string          `json:"method"`
	Params         json.RawMessage `json:"params"`
}

type AdminEnrollmentReply struct {
	Protocol     string          `json:"protocol"`
	Revision     string          `json:"contract_revision"`
	Nonce        ID              `json:"nonce"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        *Error          `json:"error,omitempty"`
	FailureField string          `json:"failure_field,omitempty"`
}

func ValidateAdminEnrollmentFrame(frame AdminEnrollmentFrame, endpoint AdminEnrollmentEndpoint) error {
	if err := ValidateAdminEnrollmentEndpoint(endpoint); err != nil {
		return AdminEnrollmentFailure("admin_enrollment", err)
	}
	for _, check := range []struct {
		field string
		ok    bool
	}{
		{"protocol", frame.Protocol == AdminEnrollmentProtocol},
		{"contract_revision", frame.Revision == ContractRevision},
		{"config", frame.Config == endpoint.Config},
		{"generation", frame.Generation == endpoint.InstallationGeneration},
		{"artifact_sha256", frame.ArtifactSHA256 == endpoint.Helper.SHA256},
		{"nonce", launchID(frame.Nonce) && len(frame.Nonce) >= 32},
		{"method", frame.Method == "enroll_begin" || frame.Method == "enroll_complete" || frame.Method == "initial_publish" || frame.Method == "spend_reconcile" || frame.Method == "invite_begin" || frame.Method == "invite_complete"},
	} {
		if !check.ok {
			return AdminEnrollmentFailure(check.field, &Error{Code: CodeForbidden, Owner: "lb-v2-admin",
				Message: "administrator enrollment frame differs at " + check.field,
				Instead: "Use the exact installed helper and enrollment configuration."})
		}
	}
	return nil
}

type adminEnrollmentFailure struct {
	field string
	cause error
}

func (e *adminEnrollmentFailure) Error() string { return e.cause.Error() }
func (e *adminEnrollmentFailure) Unwrap() error { return e.cause }

// Only fixed schema/stage names reach diagnostics. An unknown member name or
// other caller-controlled string is never used as a log field.
func AdminEnrollmentFailure(field string, err error) error {
	if err == nil {
		return nil
	}
	switch field {
	case "admin_enrollment", "protocol", "contract_revision", "config", "generation", "artifact_sha256",
		"nonce", "method", "params", "frame", "connection", "deadline", "peer_credentials", "peer_uid",
		"peer_lifetime", "helper_executable", "helper_artifact", "helper_unit", "helper_socket", "socket", "scope", "enroll_begin",
		"enroll_complete", "initial_publish", "spend_reconcile", "response", "response_write", "journal":
	default:
		field = "enrollment"
	}
	return &adminEnrollmentFailure{field: field, cause: err}
}

func AdminEnrollmentFailedField(err error) string {
	var failure *adminEnrollmentFailure
	if errors.As(err, &failure) {
		return failure.field
	}
	return ""
}

// An early refusal may have no decodable nonce. It conveys only failure from
// the independently pinned native service; a result always needs exact nonce
// correlation. A different nonempty nonce is refused even on an error reply.
func ValidateAdminEnrollmentReply(reply AdminEnrollmentReply, request AdminEnrollmentFrame) error {
	if reply.Protocol != AdminEnrollmentProtocol || reply.Revision != ContractRevision ||
		(reply.Error == nil) == (len(reply.Result) == 0) ||
		(reply.Error != nil && reply.FailureField != "" && AdminEnrollmentFailedField(AdminEnrollmentFailure(reply.FailureField, reply.Error)) != reply.FailureField) ||
		(reply.Error == nil && reply.FailureField != "") ||
		(reply.Nonce != request.Nonce && !(reply.Error != nil && reply.Nonce == "" && reply.FailureField != "")) {
		return &Error{Code: CodeIntegrity, Owner: "lb-v2-admin",
			Message: "administrator enrollment response does not match its request",
			Instead: "Retain the private channel evidence and repair the matched installed endpoints."}
	}
	return nil
}
