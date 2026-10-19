package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAdminFrameBindings(t *testing.T) {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(entropy)
	endpoint := AdminEnrollmentEndpoint{Config: "native-enroll", Socket: "/runtime/enrollment.sock", ServiceUID: 11000,
		InstallationGeneration: 2, Origin: "https://configured.example", RPID: "configured.example",
		Helper: Executable{ID: "helper", Version: "1", SHA256: Digest(hex.EncodeToString(digest[:]))}}
	request, err := json.Marshal(EnrollmentCeremonyRequest{Config: endpoint.Config, CeremonyID: "ceremony", PrincipalID: "principal"})
	if err != nil {
		t.Fatal(err)
	}
	base := AdminEnrollmentFrame{Protocol: AdminEnrollmentProtocol, Revision: ContractRevision, Config: endpoint.Config,
		Generation: endpoint.InstallationGeneration, ArtifactSHA256: endpoint.Helper.SHA256,
		Nonce: ID(hex.EncodeToString(entropy)), Method: "enroll_begin", Params: request}
	if err := ValidateAdminEnrollmentFrame(base, endpoint); err != nil {
		t.Fatal("matching helper frame was refused", err)
	}
	for name, mutate := range map[string]func(*AdminEnrollmentFrame){
		"protocol":          func(frame *AdminEnrollmentFrame) { frame.Protocol = Protocol },
		"contract_revision": func(frame *AdminEnrollmentFrame) { frame.Revision = "older" },
		"config":            func(frame *AdminEnrollmentFrame) { frame.Config = "foreign" },
		"generation":        func(frame *AdminEnrollmentFrame) { frame.Generation++ },
		"artifact_sha256":   func(frame *AdminEnrollmentFrame) { frame.ArtifactSHA256 = "foreign" },
		"nonce":             func(frame *AdminEnrollmentFrame) { frame.Nonce = "short" },
		"method":            func(frame *AdminEnrollmentFrame) { frame.Method = "lane.start" },
	} {
		t.Run(name, func(t *testing.T) {
			frame := base
			mutate(&frame)
			var typed *Error
			if err := ValidateAdminEnrollmentFrame(frame, endpoint); !errors.As(err, &typed) ||
				typed.Code != CodeForbidden || typed.Owner != "lb-v2-admin" || AdminEnrollmentFailedField(err) != name {
				t.Fatal("foreign helper frame crossed the installed binding")
			}
		})
	}
	for _, nonce := range []ID{ID("bad." + string(base.Nonce)), ID(strings.Repeat("x", 129))} {
		frame := base
		frame.Nonce = nonce
		if err := ValidateAdminEnrollmentFrame(frame, endpoint); err == nil || AdminEnrollmentFailedField(err) != "nonce" {
			t.Fatal("invalid nonce alphabet or upper bound was accepted")
		}
	}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AdminEnrollmentFrame
	if err := DecodeObject(data, &decoded); err != nil || decoded.Method != base.Method || decoded.Nonce != base.Nonce ||
		string(decoded.Params) != string(base.Params) {
		t.Fatal("helper and service frame codecs changed request bytes", err)
	}
}

func TestAdminReplyCorrelation(t *testing.T) {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		t.Fatal(err)
	}
	request := AdminEnrollmentFrame{Nonce: ID(hex.EncodeToString(entropy))}
	base := AdminEnrollmentReply{Protocol: AdminEnrollmentProtocol, Revision: ContractRevision, Nonce: request.Nonce, Result: json.RawMessage("{}")}
	for _, check := range []struct {
		name string
		edit func(*AdminEnrollmentReply)
		ok   bool
	}{
		{"matching", func(*AdminEnrollmentReply) {}, true},
		{"missing_nonce_result", func(r *AdminEnrollmentReply) { r.Nonce = "" }, false},
		{"foreign_nonce_result", func(r *AdminEnrollmentReply) { r.Nonce += "x" }, false},
		{"protocol", func(r *AdminEnrollmentReply) { r.Protocol = Protocol }, false},
		{"revision", func(r *AdminEnrollmentReply) { r.Revision = "older" }, false},
		{"empty", func(r *AdminEnrollmentReply) { r.Result = nil }, false},
		{"result_with_failure", func(r *AdminEnrollmentReply) { r.FailureField = "nonce" }, false},
		{"error_and_result", func(r *AdminEnrollmentReply) { r.Error = &Error{Code: CodeForbidden} }, false},
		{"matching_refusal", func(r *AdminEnrollmentReply) {
			r.Result = nil
			r.Error = &Error{Code: CodeForbidden}
			r.FailureField = "nonce"
		}, true},
		{"early_refusal", func(r *AdminEnrollmentReply) {
			r.Result = nil
			r.Error = &Error{Code: CodeInvalid}
			r.Nonce = ""
			r.FailureField = "frame"
		}, true},
		{"uncorrelated_without_field", func(r *AdminEnrollmentReply) { r.Result = nil; r.Error = &Error{Code: CodeInvalid}; r.Nonce = "" }, false},
		{"foreign_nonce_refusal", func(r *AdminEnrollmentReply) {
			r.Result = nil
			r.Error = &Error{Code: CodeForbidden}
			r.Nonce += "x"
			r.FailureField = "nonce"
		}, false},
		{"unknown_failure_field", func(r *AdminEnrollmentReply) {
			r.Result = nil
			r.Error = &Error{Code: CodeInvalid}
			r.Nonce = ""
			r.FailureField = "untrusted"
		}, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			reply := base
			check.edit(&reply)
			if err := ValidateAdminEnrollmentReply(reply, request); (err == nil) != check.ok {
				t.Fatal("refusal correlation or success nonce gate changed")
			}
		})
	}
	cause := &Error{Code: CodeForbidden, Owner: "lb-v2-admin"}
	wrapped := AdminEnrollmentFailure("untrusted", cause)
	if !errors.Is(wrapped, cause) || AdminEnrollmentFailedField(wrapped) != "enrollment" {
		t.Fatal("diagnostic field filtering lost the refusal or exposed an unknown name")
	}
}
