package admin

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCommittedOpenTuple(t *testing.T) {
	cause := testCause(api.InternalHelperOpen, "life-a")
	prepared := api.PreparedLaunch{ID: "prepared-a", SpecSHA256: testDigest("spec"), Target: cause.Target,
		ContainmentID: "containment-a", ProcessGeneration: "actual-generation", EndpointGeneration: 1, GateID: "gate-a"}
	identity := api.IdentityCommit{LaunchID: "launch-a", EventID: "event-a", CommittedSeq: 7, RecordSHA256: testDigest("record")}
	stored := api.LaunchBindingRequest{Prepared: prepared, Identity: identity, Record: api.LaunchRecord{Kind: "agent", ID: "launch-a", Config: "admin-case",
		Target: cause.Target, UIDLeaseID: "lease-a", HostUID: 61001, ProcessGeneration: prepared.ProcessGeneration,
		ContainmentID: prepared.ContainmentID, GrantSetID: "grants-a", GrantsSHA256: testDigest("grants"), PolicyGeneration: 1, EndpointGeneration: 1}}
	request := api.HelperOpenRequest{Cause: cause, Prepared: prepared, OperationID: cause.CauseOperationID, EffectID: cause.EffectID,
		Permit: api.LaunchPermit{LaunchID: identity.LaunchID, PreparedID: prepared.ID, RecordSHA256: identity.RecordSHA256, CommittedSeq: identity.CommittedSeq}}
	if err := validateOpenCommit(request, stored, "admin-case"); err != nil {
		t.Fatal(err)
	}
	request.Permit.RecordSHA256 = testDigest("another-record")
	if err := validateOpenCommit(request, stored, "admin-case"); err == nil {
		t.Fatal("acceptance: forged commit permit")
	}
	request.Permit.RecordSHA256 = identity.RecordSHA256
	stored.Prepared.GateID = "another-gate"
	if err := validateOpenCommit(request, stored, "admin-case"); err == nil {
		t.Fatal("acceptance: replaced committed gate")
	}
	stored.Prepared = prepared
	stored.Record.Kind = ""
	if err := validateOpenCommit(request, stored, "admin-case"); err == nil {
		t.Fatal("acceptance: legacy binding acquired worker authority")
	}
}
