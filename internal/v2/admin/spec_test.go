package admin

import (
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func testSpecRegistration(lease api.HelperLease) specRegistration {
	budget := testAllocation().Budget
	grants := api.GrantSet{ID: "grants-a", LifeID: "life-a", SHA256: testDigest("grants"), PolicyGeneration: 1, Generation: 1,
		Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, ExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))}
	ref := api.BlobRef{ID: "runtime", SHA256: testDigest("runtime"), Bytes: 100, Class: "manifest"}
	spec := api.LaunchSpec{ID: "spec-a", LaunchID: "launch-a", Kind: "worker", Target: api.LifeRef{LifeID: "life-a", Run: 1},
		Backend: "linux-bwrap-landlock", UIDLeaseID: lease.ID, Grants: grants, Budget: budget, EndpointGeneration: 1,
		PolicyGeneration: 1, RuntimeManifest: ref, Materialization: api.Materialization{GrantSetID: grants.ID, Objects: []api.MaterializedObject{}},
		Worker: &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", Argv: []string{"ordinary-command"},
			Executable: api.Executable{ID: "worker", SHA256: testDigest("worker"), Version: "1"}, GrantSetID: grants.ID, Budget: budget},
		Injection: api.Injection{Target: api.LifeRef{LifeID: "life-a", Run: 1}, SlotIDs: []api.ID{}, TaskSecretNames: []string{},
			TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}}}
	data, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	canonical, err := api.CanonicalJSON(data)
	if err != nil {
		panic(err)
	}
	cause := testCause(api.InternalHelperRegister, "life-a")
	return specRegistration{Handoff: api.PreparedSpecHandoff{Cause: cause, Config: "admin-case", Spec: spec,
		Original:   api.BlobRef{ID: "original-spec", SHA256: testDigest(string(data)), Bytes: int64(len(data)), Class: "manifest"},
		SpecSHA256: testDigest(string(canonical)), OperationID: cause.CauseOperationID, RequestID: cause.CauseRequestID}, Original: data}
}

func TestRegisteredSpecBytes(t *testing.T) {
	lease := api.HelperLease{ID: "lease-a", ContainmentID: "containment-a", EndpointGeneration: 1}
	registration := testSpecRegistration(lease)
	if err := validateSpecEnvelope(registration, "admin-case"); err != nil {
		t.Fatal(err)
	}
	changed := registration
	changed.Handoff.Spec.ID = "another-spec"
	if err := validateSpecEnvelope(changed, "admin-case"); err == nil {
		t.Fatal("acceptance: altered spec bytes")
	}
	changed = registration
	changed.Handoff.SpecSHA256 = testDigest("unrelated")
	if err := validateSpecEnvelope(changed, "admin-case"); err == nil {
		t.Fatal("acceptance: wrong JCS spec digest")
	}
	changed = registration
	changed.Handoff.Cause.Kind = api.InternalHelperOpen
	requireCode(t, validateSpecEnvelope(changed, "admin-case"), api.CodeInvalid)
}
