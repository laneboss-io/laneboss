package linux

import (
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Shape/correlation controls only. These do not issue or consume real D6 or
// ticket authority and do not stand in for a service/store or helper receipt.
func reservationInput(t *testing.T, r api.LaunchReservation, budget api.Budget) (api.BlobRef, api.Digest) {
	t.Helper()
	body := api.StartRequest{Lane: "child", ProjectID: "project", Level: r.Level, Role: r.Role, Driver: r.Driver,
		Task: metaBlob("task", "task"), ProfileGrantID: "profile-grant", Model: "fixture-model", Budget: budget,
		RootTicketID: r.Authority.ID, ExpectedPolicyGeneration: r.PolicyGeneration,
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{},
			Secrets: []api.SecretDelegation{}, Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}}
	params, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: r.Config, Actor: r.RequestedBy, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 4,
		Request: api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: r.Config, Method: "lane.start",
			RequestID: r.RequestID, IdempotencyKey: "request-key", Params: params}}
	scope.Request.RequestSHA256, err = api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	ticket := api.TicketUse{TicketID: r.Authority.ID, PrincipalID: r.RequestedBy.ID, Config: r.Config,
		EndpointGeneration: scope.EndpointGeneration, Level: r.Level, Role: r.Role, GrantSetID: "root-grants"}
	request := api.LaunchReservationRequest{
		OperationID: r.OperationID, Guards: []api.TransactionGuard{{Ticket: &ticket}},
	}
	if err := api.ValidateLaunchReservationRequest(
		scope, request,
	); err != nil {
		t.Fatal("root request/ticket metadata control:", err)
	}
	raw := metaJSON(t, scope.Request)
	ref := api.BlobRef{ID: "retained-request", Class: "launch_request", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	return ref, scope.Request.RequestSHA256
}

func TestReservationFixtures(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverCodex, api.DriverClaudock} {
		record, _ := planMetaForDriver(t, driver)
		reservation := record.Reservation
		if err := api.ValidateLaunchReservation(
			reservation,
		); err != nil {
			t.Fatal("fix-10 root reservation metadata:", err)
		}
		for _, fault := range []string{"missing", "proof", "level", "role", "driver"} {
			bad := reservation
			switch fault {
			case "missing":
				bad.Authority = api.LaunchAuthority{}
			case "proof":
				bad.Authority.Kind = "proof"
			case "level":
				bad.Level = 2
			case "role":
				bad.Role = ""
			case "driver":
				bad.Driver = "shell"
			}
			if api.ValidateLaunchReservation(
				bad,
			) == nil {
				t.Fatal("reservation fixture omitted its authority or stored pins")
			}
		}
	}
}

func refusedPlanMeta(t *testing.T) api.LaunchPlan {
	t.Helper()
	r, _ := planMeta(t)
	plan := *r.Plan
	capture := &plan.Capture
	capture.Status = "refused"
	capture.WorkerLeaseID, capture.EffectID, capture.ProducerID = "", "", ""
	capture.ProducerGeneration, capture.BootID, capture.Supervisor = "", "", nil
	capture.Streams = []api.CaptureStreamBinding{}
	capture.Refusal = api.NotImplemented("lb-v2-admin", "capture metadata")
	capture.Refusal.OperationID = r.Reservation.OperationID
	capture.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: r.Reservation.PolicyGeneration, ApprovalID: "capture-approval"}
	plan.CapturePolicy = &api.EffectivePolicy{Generation: r.Reservation.PolicyGeneration,
		AllowCaptureRefusal: true, CaptureRefusalApprovalID: capture.RefusalPolicy.ApprovalID,
		Context: api.RoleContext{Level: r.Reservation.Level, Role: r.Reservation.Role},
		SHA256:  fixtureBlob("capture-policy").SHA256, ProfileExclusions: []api.ID{},
		Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}}
	if err := api.ValidateLaunchPlan(plan); err != nil {
		t.Fatal("explicit D6 policy metadata control:", err)
	}
	return plan
}

func TestPlanCapturePolicy(t *testing.T) {
	registered, _ := planMeta(t)
	if err := validatePlanCapture(*registered.Plan); err != nil {
		t.Fatal("registered capture metadata control:", err)
	}
	for _, fault := range []string{"none", "missing", "disabled", "approval", "generation", "reservation", "allowed", "integrity"} {
		plan := refusedPlanMeta(t)
		if err := validatePlanCapture(plan); err != nil {
			t.Fatal("approved refusal metadata control:", err)
		}
		switch fault {
		case "none":
			plan.Capture.RefusalPolicy = nil
		case "missing":
			plan.CapturePolicy = nil
		case "disabled":
			plan.CapturePolicy.AllowCaptureRefusal = false
		case "approval":
			policy := plan.CapturePolicy
			policy.CaptureRefusalApprovalID = "foreign-approval"
		case "generation":
			plan.CapturePolicy.Generation++
		case "reservation":
			plan.Reservation.PolicyGeneration++
		case "allowed":
			plan.Capture.RefusalPolicy.Allowed = false
		case "integrity":
			plan.Capture.Refusal.Code = api.CodeIntegrity
		}
		if validatePlanCapture(plan) == nil {
			t.Fatal("capture refusal bypassed its reserved D6 policy")
		}
	}
}

func TestReservedActorPins(t *testing.T) {
	for _, fault := range []string{"level", "role"} {
		r, _ := planMeta(t)
		r.Phase = "bound"
		binding := bindingMeta(t, r)
		if err := validateAgentBinding(binding, r, r.Handoff.Spec.RuntimeManifest); err != nil {
			t.Fatal("reserved actor metadata control:", err)
		}
		if fault == "level" {
			binding.Record.Actor.Level--
		} else {
			binding.Record.Actor.Role = "executor"
		}
		digest, err := canonicalDigest(binding.Record)
		if err != nil {
			t.Fatal(err)
		}
		binding.Identity.RecordSHA256 = digest
		if validateReservedActor(binding.Record, r.Reservation) == nil {
			t.Fatal("bound actor bypassed its stored reservation pins")
		}
		if validateAgentBinding(binding, r, r.Handoff.Spec.RuntimeManifest) == nil {
			t.Fatal("bound actor with a valid hash escaped plan validation")
		}
	}
}

func TestReservedDriverPin(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverCodex, api.DriverClaudock} {
		r, _ := planMetaForDriver(t, driver)
		runtime := runtimeMeta(r)
		if err := validateAgentRuntime(*r.Plan, runtime); err != nil {
			t.Fatal("reserved driver metadata control:", err)
		}
		other := api.DriverClaudock
		if driver == other {
			other = api.DriverCodex
		}
		r.Plan.Reservation.Driver = other
		if validateAgentRuntime(*r.Plan, runtime) == nil {
			t.Fatal("runtime ignored the stored reservation driver")
		}
	}
}

func TestExplicitRecordKinds(t *testing.T) {
	for _, kind := range []string{"agent", "worker"} {
		source, prepared, permit := committedFixture(t)
		binding := source.binding
		if kind == "agent" {
			r, _ := planMeta(t)
			r.Phase = "bound"
			binding = bindingMeta(t, r)
			prepared = binding.Prepared
			permit = api.LaunchPermit{LaunchID: binding.Record.ID, PreparedID: prepared.ID,
				CommittedSeq: binding.Identity.CommittedSeq, RecordSHA256: binding.Identity.RecordSHA256}
			if err := validateAgentBinding(binding, r, r.Handoff.Spec.RuntimeManifest); err != nil {
				t.Fatal("complete agent binding metadata control:", err)
			}
		}
		digest, err := canonicalDigest(binding.Record)
		if err != nil {
			t.Fatal(err)
		}
		binding.Identity.RecordSHA256, permit.RecordSHA256 = digest, digest
		if err := validateIdentity(prepared, permit, binding); err != nil {
			t.Fatal("explicit kind identity shape control:", err)
		}
		if kind == "worker" {
			bad := binding
			bad.Recovery = &api.LaunchRecovery{}
			if validateRecordKind(bad) == nil {
				t.Fatal("worker acquired an agent recovery record")
			}
		}
		for _, changed := range []string{"", "legacy", "foreign"} {
			bad := binding
			bad.Record.Kind = changed
			if validateRecordKind(bad) == nil {
				t.Fatal("legacy or unknown record kind was admitted")
			}
		}
		binding.Record.Actor.Kind = "human"
		if validateRecordKind(binding) == nil {
			t.Fatal("record kind admitted a foreign actor kind")
		}
	}
}
