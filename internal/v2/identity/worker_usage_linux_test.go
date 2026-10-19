package identity

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Hostile metadata controls for the usage grammar. Existing sealed-descriptor,
// kernel and installed worker canaries own native authentication evidence.
func TestUsageWorkerHandoff(t *testing.T) {
	for _, fault := range []string{"current", "argv", "input", "data", "extra-secret", "slot", "source-version", "delegation", "budget", "cause"} {
		t.Run(fault, func(t *testing.T) {
			s, a, binding := archiveHandoffMetadata(t)
			p, spec := &a.Principal, &a.Handoff.Spec
			p.Lease.Kind, p.Lease.Input.Class = "usage", "usage_input"
			plan := *spec.Worker
			plan.Kind, plan.Input = "usage", p.Lease.Input
			plan.Argv = []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(p.Lease.ID)}
			plan.Budget = api.Budget{WallMS: 60000, CPUSeconds: 10, MemoryBytes: 256 << 20, Processes: 16, DiskBytes: 4 << 20, Currency: "USD"}
			spec.Worker, spec.PlanID, spec.Budget = &plan, "", plan.Budget
			spec.Materialization = api.Materialization{GrantSetID: spec.Grants.ID, Objects: []api.MaterializedObject{}}
			spec.Grants.Secrets = []api.SecretGrant{{ID: "usage-source", Name: "usage-login", SourceHandle: "usage-handle", Version: "1", Delivery: "file", Target: "credential.json"}}
			spec.Injection = api.Injection{Target: p.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{"usage-slot"}, GrantIDs: []api.ID{"usage-source"}, SourceVersions: []string{"1"}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}
			switch fault {
			case "argv":
				plan.Argv[2] = "usage"
			case "input":
				p.Lease.Input.Class = "archive_input"
				plan.Input = p.Lease.Input
			case "data":
				spec.Grants.Data = []api.DataGrant{{ID: "foreign-data"}}
			case "extra-secret":
				spec.Grants.Secrets = append(spec.Grants.Secrets, spec.Grants.Secrets[0])
			case "slot":
				spec.Injection.SlotIDs = nil
			case "source-version":
				spec.Injection.SourceVersions[0] = "foreign"
			case "delegation":
				spec.Grants.Secrets[0].Delegate = true
			case "budget":
				plan.Budget.WallMS++
				spec.Budget = plan.Budget
			case "cause":
				a.Handoff.Cause.CauseRequestID = "foreign-request"
			}
			p.Claim.Record.Effect.Worker = &plan
			ref := launchBlob(t, "usage-spec", "launch_spec", *spec)
			a.Handoff.Original, a.Handoff.SpecSHA256 = ref, ref.SHA256
			binding.Prepared.SpecSHA256 = ref.SHA256
			a.Binding = binding
			err := s.checkWorkerHandoff(binding, a)
			if fault == "current" {
				if err != nil {
					t.Fatal("usage job cannot reach native lifetime verification", err)
				}
			} else {
				fixtureCode(t, err, api.CodeIntegrity)
			}
		})
	}
}
