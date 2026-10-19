package api

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func contractBlob(id ID, class string, data []byte) BlobRef {
	sum := sha256.Sum256(data)
	return BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: Digest(hex.EncodeToString(sum[:]))}
}

func usageFixture(t *testing.T) (UsageWindowEvidence, UsageWindowRequest, WorkerPrincipal, []byte) {
	t.Helper()
	p := workerFixture(t)
	p.Lease.Kind = "usage"
	executable := Executable{ID: "claudock-usage", Version: "fixture-v1", SHA256: launchFixtureBlob("usage-executable", "manifest").SHA256}
	r := UsageWindowRequest{Target: p.Lease.Target, LaunchID: "causing-launch", OperationID: p.Lease.OperationID, ProfileGrantID: "from-grant", ProfileID: "from-profile", Provider: "fixture-provider",
		RunEndedAt: contractStamp(contractNow().Add(-time.Second)), AdapterVersion: "fixture-adapter-v1", Executable: executable, RuntimeManifest: p.Lease.RuntimeManifest}
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nfixture-profile\tsubscription\tcurrent\t100\t2026-01-01T01:00:00Z\n")
	e := UsageWindowEvidence{Schema: "laneboss.usage-window.v2", ID: "usage-window", Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID,
		ProfileGrantID: r.ProfileGrantID, ProfileID: r.ProfileID, Provider: r.Provider, AdapterVersion: r.AdapterVersion, Executable: executable, RuntimeManifest: r.RuntimeManifest,
		WorkerLeaseID: p.Lease.ID, ProducerID: p.Record.Actor.ID, ProducerGeneration: p.Peer.ProcessGeneration, BootID: p.BootID, ObservedAt: contractStamp(contractNow()),
		Window: "current", UsedPercent: 100, ResetsAt: "2026-01-01T01:00:00Z", Raw: contractBlob("usage-raw", "usage_raw", raw), Row: 1}
	return e, r, p, raw
}

func TestUsageWindow(t *testing.T) {
	e, r, p, raw := usageFixture(t)
	if err := ValidateUsageWindow(e, r, p, contractNow()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUsageSource(e, raw, "fixture-profile"); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"profile", "stale", "available", "producer", "reset", "exit", "kind"} {
		t.Run(fault, func(t *testing.T) {
			e, r, p, _ := usageFixture(t)
			switch fault {
			case "profile":
				e.ProfileID = "destination-profile"
			case "stale":
				r.RunEndedAt = contractStamp(contractNow().Add(-time.Minute))
				e.ObservedAt = contractStamp(contractNow().Add(-31 * time.Second))
			case "available":
				e.UsedPercent = 99
			case "producer":
				e.ProducerGeneration = "lane-writer-generation"
			case "reset":
				e.ResetsAt = "unknown"
			case "exit":
				e.ExitCode = 1
			case "kind":
				p.Lease.Kind = "materialize"
			}
			requireLaunchInvalid(t, ValidateUsageWindow(e, r, p, contractNow()), "outside usage authenticity gate was bypassed")
		})
	}
}

func TestUsageSource(t *testing.T) {
	for _, fault := range []string{"header", "percent", "profile", "plan", "reset"} {
		t.Run(fault, func(t *testing.T) {
			e, _, _, raw := usageFixture(t)
			text := string(raw)
			switch fault {
			case "header":
				text = strings.Replace(text, "USED_PERCENT", "USAGE", 1)
			case "percent":
				text = strings.Replace(text, "\t100\t", "\t99\t", 1)
			case "profile":
				text = strings.Replace(text, "fixture-profile", "foreign-profile", 1)
			case "plan":
				text += "fixture-profile\tconflicting-plan\tother-window\t1\t2026-01-01T01:00:00Z\n"
			case "reset":
				text = strings.Replace(text, "2026-01-01T01:00:00Z", "unknown", 1)
			}
			raw = []byte(text)
			// Keep valid raw hashes so the actual TSV fields decide the refusal.
			e.Raw = contractBlob("usage-raw", "usage_raw", raw)
			requireLaunchInvalid(t, ValidateUsageSource(e, raw, "fixture-profile"), "actual usage source bytes were not enforced")
		})
	}
}

func dataStageFixture(t *testing.T) (LaunchDataStage, LaunchDataRequest, LaunchDataResult) {
	t.Helper()
	p := launchFixture(t)
	w := workerFixture(t)
	w.Lease.Input = launchFixtureBlob("materialize-input", "materialize_input")
	grants := p.Inputs.Grants
	grants.ID = "data-worker-grants"
	grants.ParentLifeID = p.Reservation.Target.LifeID
	grants.Resources, grants.Secrets, grants.Profiles, grants.Network, grants.Channels = nil, nil, nil, nil, nil
	data := p.Inputs.Grants.Data[0]
	data.ID, data.ParentGrantID, data.Destination, data.Access, data.Delivery = "job-source", p.Inputs.Sources.Project.GrantID, "/job/source", "ro", "bind_ro"
	grants.Data = []DataGrant{data}
	w.Lease.GrantSetID = grants.ID
	stage := LaunchDataStage{Grants: grants, ID: "data-stage", Reservation: p.Reservation, Inputs: p.Inputs, AgentLeaseID: p.Lease.ID, ParentEffectID: "parent-plan-effect", Claim: w.Claim, Worker: w.Lease,
		WorkerLaunchID: w.Record.ID, Process: ProcessHandle{ID: "data-process", Target: p.Reservation.Target, ContainmentID: w.Record.ContainmentID, Generation: w.Record.ProcessGeneration},
		Plan: WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Executable: Executable{ID: "laneboss-worker", Version: "fixture-v1", SHA256: launchFixtureBlob("worker-binary", "manifest").SHA256},
			Argv: []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(w.Lease.ID)}, Input: w.Lease.Input, GrantSetID: grants.ID, Budget: p.Budget},
		Storage: StorageProjection{StageID: "data-stage", Storage: LaunchStorage{ReservationID: p.Reservation.ID, Target: p.Reservation.Target, LeaseID: p.Lease.ID, WorkspaceID: p.Data.Workspace.ID, Home: p.Data.Home},
			WorkerLeaseID: w.Lease.ID, OpenToken: "opened-storage", Generation: 1, SourceIdentity: p.Data.Materialization.Objects[0].SourceIdentity,
			WorkspaceIdentity: p.Data.Materialization.Objects[0].DestinationIdentity, HomeIdentity: "home-inode", Evidence: launchFixtureBlob("storage-projection", "manifest")}}
	retainedPlan := stage.Plan
	stage.Claim.Record.Effect.Worker = &retainedPlan
	zero, survivors := 0, uint64(0)
	result := LaunchDataResult{StageID: stage.ID, WorkerLeaseID: w.Lease.ID, EffectID: w.Lease.EffectID, OperationID: p.Reservation.OperationID, InputSHA256: w.Lease.Input.SHA256,
		Data: p.Data, Manifest: p.Data.Materialization.Manifest, ReadBackSHA256: p.Data.Materialization.Manifest.SHA256,
		Observation: ProcessObservation{Handle: stage.Process, State: "exited", ExitCode: &zero, Survivors: &survivors, PromptStatus: "completed", ObservedAt: contractStamp(contractNow())}}
	canonical, _ := launchFixtureHash(t, result.Data)
	result.ResultReceipt = WorkerResultReceipt{LeaseID: w.Lease.ID, StageID: stage.ID, Generation: 2, CommittedSeq: 5, Result: contractBlob("data-result", "worker_result", canonical)}
	return stage, LaunchDataRequest{ReservationID: p.Reservation.ID, GrantSetID: p.Reservation.GrantSetID, LeaseID: p.Lease.ID}, result
}

func TestDataStage(t *testing.T) {
	s, r, _ := dataStageFixture(t)
	if err := ValidateLaunchDataStage(s, r); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"parent", "input", "storage", "open", "argv", "epoch", "grants"} {
		t.Run(fault, func(t *testing.T) {
			s, r, _ := dataStageFixture(t)
			switch fault {
			case "parent":
				s.ParentEffectID = s.Claim.Record.Effect.ID
			case "input":
				s.Plan.Input.ID = "foreign-input"
			case "storage":
				s.Storage.WorkerLeaseID = "foreign-worker"
			case "open":
				s.Storage.OpenToken = ""
			case "argv":
				s.Plan.Argv = []string{"caller-command"}
			case "epoch":
				s.Claim.Record.Effect.Context.CancellationEpoch++
			case "grants":
				s.Grants.Network = []NetworkGrant{{ID: "extra-network", EndpointID: "extra-endpoint"}}
			}
			// Keep the claimed plan self-consistent; the input/argv pins decide.
			retainedPlan := s.Plan
			s.Claim.Record.Effect.Worker = &retainedPlan
			requireLaunchInvalid(t, ValidateLaunchDataStage(s, r), "materialization stage claim was bypassed")
		})
	}
}

func TestDataResult(t *testing.T) {
	s, _, r := dataStageFixture(t)
	if err := ValidateLaunchDataResult(s, r); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"run", "operation", "exit", "process", "readback", "source"} {
		t.Run(fault, func(t *testing.T) {
			s, _, r := dataStageFixture(t)
			switch fault {
			case "run":
				r.Data.Target.Run++
			case "operation":
				r.OperationID = "foreign-operation"
			case "exit":
				one := 1
				r.Observation.ExitCode = &one
			case "process":
				r.Observation.Handle.Generation = "foreign-kernel-generation"
			case "readback":
				r.ReadBackSHA256 = launchFixtureBlob("other-readback", "manifest").SHA256
			case "source":
				r.Data.Materialization.Objects[0].SourceIdentity = "replaced-source-inode"
			}
			// Preserve the acknowledged bytes so the nominated result pin decides.
			canonical, _ := launchFixtureHash(t, r.Data)
			r.ResultReceipt.Result = contractBlob("data-result", "worker_result", canonical)
			requireLaunchInvalid(t, ValidateLaunchDataResult(s, r), "materialization measured result was bypassed")
		})
	}
}
