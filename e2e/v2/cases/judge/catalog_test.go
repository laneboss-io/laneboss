package judgecase

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are structural catalog tests. Real native peer and current store
// checks remain mandatory; this value grants no process or dispatch authority.
func judgePrincipal(now time.Time) api.WorkerPrincipal {
	target := api.LifeRef{LifeID: "judge-life", Run: 1}
	expires := api.Timestamp(now.Add(time.Minute).UTC().Format(time.RFC3339Nano))
	lease := api.WorkerLease{ID: "judge-lease", Kind: "judge", Target: target,
		OperationID: "judge-operation", EffectID: "judge-effect", GrantSetID: "judge-grants",
		Generation: 1, ExpiresAt: expires, ConsumedBy: "judge-launch"}
	record := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: "judge-case", Target: target,
		Actor: api.Actor{Kind: "worker", ID: "judge-worker"}, HostUID: 12002,
		ContainmentID: "judge-containment", ProcessGeneration: "judge-leader",
		GrantSetID: lease.GrantSetID, EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Class: api.EndpointWorker, Config: record.Config,
		Target: &target, WorkerLeaseID: lease.ID, LaunchID: record.ID, EndpointGeneration: 1}
	cause := api.InternalIntent{ID: "judge-cause", Kind: api.InternalJudgeEvaluate,
		Config: record.Config, Actor: api.Actor{Kind: "service", ID: "judge-executor"},
		Target: target, CauseOperationID: lease.OperationID, EffectID: lease.EffectID, CancellationEpoch: 1}
	claim := api.EffectLease{ClaimID: "judge-claim", ExpiresAt: expires,
		Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "judge-claim",
			ClaimantID: "judge-executor", ClaimExpiresAt: expires,
			Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause}}}
	return api.WorkerPrincipal{StageID: "judge-stage", Lease: lease, Record: record, Endpoint: endpoint,
		Peer: api.PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100,
			ProcessGeneration: "judge-connector", ContainmentID: record.ContainmentID},
		BootID: "judge-boot", AllocationGeneration: 1, CancellationEpoch: 1, Claim: claim}
}

func TestJudgeNativeCatalog(t *testing.T) {
	now := time.Now()
	for _, operation := range []api.WorkerOperation{api.WorkerPrincipalRead,
		api.WorkerInputRead, api.WorkerObjectRead, api.WorkerResultAppend} {
		p := judgePrincipal(now)
		if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, operation, now); err != nil {
			t.Fatalf("native judge kind is absent from the worker catalog for %s: %v", operation, err)
		}
	}
	for _, fault := range []string{"claim", "peer", "principal", "expiry", "endpoint",
		"archive", "capture", "channel", "credential"} {
		t.Run(fault, func(t *testing.T) {
			p := judgePrincipal(now)
			endpoint, peer, operation := p.Endpoint, p.Peer, api.WorkerInputRead
			switch fault {
			case "claim":
				p.Claim.ClaimID = "foreign-claim"
			case "peer":
				peer.ProcessGeneration = "foreign-peer"
			case "principal":
				p.Record.Actor.Kind = "lane"
			case "expiry":
				p.Lease.ExpiresAt = api.Timestamp(now.UTC().Format(time.RFC3339Nano))
			case "endpoint":
				endpoint.EndpointGeneration++
			case "archive":
				operation = api.WorkerArchivePart
			case "capture":
				operation = api.WorkerCaptureAppend
			case "channel":
				operation = api.WorkerChannelReceipt
			case "credential":
				operation = api.WorkerCredentialInject
			}
			if err := api.ValidateWorkerPrincipal(p, endpoint, peer, operation, now); err == nil {
				t.Fatal("judge catalog changed an existing lease, peer or unrelated operation gate")
			}
		})
	}
}
