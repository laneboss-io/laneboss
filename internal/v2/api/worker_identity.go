package api

import (
	"context"
	"reflect"
	"time"
)

type WorkerOperation string

const (
	WorkerInputRead        WorkerOperation = "input.read"
	WorkerObjectRead       WorkerOperation = "object.read"
	WorkerResultAppend     WorkerOperation = "result.append"
	WorkerArchivePart      WorkerOperation = "archive.part"
	WorkerPrincipalRead    WorkerOperation = "principal.read"
	WorkerCaptureState     WorkerOperation = "capture.state"
	WorkerCaptureAppend    WorkerOperation = "capture.append"
	WorkerCredentialInject WorkerOperation = "credential.inject"
	WorkerChannelContext   WorkerOperation = "channel.context"
	WorkerChannelReceipt   WorkerOperation = "channel.receipt"
	WorkerJudgeContext     WorkerOperation = "judge.context"
	WorkerJudgeRetain      WorkerOperation = "judge.retain"
)

// A protected reverse lookup from installed worker lease + native peer facts.
// The store joins real helper/kernel/endpoint/job/claim records before returning.
type WorkerPrincipal struct {
	StageID              ID
	Lease                WorkerLease
	Record               LaunchRecord
	Endpoint             InstalledBinding
	Peer                 PeerFacts
	BootID               string
	AllocationGeneration Generation
	Claim                EffectLease
	CancellationEpoch    Generation
	CaptureBindingID     ID
}

type WorkerIdentityStore interface {
	WorkerBinding(context.Context, InstalledBinding, PeerFacts) (WorkerPrincipal, error)
}

func workerPermits(kind string, operation WorkerOperation) bool {
	if operation == WorkerJudgeContext || operation == WorkerJudgeRetain {
		return kind == "judge"
	}
	if operation == WorkerChannelContext || operation == WorkerChannelReceipt {
		return kind == "channel"
	}
	if operation == WorkerArchivePart {
		return kind == "archive"
	}
	if kind == "capture" {
		return operation == WorkerCaptureState || operation == WorkerCaptureAppend
	}
	switch kind {
	case "judge", "channel", "materialize", "usage", "test", "import", "export", "archive", "render", "box_run", "owner_sheet", "gateway":
		if operation == WorkerPrincipalRead || operation == WorkerInputRead || operation == WorkerObjectRead || operation == WorkerResultAppend {
			return true
		}
		return operation == WorkerCredentialInject && (kind == "channel" || kind == "usage")
	}
	return false
}

// Structural correlation only. Current expiry, claim, revocation and native
// liveness are also rechecked by identity/store on every frame and delivery.
func ValidateWorkerPrincipal(p WorkerPrincipal, endpoint InstalledBinding, peer PeerFacts, operation WorkerOperation, now time.Time) error {
	e, r, lease := p.Endpoint, p.Record, p.Lease
	expires, expiryErr := time.Parse(time.RFC3339Nano, string(lease.ExpiresAt))
	claimExpiry, claimErr := time.Parse(time.RFC3339Nano, string(p.Claim.ExpiresAt))
	cause := p.Claim.Record.Effect.Context
	if !launchID(p.StageID) || !reflect.DeepEqual(endpoint, e) || e.Class != EndpointWorker || e.Target == nil || *e.Target != lease.Target ||
		!launchID(lease.ID) || e.WorkerLeaseID != lease.ID || e.LaunchID != r.ID || e.Config != r.Config ||
		r.Kind != "worker" || r.Actor.Kind != "worker" || !launchID(r.Actor.ID) || r.Actor.Level != 0 || r.Actor.Role != "" || r.Revoked ||
		r.Target != lease.Target || lease.ConsumedBy != r.ID || r.GrantSetID != lease.GrantSetID ||
		r.EndpointGeneration != e.EndpointGeneration || !launchGeneration(e.EndpointGeneration) || !launchGeneration(lease.Generation) ||
		p.Peer != peer || peer.HostUID == 0 || peer.HostGID == 0 || peer.HostPID <= 0 || peer.ProcessGeneration == "" ||
		r.HostUID != peer.HostUID || r.ContainmentID != peer.ContainmentID || !launchID(peer.ContainmentID) || r.ProcessGeneration == "" ||
		p.BootID == "" || !launchGeneration(p.AllocationGeneration) || p.CancellationEpoch > launchMaxInteger ||
		expiryErr != nil || claimErr != nil || !now.Before(expires) || !now.Before(claimExpiry) ||
		!launchID(p.Claim.ClaimID) || p.Claim.Record.ClaimID != p.Claim.ClaimID || p.Claim.Record.ClaimExpiresAt != p.Claim.ExpiresAt || !EffectLeaseClaimed(p.Claim) ||
		p.Claim.Record.Effect.ID != lease.EffectID || p.Claim.Record.Effect.OperationID != lease.OperationID || cause == nil ||
		cause.Config != e.Config || cause.Target != lease.Target || cause.CauseOperationID != lease.OperationID || cause.CancellationEpoch != p.CancellationEpoch ||
		lease.Kind == "capture" && !launchID(p.CaptureBindingID) || lease.Kind != "capture" && p.CaptureBindingID != "" ||
		!workerPermits(lease.Kind, operation) {
		return launchInvalid("worker endpoint differs from its current leased principal")
	}
	return nil
}
