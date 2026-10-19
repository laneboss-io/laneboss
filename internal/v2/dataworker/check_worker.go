package dataworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// RunChecks is the compiled snapshot-integrity test. Every tree, object and
// multipart aggregate is actually read and hashed in its own native test job.
// No arbitrary caller command executes in this worker or in the service.
func RunChecks(ctx context.Context, job ReviewJob) (api.WorkerResultReceipt, error) {
	var zero api.WorkerResultReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	p := job.Principal
	if missing(job.Bootstrap) || missing(job.Clock) || job.Read == nil || p.Lease.Kind != "test" || p.Lease.Input.Class != "manifest" ||
		job.Scope.Actor != p.Record.Actor || job.Scope.Config != p.Endpoint.Config || job.Scope.LaunchID != p.Record.ID || job.Scope.EndpointGeneration != p.Record.EndpointGeneration || job.Scope.Request.Method != "" {
		return zero, lstate.Error(api.CodeForbidden, "check requires its own authenticated fixed test job")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, job.Clock.Now()); err != nil {
		return zero, err
	}
	envelope, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerInput(p, envelope, job.Clock.Now()); err != nil {
		return zero, err
	}
	var input reviewjob.CheckInput
	if api.DecodeObject(envelope.Bytes, &input) != nil || input.Schema != "laneboss.check-input.v2" || input.Subject.Target != p.Lease.Target || input.Request.Child != p.Lease.Target || input.Subject.EndSeq == 0 ||
		input.Plan.Kind != "test" || input.Plan.Input != input.Request.Candidate || !slices.Equal(input.Plan.Argv, []string{"laneboss", "check", reviewjob.SnapshotIntegrity}) ||
		!slices.Equal(input.Required, []string{reviewjob.SnapshotIntegrity}) || p.Claim.Record.Effect.Worker == nil || input.Plan.Executable != p.Claim.Record.Effect.Worker.Executable {
		return zero, lstate.Error(api.CodeIntegrity, "check input changed its frozen subject or declared fixed test")
	}
	read := func(ref api.BlobRef) ([]byte, error) { return readWorkerObject(ctx, job.Read, ref) }
	trees := make([]api.ObjectManifest, 0, 3)
	seen := map[api.ID]api.BlobRef{}
	for _, ref := range []api.BlobRef{input.Base, input.Subject.Snapshot, input.Request.Candidate} {
		raw, err := read(ref)
		if err != nil {
			return zero, err
		}
		var tree api.ObjectManifest
		if api.DecodeObject(raw, &tree) != nil || manifest.Object(tree) != nil {
			return zero, manifest.Invalid("check input is not an actual bounded object tree")
		}
		trees = append(trees, tree)
		for _, entry := range tree.Entries {
			for _, content := range manifest.ContentRefs(entry) {
				if prior, ok := seen[content.ID]; ok {
					if prior != content {
						return zero, manifest.Invalid("check tree aliases content identity")
					}
					continue
				}
				if len(seen) >= 4096 {
					return zero, lstate.Error(api.CodeBudget, "check tree exceeds its object bound")
				}
				seen[content.ID] = content
				if _, err := read(content); err != nil {
					return zero, err
				}
			}
			if entry.Assembly != nil {
				hash, size := sha256.New(), int64(0)
				for _, part := range entry.Assembly.Parts {
					raw, err := read(part)
					if err != nil {
						return zero, err
					}
					_, _ = hash.Write(raw)
					size += int64(len(raw))
				}
				if size != entry.Assembly.Bytes || api.Digest(hex.EncodeToString(hash.Sum(nil))) != entry.Assembly.SHA256 {
					return zero, manifest.Invalid("check multipart bytes differ from their declared aggregate")
				}
			}
		}
	}
	output := reviewjob.CheckResult{Schema: "laneboss.check-result.v2", Subject: input.Subject, Candidate: input.Request.Candidate,
		Diff: reviewTreeDiff(trees[0], trees[1], input.Base.SHA256, input.Subject.Snapshot.SHA256),
		Checks: []reviewjob.CheckRecord{{Schema: "laneboss.check.v2", Name: reviewjob.SnapshotIntegrity, Target: p.Lease.Target, EndSeq: input.Subject.EndSeq, SnapshotSHA256: input.Subject.Snapshot.SHA256,
			ExitCode: 0, WorkerLeaseID: p.Lease.ID, OperationID: p.Lease.OperationID}}}
	// All success fields above follow complete actual reads. A failed read/hash
	// returns without submitting any successful check or result acknowledgement.
	raw, err := json.Marshal(output)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return zero, err
	}
	if len(raw) > api.MaxFrameBytes {
		return zero, lstate.Error(api.CodeBudget, "check result exceeds its frame bound")
	}
	result, err := job.Bootstrap.WorkerResult(ctx, job.Scope, api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw})
	if err != nil {
		return zero, err
	}
	return result, api.ValidateWorkerResult(p, api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}, result, job.Clock.Now())
}
