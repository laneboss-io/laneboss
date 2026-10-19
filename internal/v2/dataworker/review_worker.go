package dataworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type ReviewJob struct {
	Principal api.WorkerPrincipal
	Scope     api.Scope
	Bootstrap api.WorkerBootstrap
	Read      func(context.Context, api.BlobReadRequest) (api.BlobChunk, error)
	Clock     api.Clock
}

// RunReview executes only the compiled verifier in its authenticated worker.
// It reads actual frozen bytes and prior measured test facts; it never runs
// caller argv or treats an uploaded verdict as a completed test operation.
func RunReview(ctx context.Context, job ReviewJob) (api.WorkerResultReceipt, error) {
	var zero api.WorkerResultReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if missing(job.Bootstrap) || missing(job.Clock) || job.Read == nil {
		return zero, lstate.Error(api.CodePrerequisite, "review requires native bootstrap and scoped retained-object reads")
	}
	p := job.Principal
	if p.Lease.Kind != "export" || p.Lease.Input.Class != "manifest" || job.Scope.Actor != p.Record.Actor ||
		job.Scope.Config != p.Endpoint.Config || job.Scope.LaunchID != p.Record.ID ||
		job.Scope.EndpointGeneration != p.Endpoint.EndpointGeneration || job.Scope.Request.Method != "" {
		return zero, lstate.Error(api.CodeForbidden, "review worker cannot borrow its requester's identity")
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
	var input reviewjob.Input
	if api.DecodeObject(envelope.Bytes, &input) != nil || input.Schema != "laneboss.review-input.v2" ||
		input.Subject.Target != p.Lease.Target || input.Request.Target != p.Lease.Target ||
		input.Subject.Generation == 0 || input.Required == nil || len(input.Required) > 200 ||
		input.Checks == nil || len(input.Checks) == 0 || len(input.Checks) != len(input.Request.Checks) ||
		input.Inventory.Manifest != input.Request.RecordInventory || input.Inventory.ThroughSeq != input.Subject.InventorySeq ||
		p.Claim.Record.Effect.Worker == nil || p.Claim.Record.Effect.Worker.Schema != "laneboss.worker-plan.v2" ||
		p.Claim.Record.Effect.Worker.Kind != p.Lease.Kind || p.Claim.Record.Effect.Worker.Input != p.Lease.Input ||
		p.Claim.Record.Effect.Worker.GrantSetID != p.Lease.GrantSetID {
		return zero, lstate.Error(api.CodeIntegrity, "review input differs from its original frozen worker plan")
	}
	read := func(ref api.BlobRef) ([]byte, error) { return readWorkerObject(ctx, job.Read, ref) }
	baseRaw, err := read(input.Base)
	if err != nil {
		return zero, err
	}
	currentRaw, err := read(input.Subject.Snapshot)
	if err != nil {
		return zero, err
	}
	var base, current api.ObjectManifest
	if api.DecodeObject(baseRaw, &base) != nil || api.DecodeObject(currentRaw, &current) != nil ||
		manifest.Object(base) != nil || manifest.Object(current) != nil {
		return zero, lstate.Error(api.CodeIntegrity, "review requires actual committed base and frozen workspace manifests")
	}
	// Verify the content of both trees, including parts, rather than comparing
	// manifest labels. Reads remain confined to the sealed object closure.
	seen := make(map[api.ID]api.BlobRef)
	for _, tree := range []api.ObjectManifest{base, current} {
		for _, entry := range tree.Entries {
			for _, ref := range manifest.ContentRefs(entry) {
				if prior, ok := seen[ref.ID]; ok {
					if prior != ref {
						return zero, lstate.Error(api.CodeIntegrity, "review tree reuses an object with different bytes")
					}
					continue
				}
				if len(seen) >= 4096 {
					return zero, lstate.Error(api.CodeBudget, "review object closure exceeds its fixed bound")
				}
				seen[ref.ID] = ref
				if _, err := read(ref); err != nil {
					return zero, err
				}
			}
			if entry.Assembly != nil {
				digest, size := sha256.New(), int64(0)
				for _, part := range entry.Assembly.Parts {
					body, err := read(part)
					if err != nil {
						return zero, err
					}
					_, _ = digest.Write(body)
					size += int64(len(body))
				}
				if size != entry.Assembly.Bytes || api.Digest(hex.EncodeToString(digest.Sum(nil))) != entry.Assembly.SHA256 {
					return zero, lstate.Error(api.CodeIntegrity, "review tree assembly differs from its actual ordered bytes")
				}
			}
		}
	}
	diff := reviewTreeDiff(base, current, input.Base.SHA256, input.Subject.Snapshot.SHA256)
	diffRaw, err := read(input.Request.Diff)
	if err != nil {
		return zero, err
	}
	var candidate reviewjob.Diff
	if input.Request.Diff.Class != "diff" || api.DecodeObject(diffRaw, &candidate) != nil || !reflect.DeepEqual(candidate, diff) {
		return zero, lstate.Error(api.CodeIntegrity, "candidate diff differs from the actual frozen trees")
	}
	for index, check := range input.Checks {
		if check.Receipt != input.Request.Checks[index] || check.Receipt.Class != "check" {
			return zero, manifest.Invalid("review check set changed")
		}
		raw, err := read(check.Receipt)
		if err != nil {
			return zero, err
		}
		var actual reviewjob.CheckRecord
		if api.DecodeObject(raw, &actual) != nil || actual.Schema != "laneboss.check.v2" ||
			actual.Name != check.Name || actual.Target != check.Target || actual.EndSeq != check.EndSeq ||
			actual.SnapshotSHA256 != check.SnapshotSHA256 || actual.ExitCode != check.ExitCode ||
			actual.WorkerLeaseID != check.WorkerLeaseID || actual.OperationID != check.OperationID {
			return zero, lstate.Error(api.CodeIntegrity, "review check bytes differ from their retained measured test job")
		}
	}
	raw, err := read(input.Inventory.Manifest)
	if err != nil {
		return zero, err
	}
	var inventory reviewjob.InventoryRecord
	if api.DecodeObject(raw, &inventory) != nil || inventory.Schema != "laneboss.review-inventory.v2" ||
		inventory.ThroughSeq != input.Inventory.ThroughSeq || !reflect.DeepEqual(inventory.Streams, input.Inventory.Streams) ||
		inventory.ToolRecords != input.Inventory.ToolRecords || inventory.ToolCoverage != input.Inventory.ToolCoverage {
		return zero, lstate.Error(api.CodeIntegrity, "candidate inventory differs from the authenticated drained capture")
	}
	if input.Inventory.ToolRecords.ID != "" {
		if _, err := read(input.Inventory.ToolRecords); err != nil {
			return zero, err
		}
	}
	for _, resolution := range input.Resolutions {
		if _, err := read(resolution.Evidence); err != nil {
			return zero, err
		}
	}
	evidence := api.ReviewEvidence{Schema: "laneboss.review.v2", Subject: input.Subject, VerifierLeaseID: p.Lease.ID,
		Diff: input.Request.Diff, Checks: input.Checks, Inventory: input.Inventory, Resolutions: input.Resolutions, Coverage: api.CoveragePartial}
	if err := api.ValidateReviewEvidence(evidence, input.Subject); err != nil {
		return zero, err
	}
	// Complete is earned only if the shared acceptance validator accepts all
	// measured checks, exact ranges/EOF, tool coverage and refusal resolutions.
	evidence.Coverage = api.CoverageComplete
	actor := p.Claim.Record.Effect.Context.RequestedBy
	receipt := api.ReviewReceipt{ID: p.StageID, Reviewer: actor, Diff: evidence.Diff, Checks: input.Request.Checks,
		RecordInventory: evidence.Inventory.Manifest, RefusalResolution: input.Request.RefusalResolution,
		Coverage: evidence.Coverage, Evidence: &evidence}
	if err := api.ValidateReviewAcceptance(api.Scope{Actor: actor}, receipt, input.Subject, input.Required); err != nil {
		evidence.Coverage = api.CoveragePartial
	}
	raw, err = json.Marshal(evidence)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return zero, err
	}
	if len(raw) > api.MaxFrameBytes {
		return zero, lstate.Error(api.CodeBudget, "review result exceeds its bounded frame")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, job.Clock.Now()); err != nil {
		return zero, err
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	result, err := job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return zero, err
	}
	return result, api.ValidateWorkerResult(p, submission, result, job.Clock.Now())
}

func reviewTreeDiff(base, current api.ObjectManifest, baseHash, currentHash api.Digest) reviewjob.Diff {
	before, after := make(map[string]api.ObjectEntry), make(map[string]api.ObjectEntry)
	for _, entry := range base.Entries {
		before[entry.Path] = entry
	}
	for _, entry := range current.Entries {
		if strings.HasPrefix(entry.Path, "work/") {
			entry.Path = strings.TrimPrefix(entry.Path, "work/")
			after[entry.Path] = entry
		}
	}
	paths := make(map[string]bool)
	for path := range before {
		paths[path] = true
	}
	for path := range after {
		paths[path] = true
	}
	names := make([]string, 0, len(paths))
	for path := range paths {
		names = append(names, path)
	}
	sort.Strings(names)
	diff := reviewjob.Diff{Schema: "laneboss.review-diff.v2", Base: baseHash, Current: currentHash, Changes: []reviewjob.Change{}}
	for _, path := range names {
		a, aok := before[path]
		b, bok := after[path]
		if aok && bok && sameReviewEntry(a, b) {
			continue
		}
		change := reviewjob.Change{Path: path}
		if aok {
			change.Before = &a
		}
		if bok {
			change.After = &b
		}
		diff.Changes = append(diff.Changes, change)
	}
	return diff
}

func sameReviewEntry(a, b api.ObjectEntry) bool {
	if a.Path != b.Path || a.Kind != b.Kind || a.Mode != b.Mode || a.LinkTarget != b.LinkTarget {
		return false
	}
	if a.Kind != "file" {
		return true
	}
	content := func(entry api.ObjectEntry) (api.Digest, int64) {
		if entry.Content != nil {
			return entry.Content.SHA256, entry.Content.Bytes
		}
		if entry.Assembly != nil {
			return entry.Assembly.SHA256, entry.Assembly.Bytes
		}
		return "", -1
	}
	ah, as := content(a)
	bh, bs := content(b)
	return ah != "" && ah == bh && as == bs
}
