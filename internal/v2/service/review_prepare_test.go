package service

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type reviewPreparingState struct {
	*reviewContextState
	receipt  api.MutationReceipt
	lease    api.WorkerLease
	mode     string
	reserved int
}

func (f *reviewPreparingState) LookupReceipt(_ context.Context, _ api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	if key != f.receipt.Key {
		return api.MutationReceipt{}, serviceError(api.CodeNotFound, "component original reservation is absent")
	}
	return f.receipt, nil
}
func (f *reviewPreparingState) OwnsMutation(_ context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	return f.mode != "owner" && key == f.receipt.Key && operation == f.receipt.Operation.ID && scope.Request.Method == key.Method, nil
}
func (f *reviewPreparingState) WorkerLease(_ context.Context, _ api.Scope, id api.ID) (api.WorkerLease, error) {
	if id != f.lease.ID {
		return api.WorkerLease{}, serviceError(api.CodeNotFound, "component retained worker is absent")
	}
	return f.lease, nil
}
func (f *reviewPreparingState) ReserveReviewWorker(_ context.Context, scope api.Scope, request api.ReviewRequest, subject api.ReviewSubject, required []string) (api.WorkerLease, error) {
	f.reserved++
	if scope.Request.Method != f.receipt.Key.Method || scope.Request.IdempotencyKey != f.receipt.Key.IdempotencyKey {
		return api.WorkerLease{}, serviceError(api.CodeForbidden, "component reservation changed the original dispatcher")
	}
	input := reviewjob.Input{Schema: "laneboss.review-input.v2", Subject: subject, Request: request, Required: required,
		Base: subject.Snapshot, Checks: []api.ReviewCheckFact{}, Resolutions: []api.ReviewResolution{},
		Inventory: api.ReviewInventory{Manifest: request.RecordInventory, ThroughSeq: subject.InventorySeq, Streams: []api.ReviewStreamFact{}, ToolRecords: subject.Snapshot, ToolCoverage: api.CoveragePartial}}
	if f.mode == "input" {
		input.Subject.EndSeq++
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return api.WorkerLease{}, err
	}
	ref := api.BlobRef{ID: "prepared-review-input", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	f.objects[ref.ID] = raw
	f.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: "service", SourceOperationID: f.receipt.Operation.ID,
		ACL: api.ObjectACL{Config: scope.Config, Owner: api.Actor{Kind: "service", ID: "review-coordinator"}, LifeID: subject.Target.LifeID, Audience: "private", Generation: 1}}
	f.lease.Input = ref
	if f.mode == "operation" {
		f.lease.OperationID = "foreign-operation"
	}
	if f.mode == "runtime" {
		f.lease.RuntimeManifest.SHA256 = digestBytes([]byte("foreign runtime"))
	}
	return f.lease, nil
}

func TestReviewPrepareLease(t *testing.T) {
	for _, mode := range []string{"valid", "owner", "input", "operation", "runtime"} {
		t.Run(mode, func(t *testing.T) {
			host, base, scope := reviewContextFixture(t)
			artifact := digestBytes([]byte(t.Name()))
			host.deps.Binding.ArtifactSHA256 = artifact
			runtime := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
				Artifact:  api.Executable{ID: "installed-artifact", SHA256: artifact, Version: "component"},
				Bootstrap: api.Executable{ID: "installed-bootstrap", SHA256: artifact, Version: "component"}, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
			raw, err := json.Marshal(runtime)
			if err != nil {
				t.Fatal(err)
			}
			ref := api.BlobRef{ID: "review-runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
			base.objects[ref.ID] = raw
			base.metadata[ref.ID] = api.ObjectMetadata{Ref: ref, Origin: "service", SourceOperationID: "runtime-publication", ACL: api.ObjectACL{Config: scope.Config}}
			key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
			state := &reviewPreparingState{reviewContextState: base, mode: mode,
				receipt: api.MutationReceipt{Key: key, Operation: api.Operation{ID: "original-review-operation", Status: "pending"}},
				lease: api.WorkerLease{ID: "native-review-lease", Kind: "export", Target: base.subject.Target,
					OperationID: "original-review-operation", EffectID: "review-effect", GrantSetID: "review-grants", Generation: 1,
					RuntimeManifest: ref, ExpiresAt: "2031-01-01T00:00:00Z"}}
			host.deps.Store = state
			var request api.ReviewRequest
			if err := api.DecodeObject(scope.Request.Params, &request); err != nil {
				t.Fatal(err)
			}
			prepared, err := host.PrepareReview(context.Background(), scope, request, base.subject.Generation, base.subject.EndEventID, base.subject.EndSeq)
			if mode == "valid" {
				if err != nil || prepared.Lease.ID != state.lease.ID || prepared.Lease.OperationID != state.receipt.Operation.ID || state.reserved != 1 {
					t.Fatalf("review preparation lost its exact retained worker: %v", err)
				}
			} else if err == nil || prepared.Lease.ID != "" {
				t.Fatalf("foreign review preparation was accepted: %s: %v", mode, err)
			}
		})
	}
}
