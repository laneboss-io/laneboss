package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These fixtures assert module/port interactions, not real authentication,
// transaction isolation or filesystem publication. Installed cells prove those.
func readyFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.store.snapshot = &api.OrgSnapshot{Config: f.scope.Config, Ref: f.store.change.SourceSnapshot,
		Sources: []api.ResourceFile{}, Derived: []api.ResourceFile{}, Renderer: f.store.change.Renderer,
		OwnershipManifest: f.store.change.OwnershipManifest}
	f.store.blobs["ownership"] = []byte("source ownership inventory\n")
	f.store.metadata = map[api.ID]api.BlobRef{"ownership": f.store.change.OwnershipManifest}
	approved := testApproval(f.store.change)
	f.store.approval = &approved
	// Model a renderer's retained byte plan, not reuse of its old object ID.
	// Keep this independent of later corruption of the approved object store.
	diffBytes := append([]byte(nil), f.store.blobs[f.store.change.Diff.ID]...)
	f.worker.render = func(input api.ChangeRequest) (api.ChangeRequest, error) {
		if len(input.Derived) != 0 || input.Diff != (api.BlobRef{}) || input.ManifestSHA256 != "" {
			t.Fatal("renderer received retained derived, diff or manifest outputs")
		}
		input.Diff = f.retainRendered(diffBytes, "artifact")
		rehash(t, &input)
		return input, nil
	}
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		if err := api.ValidateTransactionShape(tx); err != nil {
			t.Fatalf("module sent an invalid transaction: %v", err)
		}
		return api.Commit{Operation: api.Operation{ID: "operation-one", Status: "succeeded"}, Reply: tx.Reply}, nil
	}
	f.human.check = func(scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
		return api.VerifiedHumanProof{Ref: proof, Config: scope.Config, PrincipalID: scope.Actor.ID,
			EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration,
			CredentialID: "verified-key", NonceID: "verified-nonce", ConnectionID: "human-connection",
			Target: target, VerifiedAt: "2026-10-15T09:00:00Z", AssertionEvidence: testRef("assertion", []byte("verified assertion fixture"))}, nil
	}
	return f
}

func TestStageCommit(t *testing.T) {
	f := readyFixture(t)
	scope := f.bound("org.change.propose", f.request, false)
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		if len(tx.Writes.Changes) != 1 || len(tx.Events) != 1 || len(tx.Effects) != 0 || len(tx.Guards) != 0 {
			t.Fatal("staging did not retain exactly one inert change and event")
		}
		staged := tx.Writes.Changes[0]
		want := []api.Compare{{Kind: api.CompareOrg, ID: f.request.OrgID, Generation: f.request.BaseGeneration},
			{Kind: api.CompareChange, ID: staged.ID}}
		if !reflect.DeepEqual(tx.Compare, want) {
			t.Fatal("stage CAS did not bind the current org and absent change")
		}
		if !bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) || tx.Events[0].Kind != "org.change.proposed" {
			t.Fatal("stage lost its exact request or causal event")
		}
		var payload api.ChangeEvent
		if err := DecodeJSON(tx.Events[0].Payload, &payload); err != nil || !reflect.DeepEqual(payload.Change, staged) {
			t.Fatalf("staging event differs from the written change: %v", err)
		}
		return api.Commit{Operation: api.Operation{ID: "operation-one", Status: "succeeded"}, Reply: tx.Reply}, nil
	}
	got, err := f.service.OrgChangePropose(context.Background(), scope, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != scope.Config || got.Reason != f.request.Reason || got.SourceSnapshot != f.store.snapshot.Ref ||
		got.OwnershipManifest != f.store.snapshot.OwnershipManifest || got.Renderer != f.store.snapshot.Renderer ||
		f.worker.renders != 1 || f.store.mutations != 1 || f.human.checked != 0 {
		t.Fatal("stage omitted approved provenance or crossed the approval boundary")
	}
}

func TestApprovalCommit(t *testing.T) {
	f := readyFixture(t)
	request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
	scope := f.bound("org.change.approve", request, true)
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: request.ChangeID,
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: request.BaseGeneration}
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		if len(tx.Guards) != 1 || tx.Guards[0].Proof == nil ||
			*tx.Guards[0].Proof != (api.ProofUse{Proof: *scope.Request.Proof, Target: target}) {
			t.Fatal("approval proof-use guard missing or changed")
		}
		if len(tx.Writes.Approvals) != 1 || len(tx.Effects) != 0 || len(tx.Events) != 1 || tx.Events[0].Kind != "org.change.approved" {
			t.Fatal("approval did not atomically retain its receipt and event")
		}
		approval := tx.Writes.Approvals[0]
		if approval.ApproverKeyID != "verified-key" || approval.NonceID != "verified-nonce" ||
			approval.RequesterLifeID != f.scope.Actor.LifeID || !bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) {
			t.Fatal("approval fabricated key/nonce facts or lost its original intent")
		}
		want := []api.Compare{{Kind: api.CompareOrg, ID: f.store.change.OrgID, Generation: 7},
			{Kind: api.CompareApproval, ID: approval.ID}}
		if !reflect.DeepEqual(tx.Compare, want) {
			t.Fatal("approval CAS omitted the org or absent receipt")
		}
		return api.Commit{Operation: api.Operation{ID: "operation-one", Status: "succeeded"}, Reply: tx.Reply}, nil
	}
	got, err := f.service.OrgChangeApprove(context.Background(), scope, request)
	if err != nil {
		t.Fatalf("approval guarded transaction refused: %v", err)
	}
	if got.ExpiresAt != "2026-10-15T09:10:00Z" || f.human.checked != 1 || f.store.mutations != 1 || f.worker.renders != 0 {
		t.Fatal("approval skipped verification, lost its independent ten-minute window or ran a renderer")
	}
}

func TestApplyCompletion(t *testing.T) {
	for _, name := range []string{"complete", "unavailable", "pending_reply", "deadline"} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: f.store.approval.ID, ExpectedGeneration: 7}
			scope := f.bound("org.change.apply", request, false)
			queued, awaited := false, 0
			f.store.transact = func(tx api.Transaction) (api.Commit, error) {
				guard := api.ApprovalUse{ApprovalID: request.ApprovalID, ChangeID: request.ChangeID,
					ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
				if len(tx.Guards) != 1 || tx.Guards[0].Approval == nil || *tx.Guards[0].Approval != guard {
					t.Fatal("application approval-use guard missing or changed")
				}
				if !reflect.DeepEqual(tx.Compare, []api.Compare{{Kind: api.CompareOrg, ID: f.store.change.OrgID, Generation: 7}}) {
					t.Fatal("application CAS omitted the approved org base")
				}
				if tx.Reply != nil || len(tx.Events) != 0 || len(tx.Writes.Applications) != 0 || len(tx.Effects) != 1 {
					t.Fatal("publication was claimed before its durable completion")
				}
				effect := tx.Effects[0]
				if effect.ApplyChange == nil || *effect.ApplyChange != request || effect.Context == nil ||
					effect.Context.Kind != api.InternalOrgPublish || effect.Context.RequestedBy != scope.Actor ||
					effect.Context.CauseOperationID != "operation-one" || effect.Context.CauseRequestID != scope.Request.RequestID ||
					effect.Context.EffectID != effect.ID || effect.Context.Target != f.store.launch.Target ||
					!bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) {
					t.Fatal("publication intent lost its exact request or real causality")
				}
				deferred := api.DeferredReply{Key: requestKey(scope), OperationID: effect.OperationID, EffectID: effect.ID}
				if tx.Deferred == nil || *tx.Deferred != deferred {
					t.Fatal("publication deferred binding lost its reservation or effect")
				}
				queued = true
				return api.Commit{Operation: api.Operation{ID: effect.OperationID, Status: "pending"}, Deferred: tx.Deferred}, nil
			}
			wanted := api.ChangeReceipt{ID: "published-receipt", ChangeID: request.ChangeID, ApprovalID: request.ApprovalID,
				OldGeneration: 7, NewGeneration: 8, ManifestSHA256: f.store.change.ManifestSHA256, AppliedAt: "2026-10-15T09:01:00Z"}
			unavailable := api.NotImplemented("lb-v2-service", "fixture publisher unavailable")
			f.store.await = func(current api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
				awaited++
				if !queued || key != requestKey(scope) || current.Actor != scope.Actor {
					t.Fatal("publication wait did not follow the original guarded operation")
				}
				if name == "unavailable" {
					return api.MutationReceipt{}, unavailable
				}
				if name == "deadline" {
					return api.MutationReceipt{}, &api.Error{Code: api.CodeDeadline, Owner: "lb-v2-service", Message: "fixture wait deadline"}
				}
				raw, err := json.Marshal(wanted)
				if err != nil {
					t.Fatal(err)
				}
				status := "succeeded"
				if name == "pending_reply" {
					status = "pending"
				}
				return api.MutationReceipt{Config: scope.Config, Key: requestKey(scope), Actor: scope.Actor,
					Operation: api.Operation{ID: "operation-one", Status: status}, Reply: &api.RPCReply{Result: raw}}, nil
			}
			got, err := f.service.OrgChangeApply(context.Background(), scope, request)
			if name == "unavailable" {
				if err != unavailable || got.ID != "" {
					t.Fatalf("queued publication was reported as success: %v", err)
				}
			} else if name == "pending_reply" {
				codeIs(t, err, api.CodeIntegrity)
				if got.ID != "" {
					t.Fatal("pending completion exposed a publication receipt")
				}
			} else if name == "deadline" {
				codeIs(t, err, api.CodeDeadline)
				if err.(*api.Error).OperationID != "operation-one" || got.ID != "" {
					t.Fatal("publication deadline lost the original operation reference")
				}
			} else if err != nil || got != wanted {
				t.Fatalf("application did not return the durable publication reply: %v", err)
			}
			if awaited != 1 || f.store.mutations != 1 || f.worker.renders != 1 {
				t.Fatal("application omitted its revalidation, guarded intent or completion wait")
			}
		})
	}
}

func TestCompletedReplay(t *testing.T) {
	for _, method := range []api.Method{"org.change.propose", "org.change.approve", "org.change.apply"} {
		t.Run(string(method), func(t *testing.T) {
			f := newFixture(t)
			var request, value any
			switch method {
			case "org.change.propose":
				request, value = f.request, f.store.change
			case "org.change.approve":
				request = api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
				value = testApproval(f.store.change)
			case "org.change.apply":
				request = api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: "approval-one", ExpectedGeneration: 7}
				value = api.ChangeReceipt{ID: "old-receipt", ChangeID: f.store.change.ID, ApprovalID: "approval-one",
					OldGeneration: 7, NewGeneration: 8, ManifestSHA256: f.store.change.ManifestSHA256, AppliedAt: "2026-10-15T09:01:00Z"}
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			f.service.deps.Clock = fixtureClock{now: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)}
			scope := f.bound(method, request, method == "org.change.approve")
			retained := api.MutationReceipt{Config: scope.Config, Key: requestKey(scope), Actor: scope.Actor,
				Operation: api.Operation{ID: "old-operation", Status: "succeeded"}, Reply: &api.RPCReply{Result: raw}}
			f.store.receipts[fixtureDomain(scope, retained.Key)] = retained
			encoded, err := handlerForReplay(f, method)(context.Background(), scope, scope.Request.Params)
			if err != nil || !bytes.Equal(encoded, raw) {
				t.Fatalf("completed replay reached freshness or current state: %v", err)
			}
			if f.store.changes != 0 || f.store.reads != 0 {
				t.Fatal("completed replay re-read expired resources")
			}
			f.noEffects()
		})
	}
}

func handlerForReplay(f *fixture, method api.Method) api.Handler {
	registry := &fixtureRegistry{}
	if err := f.service.Register(registry); err != nil {
		f.t.Fatal(err)
	}
	return registry.methods[method]
}

func TestStageWorkerAlias(t *testing.T) {
	f := readyFixture(t)
	render := f.worker.render
	f.worker.render = func(input api.ChangeRequest) (api.ChangeRequest, error) {
		input.Files[0].Mode = 0600
		return render(input)
	}
	_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
	codeIs(t, err, api.CodeIntegrity)
	if f.request.Files[0].Mode != 0755 || f.store.mutations != 0 {
		t.Fatal("worker mutated retained input or committed an altered source")
	}
}

func TestVerifiedFacts(t *testing.T) {
	f := readyFixture(t)
	request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
	scope := f.bound("org.change.approve", request, true)
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: request.ChangeID,
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 7}
	facts, err := f.human.check(scope, *scope.Request.Proof, target)
	if err != nil {
		t.Fatal(err)
	}
	now := f.service.deps.Clock.Now()
	if _, err := approvalFromProof(now, scope, "operation-one", f.store.change, facts); err != nil {
		t.Fatal(err)
	}
	t.Run("expired_stage", func(t *testing.T) {
		change := f.store.change
		change.ExpiresAt = api.Timestamp(now.UTC().Format(time.RFC3339Nano))
		_, err := approvalFromProof(now, scope, "operation-one", change, facts)
		codeIs(t, err, api.CodeForbidden)
	})
	for name, edit := range map[string]func(*api.VerifiedHumanProof){
		"config":    func(p *api.VerifiedHumanProof) { p.Config = "other-config" },
		"principal": func(p *api.VerifiedHumanProof) { p.PrincipalID = "other-human" },
		"endpoint":  func(p *api.VerifiedHumanProof) { p.EndpointClass = api.EndpointLane },
		"generation": func(p *api.VerifiedHumanProof) {
			p.EndpointGeneration++
		},
		"target":   func(p *api.VerifiedHumanProof) { p.Target.TargetID = "other-change" },
		"nonce":    func(p *api.VerifiedHumanProof) { p.NonceID = "" },
		"key":      func(p *api.VerifiedHumanProof) { p.CredentialID = "" },
		"consumed": func(p *api.VerifiedHumanProof) { p.ConsumedBy = "other-operation" },
		"future":   func(p *api.VerifiedHumanProof) { p.VerifiedAt = "2026-10-15T09:00:01Z" },
		"ref":      func(p *api.VerifiedHumanProof) { p.Ref.ID = "other-proof" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := facts
			edit(&candidate)
			_, err := approvalFromProof(now, scope, "operation-one", f.store.change, candidate)
			codeIs(t, err, api.CodeForbidden)
		})
	}
}

func TestSnapshotRefusals(t *testing.T) {
	for _, name := range []string{"base", "generated", "before", "mode", "config"} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			want := api.CodeConflict
			ref := testRef("old-source", []byte("old source\n"))
			file := api.ResourceFile{Source: api.SourceRef{ID: "approved-source", Path: f.request.Files[0].Path,
				SHA256: ref.SHA256, Generation: 7}, Content: ref, Mode: 0755, RevisionGeneration: 3}
			switch name {
			case "base":
				f.store.snapshot.Ref.Generation++
			case "generated":
				f.store.snapshot.Derived = []api.ResourceFile{file}
				want = api.CodeForbidden
			case "before", "mode":
				f.store.snapshot.Sources = []api.ResourceFile{file}
				f.request.Files[0].Action, f.request.Files[0].BeforeSHA256 = "replace", testDigest([]byte("wrong preimage"))
				if name == "mode" {
					f.request.Files[0].Action, f.request.Files[0].After = "delete", nil
					f.request.Files[0].BeforeSHA256, f.request.Files[0].Mode = ref.SHA256, 0600
				}
			case "config":
				f.store.snapshot.Config = "other-config"
				want = api.CodeIntegrity
			}
			_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
			codeIs(t, err, want)
			if f.store.mutations != 0 || f.worker.renders != 0 {
				t.Fatal("invalid org source reached render or commit")
			}
		})
	}
}

func TestRetainedProvenance(t *testing.T) {
	for name, edit := range map[string]func(*api.ChangeRequest){
		"config":    func(c *api.ChangeRequest) { c.Config = "" },
		"reason":    func(c *api.ChangeRequest) { c.Reason = api.BlobRef{} },
		"ownership": func(c *api.ChangeRequest) { c.OwnershipManifest = api.BlobRef{} },
		"org":       func(c *api.ChangeRequest) { c.SourceSnapshot.OrgID = "other-org" },
		"base":      func(c *api.ChangeRequest) { c.SourceSnapshot.Generation++ },
		"hash":      func(c *api.ChangeRequest) { c.SourceSnapshot.ManifestSHA256 = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			edit(&f.store.change)
			codeIs(t, ValidateChange(f.store.change), api.CodeIntegrity)
		})
	}
}

func TestReadConfig(t *testing.T) {
	f := newFixture(t)
	f.store.change.Config = "other-config"
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	_, err := f.service.OrgChangeGet(context.Background(), f.bound("org.change.get", request, false), request)
	codeIs(t, err, api.CodeIntegrity)
	f.noEffects()
}

func TestBlobMetadata(t *testing.T) {
	f := newFixture(t)
	actual := f.request.Reason
	actual.Class = "report"
	f.store.metadata = map[api.ID]api.BlobRef{actual.ID: actual}
	codeIs(t, f.service.verifyBlob(context.Background(), f.scope, f.request.Reason), api.CodeIntegrity)
	if f.store.reads != 0 {
		t.Fatal("unmatched committed metadata reached blob reads")
	}
}

func TestRetainedFrame(t *testing.T) {
	for _, name := range []string{"absent", "changed"} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			scope := f.bound("org.change.propose", f.request, false)
			if name == "absent" {
				scope.Frame = nil
			} else {
				other := scope.Request
				other.RequestID = api.ID("other-" + string(other.RequestID))
				raw, err := json.Marshal(other)
				if err != nil {
					t.Fatal(err)
				}
				scope.Frame = fixtureFrame(raw)
			}
			_, err := f.service.OrgChangePropose(context.Background(), scope, f.request)
			codeIs(t, err, api.CodeIntegrity)
			if f.store.mutations != 0 {
				t.Fatal("unretained or changed frame reached the commit")
			}
		})
	}
}

func TestIncompleteCommit(t *testing.T) {
	f := readyFixture(t)
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		return api.Commit{Operation: api.Operation{ID: "operation-one", Status: "pending"}, Reply: tx.Reply}, nil
	}
	_, err := f.service.OrgChangePropose(context.Background(), f.bound("org.change.propose", f.request, false), f.request)
	codeIs(t, err, api.CodeIntegrity)
}
