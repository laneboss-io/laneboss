package approval

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This fixture provides a complete deferred commit and durable reply. Removing
// a handler guard must reach a viable completion, not a dependency stub.
func completeApplyFixture(t *testing.T) (*fixture, api.ChangeApplyRequest) {
	t.Helper()
	f := readyFixture(t)
	request := api.ChangeApplyRequest{ChangeID: f.store.change.ID, ApprovalID: f.store.approval.ID, ExpectedGeneration: 7}
	f.store.transact = func(tx api.Transaction) (api.Commit, error) {
		if tx.Deferred == nil || tx.Reply != nil || len(tx.Effects) != 1 {
			t.Fatal("apply fixture did not receive the deferred publication")
		}
		return api.Commit{Operation: api.Operation{ID: tx.Deferred.OperationID, Status: "pending"}, Deferred: tx.Deferred}, nil
	}
	f.store.await = func(scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
		// Decode the actual caller's request so base/approval mismatches do
		// not introduce an unrelated result-shape failure in a guard mutant.
		var actual api.ChangeApplyRequest
		if err := DecodeJSON(scope.Request.Params, &actual); err != nil {
			t.Fatal(err)
		}
		receipt := api.ChangeReceipt{ID: "measured-receipt", ChangeID: actual.ChangeID, ApprovalID: actual.ApprovalID,
			OldGeneration: actual.ExpectedGeneration, NewGeneration: actual.ExpectedGeneration + 1,
			ManifestSHA256: f.store.change.ManifestSHA256, AppliedAt: "2026-10-15T09:01:00Z"}
		raw, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		return api.MutationReceipt{Config: scope.Config, Key: key, Actor: scope.Actor,
			Operation: api.Operation{ID: "operation-one", Status: "succeeded"}, Reply: &api.RPCReply{Result: raw}}, nil
	}
	return f, request
}

func TestApplyHandlerGuards(t *testing.T) {
	for _, name := range []string{"valid", "requester", "base", "snapshot", "approval_id", "approval_hash",
		"approval_base", "approval_life", "approval_change", "approval_expired", "extra", "diff", "blob", "publication"} {
		t.Run(name, func(t *testing.T) {
			f, request := completeApplyFixture(t)
			want := api.CodeConflict
			switch name {
			case "requester":
				f.scope.Actor.ID, f.scope.Actor.LifeID = "other-instance", "other-life"
				f.store.launch.Actor, f.store.launch.Target.LifeID = f.scope.Actor, f.scope.Actor.LifeID
				want = api.CodeForbidden
			case "base":
				request.ExpectedGeneration++
			case "snapshot":
				f.store.snapshot.Ref.ManifestSHA256 = testDigest([]byte("different approved inventory"))
			case "approval_id":
				foreign := *f.store.approval
				foreign.ID = "foreign-approval"
				f.store.approvalRead = func(api.Scope, api.ID) (api.ChangeApproval, error) { return foreign, nil }
				want = api.CodeIntegrity
			case "approval_hash":
				f.store.approval.ManifestSHA256 = testDigest([]byte("another manifest"))
			case "approval_base":
				f.store.approval.BaseGeneration++
			case "approval_life":
				f.store.approval.RequesterLifeID = "another-life"
			case "approval_change":
				f.store.approval.ChangeID = "another-change"
			case "approval_expired":
				f.store.approval.ApprovedAt, f.store.approval.ExpiresAt = "2026-10-15T08:50:00Z", "2026-10-15T09:00:00Z"
				want = api.CodeForbidden
			case "extra", "diff":
				render := f.worker.render
				f.worker.render = func(input api.ChangeRequest) (api.ChangeRequest, error) {
					output, err := render(input)
					if err != nil {
						return output, err
					}
					if name == "extra" {
						ref := f.retainRendered([]byte("unreviewed effect"), "artifact")
						output.Derived = []api.ResourceDelta{{Path: "generated/extra", Action: "add", Mode: 0644, After: &ref}}
					} else {
						output.Diff = f.retainRendered([]byte("unreviewed diff"), "artifact")
					}
					rehash(t, &output)
					return output, nil
				}
			case "blob":
				f.store.blobs["diff"] = []byte("corrupted retained diff")
				want = api.CodeIntegrity
			case "publication":
				await := f.store.await
				f.store.await = func(scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
					receipt, err := await(scope, key)
					if err != nil {
						return receipt, err
					}
					var result api.ChangeReceipt
					if err := json.Unmarshal(receipt.Reply.Result, &result); err != nil {
						t.Fatal(err)
					}
					result.ManifestSHA256 = testDigest([]byte("wrong published manifest"))
					receipt.Reply.Result, err = json.Marshal(result)
					return receipt, err
				}
				want = api.CodeIntegrity
			}
			got, err := f.service.OrgChangeApply(context.Background(), f.bound("org.change.apply", request, false), request)
			if name == "valid" {
				if err != nil || got.ID == "" || f.store.mutations != 1 || f.worker.renders != 1 {
					t.Fatalf("viable apply fixture did not complete: %v", err)
				}
				return
			}
			codeIs(t, err, want)
			if got.ID != "" {
				t.Fatal("refused apply exposed a successful receipt")
			}
			if name != "publication" && f.store.mutations != 0 {
				t.Fatal("apply handler guard allowed publication intent")
			}
		})
	}
}

func TestApplyIndependentRender(t *testing.T) {
	f, request := completeApplyFixture(t)
	retained := []byte("stored generated output")
	ref := testRef("stored-derived", retained)
	f.store.blobs[ref.ID] = retained
	f.store.change.Derived = []api.ResourceDelta{{Path: "generated/retained", Action: "add", Mode: 0644, After: &ref}}
	rehash(t, &f.store.change)
	approved := testApproval(f.store.change)
	f.store.approval = &approved
	render := f.worker.render
	f.worker.render = func(input api.ChangeRequest) (api.ChangeRequest, error) {
		// A worker that echoes supplied outputs cannot attest a fresh render.
		// Only a source-only input forces this worker to reproduce its output.
		if len(input.Derived) == 0 && input.Diff == (api.BlobRef{}) && input.ManifestSHA256 == "" {
			var err error
			input, err = render(input)
			if err != nil {
				return input, err
			}
			fresh := f.retainRendered([]byte("independently generated output"), "artifact")
			input.Derived = []api.ResourceDelta{{Path: "generated/retained", Action: "add", Mode: 0644, After: &fresh}}
			rehash(t, &input)
		}
		return input, nil
	}
	_, err := f.service.OrgChangeApply(context.Background(), f.bound("org.change.apply", request, false), request)
	codeIs(t, err, api.CodeConflict)
	if f.worker.renders != 1 || f.store.mutations != 0 {
		t.Fatal("independent render failed to stop changed retained output")
	}
}

func TestApplyFreshOutputs(t *testing.T) {
	for _, name := range []string{"fresh_ids", "corrupt_diff", "corrupt_after"} {
		t.Run(name, func(t *testing.T) {
			f, request := completeApplyFixture(t)
			derive := func(files []api.ResourceDelta) []byte {
				return append([]byte("generated settings from "), f.store.blobs[files[0].After.ID]...)
			}
			approvedData := derive(f.store.change.Files)
			approvedRef := testRef("approved-derived", approvedData)
			f.store.blobs[approvedRef.ID] = append([]byte(nil), approvedData...)
			f.store.change.Derived = []api.ResourceDelta{{Path: "generated/settings.txt", Action: "add", Mode: 0644, After: &approvedRef}}
			rehash(t, &f.store.change)
			approval := testApproval(f.store.change)
			f.store.approval = &approval
			retained, err := cloneChange(f.store.change)
			if err != nil {
				t.Fatal(err)
			}

			render := f.worker.render
			var fresh api.ChangeRequest
			f.worker.render = func(input api.ChangeRequest) (api.ChangeRequest, error) {
				output, err := render(input)
				if err != nil {
					return output, err
				}
				ref := f.retainRendered(derive(input.Files), "artifact")
				output.Derived = []api.ResourceDelta{{Path: "generated/settings.txt", Action: "add", Mode: 0644, After: &ref}}
				rehash(t, &output)
				fresh = output
				// The committed metadata stays equal to the approved content;
				// only the fresh object's actual bytes are corrupted.
				switch name {
				case "corrupt_diff":
					f.store.blobs[output.Diff.ID][0] ^= 1
				case "corrupt_after":
					f.store.blobs[ref.ID][0] ^= 1
				}
				return output, nil
			}
			reads := make(map[api.ID]int)
			f.store.alterChunk = func(chunk api.BlobChunk) api.BlobChunk {
				reads[chunk.ObjectID]++
				return chunk
			}
			transact := f.store.transact
			f.store.transact = func(tx api.Transaction) (api.Commit, error) {
				if len(tx.Guards) != 1 || tx.Guards[0].Approval == nil ||
					tx.Guards[0].Approval.ManifestSHA256 != retained.ManifestSHA256 ||
					tx.Guards[0].Approval.ChangeID != retained.ID || len(tx.Writes.Changes) != 0 ||
					len(tx.Effects) != 1 || tx.Effects[0].ApplyChange == nil || *tx.Effects[0].ApplyChange != request {
					t.Fatal("publication did not retain the approved change and manifest")
				}
				return transact(tx)
			}
			got, err := f.service.OrgChangeApply(context.Background(), f.bound("org.change.apply", request, false), request)
			if name != "fresh_ids" {
				codeIs(t, err, api.CodeIntegrity)
				if got.ID != "" || f.store.mutations != 0 {
					t.Fatal("unverified fresh object reached publication")
				}
				return
			}
			if err != nil || got.ManifestSHA256 != retained.ManifestSHA256 || f.store.mutations != 1 {
				t.Fatalf("verified fresh objects did not complete approved publication: %v", err)
			}
			if fresh.Diff.ID == retained.Diff.ID || fresh.Derived[0].After.ID == approvedRef.ID ||
				fresh.ManifestSHA256 == retained.ManifestSHA256 {
				t.Fatal("apply fixture reused approved output identities")
			}
			if reads[fresh.Diff.ID] < 2 || reads[fresh.Derived[0].After.ID] < 2 {
				t.Fatal("fresh output bytes and EOF were not independently read")
			}
			if !reflect.DeepEqual(f.store.change, retained) {
				t.Fatal("fresh revalidation replaced the approved retained references")
			}
		})
	}
}

func TestApplyReplayAuthority(t *testing.T) {
	f, request := completeApplyFixture(t)
	scope := f.bound("org.change.apply", request, false)
	value := api.ChangeReceipt{ID: "original-receipt", ChangeID: request.ChangeID, ApprovalID: request.ApprovalID,
		OldGeneration: 7, NewGeneration: 8, ManifestSHA256: f.store.change.ManifestSHA256, AppliedAt: "2026-10-15T09:01:00Z"}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	key := requestKey(scope)
	retained := f.store.receipts[fixtureDomain(scope, key)]
	retained.Operation.Status, retained.Reply = "succeeded", &api.RPCReply{Result: raw}
	f.store.receipts[fixtureDomain(scope, key)] = retained
	f.store.launch.Revoked = true
	_, err = f.service.OrgChangeApply(context.Background(), scope, request)
	codeIs(t, err, api.CodeForbidden)
	if f.store.changes != 0 || f.store.reads != 0 || f.store.mutations != 0 || f.worker.renders != 0 {
		t.Fatal("revoked apply replay reached retained resources or external work")
	}
}

func TestApproveHandlerGuards(t *testing.T) {
	for _, name := range []string{"snapshot", "blob", "facts", "verifier_error"} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
			want := api.CodeConflict
			refusal := &api.Error{Code: api.CodeForbidden, Message: "verifier rejected the real assertion"}
			switch name {
			case "snapshot":
				f.store.snapshot.Ref.ManifestSHA256 = testDigest([]byte("different approved inventory"))
			case "blob":
				f.store.blobs["diff"] = []byte("corrupted retained diff")
				want = api.CodeIntegrity
			case "facts":
				check := f.human.check
				f.human.check = func(scope api.Scope, proof api.ProofRef, target api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
					facts, err := check(scope, proof, target)
					facts.PrincipalID = "another-human"
					return facts, err
				}
				want = api.CodeForbidden
			case "verifier_error":
				f.human.check = func(api.Scope, api.ProofRef, api.HumanChallengeRequest) (api.VerifiedHumanProof, error) {
					return api.VerifiedHumanProof{}, refusal
				}
				want = api.CodeForbidden
			}
			got, err := f.service.OrgChangeApprove(context.Background(), f.bound("org.change.approve", request, true), request)
			if name == "verifier_error" && err != refusal {
				t.Fatalf("CheckProof error was not propagated unchanged: %v", err)
			}
			codeIs(t, err, want)
			if got.ID != "" || f.store.mutations != 0 {
				t.Fatal("approve handler guard committed an unverified approval")
			}
		})
	}
}

func TestApprovalWindow(t *testing.T) {
	for _, name := range []string{"short_proof", "stage_clamp", "expired", "before_stage", "overlong", "zero_evidence", "large_evidence", "evidence_class"} {
		t.Run(name, func(t *testing.T) {
			f := readyFixture(t)
			request := api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
			scope := f.bound("org.change.approve", request, true)
			scope.Request.Proof.ExpiresAt = "2026-10-15T09:00:30Z"
			target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: request.ChangeID,
				RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 7}
			facts, err := f.human.check(scope, *scope.Request.Proof, target)
			if err != nil {
				t.Fatal(err)
			}
			expected := api.Timestamp("2026-10-15T09:10:00Z")
			switch name {
			case "stage_clamp":
				f.store.change.ExpiresAt, expected = "2026-10-15T09:05:00Z", "2026-10-15T09:05:00Z"
			case "expired":
				scope.Request.Proof.ExpiresAt = "2026-10-15T09:00:00Z"
				facts.Ref = *scope.Request.Proof
			case "before_stage":
				facts.VerifiedAt = "2026-10-15T08:59:59Z"
				f.store.change.CreatedAt = "2026-10-15T09:00:00Z"
			case "overlong":
				scope.Request.Proof.ExpiresAt = "2026-10-15T09:02:01Z"
				facts.Ref = *scope.Request.Proof
			case "zero_evidence":
				facts.AssertionEvidence.Bytes = 0
			case "large_evidence":
				facts.AssertionEvidence.Bytes = api.MaxFrameBytes + 1
			case "evidence_class":
				facts.AssertionEvidence.Class = "report"
			}
			got, err := approvalFromProof(f.service.deps.Clock.Now(), scope, "operation-one", f.store.change, facts)
			if name != "short_proof" && name != "stage_clamp" {
				codeIs(t, err, api.CodeForbidden)
			} else if err != nil || got.ExpiresAt != expected {
				t.Fatalf("approval lost its independent window or stage clamp: expiry=%s err=%v", got.ExpiresAt, err)
			}
		})
	}
}

type fixtureReadConnection struct {
	api.ConnectionContext
	binding   api.InstalledBinding
	authority api.ReadAuthority
	err       error
}

func (f *fixtureReadConnection) ID() api.ID                    { return "connection-one" }
func (f *fixtureReadConnection) Binding() api.InstalledBinding { return f.binding }
func (f *fixtureReadConnection) ReadAuthority(context.Context) (api.ReadAuthority, error) {
	return f.authority, f.err
}

func bindRead(scope api.Scope) api.Scope {
	authority := api.ReadAuthority{ConnectionID: "connection-one", SessionID: "session-one", CredentialID: "credential-one",
		PrincipalID: scope.Actor.ID, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration,
		IdleExpiresAt: "2026-10-15T09:05:00Z", ExpiresAt: "2026-10-15T09:10:00Z"}
	scope.Connection = &fixtureReadConnection{authority: authority,
		binding: api.InstalledBinding{Class: api.EndpointHuman, Config: scope.Config, EndpointGeneration: scope.EndpointGeneration}}
	scope.ReadAuthority = &authority
	return scope
}

func TestHumanReadAuthority(t *testing.T) {
	for _, name := range []string{"missing", "connection", "session", "principal", "config", "generation", "credential", "expired", "revoked", "lane_life", "lane_level", "lane_role", "launch", "zero_endpoint"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
			scope := bindRead(f.bound("org.change.get", request, true))
			switch name {
			case "missing":
				scope.ReadAuthority = nil
			case "connection":
				scope.ReadAuthority.ConnectionID = "other-connection"
			case "session":
				scope.ReadAuthority.SessionID = "other-session"
			case "principal":
				scope.ReadAuthority.PrincipalID = "other-person"
			case "config":
				scope.ReadAuthority.Config = "other-config"
			case "generation":
				scope.ReadAuthority.EndpointGeneration++
			case "credential":
				scope.ReadAuthority.CredentialID = "other-key"
			case "expired", "revoked":
				scope.Connection.(*fixtureReadConnection).err = &api.Error{Code: api.CodeForbidden, Message: "session is " + name}
			case "lane_life":
				scope.Actor.LifeID = "lane-life"
			case "lane_level":
				scope.Actor.Level = 6
			case "lane_role":
				scope.Actor.Role = "policy"
			case "launch":
				scope.LaunchID = "lane-launch"
			case "zero_endpoint":
				scope.EndpointGeneration = 0
			}
			_, err := f.service.OrgChangeGet(context.Background(), scope, request)
			codeIs(t, err, api.CodeForbidden)
			if f.store.changes != 0 {
				t.Fatal("unbound human read reached retained staged bytes")
			}
		})
	}
}

func TestReadOperationProof(t *testing.T) {
	f := newFixture(t)
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	scope := bindRead(f.bound("org.change.get", request, true))
	scope.Request.Proof = &api.ProofRef{ID: "operation-proof", RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: "2026-10-15T09:02:00Z"}
	_, err := f.service.OrgChangeGet(context.Background(), scope, request)
	codeIs(t, err, api.CodeForbidden)
	if f.store.changes != 0 {
		t.Fatal("operation proof was accepted on a read")
	}
}

func TestZeroRunRead(t *testing.T) {
	f := newFixture(t)
	f.store.launch.Target.Run = 0
	request := api.ChangeGetRequest{ChangeID: f.store.change.ID}
	_, err := f.service.OrgChangeGet(context.Background(), f.bound("org.change.get", request, false), request)
	codeIs(t, err, api.CodeForbidden)
	if f.store.changes != 0 {
		t.Fatal("zero-run launch reached retained staged bytes")
	}
}

func TestRawRequestDigest(t *testing.T) {
	f := readyFixture(t)
	scope := f.bound("org.change.propose", f.request, false)
	scope.Request.Params = []byte(strings.Replace(string(scope.Request.Params), "\"action\":\"add\"", "\"action\":\"add\",\"before_sha256\":\"\"", 1))
	if !strings.Contains(string(scope.Request.Params), "\"before_sha256\":\"\"") {
		t.Fatal("explicit optional-field fixture did not change raw input")
	}
	digest, err := api.RequestDigest(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Request.RequestSHA256 = digest
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = fixtureFrame(raw)
	key := requestKey(scope)
	f.store.receipts[fixtureDomain(scope, key)] = api.MutationReceipt{Config: scope.Config, Key: key, Actor: scope.Actor,
		RawRequest: raw, Operation: api.Operation{ID: "operation-one", Status: "pending"}}
	result, err := f.service.OrgChangePropose(context.Background(), scope, f.request)
	if err != nil || !reflect.DeepEqual(result.Files, f.request.Files) {
		t.Fatalf("valid retained optional member was lost by a typed digest: %v", err)
	}
}

func TestClosedCatalogs(t *testing.T) {
	for _, class := range []string{"task", "prompt", "report", "artifact", "capture", "transcript", "policy", "manifest", "judge_request", "judge_raw", "archive", "record"} {
		if !validBlob(testClassRef("blob", []byte("bytes"), class)) {
			t.Fatalf("contract class %s was rejected", class)
		}
	}
	if validBlob(testClassRef("blob", []byte("bytes"), "org-source")) {
		t.Fatal("unknown blob class was accepted")
	}
	f := newFixture(t)
	f.store.change.OwnershipManifest.Class = "artifact"
	codeIs(t, ValidateChange(f.store.change), api.CodeIntegrity)
	for _, status := range []string{"proposed", "approved", "applied", "rejected", "invented", "bad\nstatus"} {
		f := newFixture(t)
		f.store.change.Status = status
		err := ValidateChange(f.store.change)
		if status == "invented" || strings.Contains(status, "\n") {
			codeIs(t, err, api.CodeIntegrity)
		} else if err != nil {
			t.Fatalf("contract status %s was rejected: %v", status, err)
		}
	}
}

func TestClosedTransitions(t *testing.T) {
	for _, status := range []string{"applied", "rejected"} {
		t.Run(status, func(t *testing.T) {
			for _, method := range []api.Method{"org.change.approve", "org.change.apply"} {
				t.Run(string(method), func(t *testing.T) {
					// A removed status guard must reach this method's viable
					// completion, rather than another method's fixture refusal.
					var f *fixture
					var request any
					if method == "org.change.approve" {
						f = readyFixture(t)
						request = api.ChangeApproveRequest{ChangeID: f.store.change.ID, ManifestSHA256: f.store.change.ManifestSHA256, BaseGeneration: 7}
					} else {
						var apply api.ChangeApplyRequest
						f, apply = completeApplyFixture(t)
						request = apply
					}
					f.store.change.Status = status
					scope := f.bound(method, request, method == "org.change.approve")
					_, err := handlerForReplay(f, method)(context.Background(), scope, scope.Request.Params)
					codeIs(t, err, api.CodeConflict)
					if f.store.mutations != 0 || f.human.checked != 0 || f.worker.renders != 0 {
						t.Fatal("closed change reached external work")
					}
				})
			}
		})
	}
	f := newFixture(t)
	f.store.change.Status = "approved"
	codeIs(t, ValidateProposeResult(f.request, f.store.change), api.CodeIntegrity)
}

func TestRetainedEmptyDerived(t *testing.T) {
	f := newFixture(t)
	raw, err := json.Marshal(f.store.change)
	if err != nil {
		t.Fatal(err)
	}
	var retained api.ChangeRequest
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatal(err)
	}
	if retained.Derived == nil || len(retained.Derived) != 0 || ValidateChange(retained) != nil {
		t.Fatal("retained empty derived array did not survive a JSON round trip")
	}
	retained.Derived = nil
	codeIs(t, ValidateChange(retained), api.CodeIntegrity)
}
