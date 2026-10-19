package grants

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestAncestorLiveStates(t *testing.T) {
	for _, state := range []string{"preparing", "running", "stopping", "verifying", "idle", "profile_wait"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			lane := f.store.lanes["parent"]
			lane.State = state
			f.store.lanes["parent"] = lane
			actual, err := f.service.Revalidate(context.Background(), child)
			if err != nil || !reflect.DeepEqual(actual, child) {
				t.Fatal("normal ancestor state lost delegated authority", err)
			}
		})
	}
}

func TestCurrentLifecycleVocabulary(t *testing.T) {
	f := newFixture(t)
	lane := f.store.lanes["parent"]
	lane.State = "unknown"
	f.store.lanes[lane.LifeID] = lane
	_, err := f.service.Revalidate(context.Background(), f.store.sets["parent-set"])
	expectCode(t, err, api.CodeIntegrity)
}

func TestStoredGrantHistory(t *testing.T) {
	for _, name := range []string{"revoked", "expired", "cleaned", "policy"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.request.Requested.Data[0].ExpiresAt = "2030-01-01T01:00:00Z"
			child := f.child()
			switch name {
			case "revoked":
				child.Revoked = true
			case "expired":
				f.service.deps.Clock = fixedClock{now: f.clock.now.Add(2 * time.Hour)}
			case "cleaned":
				lane := f.store.lanes[child.LifeID]
				lane.Cleaned = true
				f.store.lanes[child.LifeID] = lane
			case "policy":
				f.store.policy.Generation = 2
				f.updateParent(func(p *api.GrantSet) { p.PolicyGeneration = 2 })
				lane := f.store.lanes["parent"]
				lane.PolicyGeneration = 2
				f.store.lanes["parent"] = lane
				f.store.launch.PolicyGeneration, f.scope.PolicyGeneration = 2, 2
			}
			if err := seal(&child); err != nil {
				t.Fatal(err)
			}
			f.store.sets[child.ID] = child
			actual, err := f.service.GrantsGet(context.Background(), f.scope, api.GrantGetRequest{GrantSetID: child.ID})
			if err != nil || !reflect.DeepEqual(actual, child) {
				t.Fatal("authorized historical grants became unreadable", err)
			}
		})
	}
}

func TestGrantExistenceHidden(t *testing.T) {
	for _, name := range []string{"sibling", "changed-life", "absent"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			lane := f.store.lanes[child.LifeID]
			switch name {
			case "sibling":
				lane.StarterChain = []api.ID{"sibling"}
			case "changed-life":
				lane.LifeID = "other"
			case "absent":
				delete(f.store.sets, child.ID)
			}
			f.store.lanes[child.LifeID] = lane
			_, err := f.service.GrantsGet(context.Background(), f.scope, api.GrantGetRequest{GrantSetID: child.ID})
			expectCode(t, err, api.CodeNotFound)
			_, err = f.service.GrantsRevoke(context.Background(), f.scope, api.GrantRevokeRequest{GrantSetID: child.ID, ExpectedGeneration: 1})
			expectCode(t, err, api.CodeNotFound)
		})
	}
}

func TestRevalidationContext(t *testing.T) {
	for _, boundary := range []string{"policy", "sources"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			seen := 0
			if boundary == "policy" {
				f.store.onGrantPolicy = func(scope api.Scope, request api.GrantPolicyRequest) {
					lane, found := f.store.lanes[request.Target.LifeID]
					if !found || request.Context.Level != lane.Level || request.Context.Role != lane.Role || request.Target.Run != lane.Run || request.GrantSetID != lane.GrantSetID || request.PolicyGeneration != lane.PolicyGeneration || scope.ReadView == nil || scope.Actor != (api.Actor{Kind: "service", ID: "grants"}) {
						t.Fatal("policy read lost the pinned lane context")
					}
					seen++
				}
			} else {
				allowed := map[api.ID]bool{}
				for _, grant := range child.Data {
					allowed[grant.SourceObjectID] = true
					var object api.ObjectManifest
					if err := api.DecodeObject(f.store.blobs[grant.SourceObjectID], &object); err != nil {
						t.Fatal(err)
					}
					entries, err := manifest.Select(object, grant.RelativePath)
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						for _, ref := range manifest.ContentRefs(entry) {
							allowed[ref.ID] = true
						}
					}
				}
				f.store.onMetadata = func(scope api.Scope, id api.ID) {
					view, ok := scope.ReadView.(*fixtureReadView)
					if !ok || view.closed || view.actor != scope.Actor || scope.Actor != (api.Actor{Kind: "service", ID: "grants"}) || !allowed[id] {
						t.Fatal("source read lost the live pinned child context")
					}
					seen++
				}
			}
			if _, err := f.service.Revalidate(context.Background(), child); err != nil {
				t.Fatal(err)
			}
			if seen == 0 {
				t.Fatal("revalidation context check was not reached", boundary)
			}
		})
	}
}
func TestSourceEntryMetadata(t *testing.T) {
	for _, name := range []string{"missing", "class", "config", "digest"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			metadata := f.store.metadata["input-bytes"]
			switch name {
			case "class":
				metadata.Ref.Class = "policy"
			case "config":
				metadata.ACL.Config = "other"
			case "digest":
				metadata.Ref.SHA256 = manifest.Hash([]byte("other"))
			}
			f.store.metadata["input-bytes"] = metadata
			code := api.CodeIntegrity
			if name == "missing" {
				delete(f.store.metadata, "input-bytes")
				code = api.CodeNotFound
			}
			_, err := f.service.preview(context.Background(), f.scope, f.request)
			expectCode(t, err, code)
		})
	}
}

func candidateRequest(t *testing.T, f *fixture, request api.TestChildRequest, count int) api.TestChildRequest {
	t.Helper()
	ref := f.store.metadata["input-bytes"].Ref
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	for i := 0; i < count; i++ {
		object.Entries = append(object.Entries, api.ObjectEntry{Path: "copy-" + strconv.Itoa(i), Kind: "file", Mode: 0600, Content: &ref})
	}
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[request.Candidate.ID] = raw
	request.Candidate.SHA256, request.Candidate.Bytes = manifest.Hash(raw), int64(len(raw))
	f.store.retain(request.Candidate)
	f.store.events[0].Payload, err = json.Marshal(request.Candidate)
	if err != nil {
		t.Fatal(err)
	}
	var plan api.WorkerPlan
	if err := json.Unmarshal(f.store.blobs[request.TestPlan.ID], &plan); err != nil {
		t.Fatal(err)
	}
	plan.Input, plan.Budget = request.Candidate, request.Budget
	raw, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[request.TestPlan.ID] = raw
	request.TestPlan.SHA256, request.TestPlan.Bytes = manifest.Hash(raw), int64(len(raw))
	f.store.retain(request.TestPlan)
	return request
}

func TestCandidateReadBounds(t *testing.T) {
	for _, boundary := range []string{"bodies", "metadata", "disk"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			request.Budget.DiskBytes = 65536
			request = candidateRequest(t, f, request, 10000)
			metadataReads := 0
			f.store.onMetadata = func(_ api.Scope, id api.ID) {
				if id == "input-bytes" {
					metadataReads++
				}
			}
			f.store.blobCalls = map[api.ID]int{}
			if _, err := f.service.BoundChildTest(context.Background(), f.scope, request); err != nil {
				t.Fatal("bounded repeated-reference control failed", err)
			}
			switch boundary {
			case "bodies":
				if f.store.blobCalls["input-bytes"] != 0 {
					t.Fatal("service preflight read candidate file bodies")
				}
			case "metadata":
				if metadataReads >= 10000 {
					t.Fatal("repeated candidate metadata was not deduplicated")
				}
			case "disk":
				request.Budget.DiskBytes = 9
				request = candidateRequest(t, f, request, 2)
				_, err := f.service.BoundChildTest(context.Background(), f.scope, request)
				expectCode(t, err, api.CodeBudget)
			}
		})
	}
}
func TestExpiryUpperCeiling(t *testing.T) {
	for _, boundary := range []string{"stored", "derived"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			expiry := api.Timestamp("2030-01-01T00:15:00Z")
			parent := clone(t, f.store.sets["parent-set"])
			parent.Secrets[0].ExpiresAt = expiry
			if err := seal(&parent); err != nil {
				t.Fatal(err)
			}
			if boundary == "stored" {
				if err := manifest.Set(parent, f.clock.Now()); err != nil {
					t.Fatal("stored set rejected an independent shorter member expiry", err)
				}
				return
			}
			f.request.Requested.Secrets = []api.SecretDelegation{{ParentGrantID: "secret", Name: "task-key", Version: "v1.0", Delivery: "env", Target: "TASK_KEY", ExpiresAt: expiry}}
			set, err := derive(parent, f.request.Requested, f.clock.Now())
			if err != nil || set.ExpiresAt != f.request.Requested.Data[0].ExpiresAt || set.Secrets[0].ExpiresAt != expiry {
				t.Fatal("derived set truncated independent delegation expiry", err)
			}
		})
	}
}
func TestConfigSpelling(t *testing.T) {
	for _, name := range []string{"Upper", "with_under", "-bad", "name-name-name-name-name-name-name"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			_, err := New(Dependencies{Config: name, Store: f.store, Worker: f.worker, Clock: f.clock})
			expectCode(t, err, api.CodePrerequisite)
		})
	}
}
func TestServiceReadBudget(t *testing.T) {
	for _, name := range []string{"bytes", "metadata"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			ctx := verificationContext(context.Background())
			// Account for preceding work in the same request without allocating
			// a large object merely to exercise the last read at the boundary.
			if name == "bytes" {
				if err := meterBytes(ctx, maxVerificationBytes-4); err != nil {
					t.Fatal(err)
				}
			} else {
				for i := 0; i < maxVerificationRefs*8; i++ {
					if err := meterMetadata(ctx); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err := f.service.readRef(ctx, f.scope, f.store.metadata["input-bytes"].Ref)
			expectCode(t, err, api.CodeBudget)
		})
	}
}

func TestCandidateClass(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	request := f.testRequest(child)
	request.Candidate.Class = "artifact"
	request = candidateRequest(t, f, request, 1)
	_, err := f.service.BoundChildTest(context.Background(), f.scope, request)
	expectCode(t, err, api.CodeInvalid)
}

func TestLaneProofRefused(t *testing.T) {
	f := newFixture(t)
	f.scope.Request.Proof = &api.ProofRef{ID: "borrowed", RequestSHA256: manifest.Hash([]byte("intent"))}
	_, err := f.service.GrantsGet(context.Background(), f.scope, api.GrantGetRequest{GrantSetID: "parent-set"})
	expectCode(t, err, api.CodeForbidden)
}

func TestDestinationAliases(t *testing.T) {
	f := newFixture(t)
	f.request.Requested.Data[0].Destination = "/data/A"
	other := f.request.Requested.Data[0]
	other.RelativePath, other.Destination = "private", "/data/a"
	f.request.Requested.Data = append(f.request.Requested.Data, other)
	_, err := f.service.preview(context.Background(), f.scope, f.request)
	expectCode(t, err, api.CodeInvalid)
}
