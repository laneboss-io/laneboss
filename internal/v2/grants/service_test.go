package grants

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func expectCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestNarrowPreview(t *testing.T) {
	f := newFixture(t)
	before := clone(t, f.store.sets)
	result, err := f.service.GrantsValidate(context.Background(), f.scope, f.request)
	if err != nil {
		t.Fatal(err)
	}
	actual := result.Effective
	if len(actual.Data) != 1 || actual.ParentLifeID != f.scope.Actor.LifeID ||
		actual.Data[0].RelativePath != "child" || actual.Data[0].Access != "ro" ||
		actual.Data[0].SourceObjectID != "source-tree" || actual.Data[0].Delegate ||
		actual.Data[0].ParentGrantID != "data" || actual.Data[0].Destination != "/work/main" ||
		actual.PolicyGeneration != 1 || !manifest.ValidID(actual.ID) || !manifest.ValidID(actual.LifeID) || result.Warnings == nil {
		t.Fatal("preview does not describe the exact requested scope")
	}
	if len(actual.Secrets)+len(actual.Profiles)+len(actual.Network)+len(actual.Resources)+len(actual.Channels) != 0 {
		t.Fatal("preview inherited unrequested capabilities")
	}
	if !reflect.DeepEqual(before, f.store.sets) || f.store.transactions != 0 || f.worker.materializeCalls != 0 || f.worker.testCalls != 0 {
		t.Fatal("read-only preview mutated state or launched a worker")
	}
	_, err = f.service.Revalidate(context.Background(), actual)
	expectCode(t, err, api.CodeNotFound) // a preview cannot authorize a launch
}

func TestAllCapabilityFamilies(t *testing.T) {
	f := newFixture(t)
	expiry := f.request.Requested.Data[0].ExpiresAt
	r := &f.request.Requested
	r.Secrets = []api.SecretDelegation{{ParentGrantID: "secret", Name: "task-key", Version: "v1.0",
		Delivery: "env", Target: "TASK_KEY", ExpiresAt: expiry}}
	r.Profiles = []api.ProfileDelegation{{ParentGrantID: "profile", ProfileID: "profile-one", ExpiresAt: expiry}}
	r.Network = []api.NetworkDelegation{{ParentGrantID: "network", EndpointID: "endpoint-one", ExpiresAt: expiry}}
	r.Channels = []api.ChannelDelegation{{ParentGrantID: "channel", ChannelID: "channel-one", ExpiresAt: expiry}}
	r.Resources = []api.ResourceDelegation{{ParentGrantID: "resource", Regions: []string{"region-a"},
		ImageIDs: []string{"image-a"}, MachineTypes: []string{"m7i.large"}, MaxActive: 1,
		MaxHourlyMicros: 5, TotalBudgetMicros: 50, ExpiresAt: expiry}}
	actual, err := f.service.preview(context.Background(), f.scope, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Secrets[0].SourceHandle != "key-source" || actual.Profiles[0].Driver != api.DriverCodex ||
		actual.Profiles[0].Provider != "example" || actual.Network[0].Mode != "service" ||
		actual.Resources[0].SourceHandle != "resource-source" || actual.Resources[0].MaxActive != 1 ||
		actual.Channels[0].ChannelID != "channel-one" {
		t.Fatal("capability source metadata was lost or widened")
	}
	for _, item := range []struct {
		name   string
		mutate func(*api.GrantValidateRequest)
	}{
		{"secret-name", func(v *api.GrantValidateRequest) { v.Requested.Secrets[0].Name = "another" }},
		{"secret-version", func(v *api.GrantValidateRequest) { v.Requested.Secrets[0].Version = "v2" }},
		{"secret-target", func(v *api.GrantValidateRequest) { v.Requested.Secrets[0].Target = "HOME" }},
		{"profile", func(v *api.GrantValidateRequest) { v.Requested.Profiles[0].ProfileID = "other" }},
		{"network", func(v *api.GrantValidateRequest) { v.Requested.Network[0].EndpointID = "other" }},
		{"channel", func(v *api.GrantValidateRequest) { v.Requested.Channels[0].ChannelID = "other" }},
		{"resource-region", func(v *api.GrantValidateRequest) { v.Requested.Resources[0].Regions = []string{"other"} }},
		{"resource-active", func(v *api.GrantValidateRequest) { v.Requested.Resources[0].MaxActive = 3 }},
		{"resource-hourly", func(v *api.GrantValidateRequest) { v.Requested.Resources[0].MaxHourlyMicros = 11 }},
		{"resource-total", func(v *api.GrantValidateRequest) { v.Requested.Resources[0].TotalBudgetMicros = 101 }},
	} {
		t.Run(item.name, func(t *testing.T) {
			request := clone(t, f.request)
			item.mutate(&request)
			_, err := f.service.preview(context.Background(), f.scope, request)
			expectCode(t, err, api.CodeForbidden)
		})
	}
}

func TestWideningRefused(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fixture)
		code   api.ErrorCode
	}{
		{"other-parent", func(f *fixture) { f.request.ParentLifeID = "other" }, api.CodeForbidden},
		{"same-level", func(f *fixture) { f.request.ChildLevel = 5 }, api.CodeForbidden},
		{"reserved-level", func(f *fixture) { f.request.ChildLevel = 2 }, api.CodeForbidden},
		{"traversal", func(f *fixture) { f.request.Requested.Data[0].RelativePath = "../private" }, api.CodeInvalid},
		{"absolute", func(f *fixture) { f.request.Requested.Data[0].RelativePath = "/private" }, api.CodeInvalid},
		{"dot-alias", func(f *fixture) { f.request.Requested.Data[0].RelativePath = "child/../private" }, api.CodeInvalid},
		{"unknown-data", func(f *fixture) { f.request.Requested.Data[0].ParentGrantID = "other" }, api.CodeForbidden},
		{"ro-to-rw", func(f *fixture) {
			f.updateParent(func(p *api.GrantSet) { p.Data[0].Access = "ro" })
			f.request.Requested.Data[0].Access = "rw"
		}, api.CodeForbidden},
		{"delegation", func(f *fixture) { f.updateParent(func(p *api.GrantSet) { p.Data[0].Delegate = false }) }, api.CodeForbidden},
		{"expiry", func(f *fixture) { f.request.Requested.Data[0].ExpiresAt = "2031-01-01T00:00:00Z" }, api.CodeForbidden},
		{"expired", func(f *fixture) { f.request.Requested.Data[0].ExpiresAt = "2029-01-01T00:00:00Z" }, api.CodeForbidden},
		{"publication", func(f *fixture) { f.request.Requested.Data[0].PublicationID = "other" }, api.CodeForbidden},
		{"mount", func(f *fixture) { f.request.Requested.Data[0].Delivery = "mount" }, api.CodeForbidden},
		{"runtime-path", func(f *fixture) { f.request.Requested.Data[0].Destination = "/run/control" }, api.CodeInvalid},
		{"overlap", func(f *fixture) {
			f.request.Requested.Data = append(f.request.Requested.Data, f.request.Requested.Data[0])
		}, api.CodeInvalid},
		{"null-array", func(f *fixture) { f.request.Requested.Secrets = nil }, api.CodeInvalid},
		{"policy", func(f *fixture) { f.request.ExpectedPolicyGeneration++ }, api.CodeConflict},
		{"config", func(f *fixture) { f.scope.Config = "another" }, api.CodeForbidden},
		{"launch-revoked", func(f *fixture) { f.store.launch.Revoked = true }, api.CodeForbidden},
		{"endpoint", func(f *fixture) { f.scope.EndpointGeneration++ }, api.CodeForbidden},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			item.change(f)
			before := clone(t, f.store.sets)
			_, err := f.service.preview(context.Background(), f.scope, f.request)
			expectCode(t, err, item.code)
			if f.worker.testCalls != 0 || f.worker.materializeCalls != 0 || f.store.transactions != 0 || !reflect.DeepEqual(before, f.store.sets) {
				t.Fatal("a refused grant caused an effect")
			}
		})
	}
}

func TestFileGrantAndLinkBoundary(t *testing.T) {
	for _, boundary := range []string{"file", "relative", "traversal", "link"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			switch boundary {
			case "file":
				f.request.Requested.Data[0].RelativePath = "child/input.txt"
				grant, err := f.service.preview(context.Background(), f.scope, f.request)
				if err != nil || grant.Data[0].RelativePath != "child/input.txt" {
					t.Fatalf("file snapshot: %v", err)
				}
			case "relative", "traversal":
				f.updateParent(func(p *api.GrantSet) { p.Data[0].RelativePath = "child" })
				f.request.Requested.Data[0].RelativePath = "input.txt"
				if boundary == "traversal" {
					f.request.Requested.Data[0].RelativePath = "../private/canary"
				}
				grant, err := f.service.preview(context.Background(), f.scope, f.request)
				if boundary == "traversal" {
					expectCode(t, err, api.CodeInvalid)
				} else if err != nil || grant.Data[0].RelativePath != "child/input.txt" {
					t.Fatalf("relative parent scope: %v", err)
				}
			case "link":
				var object api.ObjectManifest
				if err := json.Unmarshal(f.store.blobs["source-tree"], &object); err != nil {
					t.Fatal(err)
				}
				object.Entries = append(object.Entries, api.ObjectEntry{Path: "child/leak", Kind: "symlink", Mode: 0777, LinkTarget: "../private/canary"})
				raw, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				f.store.blobs["source-tree"] = raw
				f.store.retain(api.BlobRef{ID: "source-tree", SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"})
				f.updateParent(func(p *api.GrantSet) { p.Data[0].SourceSHA256 = manifest.Hash(raw) })
				_, err = f.service.preview(context.Background(), f.scope, f.request)
				expectCode(t, err, api.CodeInvalid)
			}
		})
	}
}
func TestAncestorRevalidation(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*fixture, *api.GrantSet)
		code   api.ErrorCode
	}{
		{"revoked-parent", func(f *fixture, c *api.GrantSet) { f.updateParent(func(p *api.GrantSet) { p.Revoked = true }) }, api.CodeForbidden},
		{"policy-changed", func(f *fixture, c *api.GrantSet) { f.store.policy.Generation++ }, api.CodeConflict},
		{"source-tamper", func(f *fixture, c *api.GrantSet) { f.store.blobs["source-tree"] = []byte("tampered") }, api.CodeIntegrity},
		{"chunk-range", func(f *fixture, c *api.GrantSet) { f.store.corruptChunk = true }, api.CodeIntegrity},
		{"parent-ended", func(f *fixture, c *api.GrantSet) {
			lane := f.store.lanes["parent"]
			lane.State = "merged"
			f.store.lanes["parent"] = lane
		}, api.CodePrerequisite},
		{"parent-narrowed", func(f *fixture, c *api.GrantSet) {
			f.updateParent(func(p *api.GrantSet) { p.Data[0].RelativePath = "private" })
		}, api.CodeForbidden},
		{"child-drift", func(f *fixture, c *api.GrantSet) {
			value := f.store.sets[c.ID]
			value.Generation++
			f.store.sets[c.ID] = value
		}, api.CodeConflict},
		{"digest-tamper", func(f *fixture, c *api.GrantSet) { c.Data[0].Access = "rw"; f.store.sets[c.ID] = clone(f.t, *c) }, api.CodeIntegrity},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			if _, err := f.service.Revalidate(context.Background(), child); err != nil {
				t.Fatal(err)
			}
			item.change(f, &child)
			_, err := f.service.Materialize(context.Background(), child)
			expectCode(t, err, item.code)
			if f.worker.materializeCalls != 0 {
				t.Fatal("invalid authority reached materialization")
			}
		})
	}
}

func TestWorkerErrorsAndEmptyReceipt(t *testing.T) {
	f := newFixture(t)
	child := f.child()
	_, err := f.service.Materialize(context.Background(), child)
	expectCode(t, err, api.CodeNotImplemented)
	if f.worker.materializeCalls != 1 {
		t.Fatal("valid materialization was not dispatched")
	}
	f.worker.materializeErr = nil
	_, err = f.service.Materialize(context.Background(), child)
	expectCode(t, err, api.CodeIntegrity)
	f.store.readErr = &api.Error{Code: api.CodeUnavailable, Message: "source store unavailable"}
	_, err = f.service.preview(context.Background(), f.scope, f.request)
	expectCode(t, err, api.CodeUnavailable)
}

func TestChildTestScope(t *testing.T) {
	for _, boundary := range []string{"worker", "budget", "run", "subtree"} {
		t.Run(boundary, func(t *testing.T) {
			f := newFixture(t)
			child := f.child()
			request := f.testRequest(child)
			bounded, err := f.service.BoundChildTest(context.Background(), f.scope, request)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(bounded, child) || len(bounded.Secrets)+len(bounded.Resources)+len(bounded.Profiles) != 0 {
				t.Fatal("parent capabilities entered the child test")
			}
			switch boundary {
			case "worker":
				_, err = f.service.GrantsTestChild(context.Background(), f.scope, request)
				expectCode(t, err, api.CodeNotImplemented)
				if f.worker.testCalls != 1 || !reflect.DeepEqual(f.worker.tested, child) {
					t.Fatal("test worker did not receive the exact child scope")
				}
			case "budget":
				request.Budget.DiskBytes = 1
				_, err = f.service.BoundChildTest(context.Background(), f.scope, request)
				expectCode(t, err, api.CodeForbidden)
			case "run":
				request.Child.Run++
				_, err = f.service.BoundChildTest(context.Background(), f.scope, request)
				expectCode(t, err, api.CodeConflict)
			case "subtree":
				lane := f.store.lanes[child.LifeID]
				lane.StarterChain = []api.ID{"another-parent"}
				f.store.lanes[child.LifeID] = lane
				_, err = f.service.BoundChildTest(context.Background(), f.scope, request)
				expectCode(t, err, api.CodeForbidden)
			}
		})
	}
}
func TestPreviewExpiry(t *testing.T) {
	f := newFixture(t)
	expires := api.Timestamp(f.clock.Now().Add(time.Hour).Format(time.RFC3339Nano))
	f.request.Requested.Data[0].ExpiresAt = expires
	result, err := f.service.preview(context.Background(), f.scope, f.request)
	if err != nil || result.ExpiresAt != expires {
		t.Fatalf("preview exceeded its selected grant expiry: %v", err)
	}
}

type fixtureRegistry struct {
	api.Registrar
	handlers map[api.Method]api.Handler
}

func (r *fixtureRegistry) Register(method api.Method, handler api.Handler) error {
	if r.handlers[method] != nil {
		return conflict("duplicate method")
	}
	r.handlers[method] = handler
	return nil
}

func TestRPCRegistration(t *testing.T) {
	f := newFixture(t)
	r := &fixtureRegistry{handlers: map[api.Method]api.Handler{}}
	if err := f.service.Register(r); err != nil {
		t.Fatal(err)
	}
	if len(r.handlers) != 6 {
		t.Fatal("missing or extra grant RPC method")
	}
	for _, method := range []api.Method{"grants.root", "grants.enroll", "grants.validate", "grants.get", "grants.revoke", "grants.test-child"} {
		if r.handlers[method] == nil {
			t.Fatal("grant RPC method missing")
		}
	}
	_, err := r.handlers["grants.get"](context.Background(), f.scope, json.RawMessage(`{"grant_set_id":"parent-set","actor":"forged"}`))
	expectCode(t, err, api.CodeInvalid)
	raw, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := r.handlers["grants.validate"](context.Background(), f.scope, raw)
	if err != nil {
		t.Fatal(err)
	}
	var parsed api.GrantValidation
	if err := manifest.Decode(response, &parsed); err != nil || len(parsed.Effective.Data) != 1 {
		t.Fatal("invalid typed response", err)
	}
}
