package grants

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func TestRootAndRevokeStayClosed(t *testing.T) {
	f := newFixture(t)
	budget := api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 2, DiskBytes: 4096, Currency: "USD"}
	root := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{}, Data: []api.DataGrant{},
		Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs["root-input"] = raw
	ref := api.BlobRef{ID: "root-input", SHA256: manifest.Hash(raw), Bytes: int64(len(raw)), Class: "manifest"}
	f.store.retain(ref)
	_, err = f.service.GrantsRoot(context.Background(), f.scope, api.RootGrantRequest{Manifest: ref, Budget: budget})
	expectCode(t, err, api.CodeForbidden)
	human := api.Scope{Config: "case-grants", Actor: api.Actor{Kind: "human", ID: "human"}, EndpointGeneration: 1}
	_, err = f.service.GrantsRoot(context.Background(), human, api.RootGrantRequest{Manifest: ref, Budget: budget})
	expectCode(t, err, api.CodeForbidden)
	// Merely having a proof reference must never substitute for atomic proof
	// verification or protected enrollment of the selected root handles.
	human.Request.Proof = &api.ProofRef{ID: "reference"}
	_, err = f.service.GrantsRoot(context.Background(), human, api.RootGrantRequest{Manifest: ref, Budget: budget})
	expectCode(t, err, api.CodeForbidden)
	// A real verified operation still cannot resolve unenrolled profiles.
	profile := f.store.sets["parent-set"].Profiles[0]
	profile.ID = ""
	root.Profiles = []api.ProfileGrant{profile}
	raw, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[ref.ID] = raw
	ref.SHA256, ref.Bytes = manifest.Hash(raw), int64(len(raw))
	f.store.retain(ref)
	request := api.RootGrantRequest{Manifest: ref, Budget: budget}
	human = humanScope(t, f, "grants.root", request)
	result, err := f.service.GrantsRoot(context.Background(), human, request)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || result.ID != "" || f.store.transactions != 0 {
		t.Fatal("unwired root profile escaped prerequisite gate", err)
	}
	child := f.child()
	f.store.blobs["reason"] = []byte("revoke")
	reason := api.BlobRef{ID: "reason", SHA256: manifest.Hash([]byte("revoke")), Bytes: 6, Class: "report"}
	f.store.retain(reason)
	op, err := f.service.GrantsRevoke(context.Background(), f.scope, api.GrantRevokeRequest{
		GrantSetID: child.ID, ExpectedGeneration: child.Generation, Reason: reason})
	expectCode(t, err, api.CodePrerequisite)
	if op.ID != "" || f.store.transactions != 0 || f.store.sets[child.ID].Revoked {
		t.Fatal("incomplete revocation claimed success or mutated authority")
	}
}

func TestRootCapabilityGates(t *testing.T) {
	for _, name := range []string{"secrets", "network", "resources", "exports"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			request := rootFixture(t, f)
			var input api.RootGrantManifest
			if err := api.DecodeObject(f.store.blobs[request.Manifest.ID], &input); err != nil {
				t.Fatal(err)
			}
			parent := f.store.sets["parent-set"]
			switch name {
			case "secrets":
				grant := parent.Secrets[0]
				grant.ID, grant.ParentGrantID = "", ""
				input.Secrets = []api.SecretGrant{grant}
			case "network":
				grant := parent.Network[0]
				grant.ID, grant.ParentGrantID = "", ""
				input.Network = []api.NetworkGrant{grant}
			case "resources":
				grant := parent.Resources[0]
				grant.ID, grant.ParentGrantID = "", ""
				input.Resources = []api.ResourceGrant{grant}
			case "exports":
				input.Data[0].Delivery = "mount"
			}
			if err := manifest.Root(input, f.clock.Now()); err != nil {
				t.Fatal("root capability control has invalid input", err)
			}
			request = saveProfileInput(t, f, request, input)
			scope := humanScope(t, f, "grants.root", request)
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			var typed *api.Error
			want := api.CodeNotImplemented
			if name == "network" {
				want = api.CodeForbidden
			} else if name == "secrets" || name == "resources" {
				want = api.CodeNotFound
			}
			if name == "secrets" {
				want = api.CodePrerequisite
			}
			if !errors.As(err, &typed) || typed.Code != want || typed.Owner != "lb-v2-grants" || result.ID != "" || f.store.transactions != 0 {
				t.Fatal("unimplemented root capability escaped its typed gate", name, err)
			}
		})
	}
}

func TestMissingDependencies(t *testing.T) {
	_, err := New(Dependencies{})
	expectCode(t, err, api.CodePrerequisite)
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = f.service.preview(ctx, f.scope, f.request)
	expectCode(t, err, api.CodeCancelled)
}
