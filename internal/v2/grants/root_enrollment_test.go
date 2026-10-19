package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Declared store/transport fixtures, with actual serialized enrollment bytes
// and the production metadata/chunk/digest readers. No secret value or cloud
// account is present; these tests do not establish installed enrollment.
func retainRootEnrollment(t *testing.T, f *fixture, handle api.ID, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	f.store.blobs[handle] = raw
	f.store.metadata[handle] = api.ObjectMetadata{
		Ref: api.BlobRef{ID: handle, Class: "manifest", SHA256: manifest.Hash(raw), Bytes: int64(len(raw))},
		ACL: api.ObjectACL{Config: f.scope.Config, Owner: api.Actor{Kind: "human", ID: "human"},
			Audience: "owner", Generation: 1, Participants: []api.ID{}},
		Origin: "service", SourceOperationID: "enrollment-operation", CommittedAt: "2030-01-01T00:00:00Z"}
}

func addRootEnrollments(t *testing.T, f *fixture, input *api.RootGrantManifest) {
	t.Helper()
	parent := clone(t, f.store.sets["parent-set"])
	resource, secret := parent.Resources[0], parent.Secrets[0]
	resource.ID, resource.ParentGrantID = "", ""
	secret.ID, secret.ParentGrantID = "", ""
	retainRootEnrollment(t, f, resource.SourceHandle, resource)
	retainRootEnrollment(t, f, secret.SourceHandle, secret)
	input.Resources, input.Secrets = []api.ResourceGrant{resource}, []api.SecretGrant{secret}
}

func enrolledRootFixture(t *testing.T) (*fixture, api.RootGrantRequest, api.RootGrantManifest) {
	t.Helper()
	f := newFixture(t)
	request := rootFixture(t, f)
	var input api.RootGrantManifest
	if err := api.DecodeObject(f.store.blobs[request.Manifest.ID], &input); err != nil {
		t.Fatal(err)
	}
	addRootEnrollments(t, f, &input)
	return f, saveProfileInput(t, f, request, input), input
}

func enrolledRootCommit(t *testing.T, f *fixture, scope api.Scope, backend *rootProfileStore) {
	t.Helper()
	f.store.onTransaction = func(tx api.Transaction) (api.Commit, error) {
		if len(tx.Guards) != 1 || tx.Guards[0].Proof == nil || tx.Guards[0].Proof.Proof != *scope.Request.Proof ||
			tx.Guards[0].Proof.Target != f.store.target || !bytes.Equal(tx.RawRequest, scope.Frame.Bytes()) ||
			tx.Scope.Actor != scope.Actor || tx.Scope.Connection != scope.Connection || tx.Scope.Frame != scope.Frame {
			t.Fatal("enrolled root issuance lost its exact human proof and frame")
		}
		if view, ok := tx.Scope.ReadView.(*fixtureReadView); !ok || view.closed {
			t.Fatal("enrolled root issuance used a closed or absent authority view")
		}
		if backend != nil && !backend.active {
			t.Fatal("mixed root issuance released the protected profile lock")
		}
		if len(tx.Writes.Grants) != 1 || len(tx.Effects) != 0 || len(tx.Writes.WorkerLeases) != 0 ||
			len(tx.Events) != 1 || tx.Events[0].Kind != "grants.issued" || len(tx.Compare) != 2 {
			t.Fatal("enrolled root issuance changed the existing transaction path")
		}
		if err := api.ValidateTransactionShape(tx); err != nil {
			t.Fatal(err)
		}
		f.store.sets[tx.Writes.Grants[0].ID] = clone(t, tx.Writes.Grants[0])
		return api.Commit{Reply: tx.Reply, Operation: api.Operation{ID: "enrolled-root-operation", Status: "succeeded"}, FirstSeq: 1, LastSeq: 1}, nil
	}
}

func TestRootEnrolledCapabilities(t *testing.T) {
	for _, name := range []string{"both", "resource-only", "secret-only", "nondelegable", "narrower", "profiles"} {
		t.Run(name, func(t *testing.T) {
			f, request, input := enrolledRootFixture(t)
			var backend *rootProfileStore
			if name == "profiles" {
				f, backend, request, input = rootProfileCase(t)
				addRootEnrollments(t, f, &input)
			}
			switch name {
			case "resource-only":
				input.Data, input.Secrets = []api.DataGrant{}, []api.SecretGrant{}
			case "secret-only":
				input.Data, input.Resources = []api.DataGrant{}, []api.ResourceGrant{}
			case "nondelegable":
				input.Resources[0].Delegate, input.Secrets[0].Delegate = false, false
				retainRootEnrollment(t, f, input.Resources[0].SourceHandle, input.Resources[0])
				retainRootEnrollment(t, f, input.Secrets[0].SourceHandle, input.Secrets[0])
			case "narrower":
				input.Resources[0].Regions = input.Resources[0].Regions[:1]
				input.Resources[0].MaxActive = 1
				input.Resources[0].MaxHourlyMicros = 5
				input.Resources[0].TotalBudgetMicros = 50
				input.Resources[0].Delegate, input.Secrets[0].Delegate = false, false
				input.Resources[0].ExpiresAt, input.Secrets[0].ExpiresAt = "2030-01-01T02:00:00Z", "2030-01-01T01:00:00Z"
			}
			request = saveProfileInput(t, f, request, input)
			scope := humanScope(t, f, "grants.root", request)
			enrolledRootCommit(t, f, scope, backend)
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			if err != nil {
				t.Fatal("enrolled resource and secret root resolution failed", err)
			}
			if f.store.transactions != 1 || !reflect.DeepEqual(result, f.store.sets[result.ID]) || result.ParentLifeID != "" {
				t.Fatal("enrolled root result is not its durable root transaction")
			}
			if err := manifest.Set(result, f.clock.Now()); err != nil {
				t.Fatal("enrolled root set is invalid", err)
			}
			if len(result.Resources) != len(input.Resources) {
				t.Fatal("resource root member was not preserved")
			}
			if len(result.Secrets) != len(input.Secrets) {
				t.Fatal("secret root member was not preserved")
			}
			ids := map[api.ID]bool{result.ID: true, result.LifeID: true}
			for i, grant := range result.Resources {
				if !manifest.ValidID(grant.ID) || ids[grant.ID] || grant.ParentGrantID != "" {
					t.Fatal("resource root member lacks a fresh issued identity")
				}
				ids[grant.ID], grant.ID = true, ""
				if !reflect.DeepEqual(grant, input.Resources[i]) {
					t.Fatal("resource root member widened or changed the approved fields")
				}
			}
			for i, grant := range result.Secrets {
				if !manifest.ValidID(grant.ID) || ids[grant.ID] || grant.ParentGrantID != "" {
					t.Fatal("secret root member lacks a fresh issued identity")
				}
				ids[grant.ID], grant.ID = true, ""
				if !reflect.DeepEqual(grant, input.Secrets[i]) {
					t.Fatal("secret root member widened or changed the approved fields")
				}
			}
			if name == "resource-only" && result.ExpiresAt != input.Resources[0].ExpiresAt || name == "secret-only" && result.ExpiresAt != input.Secrets[0].ExpiresAt {
				t.Fatal("capability-only root lost its member expiry")
			}
			if backend != nil && len(result.Profiles) != len(input.Profiles) {
				t.Fatal("mixed root issuance lost the enrolled profiles")
			}
		})
	}
}

func TestRootEnrollmentRefusals(t *testing.T) {
	for _, family := range []string{"resource", "secret"} {
		for _, boundary := range []string{"unknown", "owner", "scope", "stale", "origin", "life", "digest", "class", "identity", "malformed", "source", "delegate", "expiry", "selection", "ceiling"} {
			t.Run(family+"-"+boundary, func(t *testing.T) {
				f, request, input := enrolledRootFixture(t)
				handle := input.Resources[0].SourceHandle
				if family == "secret" {
					handle = input.Secrets[0].SourceHandle
				}
				metadata := f.store.metadata[handle]
				code := api.CodeForbidden
				switch boundary {
				case "unknown":
					delete(f.store.metadata, handle)
					code = api.CodeNotFound
				case "owner":
					metadata.ACL.Owner.ID = "another-human"
					f.store.metadata[handle] = metadata
				case "scope":
					metadata.ACL.Config = "another-config"
					f.store.metadata[handle] = metadata
				case "stale":
					metadata.ACL.Generation++
					f.store.metadata[handle] = metadata
					code = api.CodeConflict
				case "origin":
					metadata.Origin = "observation"
					f.store.metadata[handle] = metadata
				case "life":
					metadata.ACL.LifeID = "parent"
					f.store.metadata[handle] = metadata
				case "digest":
					metadata.Ref.SHA256 = manifest.Hash([]byte("different committed enrollment"))
					f.store.metadata[handle] = metadata
					code = api.CodeIntegrity
				case "class":
					metadata.Ref.Class = "artifact"
					f.store.metadata[handle] = metadata
					code = api.CodeIntegrity
				case "identity":
					metadata.Ref.ID = "another-handle"
					f.store.metadata[handle] = metadata
					code = api.CodeIntegrity
				case "malformed":
					retainRootEnrollment(t, f, handle, map[string]string{"unexpected": "field"})
					code = api.CodeIntegrity
				default:
					if family == "resource" {
						enrolled := clone(t, input.Resources[0])
						switch boundary {
						case "source":
							enrolled.SourceHandle = "different-source"
						case "delegate":
							enrolled.Delegate = false
						case "expiry":
							enrolled.ExpiresAt = "2030-01-01T01:00:00Z"
						case "selection":
							enrolled.Regions = []string{"another-region"}
						case "ceiling":
							enrolled.MaxActive = 1
						}
						retainRootEnrollment(t, f, handle, enrolled)
					} else {
						enrolled := input.Secrets[0]
						switch boundary {
						case "source":
							enrolled.SourceHandle = "different-source"
						case "delegate":
							enrolled.Delegate = false
						case "expiry":
							enrolled.ExpiresAt = "2030-01-01T01:00:00Z"
						case "selection":
							enrolled.Version = "v2.0"
						case "ceiling":
							enrolled.Target = "ANOTHER_TASK_KEY"
						}
						retainRootEnrollment(t, f, handle, enrolled)
					}
				}
				scope := humanScope(t, f, "grants.root", request)
				enrolledRootCommit(t, f, scope, nil)
				result, err := f.service.GrantsRoot(context.Background(), scope, request)
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != code || typed.Owner != "lb-v2-grants" || result.ID != "" || f.store.transactions != 0 {
					t.Fatal("root enrollment escaped its protected record", family, boundary, err)
				}
			})
		}
	}
}

func TestRootEnrollmentRecheck(t *testing.T) {
	for _, boundary := range []string{"stale", "owner", "policy", "peer"} {
		t.Run(boundary, func(t *testing.T) {
			f, request, input := enrolledRootFixture(t)
			scope := humanScope(t, f, "grants.root", request)
			enrolledRootCommit(t, f, scope, nil)
			code := api.CodeForbidden
			// Root source validation reads the manifest and checks artifact
			// references; artifact bytes are materialized by a later worker.
			f.store.onBlobObject = "source-tree"
			f.store.onBlob = func() {
				metadata := f.store.metadata[input.Resources[0].SourceHandle]
				switch boundary {
				case "stale":
					metadata.ACL.Generation++
					code = api.CodeConflict
				case "owner":
					metadata.ACL.Owner.ID = "another-human"
				case "policy":
					f.store.policy.Generation++
					code = api.CodeConflict
				case "peer":
					scope.Connection.(*humanConnection).peer.alive = false
				}
				f.store.metadata[input.Resources[0].SourceHandle] = metadata
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			var typed *api.Error
			if f.store.onBlob != nil || !errors.As(err, &typed) || typed.Code != code || result.ID != "" || f.store.transactions != 0 {
				t.Fatal("root enrollment release ignored changed authority", boundary, err)
			}
		})
	}
}

func TestRootEnrollmentOrder(t *testing.T) {
	for _, boundary := range []string{"proof", "manifest", "policy"} {
		t.Run(boundary, func(t *testing.T) {
			f, request, input := enrolledRootFixture(t)
			scope := humanScope(t, f, "grants.root", request)
			reads := 0
			f.store.onMetadata = func(_ api.Scope, id api.ID) {
				if id == input.Resources[0].SourceHandle || id == input.Secrets[0].SourceHandle {
					reads++
				}
			}
			code := api.CodeForbidden
			switch boundary {
			case "proof":
				scope.Request.Proof = nil
			case "manifest":
				f.store.blobs[request.Manifest.ID] = []byte("changed immutable root input")
				code = api.CodeIntegrity
			case "policy":
				f.store.policy.Generation++
				code = api.CodeConflict
			}
			result, err := f.service.GrantsRoot(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || result.ID != "" || reads != 0 || f.store.transactions != 0 {
				t.Fatal("root enrollment lookup preceded the authority gates", boundary, err)
			}
		})
	}
}
