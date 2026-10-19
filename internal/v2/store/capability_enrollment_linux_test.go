//go:build linux

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants"
)

type capabilityWorker struct{ api.DataWorker }

type capabilityInterceptor struct {
	api.StateStore
	mutate func(*api.Transaction)
}

func (s *capabilityInterceptor) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	s.mutate(&tx)
	return s.StateStore.Transact(ctx, tx)
}

func capabilityService(t *testing.T, c *metadataCase) *grants.Service {
	t.Helper()
	module, err := grants.New(grants.Dependencies{Config: c.state.deps.Config, Store: c.state,
		Worker: &capabilityWorker{}, Human: c.identities, Profiles: c.backend, Clock: c.state.deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	return module
}

func TestCapabilityEnrollmentRealStore(t *testing.T) {
	c := newMetadataCase(t)
	module := capabilityService(t, c)
	ctx := context.Background()
	expiry := api.Timestamp(c.state.deps.Clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	resource := api.ResourceEnrollment{Provider: "gcp", Regions: []string{"region-a"}, ImageIDs: []string{"image-a"},
		MachineTypes: []string{"small"}, MaxActive: 1, Delegate: true, ExpiresAt: expiry}
	request := api.CapabilityEnrollmentRequest{Resource: &resource}
	scope := c.scope(t, "grants.enroll", request, true)
	resourceRef, err := module.GrantsEnroll(ctx, scope, request)
	if err != nil {
		t.Fatal("operator resource enrollment failed", err)
	}
	metadata, raw, err := objectRow(ctx, c.state.db, resourceRef.ID)
	if err != nil || metadata.Ref != resourceRef || metadata.Origin != "service" || metadata.ACL.Owner != c.human.Actor ||
		metadata.ACL.Config != c.state.deps.Config || metadata.ACL.Generation != 1 {
		t.Fatal("operator enrollment did not retain protected authority", err)
	}
	var enrolledResource api.ResourceGrant
	if err := api.DecodeObject(raw, &enrolledResource); err != nil {
		t.Fatal(err)
	}
	// Derive the expected retained fields from the approved JSON, independently
	// of the proposal-to-grant conversion used by the service and writer.
	var expectedResource api.ResourceGrant
	if err := json.Unmarshal(enrollmentJSON(t, resource), &expectedResource); err != nil {
		t.Fatal(err)
	}
	expectedResource.SourceHandle = resourceRef.ID
	if !reflect.DeepEqual(enrolledResource, expectedResource) {
		t.Fatal("operator resource enrollment changed the approved fields")
	}
	material := make([]byte, 47)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	info := c.importSecret(t, "capability.canary", material)
	secret := api.SecretEnrollment{SourceHandle: info.SourceHandle, Name: info.Name, Version: info.Version,
		Delivery: "file", Target: "task-key", ExpiresAt: expiry}
	secretRequest := api.CapabilityEnrollmentRequest{Secret: &secret}
	secretRef, err := module.GrantsEnroll(ctx, c.scope(t, "grants.enroll", secretRequest, true), secretRequest)
	if err != nil {
		t.Fatal("operator secret enrollment failed", err)
	}
	secretMeta, secretRaw, err := objectRow(ctx, c.state.db, secretRef.ID)
	if err != nil || secretRef.ID != info.SourceHandle || secretMeta.ACL.Owner != c.human.Actor ||
		secretMeta.Origin != "service" || bytes.Contains(secretRaw, material) {
		t.Fatal("operator secret enrollment lost its source or exposed material", err)
	}
	var enrolledSecret api.SecretGrant
	var expectedSecret api.SecretGrant
	if err := json.Unmarshal(enrollmentJSON(t, secret), &expectedSecret); err != nil {
		t.Fatal(err)
	}
	if err := api.DecodeObject(secretRaw, &enrolledSecret); err != nil || enrolledSecret != expectedSecret {
		t.Fatal("operator secret capability differs from the protected source", err)
	}
	// Immutable root input is declared component intake, retained through the
	// actual writer. Enrollment records above use the public handler and proof.
	root := api.RootGrantManifest{Schema: "laneboss.root-grants.v2", Resources: []api.ResourceGrant{enrolledResource},
		Secrets: []api.SecretGrant{enrolledSecret}, Data: []api.DataGrant{}, Profiles: []api.ProfileGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	rootRaw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	setup := api.Scope{Config: c.state.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}, Source: "service"}
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "manifest", Bytes: rootRaw, SHA256: testDigest(rootRaw), Origin: "observation",
		ACL: api.ObjectACL{Config: setup.Config, Owner: c.human.Actor, Audience: "owner", Generation: 1}}
	intent := api.InternalIntent{ID: testID(t), Kind: api.InternalOrgBootstrap, Config: setup.Config, Actor: setup.Actor, RequestedBy: setup.Actor}
	if _, err := c.state.Transact(ctx, api.Transaction{Scope: setup, Internal: &intent, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		t.Fatal(err)
	}
	rootRequest := api.RootGrantRequest{Manifest: api.BlobRef{ID: object.ObjectKey, Class: "manifest", SHA256: object.SHA256, Bytes: int64(len(rootRaw))},
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 2, DiskBytes: 8192, Currency: "USD"}}
	issued, err := module.GrantsRoot(ctx, c.scope(t, "grants.root", rootRequest, true), rootRequest)
	if err != nil || len(issued.Resources) != 1 || len(issued.Secrets) != 1 || issued.Resources[0].SourceHandle != resourceRef.ID || issued.Secrets[0].SourceHandle != secretRef.ID {
		t.Fatal("operator-enrolled capabilities did not reach root issuance", err)
	}
}

func TestEnrollRefusesUnapproved(t *testing.T) {
	for _, boundary := range []string{"proof", "chosen-handle", "union", "secret-unenrolled"} {
		t.Run(boundary, func(t *testing.T) {
			c := newMetadataCase(t)
			module := capabilityService(t, c)
			grant := api.ResourceEnrollment{Provider: "gcp", Regions: []string{"a"}, ImageIDs: []string{"a"}, MachineTypes: []string{"a"},
				MaxActive: 1, ExpiresAt: api.Timestamp(c.state.deps.Clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
			request := api.CapabilityEnrollmentRequest{Resource: &grant}
			code := api.CodeInvalid
			switch boundary {
			case "proof":
				code = api.CodeForbidden
			case "chosen-handle":
				grant.SourceHandle = "caller-chosen"
			case "union":
				// Both arms must pass the wire decoder so this case reaches the
				// exactly-one-capability gate, rather than an empty source ID.
				request.Secret = &api.SecretEnrollment{SourceHandle: "union-source", Name: "task-key", Version: "v1",
					Delivery: "file", Target: "task-key", ExpiresAt: grant.ExpiresAt}
			case "secret-unenrolled":
				request.Resource = nil
				request.Secret = &api.SecretEnrollment{SourceHandle: "absent", Name: "task-key", Version: "v1", Delivery: "file", Target: "task-key", ExpiresAt: grant.ExpiresAt}
				code = api.CodeForbidden
			}
			scope := c.scope(t, "grants.enroll", request, boundary != "proof")
			ref, err := module.GrantsEnroll(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code || ref.ID != "" {
				t.Fatal("unapproved enrollment escaped its typed gate", boundary, err)
			}
		})
	}
}

func TestSecretCapabilityEnrollmentSource(t *testing.T) {
	for _, boundary := range []string{"current", "unknown", "owner", "stale"} {
		t.Run(boundary, func(t *testing.T) {
			c := newMetadataCase(t)
			info := c.importSecret(t, "enrollment.source", []byte(testID(t)))
			grant := api.SecretGrant{SourceHandle: info.SourceHandle, Name: info.Name, Version: info.Version,
				Delivery: "file", Target: "task-key", ExpiresAt: api.Timestamp(c.state.deps.Clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
			scope := c.human
			code := api.CodeForbidden
			switch boundary {
			case "unknown":
				grant.SourceHandle = "unenrolled"
				code = api.CodeNotFound
			case "owner":
				scope.Actor.ID = "another-human"
			case "stale":
				var head secretMetadata
				if err := storedProjection(context.Background(), c.state.db, "secret_head", secretNameID(info.Name), &head); err != nil {
					t.Fatal(err)
				}
				head.Generation++
				fixtureProjection(t, c.state, "secret_head", secretNameID(info.Name), head.Generation, head)
				code = api.CodeConflict
			}
			// Exercise the actual source predicate used again inside Transact.
			// Endpoint/proof fixtures are covered by the public handler test.
			err := c.state.secretCapability(context.Background(), c.state.db, scope, grant)
			if boundary == "current" {
				if err != nil {
					t.Fatal("current protected secret source was refused", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != code {
				t.Fatal("secret capability source escaped owner or generation validation", boundary, err)
			}
		})
	}
}

func TestCapabilityEnrollmentWriter(t *testing.T) {
	for _, boundary := range []string{"owner", "generation", "widen"} {
		t.Run(boundary, func(t *testing.T) {
			c := newMetadataCase(t)
			grant := api.ResourceEnrollment{Provider: "gcp", Regions: []string{"a"}, ImageIDs: []string{"a"}, MachineTypes: []string{"a"},
				MaxActive: 1, ExpiresAt: api.Timestamp(c.state.deps.Clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}
			request := api.CapabilityEnrollmentRequest{Resource: &grant}
			scope := c.scope(t, "grants.enroll", request, true)
			var key api.ID
			intercept := &capabilityInterceptor{StateStore: c.state, mutate: func(tx *api.Transaction) {
				object := &tx.Writes.Objects[0]
				key = object.ObjectKey
				switch boundary {
				case "owner":
					object.ACL.Owner.ID = "foreign-human"
				case "generation":
					object.ACL.Generation++
				case "widen":
					var actual api.ResourceGrant
					if err := api.DecodeObject(object.Bytes, &actual); err != nil {
						t.Fatal(err)
					}
					actual.MaxActive++
					object.Bytes = enrollmentJSON(t, actual)
					object.SHA256 = testDigest(object.Bytes)
					ref := api.BlobRef{ID: key, Class: object.Class, SHA256: object.SHA256, Bytes: int64(len(object.Bytes))}
					tx.Events[0].Payload, tx.Reply.Result = enrollmentJSON(t, ref), enrollmentJSON(t, ref)
				}
			}}
			module, err := grants.New(grants.Dependencies{Config: c.state.deps.Config, Store: intercept,
				Worker: &capabilityWorker{}, Human: c.identities, Profiles: c.backend, Clock: c.state.deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			ref, err := module.GrantsEnroll(context.Background(), scope, request)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || ref.ID != "" || key == "" {
				t.Fatal("enrollment writer accepted unapproved authority", boundary, err)
			}
			if _, _, err := objectRow(context.Background(), c.state.db, key); err == nil {
				t.Fatal("refused enrollment left an immutable record")
			}
			var proof api.VerifiedHumanProof
			if err := storedProjection(context.Background(), c.state.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
				t.Fatal("refused enrollment consumed the human proof", err)
			}
		})
	}
}
