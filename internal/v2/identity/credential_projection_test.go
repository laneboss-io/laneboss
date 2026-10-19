package identity

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are input-sensitive protected-record/native-port models. They carry
// synthetic metadata only, never credential values or descriptor/native proof.
func retainProjection(t *testing.T, store *fixtureStore, binding api.LaunchBindingRequest, plan api.LaunchPlan) {
	t.Helper()
	cause := cloneLaunchValue(t, binding.Recovery.Handoff.Cause)
	cause.ID, cause.Kind, cause.EffectID = "prepare-intent", api.InternalHelperPrepare, "prepare-effect"
	r := api.CredentialProjectionRequest{Cause: cause, Handoff: cloneLaunchValue(t, binding.Recovery.Handoff),
		Prepared: binding.Prepared, Lease: plan.Lease, Home: plan.Data.Home}
	r.Claim = api.EffectLease{ClaimID: "prepare-claim", ExpiresAt: "2100-01-01T00:00:00Z", Record: api.EffectRecord{
		State: api.EffectClaimed, Generation: 1, ClaimID: "prepare-claim", ClaimantID: "installed-service", ClaimExpiresAt: "2100-01-01T00:00:00Z",
		Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause,
			HelperPrepare: &api.HelperLaunchRequest{Cause: cause, LeaseID: plan.Lease.ID, PreparedSpecID: r.Handoff.Spec.ID, SpecSHA256: r.Handoff.SpecSHA256}}}}
	if err := api.ValidateCredentialProjectionRequest(r, time.Now().UTC()); err != nil {
		t.Fatalf("fixture setup: credential request is invalid: %v", err)
	}
	targets, err := api.CredentialTargets(r, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	a := api.CredentialProjectionAuthority{ID: "projection", Generation: 1, Request: r, Targets: targets,
		Helper:     api.Executable{ID: "root-helper", SHA256: digestBytes([]byte("enrolled helper")), Version: "fixture-v1"},
		Broker:     api.Executable{ID: "outside-broker", SHA256: digestBytes([]byte("enrolled broker")), Version: "fixture-v1"},
		HelperPeer: api.PeerFacts{HostPID: 101, ProcessGeneration: "boot:helper"},
		BrokerPeer: api.PeerFacts{HostUID: 7777, HostGID: 7777, HostPID: 102, ProcessGeneration: "boot:broker", ContainmentID: "broker-containment"},
		ServiceUID: 5678, InstallationGeneration: 1, BootID: "boot"}
	held, inherited := uint64(len(targets)), uint64(0)
	receipt := api.CredentialProjectionReceipt{ProjectionID: a.ID, Generation: 2, Prepared: r.Prepared, HelperLeaseID: r.Lease.ID,
		SpecSHA256: r.Handoff.SpecSHA256, Home: r.Home, CancellationEpoch: r.Cause.CancellationEpoch,
		HeldDescriptors: &held, InheritedSources: &inherited, GateClosed: true, ObservedAt: timestamp(time.Now().UTC())}
	for index, target := range targets {
		version := target.Version
		if target.SlotID != "" {
			version = "current-login-version"
		}
		a.Sources = append(a.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: version})
		item := api.CredentialHeldTarget{Target: target, SourceObjectID: fmt.Sprintf("source-%d", index), ObjectID: fmt.Sprintf("destination-%d", index),
			RootID: r.Home.RootID, HomeGeneration: r.Home.Generation, OwnerUID: r.Lease.UID, Mode: target.FileMode, ParentMode: 0700, Links: 1}
		if target.EnvironmentName != "" {
			item.ReadOnlyView = true
		}
		if target.Delivery == "env" {
			item.OwnerUID, item.Mode, item.Links = 0, 0600, 0
		}
		if target.FileMode == 0400 {
			item.ParentMode, item.ReadOnlyView = 0500, true
		}
		receipt.Targets = append(receipt.Targets, item)
	}
	store.projection = &api.CredentialProjectionRecord{Authority: a, State: "held", Generation: 2, Receipt: &receipt}
	effect := cloneLaunchValue(t, r.Claim.Record)
	store.projectionEffect = &effect
}

func (s *fixtureStore) CredentialProjection(_ context.Context, config string, prepared api.ID) (api.CredentialProjectionRecord, error) {
	s.projectionReads++
	s.projectionConfig, s.projectionPrepared = config, prepared
	if s.projectionRead != nil {
		s.projectionRead(s.projectionReads)
	}
	if s.projectionErr != nil {
		return api.CredentialProjectionRecord{}, s.projectionErr
	}
	if s.projection == nil {
		return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-service", "fixture protected credential projection")
	}
	return *s.projection, nil
}

func (s *fixtureStore) Effect(_ context.Context, _ api.Scope, id api.ID) (api.EffectRecord, error) {
	if s.err != nil {
		return api.EffectRecord{}, s.err
	}
	if s.projectionEffect == nil || s.projectionEffect.Effect.ID != id {
		return api.EffectRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return *s.projectionEffect, nil
}

type projectionPeers struct {
	fixturePeers
	expected api.CredentialProjectionAuthority
	peer     api.VerifiedPeer
	calls    int
	reject   error
	after    func()
}

func (p *projectionPeers) VerifyCredentialProjection(ctx context.Context, peer api.VerifiedPeer, authority api.CredentialProjectionAuthority) error {
	p.calls++
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.reject != nil {
		return p.reject
	}
	if peer != p.peer || !reflect.DeepEqual(authority, p.expected) {
		return refusal(api.CodeUnauthenticated, "fixture native executable or private-channel pin differs")
	}
	if p.after != nil {
		p.after()
	}
	return peer.Alive(ctx)
}

func projectionFixture(t *testing.T) (*Service, *fixtureStore, *fixturePeer, *projectionPeers, api.LaunchBindingRequest) {
	t.Helper()
	s, store, _ := serviceFixture(t)
	binding := fixtureLaunchBinding(t, store.record)
	retainFixturePlan(t, store, binding)
	peer := &fixturePeer{facts: store.projection.Authority.HelperPeer}
	verifier := &projectionPeers{peer: peer, expected: cloneLaunchValue(t, store.projection.Authority)}
	s.deps.Peers = verifier
	return s, store, peer, verifier, binding
}

func TestProjAuth(t *testing.T) {
	for _, rule := range []string{"valid", "peer", "channel", "helper-exec", "broker-exec", "installation", "missing-native", "request", "source", "targets", "broker-uid", "broker-group", "boot", "claim", "epoch", "grants", "policy", "drift", "late-epoch", "expiry", "missing", "error"} {
		t.Run(rule, func(t *testing.T) {
			s, store, peer, verifier, binding := projectionFixture(t)
			request := cloneLaunchValue(t, store.projection.Authority.Request)
			want := api.CodeForbidden
			sentinel := &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-admin", Message: "fixture native channel unavailable"}
			switch rule {
			case "peer":
				peer.facts.HostPID++
				want = api.CodeUnauthenticated
			case "channel":
				verifier.reject = refusal(api.CodeUnauthenticated, "fixture foreign channel")
				want = api.CodeUnauthenticated
			case "helper-exec":
				store.projection.Authority.Helper.SHA256 = digestBytes([]byte("foreign helper"))
				want = api.CodeUnauthenticated
			case "broker-exec":
				store.projection.Authority.Broker.SHA256 = digestBytes([]byte("foreign broker"))
				want = api.CodeUnauthenticated
			case "installation":
				store.projection.Authority.InstallationGeneration++
				want = api.CodeUnauthenticated
			case "missing-native":
				s.deps.Peers = &fixturePeers{}
				want = api.CodeNotImplemented
			case "request":
				request.WorkerCredentials = []api.WorkerCredential{}
				store.projection.Authority.Request.WorkerCredentials = nil
				want = api.CodeConflict
			case "source":
				store.projection.Authority.Sources[0].Revoked = true
			case "targets":
				store.projection.Authority.Targets = nil
				want = api.CodeIntegrity
			case "broker-uid":
				store.projection.Authority.BrokerPeer.HostUID = store.projection.Authority.ServiceUID
				want = api.CodeUnauthenticated
			case "broker-group":
				store.projection.Authority.BrokerPeer.ContainmentID = request.Lease.ContainmentID
				want = api.CodeUnauthenticated
			case "boot":
				store.projection.Authority.BootID = "foreign-boot"
				want = api.CodeUnauthenticated
			case "claim":
				store.projectionEffect.ClaimID = "foreign-claim"
				want = api.CodeConflict
			case "epoch":
				store.lane.CancellationEpoch++
				want = api.CodeConflict
			case "grants":
				store.grants.Revoked = true
			case "policy":
				store.policy.Generation++
				want = api.CodeConflict
			case "drift":
				verifier.after = func() { store.projection.Authority.Sources[0].Revoked = true }
				want = api.CodeConflict
			case "late-epoch":
				verifier.after = func() { store.lane.CancellationEpoch++ }
				want = api.CodeConflict
			case "expiry":
				verifier.after = func() { s.deps.Clock = fixtureClock{time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC)} }
				want = api.CodeInvalid
			case "missing":
				store.projection = nil
				want = api.CodeNotImplemented
			case "error":
				verifier.reject = sentinel
				want = api.CodeUnavailable
			}
			authority, err := s.AuthorizeCredentialProjection(context.Background(), peer, request)
			if rule != "valid" {
				fixtureCode(t, err, want)
				if !reflect.DeepEqual(authority, api.CredentialProjectionAuthority{}) {
					t.Fatal("fixture check: refused projection returned authority")
				}
				if rule == "error" && !errors.Is(err, sentinel) {
					t.Fatal("fixture check: native owner error was replaced")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(authority, store.projection.Authority) || verifier.calls != 1 || store.projectionReads != 2 ||
				store.projectionConfig != binding.Record.Config || store.projectionPrepared != binding.Prepared.ID {
				t.Fatalf("fixture check: current protected projection was not verified: %v", err)
			}
			authority.Sources[0].Revoked = true
			if store.projection.Authority.Sources[0].Revoked {
				t.Fatal("fixture check: returned projection aliases protected sources")
			}
			if _, err := s.AuthorizeCredentialProjection(context.Background(), peer, request); err != nil || verifier.calls != 2 {
				t.Fatalf("fixture check: projection verification was cached or lost: %v", err)
			}
		})
	}
}

func TestProjWorker(t *testing.T) {
	for _, rule := range []string{"valid", "policy", "selection", "materialize", "revoked"} {
		t.Run(rule, func(t *testing.T) {
			s, store, peer, verifier, _ := projectionFixture(t)
			r := cloneLaunchValue(t, store.projection.Authority.Request)
			r.Handoff.Spec.Kind, r.Handoff.Spec.Runner = "worker", nil
			r.Handoff.Spec.Worker = &api.WorkerPlan{Kind: "channel"}
			r.Worker = &api.WorkerLease{ID: "channel-lease", Kind: "channel", Target: r.Prepared.Target,
				OperationID: r.Handoff.OperationID, EffectID: "channel-effect",
				Input:      api.BlobRef{ID: "channel-input", Class: "channel_send_input", SHA256: digestBytes([]byte("sealed channel input")), Bytes: 20},
				GrantSetID: r.Handoff.Spec.Grants.ID, ConsumedBy: r.Handoff.Spec.LaunchID, Generation: 1, ExpiresAt: "2100-01-01T00:00:00Z"}
			r.WorkerCredentials = []api.WorkerCredential{{Name: "channel-key", SourceHandle: "enrolled-source", Version: "v1", Delivery: "env", Target: "CHANNEL_TOKEN"}}
			r.Handoff.Spec.Injection.SlotIDs = nil
			if rule == "materialize" {
				r.Worker.Kind, r.Handoff.Spec.Worker.Kind = "materialize", "materialize"
			}
			raw, err := api.CanonicalJSON(launchJSON(t, r.Handoff.Spec))
			if err != nil {
				t.Fatal(err)
			}
			digest := digestBytes(raw)
			r.Handoff.SpecSHA256, r.Prepared.SpecSHA256, r.Handoff.Original.SHA256 = digest, digest, digest
			r.Handoff.Original.Bytes = int64(len(raw))
			r.Claim.Record.Effect.HelperPrepare.SpecSHA256 = digest
			store.projection.Authority.Request = cloneLaunchValue(t, r)
			store.projection.State, store.projection.Generation, store.projection.Receipt = "reserved", 1, nil
			if rule != "materialize" {
				targets, err := api.CredentialTargets(r, s.deps.Clock.Now())
				if err != nil {
					t.Fatal(err)
				}
				store.projection.Authority.Targets = targets
				store.projection.Authority.Sources = []api.CredentialSourceVersion{{Key: targets[0].Key, Generation: 1, Version: "v1"}}
			}
			effect := cloneLaunchValue(t, r.Claim.Record)
			store.projectionEffect = &effect
			verifier.expected = cloneLaunchValue(t, store.projection.Authority)
			if rule == "policy" {
				store.policy.Generation++
			}
			if rule == "selection" {
				r.WorkerCredentials[0].SourceHandle = "caller-source"
			}
			if rule == "revoked" {
				store.projection.Authority.Sources[0].Revoked = true
			}
			authority, err := s.AuthorizeCredentialProjection(context.Background(), peer, r)
			if rule == "valid" || rule == "policy" {
				if err != nil || authority.Targets[0].SourceHandle != "enrolled-source" || verifier.calls != 1 {
					t.Fatalf("fixture check: protected worker selection was refused: %v", err)
				}
				return
			}
			want := api.CodeConflict
			if rule == "materialize" {
				want = api.CodeInvalid
			}
			if rule == "revoked" {
				want = api.CodeForbidden
			}
			fixtureCode(t, err, want)
			if !reflect.DeepEqual(authority, api.CredentialProjectionAuthority{}) {
				t.Fatal("fixture check: unselected worker credential returned authority")
			}
		})
	}
}

// Isolate existing plan fences from the new independent credential gate while
// retaining the original complete BindLaunch regression fixtures unchanged.
func TestPlanFence(t *testing.T) {
	for _, rule := range []string{"epoch", "grants", "contents", "policy"} {
		t.Run(rule, func(t *testing.T) {
			s, store, scope := serviceFixture(t)
			plan := fixtureLaunchPlan(t, store.record)
			plan.Capture.Status, plan.Capture.Refusal, plan.Capture.RefusalPolicy, plan.CapturePolicy = "registered", nil, nil, nil
			plan.Capture.WorkerLeaseID, plan.Capture.EffectID, plan.Capture.ProducerID = "capture-worker", "capture-effect", "capture-producer"
			plan.Capture.ProducerGeneration, plan.Capture.BootID = "kernel-generation", "boot"
			plan.Capture.Supervisor = &api.Executable{ID: "supervisor", SHA256: digestBytes([]byte("fixed supervisor")), Version: "fixture-v1"}
			plan.Capture.Streams = []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stderr", Stream: "stderr", PipeID: "pipe-err"}}
			binding := plannedFixtureBinding(t, store.record, plan)
			retainCustomPlan(t, store, binding, plan)
			want := api.CodeConflict
			switch rule {
			case "epoch":
				store.lane.CancellationEpoch++
			case "grants":
				store.grants.Generation++
				want = api.CodeForbidden
			case "contents":
				store.grants.Data[0].Access = "ro"
				want = api.CodeForbidden
			case "policy":
				store.policy = &api.EffectivePolicy{Generation: plan.Reservation.PolicyGeneration + 1}
			}
			fixtureCode(t, s.checkPlanAuthority(context.Background(), scope, plan), want)
		})
	}
}

func TestProjGate(t *testing.T) {
	for _, rule := range []string{"valid", "missing", "reserved", "fenced", "source", "held", "inherit", "home", "binding", "claim", "epoch", "drift"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _, _, binding := projectionFixture(t)
			protectedBinding := cloneLaunchValue(t, *store.binding)
			want := api.CodeInvalid
			switch rule {
			case "missing":
				store.projection = nil
				want = api.CodeNotImplemented
			case "reserved":
				store.projection.State, store.projection.Generation, store.projection.Receipt = "reserved", 1, nil
			case "fenced":
				store.projection.Fence = &api.CredentialWithdrawalRequest{}
				want = api.CodeForbidden
			case "source":
				store.projection.Authority.Sources[0].Revoked = true
				want = api.CodeForbidden
			case "held":
				*store.projection.Receipt.HeldDescriptors++
			case "inherit":
				*store.projection.Receipt.InheritedSources++
			case "home":
				store.projection.Receipt.Home.Generation++
			case "binding":
				// A self-consistent foreign request must reach the protected
				// binding comparison rather than fail the shape preflight.
				binding.Record.ProcessGeneration = "foreign-kernel"
				binding.Prepared.ProcessGeneration = binding.Record.ProcessGeneration
				binding.Identity.RecordSHA256 = launchBlob(t, "record", "manifest", binding.Record).SHA256
				if err := validateLaunch(binding.Record); err != nil {
					t.Fatalf("fixture setup: foreign launch record is invalid: %v", err)
				}
				if err := validateBindingRequest(binding); err != nil {
					t.Fatalf("fixture setup: foreign binding did not pass preflight: %v", err)
				}
				if reflect.DeepEqual(binding, protectedBinding) {
					t.Fatal("fixture setup: foreign binding did not differ from protected state")
				}
				want = api.CodeConflict
			case "claim":
				store.projectionEffect.State = api.EffectCompleted
				want = api.CodeConflict
			case "epoch":
				store.lane.CancellationEpoch++
				want = api.CodeConflict
			case "drift":
				store.projectionRead = func(read int) {
					if read == 2 {
						store.projection.Authority.Sources[0].Revoked = true
					}
				}
				want = api.CodeConflict
			}
			record, err := s.CheckLaunchCredentials(context.Background(), binding)
			if rule != "valid" {
				fixtureCode(t, err, want)
				if rule == "binding" && (store.projectionReads != 0 || !reflect.DeepEqual(*store.binding, protectedBinding)) {
					t.Fatal("fixture check: foreign binding reached projection lookup or changed protected state")
				}
				if !reflect.DeepEqual(record, api.CredentialProjectionRecord{}) {
					t.Fatal("fixture check: refused credential gate returned a record")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(record, *store.projection) {
				t.Fatalf("fixture check: held projection was refused: %v", err)
			}
			*record.Receipt.HeldDescriptors++
			if *record.Receipt.HeldDescriptors == *store.projection.Receipt.HeldDescriptors {
				t.Fatal("fixture check: held receipt aliases protected state")
			}
		})
	}
}

func TestProjPermit(t *testing.T) {
	for _, rule := range []string{"valid", "missing", "revoked"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _, _, binding := projectionFixture(t)
			if rule == "missing" {
				store.projection = nil
			}
			if rule == "revoked" {
				store.projection.Authority.Sources[0].Revoked = true
			}
			permit, err := s.BindLaunch(context.Background(), binding)
			if rule == "valid" {
				if err != nil || permit.PreparedID != binding.Prepared.ID || store.projectionReads != 2 {
					t.Fatalf("fixture check: permit omitted protected holding: %v", err)
				}
				return
			}
			want := api.CodeForbidden
			if rule == "missing" {
				want = api.CodeNotImplemented
			}
			fixtureCode(t, err, want)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: unheld credential launch returned a permit")
			}
		})
	}
}

func TestProjRecord(t *testing.T) {
	for _, rule := range []string{"valid", "source", "broker-uid", "broker-group", "boot", "targets", "fence", "generation"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _, _, _ := projectionFixture(t)
			record := cloneLaunchValue(t, *store.projection)
			want := api.CodeForbidden
			switch rule {
			case "source":
				record.Authority.Sources[0].Revoked = true
			case "broker-uid":
				record.Authority.BrokerPeer.HostUID = record.Authority.ServiceUID
				want = api.CodeUnauthenticated
			case "broker-group":
				record.Authority.BrokerPeer.ContainmentID = record.Authority.Request.Lease.ContainmentID
				want = api.CodeUnauthenticated
			case "boot":
				record.Authority.BootID = "foreign-boot"
				want = api.CodeUnauthenticated
			case "targets":
				record.Authority.Targets = nil
				want = api.CodeIntegrity
			case "fence":
				record.Fence = &api.CredentialWithdrawalRequest{}
			case "generation":
				record.Generation++
			}
			err := s.checkProjectionRecord(record)
			if rule == "valid" {
				if err != nil {
					t.Fatalf("fixture check: valid credential record refused: %v", err)
				}
				return
			}
			fixtureCode(t, err, want)
		})
	}
}

func TestProjState(t *testing.T) {
	for _, rule := range []string{"valid", "claim", "epoch", "grants", "policy"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _, _, _ := projectionFixture(t)
			request := cloneLaunchValue(t, store.projection.Authority.Request)
			want := api.CodeConflict
			switch rule {
			case "claim":
				store.projectionEffect.ClaimID = "foreign-claim"
			case "epoch":
				store.lane.CancellationEpoch++
			case "grants":
				store.grants.Revoked = true
				want = api.CodeForbidden
			case "policy":
				store.policy.Generation++
			}
			err := s.checkProjectionState(context.Background(), request)
			if rule == "valid" {
				if err != nil {
					t.Fatalf("fixture check: current credential state refused: %v", err)
				}
				return
			}
			fixtureCode(t, err, want)
		})
	}
}

func TestRegistrationID(t *testing.T) {
	for _, raw := range [][]byte{[]byte("first key"), []byte("independent second key")} {
		plain := api.HumanCredential{ID: api.ID("credential-" + string(digestBytes(raw))), RawCredentialID: raw,
			PublicKeyDER: append([]byte(nil), raw...), Generation: 7, Counter: 12}
		if got := normalizeRegistration(plain); !reflect.DeepEqual(got, plain) {
			t.Fatal("fixture check: ordinary credential normalization changed its identity")
		}
		marked := cloneLaunchValue(t, plain)
		marked.AAGUID, marked.AttestationMarker, marked.SimulatedPresence = api.SoftwareAuthenticatorAAGUID, api.SoftwareAuthenticatorAttestationMarker, true
		want := cloneLaunchValue(t, marked)
		want.ID = api.SoftwareAuthenticatorCredentialID
		if got := normalizeRegistration(marked); !reflect.DeepEqual(got, want) {
			t.Fatal("fixture check: software credential normalization lost its reserved identity or provenance")
		}
	}
}
