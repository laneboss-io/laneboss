//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This component uses the helper's real file journal and descriptor gate.
// Its in-process transport does not claim installed service authentication.
// Registration and resolution still run every production cgroup/peer check.
func checkAgentContainment(t *testing.T, m *leaseManager, open gateOpenRegistration, gate *nativeGate, output *os.File) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := &Service{deps: Dependencies{Config: m.binding.Config}, binding: m.binding}
	t.Cleanup(func() {
		if err := s.revokeEntries(open.Binding.Record.UIDLeaseID); err != nil {
			t.Error(err)
		}
	})
	client, helper := nativePair(t)
	clientPeer, helperPeer := nativePeer(t, client), nativePeer(t, helper)
	session := &workerLaunchSession{service: s, connection: client, peer: clientPeer}
	ctx = context.WithValue(ctx, workerCallKey{}, session)
	finished := make(chan error, 1)
	registeredAtOpen := false
	go func() {
		for {
			data, err := readUnixFrame(helper, helperPeer)
			if err != nil {
				finished <- err
				return
			}
			var request helperRequest
			if err := decodeStrict(data, &request); err != nil {
				finished <- err
				return
			}
			var result any
			var callErr error
			switch request.Method {
			case "containment":
				var query containmentQuery
				if callErr = decodeStrict(request.Params, &query); callErr == nil {
					result, callErr = m.containment(ctx, query)
				}
			case "open_gate":
				var registration gateOpenRegistration
				if callErr = decodeStrict(request.Params, &registration); callErr == nil {
					s.registryMu.Lock()
					entry := s.containments[registration.Request.Prepared.ContainmentID]
					registeredAtOpen = entry != nil && !entry.Binding.Revoked && entry.Binding.Directory != nil
					s.registryMu.Unlock()
					result, callErr = m.openGate(ctx, registration)
				}
			case "finish":
				finished <- nil
				return
			default:
				callErr = failure(api.CodeInvalid, "unexpected agent test helper method")
			}
			reply := helperResponse{Protocol: helperProtocol, Revision: api.ContractRevision, Nonce: request.Nonce}
			if callErr != nil {
				if !errors.As(callErr, &reply.Error) {
					finished <- callErr
					return
				}
			} else if reply.Result, err = EncodeWire(result); err != nil {
				finished <- err
				return
			}
			if err := writeFrame(helper, reply); err != nil {
				finished <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		request, err := session.request("finish", api.Empty{})
		if err == nil {
			err = writeFrame(client, request)
		}
		if err != nil {
			t.Error(err)
		}
		if err := <-finished; err != nil {
			t.Error(err)
		}
	})
	var handle api.ProcessHandle
	if err := s.call(ctx, "open_gate", open, &handle); err != nil {
		t.Fatal("agent gate did not open", err)
	}
	if handle.Generation != gate.Generation() || handle.ContainmentID != open.Request.Prepared.ContainmentID {
		t.Fatal("agent launch changed its real process identity")
	}
	if err := output.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(output, actual); err != nil || string(actual) != gate.token {
		t.Fatal("agent did not execute its real output canary", err)
	}
	record := open.Binding.Record
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: m.binding.Config, Class: api.EndpointLane,
		InstallationGeneration: m.binding.Generation, EndpointGeneration: record.EndpointGeneration,
		ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID, Socket: "/run/agent.sock",
		ArtifactSHA256: m.binding.Artifact.SHA256, ServiceVersion: m.binding.Release.Version,
		Backend: "linux-bwrap-landlock", LaunchID: record.ID, Target: &record.Target}
	facts := api.PeerFacts{HostPID: gate.PID(), HostUID: record.HostUID, HostGID: m.binding.Lanes[0].GID,
		ProcessGeneration: gate.Generation()}
	resolved, err := s.ResolveContainment(ctx, facts, endpoint)
	if err != nil {
		t.Fatal("launched agent peer did not resolve:", err)
	}
	defer resolved.Directory.Close()
	if resolved.Lease.ID != record.UIDLeaseID || resolved.Lease.ContainmentID != handle.ContainmentID ||
		resolved.Target != record.Target || resolved.BootID != m.bootID || resolved.Revoked || !registeredAtOpen {
		t.Fatal("agent containment was not pinned before native gate release")
	}
	for _, change := range []func(*api.PeerFacts){
		func(p *api.PeerFacts) { p.HostUID++ },
		func(p *api.PeerFacts) { p.HostGID++ },
		func(p *api.PeerFacts) { p.ProcessGeneration += "-stale" },
		func(p *api.PeerFacts) { p.HostPID = os.Getpid() },
	} {
		changed := facts
		change(&changed)
		if bound, err := s.ResolveContainment(ctx, changed, endpoint); err == nil {
			bound.Directory.Close()
			t.Fatal("agent registration accepted changed native peer facts")
		}
	}
	if err := s.revokeEntries(record.UIDLeaseID); err != nil {
		t.Fatal(err)
	}
	if bound, err := s.ResolveContainment(ctx, facts, endpoint); err == nil {
		bound.Directory.Close()
		t.Fatal("revoked agent containment still resolved")
	}
}

// This fixture supplies unresolved retained bytes and a real filesystem.
// It never returns a selected source, host destination, successful helper
// process, or completed materialization. It is not installed-helper evidence.
type launchFixtureStore struct {
	api.StateStore
	plan        api.LaunchPlanRecord
	claim       api.EffectRecord
	grants      api.GrantSet
	policy      api.EffectivePolicy
	objects     map[api.ID][]byte
	metadata    map[api.ID]api.ObjectMetadata
	fences      int
	objectReads int
	cancelled   bool
}

func (s *launchFixtureStore) scope(scope api.Scope) error {
	if scope.Config != s.plan.Reservation.Config || scope.Actor != s.claim.Effect.Context.Actor && scope.Actor != (api.Actor{Kind: "service", ID: s.claim.ClaimantID}) || scope.Source != "service" {
		return failure(api.CodeForbidden, "fixture store rejected foreign scope")
	}
	return nil
}
func (s *launchFixtureStore) PendingEffects(_ context.Context, request api.CursorRequest) ([]api.Effect, error) {
	if request.Limit < 1 {
		return nil, failure(api.CodeInvalid, "fixture discovery requires a bound")
	}
	return []api.Effect{s.claim.Effect}, nil
}
func (s *launchFixtureStore) Effect(_ context.Context, scope api.Scope, id api.ID) (api.EffectRecord, error) {
	if err := s.scope(scope); err != nil {
		return api.EffectRecord{}, err
	}
	if id != s.claim.Effect.ID {
		return api.EffectRecord{}, failure(api.CodeNotFound, "fixture effect missing")
	}
	return s.claim, nil
}
func (s *launchFixtureStore) LaunchPlan(_ context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	if err := s.scope(scope); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if id != s.plan.Reservation.ID {
		return api.LaunchPlanRecord{}, failure(api.CodeNotFound, "fixture reservation missing")
	}
	return s.plan, nil
}
func (s *launchFixtureStore) Operation(_ context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	if err := s.scope(scope); err != nil {
		return api.Operation{}, err
	}
	if id != s.plan.Reservation.OperationID {
		return api.Operation{}, failure(api.CodeNotFound, "fixture operation missing")
	}
	r := s.plan.Reservation
	return api.Operation{ID: id, Status: "pending", LifeID: r.Target.LifeID, Run: r.Target.Run}, nil
}
func (s *launchFixtureStore) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	if id != s.grants.ID {
		return api.GrantSet{}, failure(api.CodeNotFound, "fixture grants missing")
	}
	return s.grants, nil
}
func (s *launchFixtureStore) Policy(_ context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	if err := s.scope(scope); err != nil {
		return api.EffectivePolicy{}, err
	}
	return s.policy, nil
}
func (s *launchFixtureStore) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	s.objectReads++
	if err := s.scope(scope); err != nil {
		return api.ObjectMetadata{}, err
	}
	metadata, exists := s.metadata[id]
	if !exists {
		return api.ObjectMetadata{}, failure(api.CodeNotFound, "fixture object missing")
	}
	return metadata, nil
}
func (s *launchFixtureStore) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	if err := s.scope(scope); err != nil {
		return api.BlobChunk{}, err
	}
	data, exists := s.objects[request.ObjectID]
	if !exists || request.Offset < 0 || request.Offset >= int64(len(data)) || request.Limit < 1 {
		return api.BlobChunk{}, failure(api.CodeInvalid, "fixture range missing")
	}
	end := min(int64(len(data)), request.Offset+int64(request.Limit))
	part := append([]byte(nil), data[request.Offset:end]...)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: digestBytes(part)}, nil
}
func (s *launchFixtureStore) Transact(_ context.Context, transaction api.Transaction) (api.Commit, error) {
	if err := s.scope(transaction.Scope); err != nil {
		return api.Commit{}, err
	}
	if err := api.ValidateTransactionShape(transaction); err != nil {
		return api.Commit{}, err
	}
	r := s.plan.Reservation
	want := []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: s.plan.Generation},
		{Kind: api.CompareGrants, ID: s.grants.ID, Generation: s.grants.Generation},
		{Kind: api.CompareOrg, ID: api.ID(r.Config), Generation: s.policy.Generation}}
	if s.cancelled || !reflect.DeepEqual(transaction.Compare, want) || transaction.Internal == nil ||
		transaction.Internal.Target != r.Target || transaction.Internal.RequestedBy != r.RequestedBy ||
		len(transaction.Guards) != 1 || transaction.Guards[0].Cancellation == nil ||
		*transaction.Guards[0].Cancellation != (api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}) ||
		!reflect.ValueOf(transaction.Writes).IsZero() || len(transaction.Events)+len(transaction.Effects) != 0 {
		return api.Commit{}, failure(api.CodeConflict, "fixture launch fence refused")
	}
	s.fences++
	return api.Commit{Operation: api.Operation{ID: r.OperationID, Status: "pending"}}, nil
}

func encodeLaunchFixture(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (s *launchFixtureStore) retain(id api.ID, class string, data []byte, operation, life api.ID) api.BlobRef {
	ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: digestBytes(data)}
	s.objects[id] = append([]byte(nil), data...)
	s.metadata[id] = api.ObjectMetadata{Ref: ref, Origin: "service", SourceOperationID: operation,
		CommittedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)),
		ACL:         api.ObjectACL{Config: "admin-case", Owner: s.claim.Effect.Context.Actor, LifeID: life, Audience: "service", Generation: 1}}
	return ref
}

func seedLaunchFiles(t *testing.T) (*Service, *launchFixtureStore, api.LaunchEnrollment, api.StartRequest) {
	t.Helper()
	directory := privateTestDir(t)
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	cause := testCause(api.InternalLaunchPlan, "life-a")
	cause.CancellationEpoch = 1
	store := &launchFixtureStore{objects: map[api.ID][]byte{}, metadata: map[api.ID]api.ObjectMetadata{},
		claim: api.EffectRecord{Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause,
			PlanLaunch: &api.LaunchPlanEffect{ReservationID: "reservation-a"}}, State: api.EffectClaimed, Generation: 1,
			ClaimID: "claim-a", ClaimantID: "planner-a", ClaimExpiresAt: api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))},
		policy: api.EffectivePolicy{Generation: 1, ProfileExclusions: []api.ID{}, Rules: []api.Rule{}, Skip: []api.SkipEntry{}, Sources: []api.SourceRef{}}}
	binding := testBinding()
	manifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}}
	if err := root.Mkdir("objects", 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []api.ID{"artifact", "bootstrap", "agent"} {
		// Actual retained input bytes, never executed or represented as an ELF
		// or authenticated D8 vendor in this component test.
		data := []byte("unexecuted component bytes for " + string(id))
		ref := api.BlobRef{ID: api.ID("content-" + string(id)), Class: "artifact", Bytes: int64(len(data)), SHA256: digestBytes(data)}
		if err := os.WriteFile(filepath.Join(directory, "objects", string(id)), data, 0555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, "objects", string(id)), 0555); err != nil {
			t.Fatal(err)
		}
		manifest.Objects = append(manifest.Objects, api.RuntimeObject{ID: id, Role: string(id), RootID: "objects", RelativePath: string(id), Content: ref, Mode: 0555})
	}
	manifest.Artifact = api.Executable{ID: "artifact", SHA256: manifest.Objects[0].Content.SHA256, Version: binding.Release.Version}
	manifest.Bootstrap = api.Executable{ID: "bootstrap", SHA256: manifest.Objects[1].Content.SHA256, Version: "component-v1"}
	binding.Artifact.SHA256, binding.Artifact.Bytes = manifest.Artifact.SHA256, manifest.Objects[0].Content.Bytes
	binding.Release.Artifacts[0] = binding.Artifact
	runtimeBytes := encodeLaunchFixture(t, manifest)
	runtimeRef := store.retain("runtime", "manifest", runtimeBytes, "enroll-operation", "")
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), runtimeBytes, 0444); err != nil {
		t.Fatal(err)
	}
	roots := []enrolledRoot{{ID: "objects", Path: filepath.Join(directory, "objects")}}
	if err := os.WriteFile(filepath.Join(directory, "roots.json"), encodeLaunchFixture(t, roots), 0444); err != nil {
		t.Fatal(err)
	}
	projectRef := store.retain("project-object", "manifest", encodeLaunchFixture(t, api.ObjectManifest{Schema: "component-object", Entries: []api.ObjectEntry{}}), "enroll-operation", "")
	enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: "admin-case", Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: "project-enrollment", Generation: 1, ProjectID: "project-a", Object: projectRef,
			Base: string(testDigest("base selector only; no Git job in this component")), HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: api.DriverCodex,
			Executable: api.Executable{ID: "agent", SHA256: manifest.Objects[2].Content.SHA256, Version: "component-v1"}, Manifest: runtimeRef}}}
	enrollmentBytes := encodeLaunchFixture(t, enrollment)
	enrollmentRef := store.retain("launch-enrollment", "manifest", enrollmentBytes, "enroll-operation", "")
	if err := os.WriteFile(filepath.Join(directory, "launch-enrollment.json"), enrollmentBytes, 0444); err != nil {
		t.Fatal(err)
	}
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	store.grants = api.GrantSet{ID: "grants-a", LifeID: "life-a", SHA256: testDigest("issued-grants"), PolicyGeneration: 1, Generation: 1,
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}, ExpiresAt: expires,
		Data: []api.DataGrant{{ID: "data-a", SourceObjectID: projectRef.ID, SourceSHA256: projectRef.SHA256, RelativePath: ".", Destination: "/work/main",
			HistoryScope: "tree", Access: "rw", Delivery: "copy", ExpiresAt: expires}},
		Profiles: []api.ProfileGrant{{ID: "profile-a", ProfileID: "approved-profile", Driver: api.DriverCodex, ExpiresAt: expires}}}
	input := api.StartRequest{Lane: "child", ProjectID: "project-a", Level: 3, Role: "executor", Driver: api.DriverCodex,
		ProfileGrantID: "template-profile-a", Model: "component-model", Effort: "high", Budget: testAllocation().Budget, ExpectedPolicyGeneration: 1}
	input.Task = store.retain("task-a", "task", []byte("component launch task"), "input-operation", "")
	input.Grants = api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
		Profiles: []api.ProfileDelegation{{ParentGrantID: input.ProfileGrantID, ProfileID: store.grants.Profiles[0].ProfileID, ExpiresAt: expires}}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}
	store.plan = api.LaunchPlanRecord{Generation: 1, Phase: "reserved", Reservation: api.LaunchReservation{ID: "reservation-a", Config: "admin-case",
		Level: 3, Role: "executor", Driver: api.DriverCodex, Authority: api.LaunchAuthority{Kind: "ticket", ID: "root-ticket"},
		Mode: "start", Target: cause.Target, LaunchID: "launch-a", SpecID: "spec-a", GrantSetID: store.grants.ID, Generation: 1,
		CancellationEpoch: 1, PolicyGeneration: 1, RootLifeID: "life-a", StarterChain: []api.ID{}, OperationID: cause.CauseOperationID,
		RequestID: cause.CauseRequestID, RequestedBy: cause.RequestedBy}}
	input.RootTicketID = "root-ticket"
	resealLaunchFixture(t, store, input)
	service := &Service{deps: Dependencies{Store: store, Config: "admin-case", RuntimeManifest: runtimeRef, LaunchEnrollment: &enrollmentRef},
		binding: binding, files: &enrollmentFiles{root: root, base: directory, owner: uint32(os.Geteuid())}}
	return service, store, enrollment, input
}

func resealLaunchFixture(t *testing.T, store *launchFixtureStore, input api.StartRequest) {
	t.Helper()
	r := &store.plan.Reservation
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: r.Config, RequestID: r.RequestID,
		IdempotencyKey: "original-key", Method: "lane.start", Params: encodeLaunchFixture(t, input)}
	digest, err := api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestSHA256 = digest
	r.RequestSHA256 = digest
	r.OriginalRequest = store.retain("original-request", "launch_request", encodeLaunchFixture(t, request), r.OperationID, r.Target.LifeID)
}

func TestLaunchSourcesRetained(t *testing.T) {
	service, store, enrollment, _ := seedLaunchFiles(t)
	request := api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)}
	selected, err := service.ResolveLaunchSources(context.Background(), request)
	if err != nil {
		t.Fatalf("acceptance: retained launch sources unavailable: %v", err)
	}
	if selected.Project.ProjectID != enrollment.Projects[0].ProjectID || selected.Project.GrantID != store.grants.Data[0].ID ||
		selected.Runtime.Executable != enrollment.Runtimes[0].Executable || store.fences != 2 {
		t.Fatal("acceptance: launch source did not resolve retained bytes and fences")
	}
	store.plan.Phase, store.plan.Generation = "sourced", 2
	store.plan.Inputs = &api.LaunchInputs{Grants: store.grants, Sources: selected}
	again, err := service.ResolveLaunchSources(context.Background(), request)
	if err != nil || !reflect.DeepEqual(again, selected) {
		t.Fatalf("retained source replay changed: %v", err)
	}
	// A real changed enrollment is written and repinned. The sourced record
	// must still refuse its different generation, including after restart.
	enrollment.Runtimes[0].Generation++
	data := encodeLaunchFixture(t, enrollment)
	path := filepath.Join(service.files.base, "launch-enrollment.json")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	ref := store.retain("launch-enrollment", "manifest", data, "enroll-operation", "")
	service.deps.LaunchEnrollment = &ref
	restarted := &Service{deps: service.deps, binding: service.binding, files: service.files}
	_, err = restarted.ResolveLaunchSources(context.Background(), request)
	if err == nil {
		t.Fatal("acceptance: changed launch source replay accepted")
	}
	requireCode(t, err, api.CodeConflict)
}

func TestLaunchSourceRefusals(t *testing.T) {
	for _, name := range []string{"policy", "revoked", "claim", "claim-state", "requester", "cancelled", "grant-source", "logical-path", "profile", "upload-label", "runtime-bytes", "writable-parent", "linked-runtime"} {
		t.Run(name, func(t *testing.T) {
			service, store, _, input := seedLaunchFiles(t)
			switch name {
			case "policy":
				store.policy.Generation++
			case "revoked":
				store.grants.Revoked = true
			case "claim":
				store.claim.ClaimExpiresAt = "2000-01-01T00:00:00Z"
			case "claim-state":
				store.claim.State = "pending"
			case "requester":
				store.plan.Reservation.RequestedBy.ID = "foreign-human"
			case "cancelled":
				store.cancelled = true
			case "grant-source":
				store.grants.Data[0].SourceSHA256 = testDigest("foreign-source")
			case "logical-path":
				input.ProjectID = "/caller/path"
				resealLaunchFixture(t, store, input)
			case "profile":
				store.policy.ProfileExclusions = []api.ID{store.grants.Profiles[0].ProfileID}
			case "upload-label":
				metadata := store.metadata[service.deps.LaunchEnrollment.ID]
				metadata.Origin = "lane"
				store.metadata[metadata.Ref.ID] = metadata
			case "runtime-bytes":
				path := filepath.Join(service.files.base, "objects", "agent")
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("different runtime input"), 0555); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0555); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(filepath.Join(service.files.base, "objects"), 0777); err != nil {
					t.Fatal(err)
				}
			case "linked-runtime":
				path := filepath.Join(service.files.base, "objects", "agent")
				if err := os.Rename(path, path+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("artifact", path); err != nil {
					t.Fatal(err)
				}
			}
			allowed := captureAllowed(t)
			selected, err := service.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)})
			if name == "upload-label" {
				// Owner R181-R192: the launch object's origin pin is allowed and logged, so the sources still resolve.
				if err != nil || reflect.DeepEqual(selected, api.LaunchSources{}) || !slices.Contains(allowed(), "launch_object_private_input") {
					t.Fatal("launch object origin pin was not allowed and logged", err, allowed())
				}
				return
			}
			if err == nil || !reflect.DeepEqual(selected, api.LaunchSources{}) {
				t.Fatal("acceptance: untrusted launch source accepted")
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code == api.CodeNotImplemented {
				t.Fatalf("source refusal did not reach a guard: %v", err)
			}
			if name == "policy" && typed.Code != api.CodeForbidden {
				t.Fatal("acceptance: stale launch policy bypassed preflight")
			}
			if name == "claim" && store.objectReads != 0 {
				t.Fatal("acceptance: expired launch claim reached object work")
			}
		})
	}
}

func TestProtectedLaunchBytes(t *testing.T) {
	for _, target := range []string{"enrollment", "runtime"} {
		t.Run(target, func(t *testing.T) {
			service, _, enrollment, _ := seedLaunchFiles(t)
			path := filepath.Join(service.files.base, "launch-enrollment.json")
			data := []byte(nil)
			if target == "enrollment" {
				enrollment.Generation++
				data = encodeLaunchFixture(t, enrollment)
			} else {
				path = filepath.Join(service.files.base, "objects", "agent")
				var err error
				data, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data[0] ^= 1
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			mode := os.FileMode(0444)
			if target == "runtime" {
				mode = 0555
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := service.loadLaunchEnrollment(context.Background())
			if err == nil {
				t.Fatal("acceptance: changed protected launch bytes accepted")
			}
			requireCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestLaunchDependencyRefusal(t *testing.T) {
	service, _, _, _ := seedLaunchFiles(t)
	// A missing bound store never opens helper transport or invents state.
	service.deps.Store = nil
	_, err := service.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: "reservation-a", GrantSetID: "grants-a"})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-service" || typed.Code != api.CodeNotImplemented || strings.Contains(typed.Message, "/caller/") {
		t.Fatalf("missing dependency did not remain an owning refusal: %v", err)
	}
}

func TestLaunchAllocationInput(t *testing.T) {
	service, store, _, _ := seedLaunchFiles(t)
	sources, err := service.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)})
	if err != nil {
		t.Fatal(err)
	}
	store.plan.Phase, store.plan.Generation = "sourced", 2
	store.plan.Inputs = &api.LaunchInputs{Grants: store.grants, Sources: sources}
	request := testAllocation()
	request.ReservationID, request.Cause.CancellationEpoch = store.plan.Reservation.ID, store.plan.Reservation.CancellationEpoch
	request.Cause.Actor = api.Actor{Kind: "service", ID: store.claim.ClaimantID}
	store.claim.Effect.Context = &request.Cause
	store.claim.Effect.PlanLaunch = nil
	store.claim.Effect.HelperAllocate = &request
	changed := request
	changed.Budget.Processes--
	ctx := api.WithEffectLease(context.Background(), api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt})
	_, err = service.Allocate(ctx, changed)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "launch allocation differs from its exact retained stage input" {
		t.Fatalf("acceptance: changed allocation stage input reached helper work: %v", err)
	}
}

func TestRetainedLaunchAuthority(t *testing.T) {
	service, store, _, _ := seedLaunchFiles(t)
	query := api.LaunchSourceRequest{ReservationID: store.plan.Reservation.ID, GrantSetID: store.grants.ID, Claim: fixtureLaunchClaim(store)}
	if _, err := service.ResolveLaunchSources(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	store.plan.Reservation.Authority.ID = "foreign-consumed-ticket"
	if _, err := service.ResolveLaunchSources(context.Background(), query); err == nil {
		t.Fatal("acceptance: retained authority reference differs from original request")
	}
}

func TestReservedLaunchSelection(t *testing.T) {
	for _, pin := range []string{"level", "role", "driver"} {
		t.Run(pin, func(t *testing.T) {
			service, store, enrollment, input := seedLaunchFiles(t)
			authority, err := service.launchAuthority(context.Background(), store.plan.Reservation.ID, store.grants.ID, nil, fixtureLaunchClaim(store))
			if err != nil {
				t.Fatal(err)
			}
			_, manifest, err := service.loadLaunchEnrollment(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := selectLaunchSources(authority, enrollment, manifest, input.ProjectID, input.Driver, input.Level, input.Role, store.grants.Profiles[0].ID); err != nil {
				t.Fatal(err)
			}
			switch pin {
			case "level":
				authority.Record.Reservation.Level++
			case "role":
				authority.Record.Reservation.Role = "reviewer"
			case "driver":
				authority.Record.Reservation.Driver = api.DriverClaudock
			}
			if _, err := selectLaunchSources(authority, enrollment, manifest, input.ProjectID, input.Driver, input.Level, input.Role, store.grants.Profiles[0].ID); err == nil {
				t.Fatal("acceptance: reserved launch pins were ignored")
			}
		})
	}
}

func TestAuthorityNeedsClaimant(t *testing.T) {
	service, store, _, _ := seedLaunchFiles(t)
	cause := *store.claim.Effect.Context
	cause.Kind = api.InternalHelperAllocate
	store.claim.Effect.Context = &cause
	store.claim.Effect.PlanLaunch = nil
	store.claim.Effect.HelperAllocate = &api.HelperLeaseRequest{ReservationID: store.plan.Reservation.ID, Cause: cause,
		Config: store.plan.Reservation.Config, LifeID: store.plan.Reservation.Target.LifeID, Backend: "linux-bwrap-landlock",
		RuntimeManifestID: store.grants.ID, Budget: api.Budget{WallMS: 1, MemoryBytes: 4096, Processes: 1, DiskBytes: 4096}}
	stale := store.claim
	stale.ClaimID = "stale-claim"
	ctx := api.WithEffectLease(context.Background(), api.EffectLease{Record: stale, ClaimID: stale.ClaimID, ExpiresAt: stale.ClaimExpiresAt})
	if _, err := service.launchAuthority(ctx, store.plan.Reservation.ID, store.grants.ID, &cause); err == nil {
		t.Fatal("stale cause author was rebound to the current planning claim")
	} else {
		requireCode(t, err, api.CodeConflict)
	}
	cause.Actor = api.Actor{Kind: "service", ID: store.claim.ClaimantID}
	ctx = api.WithEffectLease(context.Background(), api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt})
	if _, err := service.launchAuthority(ctx, store.plan.Reservation.ID, store.grants.ID, &cause); err != nil {
		t.Fatalf("current planning claimant was refused: %v", err)
	}
}

type currentStageFixtureStore struct {
	api.StateStore
	claim        api.EffectRecord
	transactions int
}

func (s *currentStageFixtureStore) Effect(context.Context, api.Scope, api.ID) (api.EffectRecord, error) {
	return s.claim, nil
}

func (s *currentStageFixtureStore) Transact(context.Context, api.Transaction) (api.Commit, error) {
	s.transactions++
	return api.Commit{}, nil
}

func TestStageRejectsStaleCause(t *testing.T) {
	cause := testCause(api.InternalHelperPrepare, "life-a")
	request := api.HelperLaunchRequest{Cause: cause, LeaseID: "lease-a", PreparedSpecID: "spec-a", SpecSHA256: testDigest("spec-a")}
	expires := api.Timestamp(time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano))
	store := &currentStageFixtureStore{claim: api.EffectRecord{Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID,
		Context: &cause, HelperPrepare: &request}, State: api.EffectClaimed, Generation: 2, ClaimID: "claim-b", ClaimantID: "claimant-b", ClaimExpiresAt: expires}}
	service := &Service{deps: Dependencies{Store: store, Config: "admin-case"}}
	stale := store.claim
	stale.ClaimID, stale.ClaimantID = "claim-a", "claimant-a"
	ctx := api.WithEffectLease(context.Background(), api.EffectLease{Record: stale, ClaimID: stale.ClaimID, ExpiresAt: stale.ClaimExpiresAt})
	if _, err := service.currentStage(ctx, cause, api.InternalHelperPrepare); err == nil {
		t.Fatal("stale helper cause was accepted after a reclaim")
	} else {
		requireCode(t, err, api.CodeConflict)
	}
	current := cause
	current.Actor = api.Actor{Kind: "service", ID: "claimant-b"}
	ctx = api.WithEffectLease(context.Background(), api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt})
	if _, err := service.currentStage(ctx, current, api.InternalHelperPrepare); err != nil {
		t.Fatalf("fresh helper claimant was refused: %v", err)
	}
	if store.transactions != 1 {
		t.Fatalf("stale helper reached the transaction fence: %d", store.transactions)
	}
}
