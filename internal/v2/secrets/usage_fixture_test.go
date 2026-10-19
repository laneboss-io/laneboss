package secrets

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type usagePeerFixture struct {
	facts api.PeerFacts
	err   error
}

func (p *usagePeerFixture) Facts(context.Context) (api.PeerFacts, error) { return p.facts, p.err }
func (p *usagePeerFixture) Alive(context.Context) error                  { return p.err }
func (p *usagePeerFixture) Close() error {
	p.err = wire.Error(api.CodeUnauthenticated, "fixture usage peer closed")
	return nil
}

func (s *launchCaseStore) WorkerBinding(_ context.Context, endpoint api.InstalledBinding, _ api.PeerFacts) (api.WorkerPrincipal, error) {
	if err := s.fail["worker-binding"]; err != nil {
		return api.WorkerPrincipal{}, err
	}
	var principal api.WorkerPrincipal
	if err := s.read("usage-principal.json", &principal); err != nil {
		return principal, err
	}
	if !reflect.DeepEqual(endpoint, principal.Endpoint) {
		if err := s.read("usage-principal-"+string(endpoint.WorkerLeaseID)+".json", &principal); err != nil || !reflect.DeepEqual(endpoint, principal.Endpoint) {
			return principal, wire.Error(api.CodeForbidden, "fixture worker selector differs from the protected mapping")
		}
	}
	// This is a post-authentication consumer fixture. Corruption cells can return
	// a bad retained tuple so the consumer must compare the independent facts.
	return principal, nil
}

type usageJobFixture struct {
	c        *launchCase
	request  api.UsageWindowRequest
	scope    api.Scope
	input    api.WorkerJobInput
	output   UsageCommandResult
	startErr error
	runErr   error
	starts   int
	runs     int
	omitAck  bool
	resultID api.ID
}

func (j *usageJobFixture) StartUsage(_ context.Context, scope api.Scope, request api.UsageWindowRequest) (api.Scope, error) {
	j.starts++
	if j.startErr != nil {
		return api.Scope{}, j.startErr
	}
	if scope.Config != j.scope.Config || request != j.request {
		return api.Scope{}, wire.Error(api.CodeForbidden, "fixture usage dispatch changed the sealed query")
	}
	return j.scope, nil
}

func (j *usageJobFixture) RunUsage(ctx context.Context, id api.ID) (UsageCommandResult, error) {
	j.runs++
	if j.runErr != nil {
		return UsageCommandResult{}, j.runErr
	}
	var principal api.WorkerPrincipal
	if err := j.c.store.read("usage-principal.json", &principal); err != nil {
		return UsageCommandResult{}, err
	}
	if id != principal.StageID {
		return UsageCommandResult{}, wire.Error(api.CodeForbidden, "fixture usage selected another stage")
	}
	// A real bounded pipe/exit measurement for the consumer fixture. Cat copies
	// synthetic bytes only; this is explicitly not an authenticated vendor query.
	command := exec.CommandContext(ctx, "/bin/cat", filepath.Join(j.c.store.root, "usage.tsv"))
	if j.output.ExitCode != 0 {
		command = exec.CommandContext(ctx, "/bin/false")
	}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	var out bytes.Buffer
	command.Stdout = &out
	err := command.Run()
	if command.ProcessState == nil {
		return UsageCommandResult{}, wire.Error(api.CodeUnavailable, "fixture usage source process failed")
	}
	if err != nil {
		if _, exited := err.(*exec.ExitError); !exited {
			return UsageCommandResult{}, wire.Error(api.CodeUnavailable, "fixture usage source process was not collected")
		}
	}
	result := j.output
	result.Raw = append([]byte(nil), out.Bytes()...)
	result.ExitCode = command.ProcessState.ExitCode()
	return result, nil
}

func (j *usageJobFixture) WorkerInput(_ context.Context, scope api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if request.LeaseID != j.input.LeaseID || scope.Actor != j.scope.Actor {
		return api.WorkerJobInput{}, wire.Error(api.CodeForbidden, "fixture usage input belongs to another worker")
	}
	var input api.WorkerJobInput
	if err := j.c.store.read("usage-input.json", &input); err != nil {
		return input, err
	}
	return input, nil
}

func (j *usageJobFixture) WorkerResult(ctx context.Context, scope api.Scope, submission api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	var p api.WorkerPrincipal
	if err := j.c.store.read("usage-principal.json", &p); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if scope.Actor != p.Record.Actor || submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 {
		return api.WorkerResultReceipt{}, wire.Error(api.CodeForbidden, "fixture usage result lost its original claim")
	}
	sum := sha256.Sum256(submission.Result)
	id := j.resultID
	if id == "" {
		id = "usage-result"
	}
	ref := api.BlobRef{ID: id, Class: "worker_result", Bytes: int64(len(submission.Result)), SHA256: api.Digest(hex.EncodeToString(sum[:]))}
	if !j.omitAck {
		var err error
		ref, err = j.c.store.RetainObject(ctx, j.c.service.deps.ServiceScope, api.RetainObjectRequest{Intent: *p.Claim.Record.Effect.Context, Object: api.ObjectWrite{ObjectKey: ref.ID, Class: ref.Class, Bytes: submission.Result, SHA256: ref.SHA256,
			ACL: api.ObjectACL{Config: "service-case", Owner: p.Record.Actor, LifeID: p.Lease.Target.LifeID, Audience: "service", Generation: 1}, Origin: "service", InputRefs: []api.BlobRef{p.Lease.Input}}})
		if err != nil {
			return api.WorkerResultReceipt{}, err
		}
	}
	return api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, CommittedSeq: 7, Result: ref}, nil
}

func selfUsageFacts(t *testing.T) (api.PeerFacts, string) {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("usage worker checks require the authorized nonroot Linux test identity")
	}
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal("cannot read the owned fixture process generation")
	}
	fields := strings.Fields(string(data[strings.LastIndex(string(data), ")")+2:]))
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(fields) < 20 {
		t.Fatal("cannot read the owned fixture boot and process scope")
	}
	return api.PeerFacts{HostUID: uint32(os.Geteuid()), HostGID: uint32(os.Getegid()), HostPID: os.Getpid(), ProcessGeneration: fields[19], ContainmentID: "usage-containment"}, strings.TrimSpace(string(boot))
}

func newUsageCase(t *testing.T) (*launchCase, *usageJobFixture) {
	t.Helper()
	c := newLaunchCaseWithAlternate(t, "helper", api.DriverClaudock)
	c.registeredCapture = true
	executableBytes, err := os.ReadFile(filepath.Join(c.store.root, "runtime.bin"))
	if err != nil {
		t.Fatal("cannot load actual synthetic runtime bytes")
	}
	content := c.store.putRawObject(t, "usage-executable-object", "artifact", executableBytes, "usage-enrollment")
	manifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: c.profile.Runtime, Bootstrap: c.profile.Runtime,
		Objects: []api.RuntimeObject{{ID: c.profile.Runtime.ID, Role: "usage", RootID: "runtime-root", RelativePath: "claudock", Content: content, Mode: 0500}}, Bindings: []api.InstalledBinding{}}
	manifestRef := c.store.putObject(t, "usage-runtime", "manifest", manifest, "usage-enrollment")
	profile := c.profile
	profile.Generation++
	profile.Usage = &bstate.UsageProfile{VendorProfile: "synthetic-" + hex.EncodeToString(syntheticBytes(t, 9)), AdapterVersion: "fixture-v1", Executable: profile.Runtime, RuntimeManifest: manifestRef}
	evidence := bstate.Observation{Schema: "laneboss.credential-evidence.v2", Config: "service-case", ProfileID: profile.ID, LoginID: profile.LoginID, Generation: profile.Generation, Driver: profile.Driver, Provider: profile.Provider,
		Available: true, CheckedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(c.clock.now.Add(3 * time.Minute).Format(time.RFC3339Nano))}
	profile.Evidence = c.store.putObject(t, "usage-profile-evidence", "credential_evidence", evidence, "usage-observation")
	if err := c.service.InstallProfile(context.Background(), profile); err != nil {
		t.Fatal("cannot install protected usage profile metadata")
	}
	c.profile = profile
	c.installOtherProfile(t)
	slot, err := c.acquire(context.Background(), c.target, c.grant)
	if err != nil {
		t.Fatal("cannot acquire the causing usage profile", err)
	}
	injection, err := c.inject(context.Background(), c.target, []api.SecretGrant{})
	if err != nil {
		t.Fatal("cannot prepare the causing usage injection")
	}
	observation := c.bind(t, slot, injection)
	observation = c.finish(t, observation)
	observation.ObservedAt = api.Timestamp(c.clock.now.Format(time.RFC3339Nano))
	end, err := json.Marshal(api.RunEndEvent{LaunchID: "launch-a", Reason: "exit", Observation: observation})
	if err != nil {
		t.Fatal("cannot retain the actual owned fixture exit")
	}
	c.store.events = append(c.store.events, api.Event{Schema: api.SchemaVersion, ID: "usage-causing-end", Config: "service-case", Kind: "lane.ended", Seq: 4, Origin: "service", Actor: api.Actor{Kind: "service", ID: "service-a"}, LifeID: c.target.LifeID, Run: c.target.Run, OperationID: "usage-operation", Payload: end})
	c.clock.now = c.clock.now.Add(time.Second)
	request := api.UsageWindowRequest{Target: c.target, LaunchID: "launch-a", OperationID: "usage-operation", ProfileGrantID: c.grant.ID, ProfileID: c.profile.ID, Provider: c.profile.Provider, RunEndedAt: observation.ObservedAt,
		AdapterVersion: profile.Usage.AdapterVersion, Executable: profile.Usage.Executable, RuntimeManifest: profile.Usage.RuntimeManifest}
	inputRef := c.store.putObject(t, "usage-job-input", "usage_input", UsageInput{Schema: "laneboss.usage-input.v1", Request: request, VendorProfile: profile.Usage.VendorProfile, ProfileGeneration: profile.Generation, Source: profile.Source}, request.OperationID)
	blob, err := c.store.Blob(context.Background(), api.Scope{}, api.BlobReadRequest{ObjectID: inputRef.ID})
	if err != nil {
		t.Fatal("cannot read sealed usage input bytes")
	}
	expires := api.Timestamp(c.clock.now.Add(time.Minute).Format(time.RFC3339Nano))
	jobGrants := api.GrantSet{ID: "usage-job-grants", LifeID: c.target.LifeID, PolicyGeneration: 1, Generation: 1, ExpiresAt: expires,
		Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Secrets: []api.SecretGrant{profile.Source}, Profiles: []api.ProfileGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	jobGrants.SHA256, err = valueDigest(jobGrants)
	if err != nil {
		t.Fatal("cannot hash the narrow retained usage grants")
	}
	c.store.workerGrants = &jobGrants
	lease := api.WorkerLease{ID: "usage-lease", Kind: "usage", Target: request.Target, OperationID: request.OperationID, EffectID: "usage-effect", Input: inputRef, RuntimeManifest: manifestRef, GrantSetID: c.store.grants.ID, Generation: 1, ExpiresAt: expires, ConsumedBy: "usage-launch"}
	lease.GrantSetID = jobGrants.ID
	facts, boot := selfUsageFacts(t)
	workerRecord := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: "service-case", Target: c.target, Actor: api.Actor{Kind: "worker", ID: "usage-principal", LifeID: c.target.LifeID}, HostUID: facts.HostUID,
		UIDLeaseID: "usage-uid-lease", ContainmentID: facts.ContainmentID, ProcessGeneration: facts.ProcessGeneration, GrantSetID: lease.GrantSetID, GrantsSHA256: jobGrants.SHA256, EndpointGeneration: 1, PolicyGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: "service-case", Class: api.EndpointWorker,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: facts.HostUID + 1000, ServiceGID: facts.HostGID + 1000, Socket: "/runtime/worker.sock", ArtifactSHA256: manifestRef.SHA256, ServiceVersion: "fixture", Backend: "linux-bwrap-landlock", LaunchID: workerRecord.ID, Target: &c.target, WorkerLeaseID: lease.ID}
	cause := api.InternalIntent{ID: "usage-cause", Kind: api.InternalObjectRetain, Config: "service-case", Actor: api.Actor{Kind: "service", ID: "usage-outbox"}, RequestedBy: c.plan(t).Reservation.RequestedBy, Target: c.target,
		CauseOperationID: request.OperationID, CauseRequestID: "usage-request", EffectID: lease.EffectID, CancellationEpoch: 1}
	worker := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "usage", Executable: manifest.Bootstrap, Argv: []string{"laneboss", "internal", "credential"}, Input: lease.Input, GrantSetID: lease.GrantSetID}
	p := api.WorkerPrincipal{StageID: "usage-stage", Lease: lease, Record: workerRecord, Endpoint: endpoint, Peer: facts, BootID: boot, AllocationGeneration: 1, CancellationEpoch: 1,
		Claim: api.EffectLease{ClaimID: "usage-claim", ExpiresAt: expires, Record: api.EffectRecord{State: "claimed", Generation: 1, ClaimID: "usage-claim", ClaimantID: "usage-outbox", ClaimExpiresAt: expires, Effect: api.Effect{ID: lease.EffectID, OperationID: lease.OperationID, Context: &cause, Worker: &worker}}}}
	if err := c.store.save("usage-principal.json", p); err != nil {
		t.Fatal("cannot retain independently read usage mapping")
	}
	connection := &connectionFixture{id: "usage-connection", binding: endpoint, peer: &usagePeerFixture{facts: facts}}
	scope := api.Scope{Config: "service-case", Actor: workerRecord.Actor, LaunchID: workerRecord.ID, EndpointGeneration: 1, Connection: connection, Frame: &frameFixture{connection: connection.ID(), data: []byte("private fixture frame")}}
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: lease.ID, Kind: "usage", OperationID: lease.OperationID, EffectID: lease.EffectID, Input: inputRef, Bytes: blob.Data}
	if err := c.store.save("usage-input.json", input); err != nil {
		t.Fatal("cannot retain actual usage bootstrap input")
	}
	j := &usageJobFixture{c: c, request: request, scope: scope, input: input, output: UsageCommandResult{Scope: scope, ObservedAt: api.Timestamp(c.clock.now.Format(time.RFC3339Nano))}}
	c.service.deps.UsageJobs, c.service.deps.Bootstrap = j, j
	j.raw(t, "100", c.clock.now.Add(time.Hour).Format(time.RFC3339Nano))
	return c, j
}

func (j *usageJobFixture) raw(t *testing.T, used, reset string) {
	t.Helper()
	data := []byte(fmt.Sprintf("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\n%s\tsynthetic-plan\tcurrent\t%s\t%s\n", j.c.profile.Usage.VendorProfile, used, reset))
	if err := os.WriteFile(filepath.Join(j.c.store.root, "usage.tsv"), data, 0600); err != nil {
		t.Fatal("cannot retain synthetic outside usage bytes")
	}
}
