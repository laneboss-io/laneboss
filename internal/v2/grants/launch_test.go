package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// These are input-dependent retained-state/journal fixtures, not an installed
// helper, worker execution or authenticated AI-service acceptance result.
type launchClock struct{}

func (launchClock) Now() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }

type launchView struct {
	actor  api.Actor
	plans  map[api.ID]api.LaunchPlanRecord
	lanes  map[api.ID]api.Lane
	policy api.Generation
	closed bool
}

func (v *launchView) Snapshot() api.ReadSnapshot {
	return api.ReadSnapshot{ID: "snapshot", Config: "case-grants", PolicyGeneration: v.policy}
}
func (v *launchView) Close() error { v.closed = true; return nil }

type launchGraph struct {
	api.StateStore
	t                 *testing.T
	plans             map[api.ID]api.LaunchPlanRecord
	sets              map[api.ID]api.GrantSet
	lanes             map[api.ID]api.Lane
	operations        map[api.ID]api.Operation
	tickets           map[api.ID]api.Ticket
	bindings          map[api.ID]api.LaunchBindingRequest
	blobs             map[api.ID][]byte
	metadata          map[api.ID]api.ObjectMetadata
	events            []api.Event
	views             []*launchView
	policy            api.Generation
	profileExclusions []api.ID
	capturePolicy     bool
	captureRefused    bool
	policyScopes      []api.Scope
	policyRequests    []api.GrantPolicyRequest
	launches          map[api.ID]api.LaunchRecord
	enrollment        api.BlobRef
	runtime           api.BlobRef
	selection         api.StartRequest
	scope             api.Scope
	resolver          *grants.Service
	helper            *launchJournal
	worker            *dataworker.Service
	onBlob            func(api.ID)
	planError         error
	planAlias         api.ID
	reads             int
}

func launchCopy[T any](t *testing.T, value T) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func (g *launchGraph) check(scope api.Scope) {
	g.t.Helper()
	if scope.Config != "case-grants" || scope.Actor.Kind != "service" ||
		(scope.Actor.ID != "planner" && scope.Actor.ID != "grants-dataworker" && scope.Actor.ID != "grants") {
		g.t.Fatal("launch read relabelled its actual service execution actor")
	}
	if view, ok := scope.ReadView.(*launchView); ok && view.closed {
		g.t.Fatal("launch read used a closed view")
	}
	if view, ok := scope.ReadView.(*launchView); ok && view.actor != scope.Actor {
		g.t.Fatal("launch read changed the pinned authenticated actor")
	}
}

func (g *launchGraph) BeginRead(_ context.Context, scope api.Scope) (api.ReadView, error) {
	g.check(scope)
	if scope.ReadView != nil {
		g.t.Fatal("launch verification reused its caller's read view")
	}
	v := &launchView{actor: scope.Actor, plans: launchCopy(g.t, g.plans), lanes: launchCopy(g.t, g.lanes), policy: g.policy}
	g.views = append(g.views, v)
	return v, nil
}

func (g *launchGraph) LaunchPlan(_ context.Context, scope api.Scope, id api.ID) (api.LaunchPlanRecord, error) {
	g.check(scope)
	g.reads++
	if g.planError != nil {
		return api.LaunchPlanRecord{}, g.planError
	}
	if g.planAlias != "" {
		id = g.planAlias
	}
	plans := g.plans
	if view, ok := scope.ReadView.(*launchView); ok {
		plans = view.plans
	}
	value, ok := plans[id]
	if !ok {
		return api.LaunchPlanRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) Policy(_ context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	g.check(scope)
	g.policyScopes = append(g.policyScopes, scope)
	generation := g.policy
	if view, ok := scope.ReadView.(*launchView); ok {
		generation = view.policy
	}
	return api.EffectivePolicy{Generation: generation, Context: api.RoleContext{Level: scope.Actor.Level, Role: scope.Actor.Role}, ProfileExclusions: append([]api.ID(nil), g.profileExclusions...),
		AllowCaptureRefusal: g.capturePolicy, CaptureRefusalApprovalID: "capture-approval"}, nil
}

func (g *launchGraph) GrantPolicy(ctx context.Context, scope api.Scope, request api.GrantPolicyRequest) (api.EffectivePolicy, error) {
	g.check(scope)
	if request.ReservationID != "" {
		record, err := g.LaunchPlan(ctx, scope, request.ReservationID)
		if err != nil {
			return api.EffectivePolicy{}, err
		}
		r := record.Reservation
		if request.Target != r.Target || request.GrantSetID != r.GrantSetID || request.Context != (api.RoleContext{Level: r.Level, Role: r.Role}) || request.PolicyGeneration != r.PolicyGeneration {
			g.t.Fatal("policy request changed its protected reservation pins")
		}
	} else {
		lane, err := g.Lane(ctx, scope, request.Target)
		if err != nil {
			return api.EffectivePolicy{}, err
		}
		if request.Context != (api.RoleContext{Level: lane.Level, Role: lane.Role}) || request.GrantSetID != lane.GrantSetID || request.PolicyGeneration != lane.PolicyGeneration {
			g.t.Fatal("policy request changed its protected lane pins")
		}
	}
	g.policyRequests = append(g.policyRequests, request)
	policy, err := g.Policy(ctx, scope)
	if err == nil && policy.Generation != request.PolicyGeneration {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeConflict}
	}
	return policy, err
}

func (g *launchGraph) Launch(_ context.Context, id api.ID) (api.LaunchRecord, error) {
	value, ok := g.launches[id]
	if !ok {
		return api.LaunchRecord{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) Grants(_ context.Context, id api.ID) (api.GrantSet, error) {
	value, ok := g.sets[id]
	if !ok {
		return api.GrantSet{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) Operation(_ context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	g.check(scope)
	value, ok := g.operations[id]
	if !ok {
		return api.Operation{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) LaunchTicket(ctx context.Context, scope api.Scope, request api.LaunchTicketRequest) (api.Ticket, error) {
	g.check(scope)
	record, err := g.LaunchPlan(ctx, scope, request.ReservationID)
	if err != nil {
		return api.Ticket{}, err
	}
	if record.Reservation.Authority.Kind != "ticket" || record.Reservation.RequestedBy.Kind != "human" {
		return api.Ticket{}, &api.Error{Code: api.CodeForbidden}
	}
	value, ok := g.tickets[record.Reservation.Authority.ID]
	if !ok {
		return api.Ticket{}, &api.Error{Code: api.CodeNotFound}
	}
	return value, nil
}

func (g *launchGraph) Lane(_ context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	g.check(scope)
	lanes := g.lanes
	if view, ok := scope.ReadView.(*launchView); ok {
		lanes = view.lanes
	}
	value, ok := lanes[target.LifeID]
	if !ok {
		return api.Lane{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	value, ok := g.bindings[id]
	if !ok {
		return api.LaunchBindingRequest{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) Events(_ context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	g.check(scope)
	page := api.EventPage{Events: []api.Event{}, Complete: true}
	for _, event := range g.events {
		if event.LifeID == request.LifeID && event.Run == request.Run && event.Seq > request.Since {
			page.Events = append(page.Events, event)
		}
	}
	return page, nil
}

func (g *launchGraph) ObjectMetadata(_ context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	g.check(scope)
	value, ok := g.metadata[id]
	if !ok {
		return api.ObjectMetadata{}, &api.Error{Code: api.CodeNotFound}
	}
	return launchCopy(g.t, value), nil
}

func (g *launchGraph) Blob(_ context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	g.check(scope)
	if g.onBlob != nil {
		g.onBlob(request.ObjectID)
	}
	raw, ok := g.blobs[request.ObjectID]
	if !ok {
		return api.BlobChunk{}, &api.Error{Code: api.CodeNotFound}
	}
	if request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit <= 0 {
		g.t.Fatal("invalid launch blob range")
	}
	end := min(int64(len(raw)), request.Offset+int64(request.Limit))
	data := append([]byte{}, raw[request.Offset:end]...)
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: manifest.Hash(data)}, nil
}

func (g *launchGraph) object(id api.ID, class string, raw []byte, operation api.ID) api.BlobRef {
	g.t.Helper()
	ref := api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	g.blobs[id] = append([]byte{}, raw...)
	g.metadata[id] = api.ObjectMetadata{Ref: ref, Origin: "service", SourceOperationID: operation, CommittedAt: api.Timestamp(launchClock{}.Now().UTC().Format(time.RFC3339Nano)),
		ACL: api.ObjectACL{Config: "case-grants", Owner: api.Actor{Kind: "service", ID: "retainer"}, Audience: "owner", Generation: 1}}
	return ref
}

func (g *launchGraph) encoded(id api.ID, class string, value any, operation api.ID) api.BlobRef {
	g.t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		g.t.Fatal(err)
	}
	return g.object(id, class, raw, operation)
}

func launchSeal(t *testing.T, set *api.GrantSet) {
	t.Helper()
	set.SHA256 = ""
	digest, err := manifest.HashValue(*set)
	if err != nil {
		t.Fatal(err)
	}
	set.SHA256 = digest
}

func (g *launchGraph) request(body any, method api.Method, reservation *api.LaunchReservation) {
	g.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		g.t.Fatal(err)
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: "case-grants", Method: method,
		RequestID: reservation.RequestID, IdempotencyKey: api.ID(strings.Repeat("a", 32)), Params: raw}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		g.t.Fatal(err)
	}
	if reservation.Authority.Kind == "proof" {
		request.Proof = &api.ProofRef{ID: reservation.Authority.ID, RequestSHA256: request.RequestSHA256}
	}
	reservation.RequestSHA256 = request.RequestSHA256
	reservation.OriginalRequest = g.encoded(api.ID("input-"+string(reservation.ID)), "launch_request", request, reservation.OperationID)
}

// Fixture construction goes through the production validators. Fault cells
// mutate a validated seed afterwards; none can bypass the live loader gate.
func (g *launchGraph) validReservation(r api.LaunchReservation) {
	g.t.Helper()
	if err := api.ValidateLaunchReservation(r); err != nil {
		g.t.Fatal("fixture reservation rejected by production validator", err)
	}
	var frame api.Request
	if err := api.DecodeObject(g.blobs[r.OriginalRequest.ID], &frame); err != nil {
		g.t.Fatal(err)
	}
	scope := api.Scope{Config: r.Config, Actor: r.RequestedBy, LaunchID: r.Authority.ID,
		PolicyGeneration: r.PolicyGeneration, EndpointGeneration: 1, Request: frame}
	request := api.LaunchReservationRequest{OperationID: r.OperationID}
	if r.Mode == "start" || r.Mode == "adopt" {
		if r.RequestedBy.Kind == "human" {
			ticket := g.tickets[r.Authority.ID]
			request.Guards = []api.TransactionGuard{{Ticket: &api.TicketUse{TicketID: ticket.ID, PrincipalID: ticket.PrincipalID,
				Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Level: ticket.Level, Role: ticket.Role, GrantSetID: ticket.GrantSetID}}}
		}
	} else {
		request.Guards = []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}
		if r.Mode == "continue" {
			request.ContinuationID, scope.Request = "continuation-one", api.Request{}
		} else if r.RequestedBy.Kind == "human" {
			if frame.Proof == nil {
				g.t.Fatal("retained fixture omitted its original human proof")
			}
			request.Guards = append(request.Guards, api.TransactionGuard{Proof: &api.ProofUse{Proof: *frame.Proof,
				Target: api.HumanChallengeRequest{Method: frame.Method, TargetID: r.Target.LifeID,
					RequestSHA256: r.RequestSHA256, BaseGeneration: r.BaseGeneration}}})
		}
	}
	if err := api.ValidateLaunchReservationRequest(scope, request); err != nil {
		g.t.Fatal("fixture reservation authority rejected by production validator", err)
	}
}

type launchProbe struct{ api.Launcher }

type launchJournal struct {
	api.HelperControl
	g            *launchGraph
	storage      map[api.ID]api.LaunchStorage
	directories  map[api.ID]string
	onSources    func(*api.LaunchSources)
	onStorage    func(*api.LaunchStorage)
	sourceErr    error
	storageErr   error
	storageCalls int
}

func (j *launchJournal) ResolveLaunchSources(_ context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	if j.sourceErr != nil {
		return api.LaunchSources{}, j.sourceErr
	}
	r, ok := j.g.plans[request.ReservationID]
	if !ok || r.Reservation.GrantSetID != request.GrantSetID {
		return api.LaunchSources{}, &api.Error{Code: api.CodeForbidden}
	}
	metadata := j.g.metadata[j.g.enrollment.ID]
	raw := j.g.blobs[j.g.enrollment.ID]
	if metadata.Origin != "installation" || metadata.Ref.SHA256 != manifest.Hash(raw) {
		return api.LaunchSources{}, &api.Error{Code: api.CodeIntegrity}
	}
	var installed api.LaunchEnrollment
	if err := api.DecodeObject(raw, &installed); err != nil {
		return api.LaunchSources{}, err
	}
	if err := api.ValidateLaunchEnrollment(installed, r.Reservation.Config, j.g.runtime); err != nil {
		return api.LaunchSources{}, err
	}
	var original api.Request
	if err := api.DecodeObject(j.g.blobs[r.Reservation.OriginalRequest.ID], &original); err != nil {
		return api.LaunchSources{}, err
	}
	var selected api.StartRequest
	if original.Method == "lane.start" {
		if err := api.DecodeObject(original.Params, &selected); err != nil {
			return api.LaunchSources{}, err
		}
	} else {
		selected = j.g.selection
	} // Retained logical selection from the journal, never caller input.
	var result api.LaunchSources
	result.ReservationID = request.ReservationID
	set, found := j.g.sets[request.GrantSetID]
	if !found {
		return result, &api.Error{Code: api.CodeNotFound}
	}
	for _, project := range installed.Projects {
		if project.ProjectID != selected.ProjectID {
			continue
		}
		for _, grant := range set.Data {
			if grant.Destination == "/work/main" && grant.SourceObjectID == project.Object.ID && grant.SourceSHA256 == project.Object.SHA256 && grant.HistoryScope == project.HistoryScope {
				result.Project = api.ProjectLaunchSource{EnrollmentID: project.ID, Generation: project.Generation, ProjectID: project.ProjectID,
					GrantID: grant.ID, Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}
			}
		}
	}
	for _, runtime := range installed.Runtimes {
		if runtime.Driver == r.Reservation.Driver {
			result.Runtime = runtime
		}
	}
	if result.Project.GrantID == "" || result.Runtime.EnrollmentID == "" {
		return result, &api.Error{Code: api.CodeForbidden}
	}
	if j.onSources != nil {
		j.onSources(&result)
	}
	return result, nil
}

func (j *launchJournal) ResolveLaunchStorage(_ context.Context, request api.LaunchDataRequest) (api.LaunchStorage, error) {
	j.storageCalls++
	if j.storageErr != nil {
		return api.LaunchStorage{}, j.storageErr
	}
	entry, ok := j.storage[request.LeaseID]
	plan, exists := j.g.plans[request.ReservationID]
	if !ok || !exists || entry.ReservationID != request.ReservationID || entry.Target != plan.Reservation.Target || plan.Reservation.GrantSetID != request.GrantSetID {
		return api.LaunchStorage{}, &api.Error{Code: api.CodeForbidden}
	}
	for _, id := range []api.ID{entry.WorkspaceID, entry.Home.RootID} {
		path, registered := j.directories[id]
		if !registered {
			return api.LaunchStorage{}, &api.Error{Code: api.CodeNotFound}
		}
		info, err := os.Lstat(path)
		if err != nil {
			return api.LaunchStorage{}, err
		}
		facts, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode().Perm() != 0700 || !ok || facts.Uid != uint32(os.Getuid()) {
			return api.LaunchStorage{}, &api.Error{Code: api.CodeIntegrity}
		}
	}
	if j.onStorage != nil {
		j.onStorage(&entry)
	}
	return entry, nil
}

func newLaunchGraph(t *testing.T) *launchGraph {
	t.Helper()
	g := &launchGraph{t: t, plans: map[api.ID]api.LaunchPlanRecord{}, sets: map[api.ID]api.GrantSet{}, lanes: map[api.ID]api.Lane{},
		launches:   map[api.ID]api.LaunchRecord{},
		operations: map[api.ID]api.Operation{}, tickets: map[api.ID]api.Ticket{}, bindings: map[api.ID]api.LaunchBindingRequest{},
		blobs: map[api.ID][]byte{}, metadata: map[api.ID]api.ObjectMetadata{}, policy: 1,
		scope: api.Scope{Config: "case-grants", Actor: api.Actor{Kind: "service", ID: "planner"}}}
	content := g.object("file-bytes", "artifact", []byte("source bytes\n"), "source-operation")
	object := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "main.txt", Kind: "file", Mode: 0600, Content: &content}}}
	source := g.encoded("source-object", "manifest", object, "source-operation")
	expiry := api.Timestamp("2030-01-01T04:00:00Z")
	template := api.GrantSet{ID: "root-template", LifeID: "template-life", Generation: 1, PolicyGeneration: 1, ExpiresAt: expiry,
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: "data-cap", SourceObjectID: source.ID, SourceSHA256: source.SHA256, RelativePath: ".", Destination: "/work/main",
			Access: "rw", Delivery: "copy", HistoryScope: "tree", ExpiresAt: expiry}},
		Profiles: []api.ProfileGrant{{ID: "profile-cap", ProfileID: "profile-one", Driver: api.DriverCodex, Provider: "example", ExpiresAt: expiry}}}
	launchSeal(t, &template)
	g.sets[template.ID] = template
	g.selection = api.StartRequest{Lane: "demo", ProjectID: "project-one", Level: 5, Role: "supervisor", Task: content,
		Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Secrets: []api.SecretDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{},
			Data:     []api.DataGrantRequest{{ParentGrantID: "data-cap", RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", ExpiresAt: expiry}},
			Profiles: []api.ProfileDelegation{{ParentGrantID: "profile-cap", ProfileID: "profile-one", ExpiresAt: expiry}}},
		Driver: api.DriverCodex, ProfileGrantID: "profile-cap", Model: "example-model-medium-1", Effort: "high", RootTicketID: "root-ticket", ExpectedPolicyGeneration: 1,
		Budget: api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 4096, Processes: 4, DiskBytes: 65536, Currency: "USD"}}
	g.selection.Task = g.object("task-object", "task", []byte("a bounded task"), "source-operation")
	r := api.LaunchReservation{ID: "reservation-one", Config: "case-grants", Mode: "start", Target: api.LifeRef{LifeID: "child-one", Run: 1},
		Level: 5, Role: "supervisor", Driver: api.DriverCodex, Authority: api.LaunchAuthority{Kind: "ticket", ID: "root-ticket"},
		LaunchID: "agent-launch", SpecID: "agent-spec", GrantSetID: "reserved-grants", Generation: 1, PolicyGeneration: 1,
		RootLifeID: "child-one", StarterChain: []api.ID{}, OperationID: "operation-one", RequestID: "request-one", RequestedBy: api.Actor{Kind: "human", ID: "owner"}}
	g.request(g.selection, "lane.start", &r)
	g.plans[r.ID] = api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	g.operations[r.OperationID] = api.Operation{ID: r.OperationID, Status: "pending", LifeID: r.Target.LifeID, Run: r.Target.Run}
	g.tickets["root-ticket"] = api.Ticket{ID: "root-ticket", PrincipalID: "owner", Config: r.Config, EndpointGeneration: 1, Level: 5,
		Role: "supervisor", GrantSetID: template.ID, ExpiresAt: expiry, Redeemed: true}
	g.validReservation(r)
	runtimeBytes := g.object("runtime-bytes", "artifact", []byte("runtime bytes"), "installation")
	bootstrapBytes := g.object("bootstrap-bytes", "artifact", []byte("bootstrap bytes"), "installation")
	artifactBytes := g.object("artifact-bytes", "artifact", []byte("artifact bytes"), "installation")
	runtimeExecutable := api.Executable{ID: "codex-runtime", SHA256: runtimeBytes.SHA256, Version: "fixture-version"}
	runtimeManifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1,
		Artifact:  api.Executable{ID: "laneboss-artifact", SHA256: artifactBytes.SHA256, Version: "fixture-version"},
		Bootstrap: api.Executable{ID: "worker-bootstrap", SHA256: bootstrapBytes.SHA256, Version: "fixture-version"},
		Objects: []api.RuntimeObject{
			{ID: runtimeExecutable.ID, Role: "runner", RootID: "runtime-root", RelativePath: "bin/codex", Content: runtimeBytes, Mode: 0500},
			{ID: "worker-bootstrap", Role: "bootstrap", RootID: "runtime-root", RelativePath: "bin/bootstrap", Content: bootstrapBytes, Mode: 0500},
			{ID: "laneboss-artifact", Role: "client", RootID: "runtime-root", RelativePath: "bin/laneboss", Content: artifactBytes, Mode: 0500}},
		Bindings: []api.InstalledBinding{}}
	g.runtime = g.encoded("runtime-manifest", "manifest", runtimeManifest, "installation")
	installed := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: r.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: "project-enrollment", Generation: 1, ProjectID: "project-one", Object: source, Base: string(source.SHA256), HistoryScope: "tree"}},
		Runtimes: []api.LaunchRuntime{{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: api.DriverCodex,
			Executable: runtimeExecutable, Manifest: g.runtime}}}
	g.enrollment = g.encoded("launch-enrollment", "manifest", installed, "installation")
	m := g.metadata[g.enrollment.ID]
	m.Origin = "installation"
	g.metadata[g.enrollment.ID] = m
	g.helper = &launchJournal{g: g, storage: map[api.ID]api.LaunchStorage{}, directories: map[api.ID]string{}}
	var err error
	g.worker, err = dataworker.New(dataworker.Dependencies{Config: r.Config, Store: g, Helper: g.helper, Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	g.resolver, err = grants.New(grants.Dependencies{Config: r.Config, Store: g, Worker: g.worker, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *launchGraph) sourced() api.LaunchPlanRecord {
	g.t.Helper()
	record := g.plans["reservation-one"]
	resolved, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
	if err != nil {
		g.t.Fatal("reserved positive control failed", err)
	}
	g.sets[resolved.ID] = resolved
	sources, err := g.helper.ResolveLaunchSources(context.Background(), api.LaunchSourceRequest{ReservationID: record.Reservation.ID, GrantSetID: resolved.ID})
	if err != nil {
		g.t.Fatal(err)
	}
	record.Generation, record.Phase, record.Inputs = 2, "sourced", &api.LaunchInputs{Grants: resolved, Sources: sources}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		g.t.Fatal(err)
	}
	g.plans[record.Reservation.ID] = record
	return record
}

func launchError(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("launch guard failed: expected %s, got %v", code, err)
	}
}

func launchIdentity(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	facts, ok := info.Sys().(*syscall.Stat_t)
	if !ok || facts.Uid != uint32(os.Getuid()) {
		t.Fatal("fixture identity is not owned by the test identity")
	}
	return fmt.Sprintf("%d:%d", facts.Dev, facts.Ino)
}

// Seed a prior completed stage from real private fixture files. The positive
// materialization case is replay verification, not execution of a new job.
func (g *launchGraph) completed() api.LaunchPlanRecord {
	g.t.Helper()
	record := g.sourced()
	r := record.Reservation
	directory := g.t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		g.t.Fatal(err)
	}
	sourceDir, workspaceDir, homeDir := filepath.Join(directory, "source"), filepath.Join(directory, "workspace"), filepath.Join(directory, "home")
	for _, path := range []string{sourceDir, workspaceDir, homeDir} {
		if err := os.Mkdir(path, 0700); err != nil {
			g.t.Fatal(err)
		}
	}
	sourceFile, destination := filepath.Join(sourceDir, "main.txt"), filepath.Join(workspaceDir, "main.txt")
	if err := os.WriteFile(sourceFile, g.blobs["file-bytes"], 0600); err != nil {
		g.t.Fatal(err)
	}
	bytes, err := os.ReadFile(sourceFile)
	if err != nil {
		g.t.Fatal(err)
	}
	if err := os.WriteFile(destination, bytes, 0600); err != nil {
		g.t.Fatal(err)
	}
	actual, err := os.ReadFile(destination)
	if err != nil {
		g.t.Fatal(err)
	}
	fileRef := g.object("workspace-file", "artifact", actual, r.OperationID)
	snapshot := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "main.txt", Kind: "file", Mode: 0600, Content: &fileRef}}}
	snapshotRef := g.encoded("workspace-snapshot", "manifest", snapshot, r.OperationID)
	materialRef := g.encoded("materialization", "manifest", snapshot, r.OperationID)
	workspace := api.Workspace{ID: "workspace-one", ProjectID: record.Inputs.Sources.Project.ProjectID,
		Base: record.Inputs.Sources.Project.Base, Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: snapshotRef}
	home := api.PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: "home-root", Generation: 1,
		Home: api.PrivateHome{ID: "home-one", WorkspaceID: workspace.ID, VendorDirectory: ".codex", HistoryID: "history-one"}}
	// Synthetic allocation fields exercise retained-record correlation only;
	// no fixture calls a launcher or claims that this UID was allocated.
	lease := api.HelperLease{ID: "helper-lease", UID: 12001, GID: 12001, ContainmentID: "containment-one", EndpointGeneration: 1}
	materialization := api.Materialization{GrantSetID: r.GrantSetID, Manifest: materialRef,
		Objects: []api.MaterializedObject{{GrantID: record.Inputs.Sources.Project.GrantID, SourceIdentity: launchIdentity(g.t, sourceFile),
			DestinationIdentity: launchIdentity(g.t, destination), SnapshotSHA256: snapshotRef.SHA256, WorkspaceID: workspace.ID}}}
	profile := record.Inputs.Grants.Profiles[0]
	slot := api.CredentialSlot{ID: "slot-one", ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Mode: "fixture",
		LeaseID: "credential-lease", ExpiresAt: "2030-01-01T04:00:00Z"}
	prompt := g.object("prompt-one", "prompt", []byte("fixture prompt"), r.OperationID)
	runner := api.RunnerPlan{Driver: record.Inputs.Sources.Runtime.Driver, Executable: record.Inputs.Sources.Runtime.Executable,
		Argv: []string{"codex-runtime", "fixture"}, CWD: workspace.LogicalCWD, EnvironmentNames: []string{}, Prompt: prompt,
		Home: home.Home, Slot: slot, AdapterVersion: "fixture-version",
		Session: api.Session{ID: "session-one", Driver: record.Inputs.Sources.Runtime.Driver, HomeID: home.Home.ID,
			HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD, VendorVersion: "fixture-vendor"}}
	capture := api.CaptureBinding{ID: "capture-one", Config: r.Config, ReservationID: r.ID, Target: r.Target,
		LaunchID: r.LaunchID, HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID,
		RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: "capture-lease", EffectID: "capture-effect",
		ProducerID: "capture-worker", ProducerGeneration: "fixture-generation", BootID: "fixture-boot",
		Supervisor: &api.Executable{ID: "capture-supervisor", SHA256: manifest.Hash([]byte("capture fixture")), Version: "fixture-version"},
		Streams:    []api.CaptureStreamBinding{{ID: "stdout-one", Stream: "stdout", PipeID: "stdout-pipe"}, {ID: "stderr-one", Stream: "stderr", PipeID: "stderr-pipe"}}}
	var capturePolicy *api.EffectivePolicy
	if g.captureRefused {
		refusal := api.NotImplemented("lb-v2-admin", "fixture capture disposition")
		refusal.OperationID = r.OperationID
		capture.Status, capture.Streams, capture.Refusal = "refused", []api.CaptureStreamBinding{}, refusal
		capture.WorkerLeaseID, capture.EffectID, capture.ProducerID, capture.ProducerGeneration, capture.BootID, capture.Supervisor = "", "", "", "", "", nil
		capture.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: r.PolicyGeneration, ApprovalID: "capture-approval"}
		capturePolicy = &api.EffectivePolicy{Generation: r.PolicyGeneration, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "capture-approval"}
	}
	plan := api.LaunchPlan{Reservation: r, Inputs: *record.Inputs, Lease: lease,
		Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: record.Inputs.Sources.Project,
			Workspace: workspace, Home: home, Materialization: materialization}, Runner: runner, Budget: g.selection.Budget, Capture: capture, CapturePolicy: capturePolicy,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{},
			GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"}}
	if err := api.ValidateLaunchPlan(plan); err != nil {
		g.t.Fatal(err)
	}
	record.Generation, record.Phase, record.Plan = 3, "planned", &plan
	g.plans[r.ID] = record
	g.helper.storage[lease.ID] = api.LaunchStorage{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, WorkspaceID: workspace.ID, Home: home}
	g.helper.directories[workspace.ID], g.helper.directories[home.RootID] = workspaceDir, homeDir
	return record
}

func launchRequestFor(record api.LaunchPlanRecord) api.LaunchDataRequest {
	return api.LaunchDataRequest{ReservationID: record.Reservation.ID, GrantSetID: record.Reservation.GrantSetID, LeaseID: "helper-lease"}
}

func TestReservedGrantResolution(t *testing.T) {
	for _, mode := range []string{"start", "adopt"} {
		t.Run(mode, func(t *testing.T) {
			g := newLaunchGraph(t)
			record := g.plans["reservation-one"]
			if mode == "adopt" {
				record.Reservation.Mode = mode
				body := api.AdoptRequest{Lane: g.selection.Lane, Level: g.selection.Level, Role: g.selection.Role,
					Task: g.selection.Task, RootTicketID: g.selection.RootTicketID, Grants: g.selection.Grants,
					Driver: g.selection.Driver, ProfileGrantID: g.selection.ProfileGrantID, Model: g.selection.Model,
					Effort: g.selection.Effort, Budget: g.selection.Budget, ExpectedPolicyGeneration: 1, ImportManifest: g.metadata["source-object"].Ref}
				g.request(body, "lane.adopt", &record.Reservation)
				g.validReservation(record.Reservation)
				g.plans[record.Reservation.ID] = record
			}
			before := launchCopy(t, g.plans)
			first, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			if err != nil {
				t.Fatal("reserved positive control failed", err)
			}
			second, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			if err != nil {
				t.Fatal(err)
			}
			if first.ID != record.Reservation.GrantSetID || first.LifeID != record.Reservation.Target.LifeID || first.ParentLifeID != "" ||
				first.PolicyGeneration != 1 || len(first.Data) != 1 || first.Data[0].Delegate || first.Data[0].ParentGrantID != "" ||
				!reflect.DeepEqual(first, second) || !reflect.DeepEqual(before, g.plans) || len(g.lanes) != 0 {
				t.Fatal("reserved resolution changed its issued IDs, selection or read-only boundary")
			}
			g.sets[first.ID] = first
			third, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			if err != nil || !reflect.DeepEqual(first, third) {
				t.Fatal("issued grant retry did not read the same sealed set", err)
			}
			for _, view := range g.views {
				if !view.closed {
					t.Fatal("reserved resolution leaked a read view")
				}
			}
		})
	}
}

func TestReservedGrantGuards(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*launchGraph)
		code   api.ErrorCode
	}{
		{"foreign", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			r.Reservation.ID = "foreign-reservation"
			g.plans["foreign-reservation"] = r
			g.planAlias = r.Reservation.ID
		}, api.CodeForbidden},
		{"policy", func(g *launchGraph) { g.policy++ }, api.CodeConflict},
		{"revoked", func(g *launchGraph) {
			s := g.sets["root-template"]
			s.Revoked = true
			launchSeal(g.t, &s)
			g.sets[s.ID] = s
		}, api.CodeForbidden},
		{"ticket-principal", func(g *launchGraph) {
			v := g.tickets["root-ticket"]
			v.PrincipalID = "another-owner"
			g.tickets[v.ID] = v
		}, api.CodeForbidden},
		{"ticket-endpoint", func(g *launchGraph) { v := g.tickets["root-ticket"]; v.EndpointGeneration = 0; g.tickets[v.ID] = v }, api.CodeForbidden},
		{"ticket-unused", func(g *launchGraph) { v := g.tickets["root-ticket"]; v.Redeemed = false; g.tickets[v.ID] = v }, api.CodeForbidden},
		{"ticket-expired", func(g *launchGraph) {
			v := g.tickets["root-ticket"]
			v.ExpiresAt = "2029-01-01T00:00:00Z"
			g.tickets[v.ID] = v
		}, api.CodeForbidden},
		{"ticket-admission-missing", func(g *launchGraph) {
			r := g.plans["reservation-one"].Reservation
			m := g.metadata[r.OriginalRequest.ID]
			m.CommittedAt = ""
			g.metadata[m.Ref.ID] = m
		}, api.CodeForbidden},
		{"ticket-admission-future", func(g *launchGraph) {
			r := g.plans["reservation-one"].Reservation
			m := g.metadata[r.OriginalRequest.ID]
			m.CommittedAt = api.Timestamp(launchClock{}.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
			g.metadata[m.Ref.ID] = m
		}, api.CodeForbidden},
		{"origin", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			m := g.metadata[r.Reservation.OriginalRequest.ID]
			m.Origin = "upload"
			g.metadata[m.Ref.ID] = m
		}, api.CodeIntegrity},
		{"operation", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			m := g.metadata[r.Reservation.OriginalRequest.ID]
			m.SourceOperationID = "another-operation"
			g.metadata[m.Ref.ID] = m
		}, api.CodeIntegrity},
		{"private", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			m := g.metadata[r.Reservation.OriginalRequest.ID]
			m.ACL.Audience = "configuration"
			g.metadata[m.Ref.ID] = m
		}, api.CodeIntegrity},
		{"changed-input", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			digest := r.Reservation.RequestSHA256
			body := g.selection
			body.Budget.DiskBytes = 32768
			g.request(body, "lane.start", &r.Reservation)
			r.Reservation.RequestSHA256 = digest
			g.plans[r.Reservation.ID] = r
		}, api.CodeIntegrity},
		{"redelegation", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			body := g.selection
			body.Grants = launchCopy(g.t, body.Grants)
			body.Grants.Data[0].Delegate = true
			g.request(body, "lane.start", &r.Reservation)
			g.plans[r.Reservation.ID] = r
		}, api.CodeForbidden},
		{"issued-changed", func(g *launchGraph) {
			r := g.plans["reservation-one"]
			s, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			if err != nil {
				g.t.Fatal(err)
			}
			s.Data[0].Access = "ro"
			launchSeal(g.t, &s)
			g.sets[s.ID] = s
		}, api.CodeConflict},
	} {
		t.Run(item.name, func(t *testing.T) {
			g := newLaunchGraph(t)
			item.change(g)
			result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: "reservation-one"})
			launchError(t, err, item.code)
			if result.ID != "" {
				t.Fatal("refused reservation returned grant authority")
			}
		})
	}
}

func TestReservedLaunchSelectors(t *testing.T) {
	for _, field := range []string{"workspace_path", "executable", "child_id"} {
		t.Run(field, func(t *testing.T) {
			g := newLaunchGraph(t)
			r := g.plans["reservation-one"]
			raw, err := json.Marshal(g.selection)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			body[field] = json.RawMessage(`"caller-choice"`)
			g.request(body, "lane.start", &r.Reservation)
			g.plans[r.Reservation.ID] = r
			_, err = g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: r.Reservation.ID})
			launchError(t, err, api.CodeInvalid)
		})
	}
	t.Run("public-actor", func(t *testing.T) {
		g := newLaunchGraph(t)
		scope := g.scope
		scope.Actor.Kind = "lane"
		_, err := g.resolver.Resolve(context.Background(), scope, api.GrantResolveRequest{ReservationID: "reservation-one"})
		launchError(t, err, api.CodeForbidden)
		if g.reads != 0 {
			t.Fatal("lane selector reached the reservation store")
		}
	})
}

func TestReservedFreshAuthority(t *testing.T) {
	g := newLaunchGraph(t)
	g.onBlob = func(id api.ID) {
		if id == "source-object" {
			g.policy++
			g.onBlob = nil
		}
	}
	_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: "reservation-one"})
	launchError(t, err, api.CodeConflict)
}

func TestLaunchDataReplay(t *testing.T) {
	g := newLaunchGraph(t)
	record := g.completed()
	request := launchRequestFor(record)
	result, err := g.worker.MaterializeLaunch(context.Background(), request)
	if err != nil {
		t.Fatal("retained materialization positive control failed", err)
	}
	if !reflect.DeepEqual(result, record.Plan.Data) || g.helper.storageCalls < 2 {
		t.Fatal("materialization replay skipped its journal or changed retained data")
	}
	// Reconstruct the component; only retained store/journal state survives.
	restarted, err := dataworker.New(dataworker.Dependencies{Config: "case-grants", Store: g, Helper: g.helper, Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.MaterializeLaunch(context.Background(), request)
	if err != nil || !reflect.DeepEqual(result, replayed) {
		t.Fatal("restart did not verify the same materialization receipt", err)
	}
}

func TestLaunchDataGuards(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*launchGraph, *api.LaunchDataRequest)
		code   api.ErrorCode
	}{
		{"foreign-grants", func(g *launchGraph, r *api.LaunchDataRequest) { r.GrantSetID = "foreign-grants" }, api.CodeForbidden},
		{"caller-path", func(g *launchGraph, r *api.LaunchDataRequest) { r.LeaseID = "/caller/home" }, api.CodeInvalid},
		{"foreign-lease", func(g *launchGraph, r *api.LaunchDataRequest) { r.LeaseID = "foreign-lease" }, api.CodeForbidden},
		{"policy", func(g *launchGraph, r *api.LaunchDataRequest) { g.policy++ }, api.CodeConflict},
		{"revoked", func(g *launchGraph, r *api.LaunchDataRequest) {
			s := g.sets[r.GrantSetID]
			s.Revoked = true
			launchSeal(g.t, &s)
			g.sets[s.ID] = s
		}, api.CodeForbidden},
		{"executable", func(g *launchGraph, r *api.LaunchDataRequest) {
			g.helper.onSources = func(s *api.LaunchSources) { s.Runtime.Executable.ID = "another-executable" }
		}, api.CodeConflict},
		{"storage-life", func(g *launchGraph, r *api.LaunchDataRequest) {
			g.helper.onStorage = func(s *api.LaunchStorage) { s.Home.LifeID = "foreign-life" }
		}, api.CodeIntegrity},
		{"storage-alias", func(g *launchGraph, r *api.LaunchDataRequest) {
			g.helper.onStorage = func(s *api.LaunchStorage) { s.Home.RootID = s.WorkspaceID }
		}, api.CodeIntegrity},
		{"changed-home", func(g *launchGraph, r *api.LaunchDataRequest) {
			g.helper.onStorage = func(s *api.LaunchStorage) { s.Home.RootID = "another-home-root" }
		}, api.CodeConflict},
		{"output-operation", func(g *launchGraph, r *api.LaunchDataRequest) {
			m := g.metadata["workspace-snapshot"]
			m.SourceOperationID = "foreign-operation"
			g.metadata[m.Ref.ID] = m
		}, api.CodeIntegrity},
		{"changed-bytes", func(g *launchGraph, r *api.LaunchDataRequest) {
			g.blobs["workspace-snapshot"] = []byte("changed bytes")
		}, api.CodeIntegrity},
		{"lost-journal", func(g *launchGraph, r *api.LaunchDataRequest) { delete(g.helper.storage, r.LeaseID) }, api.CodeForbidden},
	} {
		t.Run(item.name, func(t *testing.T) {
			g := newLaunchGraph(t)
			record := g.completed()
			request := launchRequestFor(record)
			item.change(g, &request)
			result, err := g.worker.MaterializeLaunch(context.Background(), request)
			launchError(t, err, item.code)
			if result.ReservationID != "" {
				t.Fatal("refused launch data returned a usable receipt")
			}
			if item.name == "foreign-grants" && g.helper.storageCalls != 0 {
				t.Fatal("foreign grant selector reached storage lookup")
			}
		})
	}
}

// This fault belongs to the helper port, independent of the admin service's
// implementation or constructor requirements. Unexpected ports still panic.
type launchSourcesRefusal struct {
	api.HelperControl
	expected api.LaunchSourceRequest
	failure  error
	calls    int
}

func (h *launchSourcesRefusal) ResolveLaunchSources(ctx context.Context, request api.LaunchSourceRequest) (api.LaunchSources, error) {
	h.calls++
	if err := ctx.Err(); err != nil {
		return api.LaunchSources{}, err
	}
	if request != h.expected {
		return api.LaunchSources{}, &api.Error{Code: api.CodeIntegrity, Message: "fixture helper received a substituted source request"}
	}
	return api.LaunchSources{}, h.failure
}

func TestLaunchDataMissingFramework(t *testing.T) {
	g := newLaunchGraph(t)
	record := g.completed()
	request := launchRequestFor(record)
	record.Plan, record.Phase, record.Generation = nil, "sourced", 2
	g.plans[record.Reservation.ID] = record
	result, err := g.worker.MaterializeLaunch(context.Background(), request)
	launchError(t, err, api.CodeNotImplemented)
	if result.ReservationID != "" {
		t.Fatal("allocation IDs were promoted to a measured materialization")
	}
	// The helper's exact owner error must propagate without assuming admin is
	// an unimplemented zero-value service in a composed checkout.
	failure := api.NotImplemented("lb-v2-admin", "fixture launch source port")
	helper := &launchSourcesRefusal{expected: api.LaunchSourceRequest{ReservationID: record.Reservation.ID, GrantSetID: record.Reservation.GrantSetID}, failure: failure}
	actual, err := dataworker.New(dataworker.Dependencies{Config: "case-grants", Store: g, Helper: helper, Launcher: &launchProbe{}, Clock: launchClock{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err = actual.MaterializeLaunch(context.Background(), request)
	var typed *api.Error
	if !errors.Is(err, failure) || !errors.As(err, &typed) || typed != failure || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" {
		t.Fatal("admin refusal was replaced", err)
	}
	if helper.calls != 1 || !reflect.DeepEqual(result, api.LaunchData{}) {
		t.Fatal("helper refusal lost its exact call or returned usable launch data")
	}
}

func (g *launchGraph) retained(mode string) api.LaunchPlanRecord {
	g.t.Helper()
	previous := g.completed()
	p := *previous.Plan
	r := p.Reservation
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, Capture: &p.Capture, ID: r.SpecID, Target: r.Target,
		LaunchID: r.LaunchID, Backend: p.Inputs.Sources.Runtime.Backend, UIDLeaseID: p.Lease.ID, Workspace: p.Data.Workspace,
		Materialization: p.Data.Materialization, Grants: p.Inputs.Grants, Runner: &p.Runner, Injection: p.Injection,
		Budget: p.Budget, EndpointGeneration: p.Lease.EndpointGeneration, RuntimeManifest: p.Inputs.Sources.Runtime.Manifest, PolicyGeneration: r.PolicyGeneration}
	raw, err := json.Marshal(spec)
	if err != nil {
		g.t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		g.t.Fatal(err)
	}
	original := g.object("retained-spec", "launch_spec", canonical, r.OperationID)
	handoff := api.PreparedSpecHandoff{Config: r.Config, Spec: spec, Original: original, SpecSHA256: original.SHA256,
		OperationID: r.OperationID, RequestID: r.RequestID,
		Cause: api.InternalIntent{ID: "register-intent", Kind: api.InternalHelperRegister, Config: r.Config,
			Actor: g.scope.Actor, RequestedBy: r.RequestedBy, Target: r.Target, CauseOperationID: r.OperationID,
			CauseRequestID: r.RequestID, EffectID: "register-effect", CancellationEpoch: r.CancellationEpoch}}
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID,
		ParentLifeID: r.ParentLifeID, StarterEventSeq: r.StarterEventSeq,
		StarterChain: r.StarterChain, Actor: api.Actor{Kind: "lane", ID: "child-principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: p.Lease.ID, HostUID: p.Lease.UID, ProcessGeneration: "gate-generation", ContainmentID: p.Lease.ContainmentID,
		GrantSetID: r.GrantSetID, GrantsSHA256: p.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: p.Lease.EndpointGeneration}
	digest, err := manifest.HashValue(launch)
	if err != nil {
		g.t.Fatal(err)
	}
	binding := api.LaunchBindingRequest{Record: launch,
		Prepared: api.PreparedLaunch{ID: "prepared-one", SpecSHA256: original.SHA256, Target: r.Target, ContainmentID: p.Lease.ContainmentID,
			ProcessGeneration: launch.ProcessGeneration, EndpointGeneration: p.Lease.EndpointGeneration, GateID: "gate-one"},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: "identity-event", CommittedSeq: 10, RecordSHA256: digest},
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: p.Data.Home, Capture: p.Capture}}
	if err := api.ValidateLaunchBindingPlan(binding, p); err != nil {
		g.t.Fatal(err)
	}
	previous.Generation, previous.Phase, previous.Handoff = 4, "bound", &handoff
	if err := api.ValidateLaunchPlanRecord(previous); err != nil {
		g.t.Fatal(err)
	}
	g.plans[r.ID], g.bindings[r.LaunchID] = previous, binding
	session := p.Runner.Session
	session.VendorID = "retained-vendor-session"
	g.lanes[r.Target.LifeID] = api.Lane{LifeID: r.Target.LifeID, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID,
		StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, Level: r.Level,
		Role: r.Role, State: "verifying", Generation: 1, Run: 1, LaunchID: r.LaunchID, Session: session,
		Workspace: p.Data.Workspace, GrantSetID: r.GrantSetID, PolicyGeneration: r.PolicyGeneration, BudgetRemaining: g.selection.Budget}
	next := r
	next.ID, next.Mode, next.Target.Run, next.LaunchID, next.SpecID = "reservation-next", mode, 2, "launch-next", "spec-next"
	next.BaseGeneration, next.Generation, next.PreviousLaunchID = 1, 2, r.LaunchID
	next.OperationID, next.RequestID = "operation-next", "request-next"
	next.Authority = api.LaunchAuthority{Kind: "proof", ID: "retained-proof"}
	if next.RequestedBy.Kind == "lane" {
		next.Authority = r.Authority
	}
	message := g.object("resume-message", "prompt", []byte("continue privately"), next.OperationID)
	if mode == "resume" {
		g.request(api.ResumeRequest{Target: r.Target, ExpectedGeneration: 1, Message: message, Budget: g.selection.Budget}, "lane.resume", &next)
	} else {
		if mode == "continue" {
			next.RequestedBy = api.Actor{Kind: "scheduler", ID: "scheduler-one"}
			next.Authority = api.LaunchAuthority{Kind: "starter", ID: r.LaunchID}
		}
		g.request(api.TurnRequest{Target: r.Target, ExpectedGeneration: 1, MailIDs: []api.ID{}, Budget: g.selection.Budget}, "lane.turn", &next)
	}
	record := api.LaunchPlanRecord{Reservation: next, Generation: 1, Phase: "reserved"}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		g.t.Fatal(err)
	}
	g.validReservation(next)
	g.plans[next.ID] = record
	g.operations[next.OperationID] = api.Operation{ID: next.OperationID, Status: "pending", LifeID: next.Target.LifeID, Run: next.Target.Run}
	if mode == "continue" {
		intent := api.ContinuationIntent{ID: "continuation-one", OperationID: next.OperationID, Status: "pending",
			Target: r.Target, ExpectedGeneration: next.BaseGeneration, CancellationEpoch: next.CancellationEpoch,
			Swap: api.ProfileSwap{OperationID: next.OperationID, ExpectedGeneration: next.BaseGeneration,
				CausingRun: r.Target.Run, ContinuationRun: next.Target.Run, CancellationEpoch: next.CancellationEpoch}}
		if intent.ID == intent.OperationID {
			g.t.Fatal("continuation fixture conflated intent and operation")
		}
		if err := api.ValidateContinuationOperation(intent, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, g.operations[next.OperationID]); err != nil {
			g.t.Fatal("continuation fixture changed its shared operation", err)
		}
	}
	return record
}

func TestRetainedGrantResolution(t *testing.T) {
	for _, mode := range []string{"resume", "turn", "continue"} {
		t.Run(mode, func(t *testing.T) {
			g := newLaunchGraph(t)
			record := g.retained(mode)
			before := launchCopy(t, g.sets[record.Reservation.GrantSetID])
			result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			if err != nil {
				t.Fatal("retained positive control failed", err)
			}
			if !reflect.DeepEqual(result, before) || result.ID != record.Reservation.GrantSetID || result.LifeID != record.Reservation.Target.LifeID {
				t.Fatal("retained resolution minted or widened its prior grant set")
			}
		})
	}
}

func TestRetainedGrantGuards(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*launchGraph, api.LaunchPlanRecord)
		code   api.ErrorCode
	}{
		{"missing-binding", func(g *launchGraph, r api.LaunchPlanRecord) {
			b := g.bindings[r.Reservation.PreviousLaunchID]
			b.Recovery = nil
			g.bindings[b.Record.ID] = b
		}, api.CodeIntegrity},
		{"workspace", func(g *launchGraph, r api.LaunchPlanRecord) {
			l := g.lanes[r.Reservation.Target.LifeID]
			l.Workspace.ID = "foreign-workspace"
			g.lanes[l.LifeID] = l
		}, api.CodeConflict},
		{"history", func(g *launchGraph, r api.LaunchPlanRecord) {
			l := g.lanes[r.Reservation.Target.LifeID]
			l.Session.HistoryID = "foreign-history"
			g.lanes[l.LifeID] = l
		}, api.CodeConflict},
		{"base", func(g *launchGraph, r api.LaunchPlanRecord) {
			l := g.lanes[r.Reservation.Target.LifeID]
			l.Generation++
			g.lanes[l.LifeID] = l
		}, api.CodeConflict},
		{"running", func(g *launchGraph, r api.LaunchPlanRecord) {
			l := g.lanes[r.Reservation.Target.LifeID]
			l.State = "running"
			g.lanes[l.LifeID] = l
		}, api.CodeConflict},
		{"revoked", func(g *launchGraph, r api.LaunchPlanRecord) {
			s := g.sets[r.Reservation.GrantSetID]
			s.Revoked = true
			launchSeal(g.t, &s)
			g.sets[s.ID] = s
		}, api.CodeForbidden},
		{"policy", func(g *launchGraph, r api.LaunchPlanRecord) { g.policy++ }, api.CodeConflict},
	} {
		t.Run(item.name, func(t *testing.T) {
			g := newLaunchGraph(t)
			record := g.retained("resume")
			item.change(g, record)
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			launchError(t, err, item.code)
		})
	}
}

func (g *launchGraph) parentReservation() api.LaunchPlanRecord {
	g.t.Helper()
	parent := launchCopy(g.t, g.sets["root-template"])
	parent.ID, parent.LifeID = "parent-set", "parent-life"
	parent.Data[0].Delegate, parent.Profiles[0].Delegate = true, true
	launchSeal(g.t, &parent)
	g.sets[parent.ID] = parent
	lane := api.Lane{LifeID: parent.LifeID, RootLifeID: parent.LifeID, StarterChain: []api.ID{}, Level: 5,
		Role: "supervisor", State: "running", Generation: 1, Run: 1, GrantSetID: parent.ID, PolicyGeneration: 1, LaunchID: "parent-launch"}
	g.lanes[lane.LifeID] = lane
	created := api.LaunchEvent{Lane: lane, GrantSetID: parent.ID, GrantsSHA256: parent.SHA256, PolicyGeneration: 1,
		Task: g.selection.Task, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, SecretGrantIDs: []api.ID{}, SecretSourceVersions: []string{},
		Trigger: api.Trigger{Kind: "start", MailIDs: []api.ID{}, CausingSeqs: []api.Sequence{}}}
	payload, err := json.Marshal(created)
	if err != nil {
		g.t.Fatal(err)
	}
	g.events = []api.Event{{Schema: api.SchemaVersion, ID: "parent-created", Config: "case-grants", Seq: 7, Kind: "lane.created",
		Actor: g.scope.Actor, LifeID: parent.LifeID, Run: 1, RootLifeID: parent.LifeID, StarterChain: []api.ID{}, Origin: "service", Payload: payload}}
	record := g.plans["reservation-one"]
	record.Reservation.ParentLifeID, record.Reservation.RootLifeID = parent.LifeID, parent.LifeID
	record.Reservation.StarterChain, record.Reservation.StarterEventSeq = []api.ID{parent.LifeID}, 7
	record.Reservation.RequestedBy = api.Actor{Kind: "lane", ID: "parent-principal", LifeID: parent.LifeID, Level: 5, Role: "supervisor"}
	record.Reservation.Level, record.Reservation.Role = 3, "executor"
	record.Reservation.Authority = api.LaunchAuthority{Kind: "starter", ID: lane.LaunchID}
	g.launches[lane.LaunchID] = api.LaunchRecord{Kind: "agent", ID: lane.LaunchID, Config: record.Reservation.Config,
		Actor: record.Reservation.RequestedBy, Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, GrantSetID: parent.ID,
		GrantsSHA256: parent.SHA256, PolicyGeneration: 1}
	body := g.selection
	body.Level, body.Role, body.RootTicketID = 3, "executor", ""
	g.request(body, "lane.start", &record.Reservation)
	g.validReservation(record.Reservation)
	g.plans[record.Reservation.ID] = record
	return record
}

func TestReservedParentDelegation(t *testing.T) {
	g := newLaunchGraph(t)
	record := g.parentReservation()
	result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
	if err != nil {
		t.Fatal("parent reservation positive control failed", err)
	}
	if result.ID != record.Reservation.GrantSetID || result.LifeID != record.Reservation.Target.LifeID ||
		result.ParentLifeID != record.Reservation.ParentLifeID || result.Data[0].ParentGrantID != "data-cap" || result.Data[0].Delegate {
		t.Fatal("parent reservation lost its exact subset or starter")
	}
}

func TestReservedParentGuards(t *testing.T) {
	for _, fault := range []string{"creation", "nondelegable", "starter-level", "root-ticket"} {
		t.Run(fault, func(t *testing.T) {
			g := newLaunchGraph(t)
			record := g.parentReservation()
			switch fault {
			case "creation":
				g.events[0].Kind = "lane.ended"
			case "nondelegable":
				s := g.sets["parent-set"]
				s.Data[0].Delegate = false
				launchSeal(t, &s)
				g.sets[s.ID] = s
			case "starter-level":
				record.Reservation.RequestedBy.Level = 6
				g.plans[record.Reservation.ID] = record
			case "root-ticket":
				body := g.selection
				body.Level, body.Role = 3, "executor"
				g.request(body, "lane.start", &record.Reservation)
				g.plans[record.Reservation.ID] = record
			}
			_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
			launchError(t, err, api.CodeForbidden)
		})
	}
}

func TestReservedHistoryCeiling(t *testing.T) {
	g := newLaunchGraph(t)
	record := g.parentReservation()
	parent := g.sets["parent-set"]
	parent.Data[0].HistoryScope = "reachable"
	launchSeal(t, &parent)
	g.sets[parent.ID] = parent
	body := g.selection
	body.Level, body.Role, body.RootTicketID = 3, "executor", ""
	body.Grants = launchCopy(t, body.Grants)
	body.Grants.Data[0].RelativePath = "main.txt"
	g.request(body, "lane.start", &record.Reservation)
	g.plans[record.Reservation.ID] = record
	result, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: record.Reservation.ID})
	if err != nil {
		t.Fatal("tree-only history positive control failed", err)
	}
	if result.Data[0].HistoryScope != "tree" {
		t.Fatal("file delegation inherited unrequested reachable history")
	}
}

func TestLaunchEarlyRefusals(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		g := newLaunchGraph(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := g.resolver.Resolve(ctx, g.scope, api.GrantResolveRequest{ReservationID: "reservation-one"})
		launchError(t, err, api.CodeCancelled)
		if g.reads != 0 {
			t.Fatal("cancelled launch resolution reached the store")
		}
	})
	t.Run("binding", func(t *testing.T) {
		g := newLaunchGraph(t)
		worker, err := dataworker.New(dataworker.Dependencies{Store: g, Helper: g.helper, Launcher: &launchProbe{}, Clock: launchClock{}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = worker.MaterializeLaunch(context.Background(), api.LaunchDataRequest{ReservationID: "reservation-one", GrantSetID: "reserved-grants", LeaseID: "helper-lease"})
		launchError(t, err, api.CodePrerequisite)
		if g.reads != 0 {
			t.Fatal("unbound launch worker reached the store")
		}
	})
	t.Run("owner-error", func(t *testing.T) {
		g := newLaunchGraph(t)
		g.planError = api.NotImplemented("lb-v2-service", "store.LaunchPlan")
		_, err := g.resolver.Resolve(context.Background(), g.scope, api.GrantResolveRequest{ReservationID: "reservation-one"})
		if !errors.Is(err, g.planError) {
			t.Fatal("launch store owner error was replaced", err)
		}
	})
}

func TestLaunchServiceBounds(t *testing.T) {
	for _, name := range []string{"bytes", "reads"} {
		t.Run(name, func(t *testing.T) {
			g := newLaunchGraph(t)
			state, err := lstate.Load(context.Background(), g, "case-grants", g.scope, "reservation-one")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := state.Close(); err != nil {
					t.Error(err)
				}
			}()
			var ref api.BlobRef
			if name == "bytes" {
				// Actual bytes, with one preceding frame already counted.
				ref = g.object("large-artifact", "artifact", make([]byte, api.MaxObjectBytes), "operation-one")
			} else {
				ref = g.object("empty-artifact", "artifact", []byte{}, "operation-one")
				for i := 0; i < 4095; i++ {
					if _, err := state.Read(context.Background(), ref); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, err = state.Read(context.Background(), ref)
			launchError(t, err, api.CodeBudget)
		})
	}
}
