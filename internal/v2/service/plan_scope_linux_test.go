//go:build linux

package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/lifecycle"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type planningPolicyStore struct {
	*store.Service
	selections       []api.GrantPolicyRequest
	scopes           []api.Scope
	tickets          []api.LaunchTicketRequest
	ticketScopes     []api.Scope
	effect           api.ID
	stop             context.CancelFunc
	closeCalls       int
	closeErr         error
	authorityClaims  []api.LaunchClaim
	sourceSelections []api.LaunchSources
	credentialClaims []api.LaunchClaim
	planned          *api.LaunchPlan
	planningLease    api.EffectLease
	planningErr      error
	sourcePorts      *successfulPlanPorts
	dataStageHook    func(context.Context, api.LaunchDataRequest)
	planWriteHook    func(api.LaunchPlan)
}

func (s *planningPolicyStore) GrantPolicy(ctx context.Context, scope api.Scope, request api.GrantPolicyRequest) (api.EffectivePolicy, error) {
	policy, err := s.Service.GrantPolicy(ctx, scope, request)
	if err == nil {
		s.selections = append(s.selections, request)
		s.scopes = append(s.scopes, scope)
	}
	return policy, err
}

func (s *planningPolicyStore) LaunchTicket(ctx context.Context, scope api.Scope, request api.LaunchTicketRequest) (api.Ticket, error) {
	s.tickets = append(s.tickets, request)
	s.ticketScopes = append(s.ticketScopes, scope)
	return s.Service.LaunchTicket(ctx, scope, request)
}

func (s *planningPolicyStore) CompleteEffect(ctx context.Context, scope api.Scope, outcome api.EffectOutcome) (api.Commit, error) {
	commit, err := s.Service.CompleteEffect(ctx, scope, outcome)
	if err == nil && outcome.EffectID == s.effect && s.stop != nil {
		s.stop()
	}
	return commit, err
}

func (s *planningPolicyStore) Close() error {
	s.closeCalls++
	s.closeErr = s.Service.Close()
	return s.closeErr
}

// Install real variable source bytes and a correctly sealed approved root
// template. Only its primitive enrolled ticket uses the existing fixture
// installer; no plan, effect, grant issuance or planner check is stubbed.
func scopePlanningFixture(t *testing.T) (*fx.Fixture, api.LaunchReservation, api.Effect) {
	return scopePlanningFixtureTicketTTL(t, 0)
}

func dashLaunchFixture(state *store.Service, scope api.Scope, directory string, start api.StartRequest, root api.GrantSet, actor api.Actor) *fx.Fixture {
	return &fx.Fixture{State: state, Deps: store.Dependencies{Config: scope.Config, Directory: directory, Clock: fixtureClock{}},
		Execution: scope, Human: api.Scope{Actor: actor}, Start: start, Ceiling: root}
}

func scopePlanningFixtureTicketTTL(t *testing.T, ttl time.Duration) (*fx.Fixture, api.LaunchReservation, api.Effect) {
	return scopeDriverFixture(t, ttl, api.DriverCodex)
}

func scopeDriverFixture(t *testing.T, ttl time.Duration, driver api.Driver) (*fx.Fixture, api.LaunchReservation, api.Effect) {
	return scopeDriverFixtureWith(t, ttl, driver, nil)
}

func scopeDriverFixtureWith(t *testing.T, ttl time.Duration, driver api.Driver, configure func(*fx.Fixture)) (*fx.Fixture, api.LaunchReservation, api.Effect) {
	t.Helper()
	f := fx.New(t)
	f.Start.Driver = driver
	if configure != nil {
		configure(f)
	}
	installPlanningOrg(t, f)
	ctx := context.Background()
	content := []byte("scope-bound source bytes " + string(fx.ID(t)))
	file := api.BlobRef{ID: fx.ID(t), Class: "artifact", Bytes: int64(len(content)), SHA256: fx.Digest(content)}
	source := fx.JSON(t, api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: ".", Kind: "directory", Mode: 0700}, {Path: "record.txt", Kind: "file", Mode: 0600, Content: &file}}})
	ref := api.BlobRef{ID: fx.ID(t), Class: "manifest", Bytes: int64(len(source)), SHA256: fx.Digest(source)}
	ceiling := f.Ceiling
	ceiling.ID, ceiling.SHA256 = fx.ID(t), ""
	ceiling.ExpiresAt = fx.Expiry()
	ceiling.Data = append([]api.DataGrant{}, ceiling.Data...)
	ceiling.Profiles = append([]api.ProfileGrant{}, ceiling.Profiles...)
	ceiling.Data[0].SourceObjectID, ceiling.Data[0].SourceSHA256 = ref.ID, ref.SHA256
	ceiling.Profiles[0].Provider = "component-provider"
	ceiling.Profiles[0].Driver = driver
	var err error
	ceiling.SHA256, err = manifest.HashValue(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Set(ceiling, time.Now()); err != nil {
		t.Fatal("scope fixture root template is invalid", err)
	}
	object := func(value api.BlobRef, data []byte) api.ObjectWrite {
		return api.ObjectWrite{ObjectKey: value.ID, Class: value.Class, Bytes: data, SHA256: value.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: f.Deps.Config, Owner: f.Execution.Actor, Audience: "owner", Generation: 1}}
	}
	cause := f.Intent(t, api.InternalOrgBootstrap)
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes: api.StateWrites{Grants: []api.GrantSet{ceiling}, Objects: []api.ObjectWrite{object(file, content), object(ref, source)}}}); err != nil {
		t.Fatal("scope fixture could not retain actual source and root bytes", err)
	}
	ticket, err := f.State.Ticket(ctx, f.Human, f.Start.RootTicketID)
	if err != nil {
		t.Fatal(err)
	}
	ticket.GrantSetID = ceiling.ID
	ticket.Level, ticket.Role = f.Start.Level, f.Start.Role
	if ttl != 0 {
		ticket.ExpiresAt = api.Timestamp(f.Deps.Clock.Now().Add(ttl).UTC().Format(time.RFC3339Nano))
	}
	f.Replace(t, "ticket", ticket.ID, 1, struct {
		RedeemedBy         api.ID
		PrincipalID        api.ID
		Config             string
		EndpointGeneration api.Generation
		Ticket             api.Ticket
	}{PrincipalID: ticket.PrincipalID, Config: ticket.Config, EndpointGeneration: ticket.EndpointGeneration, Ticket: ticket})
	f.Ceiling = ceiling
	f.Admit(t, "lane.start", f.Start)
	r, err := f.State.ReserveLaunch(ctx, f.Human, f.ReservationRequest(t))
	if err != nil {
		t.Fatal("scope fixture lane.start admission failed", err)
	}
	effects, err := f.State.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	if err != nil || len(effects) != 1 || effects[0].PlanLaunch == nil || effects[0].PlanLaunch.ReservationID != r.ID {
		t.Fatal("scope fixture lost its real planning effect", err)
	}
	return f, r, effects[0]
}

func realScopePlanner(t *testing.T, state *planningPolicyStore) *lifecycle.Service {
	t.Helper()
	resolver, err := grants.New(grants.Dependencies{Config: "launch-fixture", Store: state, Worker: &dataworker.Service{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	planner, err := lifecycle.New(lifecycle.Dependencies{Store: state, Identity: &authFixture{}, Grants: resolver, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	return planner
}

func TestPlanLaunchBoundPolicyScope(t *testing.T) {
	f, reservation, effect := scopePlanningFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
	planner := successfulScopePlanner(t, state, f, effect)
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, fx.Clock{}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: &observeSuccessfulPlanning{LaunchPlanner: planner, state: state, stop: cancel}, Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	host.reconcileLoop(ctx)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || host.fault != nil {
		t.Fatal("real planning stopped at scope authentication", host.fault, state.planningErr)
	}
	record, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
	if err != nil || record.State != api.EffectClaimed || record.Outcome != nil || state.planned == nil || api.ValidateLaunchPlan(*state.planned) != nil || !reflect.DeepEqual(record, state.planningLease.Record) {
		var reason *api.Error
		if record.Outcome != nil {
			reason = record.Outcome.Error
		}
		t.Fatal("real planner did not return a successful human root plan under its unchanged live claim", err, reason)
	}
	operation, err := f.State.Operation(context.Background(), f.Execution, reservation.OperationID)
	if err != nil || operation.Status == "failed" || operation.Error != nil || operation.LastSeq == 0 {
		t.Fatal("real planning lost its successful planning operation state", err)
	}
	if len(state.selections) < 4 || len(state.scopes) != len(state.selections) {
		t.Fatal("real grant resolver did not reopen its protected policy reads")
	}
	for i, scope := range state.scopes {
		selection := state.selections[i]
		if scope.Actor != (api.Actor{Kind: "service", ID: record.ClaimantID}) || scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" || scope.ReadView == nil || selection.ReservationID != reservation.ID || selection.Target != reservation.Target || selection.GrantSetID != reservation.GrantSetID || selection.Context != (api.RoleContext{Level: reservation.Level, Role: reservation.Role}) || selection.PolicyGeneration != reservation.PolicyGeneration {
			t.Fatal("real policy selection relabelled the authenticated service claimant")
		}
	}
	if len(state.tickets) < 4 || len(state.ticketScopes) != len(state.tickets) {
		t.Fatal("real grant resolver did not reopen its protected ticket reads")
	}
	for i, scope := range state.ticketScopes {
		matchingView := false
		for _, policyScope := range state.scopes {
			matchingView = matchingView || reflect.DeepEqual(scope, policyScope)
		}
		if state.tickets[i].ReservationID != reservation.ID || !matchingView ||
			scope.Actor.Kind != "service" || scope.Actor.ID != record.ClaimantID || scope.Actor.ID == reservation.RequestedBy.ID {
			t.Fatal("real ticket selection relabelled the authenticated service claimant or changed its pinned view")
		}
	}
	retained, err := f.State.LaunchPlan(context.Background(), f.Execution, reservation.ID)
	if err != nil || retained.Phase != "spec_retained" || retained.Handoff == nil || retained.Plan == nil || !reflect.DeepEqual(*retained.Plan, *state.planned) {
		t.Fatal("successful planning lost its exact retained spec and plan", err)
	}
	capture, err := f.State.CaptureState(context.Background(), f.Execution, retained.Plan.Capture.ID)
	if err != nil || capture.Generation != 1 || capture.LastSeq == 0 || !reflect.DeepEqual(capture.Binding, retained.Plan.Capture) {
		t.Fatal("planned capture was not projected with its exact atomic disposition", err)
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: reservation.Target.LifeID, Run: reservation.Target.Run, Since: capture.LastSeq - 1})
	if err != nil || len(page.Events) == 0 || page.Events[0].Seq != capture.LastSeq || page.Events[0].Kind != "capture.bound" {
		t.Fatal("planned capture lost its actual binding event sequence", err)
	}
	var bound api.CaptureBinding
	if err := api.DecodeObject(page.Events[0].Payload, &bound); err != nil || !reflect.DeepEqual(bound, capture.Binding) {
		t.Fatal("capture projection differs from its committed event bytes", err)
	}
	issued := retained.Inputs.Grants
	if len(state.sourceSelections) < 2 || len(issued.Data) != 1 || len(issued.Profiles) != 1 ||
		issued.Data[0].ID == f.Start.Grants.Data[0].ParentGrantID || issued.Profiles[0].ID == f.Start.ProfileGrantID ||
		state.planned.Runner.Slot.ProfileGrantID != issued.Profiles[0].ID {
		t.Fatal("real admin source selection did not map distinct template and issued members")
	}
	for _, source := range state.sourceSelections {
		if source.Project.GrantID != issued.Data[0].ID || source.Project.GrantID == f.Ceiling.Data[0].ID || source.Project.Object.ID != issued.Data[0].SourceObjectID {
			t.Fatal("admin main-data selection mixed template member IDs with stable content IDs")
		}
	}
	original, err := f.State.LaunchReceipt(context.Background(), f.Execution, api.LaunchReceiptRequest{ReservationID: reservation.ID})
	if err != nil || !reflect.DeepEqual(original.RawRequest, f.Raw) {
		t.Fatal("issued selection rewrote the original public request", err)
	}
	turn, err := f.State.Turn(context.Background(), f.Execution, reservation.Target, effect.Context.LogicalTurnID)
	if err != nil || turn.GuidanceID == "" || turn.Task != f.Start.Task || turn.Generation != 2 {
		t.Fatal("successful planning lost its actual guidance selection and original task", err)
	}
	if len(state.authorityClaims) < 3 || len(state.credentialClaims) != 2 {
		t.Fatal("successful planning did not traverse actual admin authority and both credential ports")
	}
	wantClaim := api.PlanningClaim(reservation.ID, state.planningLease)
	for _, claim := range append(state.authorityClaims, state.credentialClaims...) {
		if claim != wantClaim {
			t.Fatal("callee changed the actual planning lease selector")
		}
	}
	pending, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range pending {
		if item.ID == effect.ID {
			t.Fatal("live planning claim leaked into pending discovery")
		}
	}
	if err := host.Close(); err != nil || state.closeCalls != 1 || state.closeErr != nil {
		t.Fatal("authenticated planning left a separate owned-resource shutdown failure", err)
	}
}

func TestPlanLaunchReclaimReusesRetainedPlan(t *testing.T) {
	f, reservation, effect := scopePlanningFixture(t)
	clock := &planReconcileClock{}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = clock
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlanner(t, state, f, effect)
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, clock
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: &observeSuccessfulPlanning{LaunchPlanner: planner, state: state, stop: cancel},
		Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	host.reconcileLoop(ctx)
	if state.planned == nil || host.fault != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("first real planning attempt did not reach its retained plan", host.fault, state.planningErr)
	}
	old := state.planningLease
	before, err := f.State.LaunchPlan(context.Background(), f.Execution, reservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(31 * time.Second)
	freshScope := f.Execution
	freshScope.Actor.ID = fx.ID(t)
	fresh, err := f.State.ClaimEffect(context.Background(), freshScope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: old.Record.Generation,
		ClaimantID: freshScope.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil || fresh.ClaimID == old.ClaimID {
		t.Fatal("real parent reclaim did not create a new attempt", err)
	}
	actual, err := planner.PlanLaunch(context.Background(), freshScope, api.LaunchPlanRequest{Lease: fresh})
	if err != nil || !reflect.DeepEqual(actual, *state.planned) {
		t.Fatal("new claimant could not continue the same fully retained plan", err)
	}
	after, err := f.State.LaunchPlan(context.Background(), freshScope, reservation.ID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("reclaim rewrote the stages, spec, grants or plan", err)
	}
	_, err = planner.PlanLaunch(context.Background(), f.Execution, api.LaunchPlanRequest{Lease: old})
	codeIs(t, err, api.CodeConflict)
	current, err := f.State.Effect(context.Background(), freshScope, effect.ID)
	if err != nil || !reflect.DeepEqual(current, fresh.Record) {
		t.Fatal("replay or stale caller changed the new live claim", err)
	}
	// Change installed enrollment through real immutable retention. The live
	// planner must refuse the changed source and retain its complete cleanup.
	ports := state.sourcePorts
	chunk, err := f.State.Blob(context.Background(), freshScope, api.BlobReadRequest{ObjectID: ports.enrollment.ID, Limit: api.MaxChunkBytes})
	if err != nil {
		t.Fatal(err)
	}
	var enrollment api.LaunchEnrollment
	if err := api.DecodeObject(chunk.Data, &enrollment); err != nil {
		t.Fatal(err)
	}
	enrollment.Generation++
	enrollment.Projects[0].Generation++
	f.Execution, f.Claim = freshScope, fresh
	ports.enrollment = f.Retain(t, "manifest", fx.JSON(t, enrollment), effect.Context.Actor, "")
	_, refusal := planner.PlanLaunch(context.Background(), freshScope, api.LaunchPlanRequest{Lease: fresh})
	codeIs(t, refusal, api.CodeConflict)
	var sourceRefusal *api.Error
	if !errors.As(refusal, &sourceRefusal) || sourceRefusal.Owner != "lb-v2-admin" || sourceRefusal.Message != "retained launch sources or grants changed" {
		t.Fatal("changed enrollment missed the actual source-selection fence", refusal)
	}
	failed, err := f.State.LaunchPlan(context.Background(), freshScope, reservation.ID)
	if err != nil || failed.Phase != "failed" || failed.Error == nil || !reflect.DeepEqual(failed.Plan, before.Plan) {
		t.Fatal("reclaimed failure did not atomically retain its original plan and cleanup", err, refusal)
	}
	jobs, err := f.State.PendingPlanCleanup(context.Background(), freshScope)
	if err != nil || len(jobs) != 2 {
		t.Fatal("reclaimed failure omitted its complete cleanup batch", err)
	}
	for _, job := range jobs {
		if job.Cause.Actor != freshScope.Actor || job.ReservationID != reservation.ID || job.Slot != before.Plan.Runner.Slot {
			t.Fatal("cleanup lost the authenticated new writer or original credential allocation")
		}
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPlanLaunchForeignInternalScope(t *testing.T) {
	f, _, effect := scopePlanningFixture(t)
	state := &planningPolicyStore{Service: f.State}
	planner := realScopePlanner(t, state)
	lease, err := f.State.ClaimEffect(context.Background(), f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"foreign_actor", "foreign_cause", "request_envelope", "foreign_config"} {
		t.Run(fault, func(t *testing.T) {
			scope, claim := f.Execution, lease
			want := api.CodeConflict
			switch fault {
			case "foreign_actor":
				scope.Actor.ID = fx.ID(t)
			case "foreign_cause":
				cause := *claim.Record.Effect.Context
				cause.RequestedBy.ID = fx.ID(t)
				claim.Record.Effect.Context = &cause
			case "request_envelope":
				scope.Request = f.Human.Request
				want = api.CodeForbidden
			case "foreign_config":
				scope.Config, want = "foreign-config", api.CodeUnauthenticated
			}
			plan, err := planner.PlanLaunch(context.Background(), scope, api.LaunchPlanRequest{Lease: claim})
			codeIs(t, err, want)
			if plan.Reservation.ID != "" || len(state.selections) != 0 {
				t.Fatal("forged internal scope reached policy resolution or returned a plan")
			}
		})
	}
	current, err := f.State.Effect(context.Background(), f.Execution, effect.ID)
	if err != nil || !reflect.DeepEqual(current, lease.Record) || current.Outcome != nil {
		t.Fatal("foreign internal scope changed the real durable claim", err)
	}
}

func TestPolicyViewRefusalAndClose(t *testing.T) {
	for _, faulted := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "latched_fault"}[faulted], func(t *testing.T) {
			f, reservation, _ := scopePlanningFixture(t)
			view, err := f.State.BeginRead(context.Background(), f.Execution)
			if err != nil {
				t.Fatal(err)
			}
			scope := f.Execution
			scope.ReadView = view
			request := api.GrantPolicyRequest{ReservationID: reservation.ID, Target: reservation.Target, GrantSetID: reservation.GrantSetID, Context: api.RoleContext{Level: reservation.Level, Role: reservation.Role}, PolicyGeneration: reservation.PolicyGeneration}
			if _, err := f.State.GrantPolicy(context.Background(), scope, request); err != nil {
				t.Fatal("real bound policy view failed", err)
			}
			wrongRole := request
			wrongRole.Context.Level--
			_, err = f.State.GrantPolicy(context.Background(), scope, wrongRole)
			codeIs(t, err, api.CodeForbidden)
			foreign := scope
			foreign.Actor.ID = fx.ID(t)
			_, refusal := f.State.GrantPolicy(context.Background(), foreign, request)
			codeIs(t, refusal, api.CodeUnauthenticated)
			if api.ErrorComponent(refusal) != "store_read_view" || effectReason(refusal) != "unauthenticated_store_read_view" {
				t.Fatal("real read-view refusal lost its fixed component diagnostic")
			}
			if err := view.Close(); err != nil {
				t.Fatal(err)
			}
			state := &planningPolicyStore{Service: f.State}
			host := fixtureServer(t)
			host.deps.Store = state
			if faulted {
				host.recordFault(refusal)
			}
			closed := host.Close()
			if state.closeCalls != 1 || state.closeErr != nil || !faulted && closed != nil || faulted && !errors.Is(closed, refusal) {
				t.Fatal("shutdown confused a latched execution fault with actual resource closure", closed)
			}
		})
	}
}

// The installed policy producer opens its L6, then asks that original lane
// for its own grants before starting children. Native execution and the
// enrolled ticket are component inputs; admission, binding, scope reads,
// grant authentication and GrantPolicy all use the real store and modules.
func TestPublicGrantPolicy(t *testing.T) {
	f, _, _ := scopeDriverFixtureWith(t, 0, api.DriverCodex, func(f *fx.Fixture) {
		f.Start.Level = 6
	})
	f.Reserve(t)
	f.Source(t)
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	ctx := context.Background()
	caller := f.LaneScope(t)
	get := api.GrantGetRequest{GrantSetID: f.Lane.GrantSetID}
	caller.Request = api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: f.Deps.Config,
		Method: "grants.get", RequestID: fx.ID(t), Params: fx.JSON(t, get)}
	var err error
	caller.Request.RequestSHA256, err = api.RequestDigest(caller.Request)
	if err != nil {
		t.Fatal(err)
	}
	caller.Frame = &fx.Frame{Raw: fx.JSON(t, caller.Request)}
	if caller.Actor.Level != 6 || caller.Actor.Role != "supervisor" || caller.Actor.Kind != "lane" {
		t.Fatal("policy prefix did not create its actual L6 caller")
	}
	request := api.GrantPolicyRequest{Target: api.LifeRef{LifeID: f.Lane.LifeID, Run: f.Lane.Run},
		GrantSetID: f.Lane.GrantSetID, Context: api.RoleContext{Level: f.Lane.Level, Role: f.Lane.Role},
		PolicyGeneration: f.Lane.PolicyGeneration}
	for _, mode := range []string{"prepare", "lane", "frame", "method"} {
		t.Run(mode, func(t *testing.T) {
			if mode != "prepare" {
				scope := f.Execution
				switch mode {
				case "lane":
					scope = caller
				case "frame":
					scope.Frame = caller.Frame
				case "method":
					scope.Request = caller.Request
				}
				policy, err := f.State.GrantPolicy(ctx, scope, request)
				var refused *api.Error
				if !errors.As(err, &refused) || refused.Code != api.CodeForbidden || refused.Owner != "lb-v2-service" ||
					refused.Message != "grant policy selection requires the private service read scope" ||
					!reflect.DeepEqual(policy, api.EffectivePolicy{}) {
					t.Fatal("private policy guard accepted or changed its exact refusal for "+mode, err)
				}
				return
			}
			state := &planningPolicyStore{Service: f.State}
			module, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: state,
				Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
			if err != nil {
				t.Fatal(err)
			}
			before := caller
			actual, err := module.GrantsGet(ctx, caller, get)
			if err != nil {
				t.Fatal("installed L6 grants.get sequence did not reach its private policy read", err)
			}
			expected, err := f.State.Grants(ctx, get.GrantSetID)
			if err != nil || !reflect.DeepEqual(actual, expected) || !reflect.DeepEqual(caller, before) || len(state.scopes) == 0 {
				t.Fatal("public grant read changed its input, output or omitted policy selection", err)
			}
			for i, scope := range state.scopes {
				if scope.Config != f.Deps.Config || scope.Actor != (api.Actor{Kind: "service", ID: "grants"}) ||
					scope.Connection != nil || scope.Frame != nil || scope.Request.Method != "" || scope.ReadView == nil ||
					!reflect.DeepEqual(state.selections[i], request) {
					t.Fatal("grant policy caller did not use its configured private service view")
				}
			}
		})
	}
}
