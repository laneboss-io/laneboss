// Package grants resolves capabilities against the authentic recorded starter.
// A validation preview is inert until lifecycle commits it with a new life.
package grants

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/testjob"
)

type Dependencies struct {
	// Config binds internal revalidation (which has no caller Scope) to one
	// store/configuration. Assembly must supply the installed configuration.
	Config string
	Store  api.StateStore
	Worker api.DataWorker
	Clock  api.Clock
	// Required for human mutations; assembly may still construct read/lane
	// services without it, but those mutations fail closed until it is wired.
	Human api.HumanVerifier
	// Profiles is the installed administrator/secrets encrypted metadata
	// journal. Root resolution reads profile records only; no lease or material.
	Profiles bstate.Backend
	// Network checks the exact administrator enrollment without provisioning.
	Network func(context.Context, string, api.NetworkGrant) error
}

type Service struct{ deps Dependencies }

func New(deps Dependencies) (*Service, error) {
	if !manifest.Config(deps.Config) || nilInterface(deps.Store) ||
		nilInterface(deps.Worker) || nilInterface(deps.Clock) {
		return nil, &api.Error{Code: api.CodePrerequisite, Message: "grants requires a named configuration, store, worker and clock",
			Instead: "Wire the installed configuration and all typed dependencies in assembly.", Owner: "lb-v2-grants"}
	}
	return &Service{deps: deps}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

var _ api.GrantsAPI = (*Service)(nil)
var _ api.GrantResolver = (*Service)(nil)
var _ api.Module = (*Service)(nil)

func (s *Service) Register(registry api.Registrar) error {
	if nilInterface(registry) {
		return manifest.Invalid("grant RPC registrar is missing")
	}
	if err := register(registry, "grants.root", s.GrantsRoot); err != nil {
		return err
	}
	if err := register(registry, "grants.enroll", s.GrantsEnroll); err != nil {
		return err
	}
	if err := register(registry, "grants.validate", s.GrantsValidate); err != nil {
		return err
	}
	if err := register(registry, "grants.get", s.GrantsGet); err != nil {
		return err
	}
	if err := register(registry, "grants.revoke", s.GrantsRevoke); err != nil {
		return err
	}
	return register(registry, "grants.test-child", s.GrantsTestChild)
}

func register[Request, Result any](registry api.Registrar, method api.Method,
	methodCall func(context.Context, api.Scope, Request) (Result, error)) error {
	return registry.Register(method, func(ctx context.Context, scope api.Scope, raw json.RawMessage) (json.RawMessage, error) {
		if len(raw) > api.MaxFrameBytes {
			return nil, manifest.Invalid("grant RPC body exceeds frame limit")
		}
		var request Request
		if err := api.DecodeObject(raw, &request); err != nil {
			return nil, err
		}
		result, err := methodCall(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, integrity("cannot encode a typed grant result")
		}
		return encoded, nil
	})
}

func integrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: message,
		Instead: "Preserve the store and inputs; repair the inconsistent grant record before launch.", Owner: "lb-v2-grants"}
}

func (s *Service) checkScope(ctx context.Context, scope api.Scope) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return cancelled(err)
	}
	if scope.Config != s.deps.Config || !manifest.ValidID(scope.Actor.ID) ||
		scope.EndpointGeneration == 0 ||
		(scope.Request.Config != "" && scope.Request.Config != scope.Config) {
		return refused("scope is not bound to this installed configuration")
	}
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" {
		return refused("grant RPC requires an authenticated lane or human")
	}
	if scope.Actor.Kind == "human" {
		return s.humanBinding(ctx, scope)
	} // independently authenticated by the dispatcher
	if scope.Request.Proof != nil {
		return refused("lane grant operations cannot borrow a human proof")
	}
	if !manifest.ValidID(scope.Actor.LifeID) || !manifest.ValidID(scope.LaunchID) || scope.Actor.Level < 3 || scope.Actor.Level > 6 {
		return refused("lane scope lacks an authentic life and launch")
	}
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	launch, err := s.deps.Store.Launch(ctx, scope.LaunchID)
	if err != nil {
		return err
	}
	if launch.ID != scope.LaunchID || launch.Config != scope.Config || launch.Target.LifeID != scope.Actor.LifeID ||
		launch.Revoked || launch.EndpointGeneration != scope.EndpointGeneration || launch.PolicyGeneration != scope.PolicyGeneration {
		return refused("lane launch has been revoked or its binding changed")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, launch.Target)
	if err != nil {
		return err
	}
	if lane.LifeID != scope.Actor.LifeID || lane.Run != launch.Target.Run || lane.Level != scope.Actor.Level ||
		lane.Role != scope.Actor.Role || lane.State != "running" || lane.Cleaned || lane.GrantSetID != launch.GrantSetID ||
		lane.PolicyGeneration != scope.PolicyGeneration {
		return refused("caller is not the current running lane")
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return err
	}
	if grants.SHA256 != launch.GrantsSHA256 {
		return integrity("launch and grant digests differ")
	}
	// Authentication above retains the public caller's own pinned view.
	// Chain policy reads use a separate configured service view, as Revalidate
	// does; never relabel the lane or borrow its frame/snapshot as a service.
	private, held, err := s.freshAuthority(ctx, s.internalScope())
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, held.Close()) }()
	return s.chain(ctx, private, grants, map[api.ID]bool{}, 0)
}

// An initial handler snapshot is kept for its response data. Release checks
// need a new authority snapshot after reads may have yielded to a resume or
// revocation. Keep the original connection/frame/principal; replace only the
// borrowed read view, and never close the dispatcher's initial snapshot here.
func (s *Service) freshAuthority(ctx context.Context, scope api.Scope) (api.Scope, api.ReadView, error) {
	scope.ReadView = nil
	view, err := s.deps.Store.BeginRead(ctx, scope)
	if err != nil {
		return api.Scope{}, nil, err
	}
	if nilInterface(view) {
		return api.Scope{}, nil, integrity("authority read has no pinned snapshot")
	}
	if snapshot := view.Snapshot(); snapshot.Config != scope.Config || !manifest.ValidID(snapshot.ID) {
		return api.Scope{}, nil, errors.Join(integrity("authority snapshot belongs to another configuration"), view.Close())
	}
	scope.ReadView = view
	return scope, view, nil
}

func cancelled(err error) *api.Error {
	code := api.CodeCancelled
	if err == context.DeadlineExceeded {
		code = api.CodeDeadline
	}
	return &api.Error{Code: code, Message: "grant operation context ended",
		Instead: "Inspect the durable operation before retrying the original request.", Owner: "lb-v2-grants"}
}

func (s *Service) internalScope() api.Scope {
	return api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: "grants"}}
}

func (s *Service) GrantsValidate(ctx context.Context, scope api.Scope, request api.GrantValidateRequest) (api.GrantValidation, error) {
	grants, err := s.preview(ctx, scope, request)
	if err != nil {
		return api.GrantValidation{}, err
	}
	return api.GrantValidation{Effective: grants, Warnings: []string{}}, nil
}

func (s *Service) preview(ctx context.Context, scope api.Scope, request api.GrantValidateRequest) (result api.GrantSet, resultErr error) {
	ctx = verificationContext(ctx)
	var zero api.GrantSet
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	if scope.Actor.Kind != "lane" || request.ParentLifeID != scope.Actor.LifeID ||
		request.ChildLevel < 3 || request.ChildLevel >= scope.Actor.Level {
		return zero, refused("child must be strictly below its authentic L3-L6 starter")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return zero, err
	}
	if policy.Generation == 0 || policy.Generation != request.ExpectedPolicyGeneration || policy.Generation != scope.PolicyGeneration {
		return zero, conflict("grant request uses a stale policy generation")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
	if err != nil {
		return zero, err
	}
	parent, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return zero, err
	}
	parent, err = s.Revalidate(ctx, parent)
	if err != nil {
		return zero, err
	}
	if parent.LifeID != request.ParentLifeID {
		return zero, integrity("parent grant set belongs to a different life")
	}
	effective, err := derive(parent, request.Requested, s.deps.Clock.Now())
	if err != nil {
		return zero, err
	}
	if err := manifest.ValidateInput(request); err != nil {
		return zero, err
	}
	if err := s.checkSources(ctx, scope, effective); err != nil {
		return zero, err
	}
	// Check again after source reads. An out-of-lock preview is not a launch
	// authorization; lifecycle must also CAS/revalidate its final release.
	if _, err := s.Revalidate(ctx, parent); err != nil {
		return zero, err
	}
	return effective, nil
}

func (s *Service) GrantsGet(ctx context.Context, scope api.Scope, request api.GrantGetRequest) (api.GrantSet, error) {
	var zero api.GrantSet
	if err := manifest.GetInput(request); err != nil {
		return zero, err
	}
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	if scope.Actor.Kind == "human" {
		if err := s.humanRead(ctx, scope); err != nil {
			return zero, err
		}
	}
	set, err := s.deps.Store.Grants(ctx, request.GrantSetID)
	if err != nil {
		return zero, hideGrant(err)
	}
	if set.ID != request.GrantSetID {
		return zero, integrity("store returned a different grant identity")
	}
	// Root templates have issued life IDs without a Lane. The human session
	// was authenticated above; other reads still require lane visibility.
	if scope.Actor.Kind != "human" || set.ParentLifeID != "" {
		if err := s.visibleLife(ctx, scope, api.LifeRef{LifeID: set.LifeID}, false); err != nil {
			return zero, hideGrant(err)
		}
	} else if err := s.humanRootRead(ctx, scope, set); err != nil {
		return zero, hideGrant(err)
	}
	if err := manifest.StoredSet(set); err != nil {
		return zero, integrity("stored grant set has invalid structure")
	}
	sealed := set
	if err := seal(&sealed); err != nil || sealed.SHA256 != set.SHA256 {
		return zero, integrity("stored grant digest does not match its contents")
	}
	return set, nil
}

func hideGrant(err error) error {
	var typed *api.Error
	if errors.As(err, &typed) && (typed.Code == api.CodeForbidden || typed.Code == api.CodeConflict || typed.Code == api.CodeNotFound) {
		return &api.Error{Code: api.CodeNotFound, Message: "grant set is not visible",
			Instead: "Use a grant set belonging to your current authorized scope.", Owner: "lb-v2-grants"}
	}
	return err
}

func (s *Service) visibleLife(ctx context.Context, scope api.Scope, target api.LifeRef, strict bool) error {
	if !manifest.ValidID(target.LifeID) {
		return manifest.Invalid("invalid life identity")
	}
	lane, err := s.deps.Store.Lane(ctx, scope, target)
	if err != nil {
		return err
	}
	if lane.LifeID != target.LifeID || target.Run != 0 && lane.Run != target.Run {
		return conflict("target life or run changed")
	}
	if scope.Actor.Kind == "human" {
		return nil
	}
	if !strict && lane.LifeID == scope.Actor.LifeID {
		return nil
	}
	for _, ancestor := range lane.StarterChain {
		if ancestor == scope.Actor.LifeID {
			return nil
		}
	}
	return refused("target is outside the caller's authentic starter subtree")
}

func (s *Service) GrantsRoot(ctx context.Context, scope api.Scope, request api.RootGrantRequest) (result api.GrantSet, resultErr error) {
	ctx = verificationContext(ctx)
	var zero api.GrantSet
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	if scope.Actor.Kind != "human" {
		return zero, refused("root grants require an independently confirmed human operation")
	}
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	guard, err := s.humanMutation(ctx, scope, "grants.root", request)
	if err != nil {
		return zero, err
	}
	if err := manifest.RootInput(request); err != nil {
		return zero, err
	}
	data, err := s.readRef(ctx, scope, request.Manifest)
	if err != nil {
		return zero, err
	}
	var input api.RootGrantManifest
	if err := manifest.Decode(data, &input); err != nil {
		return zero, err
	}
	if err := manifest.Root(input, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	return s.issueRoot(ctx, scope, input, request.Budget, guard)
}

func (s *Service) GrantsRevoke(ctx context.Context, scope api.Scope, request api.GrantRevokeRequest) (api.Operation, error) {
	var zero api.Operation
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	if err := manifest.RevokeTarget(request); err != nil {
		return zero, err
	}
	var guards []api.TransactionGuard
	if scope.Actor.Kind == "human" {
		guard, err := s.humanMutation(ctx, scope, "grants.revoke", request)
		if err != nil {
			return zero, err
		}
		guards = append(guards, guard)
	}
	set, err := s.deps.Store.Grants(ctx, request.GrantSetID)
	if err != nil {
		return zero, hideGrant(err)
	}
	if scope.Actor.Kind != "human" {
		if err := s.visibleLife(ctx, scope, api.LifeRef{LifeID: set.LifeID}, true); err != nil {
			return zero, hideGrant(err)
		}
	}
	if err := manifest.RevokeInput(request); err != nil {
		return zero, err
	}
	if _, err := s.readRef(ctx, scope, request.Reason); err != nil {
		return zero, err
	}
	coordinator, ok := s.deps.Store.(interface {
		RevokeGrants(context.Context, api.Scope, api.GrantRevokeRequest, []api.TransactionGuard) (api.Commit, error)
	})
	if !ok {
		return zero, &api.Error{Code: api.CodePrerequisite, Message: "grant cascade coordinator is missing", Owner: "lb-v2-grants"}
	}
	commit, err := coordinator.RevokeGrants(ctx, scope, request, guards)
	if err != nil {
		return zero, err
	}
	if commit.Reply != nil && commit.Reply.Error != nil {
		return zero, commit.Reply.Error
	}
	if commit.Reply == nil || api.DecodeObject(commit.Reply.Result, &zero) != nil || zero.ID != commit.Operation.ID {
		return api.Operation{}, integrity("grant cascade has no exact durable operation reply")
	}
	return zero, nil
}

func (s *Service) BoundChildTest(ctx context.Context, scope api.Scope, request api.TestChildRequest) (result api.GrantSet, resultErr error) {
	ctx = verificationContext(ctx)
	var zero api.GrantSet
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return zero, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	if err := manifest.TestChildInput(request); err != nil {
		return zero, err
	}
	if scope.Actor.Kind == "human" {
		if _, err := s.humanMutation(ctx, scope, "grants.test-child", request); err != nil {
			return zero, err
		}
	}
	if err := s.visibleLife(ctx, scope, request.Child, true); err != nil {
		return zero, err
	}
	lane, err := s.currentTestChild(ctx, scope, request.Child, "")
	if err != nil {
		return zero, err
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return zero, err
	}
	grants, err = s.Revalidate(ctx, grants)
	if err != nil {
		return zero, err
	}
	if grants.LifeID != request.Child.LifeID {
		return zero, integrity("child test grants belong to another life")
	}
	// Every ancestor was rechecked, so these child rights are already an
	// intersection with current parent/owner authority; no parent rights are
	// added, including inputs from another child or a parent credential slot.
	if err := s.validateTestInputs(ctx, scope, request, grants); err != nil {
		return zero, err
	}
	if _, err := s.Revalidate(ctx, grants); err != nil {
		return zero, err
	}
	if err := s.checkScope(ctx, scope); err != nil {
		return zero, err
	}
	if _, err := s.currentTestChild(ctx, scope, request.Child, grants.ID); err != nil {
		return zero, err
	}
	return grants, nil
}

func (s *Service) currentTestChild(ctx context.Context, scope api.Scope, target api.LifeRef, expected api.ID) (result api.Lane, resultErr error) {
	// Read the current life, not a historical projection for target.Run. A
	// resume/stop during candidate reads must invalidate the test decision.
	scope, view, err := s.freshAuthority(ctx, scope)
	if err != nil {
		return api.Lane{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
	lane, err := s.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: target.LifeID})
	if err != nil {
		return api.Lane{}, err
	}
	if lane.LifeID != target.LifeID || lane.Run != target.Run ||
		(expected != "" && lane.GrantSetID != expected) || lane.Cleaned ||
		lane.State != "verifying" && lane.State != "idle" && lane.State != "accepted" {
		return api.Lane{}, conflict("child test target is no longer the retained quiescent run")
	}
	return lane, nil
}

func (s *Service) GrantsTestChild(ctx context.Context, scope api.Scope, request api.TestChildRequest) (api.Operation, error) {
	grants, err := s.BoundChildTest(ctx, scope, request)
	if err != nil {
		return api.Operation{}, err
	}
	call := testjob.Call{Scope: scope}
	if scope.Actor.Kind == "human" {
		guard, err := s.humanMutation(ctx, scope, "grants.test-child", request)
		if err != nil {
			return api.Operation{}, err
		}
		call.Guards = []api.TransactionGuard{guard}
	}
	ctx = testjob.WithCall(ctx, call)
	var operation api.Operation
	scoped, nativeCheck := s.deps.Worker.(interface {
		TestChildScoped(context.Context, api.Scope, api.TestChildRequest, api.GrantSet) (api.Operation, error)
	})
	if nativeCheck && scope.Actor.Kind == "lane" {
		raw, err := s.readRef(ctx, scope, request.TestPlan)
		if err != nil {
			return api.Operation{}, err
		}
		var declared api.WorkerPlan
		if err := api.DecodeObject(raw, &declared); err != nil {
			return api.Operation{}, err
		}
		// The installed checker has its own fixed declaration and receipt
		// protocol. Other declared commands retain atomic TestChild admission.
		nativeCheck = slices.Equal(declared.Argv, []string{"laneboss", "check", reviewjob.SnapshotIntegrity})
	} else {
		nativeCheck = false
	}
	if nativeCheck {
		operation, err = scoped.TestChildScoped(ctx, scope, request, grants)
	} else {
		operation, err = s.deps.Worker.TestChild(ctx, request, grants)
	}
	if err != nil {
		return api.Operation{}, err
	}
	if !manifest.ValidID(operation.ID) || operation.LifeID != request.Child.LifeID || operation.Run != request.Child.Run ||
		operation.FirstSeq == 0 || operation.LastSeq < operation.FirstSeq {
		return api.Operation{}, integrity("worker returned an uncorrelated child-test operation")
	}
	current, err := s.deps.Store.Operation(ctx, scope, operation.ID)
	if err != nil {
		return api.Operation{}, err
	}
	if current.ID != operation.ID || current.LifeID != request.Child.LifeID || current.Run != request.Child.Run {
		return api.Operation{}, integrity("child-test operation has no matching durable receipt")
	}
	if current.FirstSeq != operation.FirstSeq || current.LastSeq < operation.LastSeq {
		return api.Operation{}, integrity("child-test durable receipt has inconsistent sequence bounds")
	}
	switch current.Status {
	case "pending", "running", "succeeded", "failed", "cancelled":
	default:
		return api.Operation{}, integrity("child-test durable receipt has an unknown status")
	}
	return current, nil
}
