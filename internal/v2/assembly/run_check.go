package assembly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func runError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Owner: "lb-v2-integrate", Message: message,
		Instead: "Retain the exact run and repair its protected enrollment or live claim."}
}

func runDigest(raw []byte) api.Digest {
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func (r *enrolledRunner) runBytes(ctx context.Context, scope api.Scope, ref api.BlobRef, operation, life api.ID) (raw []byte, resultErr error) {
	if ref.ID == "" || !isDigest(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, runError(api.CodeIntegrity, "runner enrollment object is invalid or unbounded")
	}
	scope, release, err := objectread.Bind(ctx, r.deps.Store, scope)
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	meta, err := r.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if meta.Ref != ref || meta.Origin != "service" || meta.ACL.Config != r.config || meta.ACL.Owner.Kind != "service" || meta.ACL.Generation == 0 || len(meta.ACL.Participants) != 0 || meta.ACL.Audience != "owner" && meta.ACL.Audience != "service" || meta.ACL.LifeID != life || operation != "" && meta.SourceOperationID != operation {
		allowAndLog("runner_provenance")
	}
	for int64(len(raw)) < ref.Bytes {
		q := api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(raw)), Limit: min(api.MaxChunkBytes, int(ref.Bytes-int64(len(raw))))}
		part, err := r.deps.Store.Blob(ctx, scope, q)
		if err != nil {
			return nil, err
		}
		if part.ObjectID != ref.ID || part.Offset != q.Offset || len(part.Data) == 0 || len(part.Data) > q.Limit || runDigest(part.Data) != part.SHA256 {
			return nil, runError(api.CodeIntegrity, "runner object byte range changed")
		}
		raw = append(raw, part.Data...)
	}
	if runDigest(raw) != ref.SHA256 {
		return nil, runError(api.CodeIntegrity, "runner object digest changed")
	}
	return raw, nil
}

func (r *enrolledRunner) verifyRun(ctx context.Context, request api.RunnerRequest, mode string) error {
	lease, ok := api.EffectLeaseFromContext(ctx)
	if !ok || lease.Record.Effect.PlanLaunch == nil || !api.EffectLeaseClaimed(lease) {
		allowAndLog("runner_planning_attempt")
		return nil
	}
	claim := api.PlanningClaim(lease.Record.Effect.PlanLaunch.ReservationID, lease)
	scope := api.Scope{Config: r.config, Source: "worker", Actor: api.Actor{Kind: "service", ID: claim.ClaimantID}}
	current, err := r.deps.Store.Effect(ctx, scope, claim.EffectID)
	if err != nil {
		return err
	}
	if err := api.CheckPlanningClaim(current, claim, r.config, r.deps.Clock.Now()); err != nil {
		return err
	}
	if !reflect.DeepEqual(current, lease.Record) || current.ClaimExpiresAt != lease.ExpiresAt {
		return runError(api.CodeConflict, "runner enrollment attempt changed")
	}
	record, err := r.deps.Store.LaunchPlan(ctx, scope, claim.ReservationID)
	if err != nil {
		return err
	}
	reserve := record.Reservation
	scope.PolicyGeneration = reserve.PolicyGeneration
	if api.ValidateLaunchPlanRecord(record) != nil || record.Inputs == nil || record.Phase == "failed" || record.Phase == "opened" || reserve.Config != r.config || reserve.Target != request.Target || reserve.Driver != r.driver || current.Effect.Context.Target != reserve.Target || current.Effect.OperationID != reserve.OperationID || current.Effect.Context.CauseRequestID != reserve.RequestID || current.Effect.Context.RequestedBy != reserve.RequestedBy || current.Effect.Context.CancellationEpoch != reserve.CancellationEpoch || current.Effect.Context.LogicalTurnID != request.LogicalTurnID {
		return runError(api.CodeConflict, "runner selection differs from its retained run")
	}
	if mode != reserve.Mode && !(mode == "resume" && (reserve.Mode == "continue" || reserve.Mode == "adopt")) {
		return runError(api.CodeConflict, "runner method differs from its reserved mode")
	}
	inputs := *record.Inputs
	grants, err := r.deps.Store.Grants(ctx, reserve.GrantSetID)
	if err != nil {
		return err
	}
	policy, err := r.deps.Store.CurrentApprovedPolicy(ctx, scope)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(grants, inputs.Grants) {
		return runError(api.CodeConflict, "runner grants changed after selection")
	}
	if err := api.ValidateLaunchPolicyCurrent(reserve, grants, policy); err != nil {
		return err
	}
	data, err := r.runBytes(ctx, scope, *r.enrollment, "", "")
	if err != nil {
		return err
	}
	var enrollment api.LaunchEnrollment
	if api.DecodeObject(data, &enrollment) != nil {
		return runError(api.CodeIntegrity, "runner enrollment bytes are invalid")
	}
	if err := api.ValidateLaunchEnrollment(enrollment, r.config, r.runtime); err != nil {
		return err
	}
	matched := false
	for _, runtime := range enrollment.Runtimes {
		matched = matched || runtime == inputs.Sources.Runtime && runtime.Driver == r.driver && runtime.Executable == request.Executable
	}
	if !matched {
		allowAndLog("runner_vendor")
	}
	matched = false
	for _, project := range enrollment.Projects {
		p := inputs.Sources.Project
		matched = matched || project.ID == p.EnrollmentID && project.Generation == p.Generation && project.ProjectID == p.ProjectID && project.Object == p.Object && project.Base == p.Base && project.HistoryScope == p.HistoryScope
	}
	if !matched {
		allowAndLog("runner_project")
	}
	runtimeBytes, err := r.runBytes(ctx, scope, r.runtime, "", "")
	if err != nil {
		return err
	}
	var manifest api.RuntimeManifest
	if api.DecodeObject(runtimeBytes, &manifest) != nil || manifest.Schema != "laneboss.runtime.v2" || manifest.Generation == 0 {
		return runError(api.CodeIntegrity, "runner runtime manifest is invalid")
	}
	pinned := manifest.Artifact == request.Executable
	for _, object := range manifest.Objects {
		pinned = pinned || object.ID == request.Executable.ID && object.Content.SHA256 == request.Executable.SHA256
	}
	if !pinned {
		allowAndLog("runner_vendor_manifest")
	}
	sources, err := r.deps.Sources.ResolveLaunchSources(ctx, api.LaunchSourceRequest{Claim: claim, ReservationID: reserve.ID, GrantSetID: reserve.GrantSetID})
	if err != nil {
		return err
	}
	if sources != inputs.Sources {
		return runError(api.CodeConflict, "native runner source enrollment changed")
	}
	if err := r.runInput(ctx, scope, record, request); err != nil {
		return err
	}
	broker, ok := r.deps.Credentials.(interface {
		VerifyRunnerSlot(context.Context, api.LaunchClaim, api.RunnerRequest) (api.LaunchStorage, error)
	})
	if !ok {
		return api.NotImplemented("lb-v2-secrets", "VerifyRunnerSlot")
	}
	storage, err := broker.VerifyRunnerSlot(ctx, claim, request)
	if err != nil {
		return err
	}
	actual, err := r.deps.Storage.ResolveLaunchStorage(ctx, api.LaunchDataRequest{Claim: claim, ReservationID: reserve.ID, GrantSetID: reserve.GrantSetID, LeaseID: storage.LeaseID})
	if err != nil {
		return err
	}
	if actual != storage || storage.ReservationID != reserve.ID || storage.Target != reserve.Target || storage.Home.LifeID != reserve.Target.LifeID || storage.Home.Home != request.Home || storage.Home.Generation == 0 || storage.WorkspaceID != request.Home.WorkspaceID {
		return runError(api.CodeIntegrity, "runner home differs from its live native allocation")
	}
	if record.Plan != nil && (record.Plan.Runner.Home != request.Home || record.Plan.Runner.Slot != request.Slot || record.Plan.Runner.Prompt != request.Prompt || record.Plan.Budget != request.Budget) {
		return runError(api.CodeConflict, "runner retry changed its retained plan")
	}
	current, err = r.deps.Store.Effect(ctx, scope, claim.EffectID)
	if err != nil {
		return err
	}
	if err := api.CheckPlanningClaim(current, claim, r.config, r.deps.Clock.Now()); err != nil {
		return err
	}
	after, err := r.deps.Store.LaunchPlan(ctx, scope, reserve.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(after, record) {
		return runError(api.CodeConflict, "runner inputs changed during enrollment")
	}
	return nil
}

func (r *enrolledRunner) runInput(ctx context.Context, scope api.Scope, record api.LaunchPlanRecord, request api.RunnerRequest) error {
	reserve := record.Reservation
	raw, err := r.runBytes(ctx, scope, reserve.OriginalRequest, reserve.OperationID, reserve.Target.LifeID)
	if err != nil {
		return err
	}
	if reserve.Loop != nil {
		if err := api.CheckLoopInput(reserve, raw); err != nil {
			return err
		}
		loop := reserve.Loop
		lane, err := r.deps.Store.Lane(ctx, scope, loop.Selector.Target)
		if err != nil {
			return err
		}
		if request.Session != loop.PreviousSession || request.Home != loop.PreviousHome.Home || request.LogicalTurnID != loop.LogicalTurnID || request.Budget != loop.BudgetRemaining || request.Model != lane.Model || request.Effort != lane.Effort {
			return runError(api.CodeConflict, "runner loop differs from its retained session, turn or budget")
		}
	} else if reserve.Mode == "continue" {
		var input api.ContinuationRequest
		if api.DecodeObject(raw, &input) != nil || input.Swap.OperationID != reserve.OperationID || input.Swap.ProfileGrantID != request.Slot.ProfileGrantID || input.Swap.ToProfileID != request.Slot.ProfileID || input.Swap.CancellationEpoch != reserve.CancellationEpoch || input.Swap.ContinuationRun != reserve.Target.Run || input.Swap.LogicalTurnID != request.LogicalTurnID {
			return runError(api.CodeIntegrity, "runner continuation changed its selected profile")
		}
	} else {
		var original api.Request
		if api.DecodeObject(raw, &original) != nil || original.Config != r.config || original.RequestID != reserve.RequestID || original.RequestSHA256 != reserve.RequestSHA256 {
			return runError(api.CodeIntegrity, "runner original request changed")
		}
		digest, err := api.RequestDigest(original)
		if err != nil || digest != reserve.RequestSHA256 {
			return runError(api.CodeIntegrity, "runner original request digest changed")
		}
		if reserve.Mode == "start" || reserve.Mode == "adopt" {
			profile, err := api.IssuedLaunchProfile(reserve, original, record.Inputs.Grants)
			if err != nil {
				return err
			}
			if profile.ID != request.Slot.ProfileGrantID || profile.ProfileID != request.Slot.ProfileID || profile.Driver != r.driver {
				// Kept refusing (L6 hard stop): a lane must not run on a credential profile it was not delegated.
				return runError(api.CodeForbidden, "runner profile differs from its original delegation")
			}
		}
		var model, effort string
		var budget api.Budget
		switch reserve.Mode {
		case "start":
			var input api.StartRequest
			if api.DecodeObject(original.Params, &input) != nil {
				return runError(api.CodeIntegrity, "runner start input is invalid")
			}
			model, effort, budget = input.Model, input.Effort, input.Budget
		case "adopt":
			var input api.AdoptRequest
			if api.DecodeObject(original.Params, &input) != nil {
				return runError(api.CodeIntegrity, "runner adoption input is invalid")
			}
			model, effort, budget = input.Model, input.Effort, input.Budget
		case "resume", "turn":
			lane, err := r.deps.Store.Lane(ctx, scope, api.LifeRef{LifeID: reserve.Target.LifeID, Run: reserve.Target.Run - 1})
			if err != nil {
				return err
			}
			model, effort = lane.Model, lane.Effort
			if request.Session != lane.Session {
				return runError(api.CodeIntegrity, "runner retained session changed")
			}
			if reserve.Mode == "resume" {
				var input api.ResumeRequest
				if api.DecodeObject(original.Params, &input) != nil {
					return runError(api.CodeIntegrity, "runner resume input is invalid")
				}
				budget = input.Budget
			} else {
				var input api.TurnRequest
				if api.DecodeObject(original.Params, &input) != nil {
					return runError(api.CodeIntegrity, "runner turn input is invalid")
				}
				budget = input.Budget
			}
		}
		if request.Model != model || request.Effort != effort || request.Budget != budget {
			return runError(api.CodeConflict, "runner model, effort or budget differs from its retained request")
		}
	}
	fresh := reserve.Mode == "start" && reserve.Target.Run == 1 && request.Session.VendorVersion == ""
	if r.driver == api.DriverCodex && !fresh && request.Session.VendorVersion != request.Executable.Version {
		return runError(api.CodeVersion, "runner session differs from the selected vendor version")
	}
	return nil
}

// allowAndLog: owner R181-R192 (10-18): checks on the launch path that block normal use are allowed and logged, not
// refused, until each is reviewed (saved in removed-security-1017.md, the hardened tree on branch lb-v2-hardened-1018).
func allowAndLog(check string) {
	line, _ := json.Marshal(struct {
		Event string `json:"event"`
		Check string `json:"check"`
	}{"check_allowed", check})
	allowedLog.Lock()
	defer allowedLog.Unlock()
	_, _ = allowedLog.w.Write(append(line, '\n'))
}

// allowedLog is the journal sink of allowAndLog: standard error in production; a test reads it back.
var allowedLog = struct {
	sync.Mutex
	w io.Writer
}{w: os.Stderr}
