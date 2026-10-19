package api

import (
	"path/filepath"
	"reflect"
	"regexp"
)

var bindingConfigName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var bindingDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidateBinding checks shape/compatibility only. Its caller must additionally
// prove installed ownership, endpoint/server identity and current generation.
func ValidateBinding(binding InstalledBinding, config, version string) error {
	invalid := func() error {
		return &Error{Code: CodeInvalid, Message: "invalid installed binding", Instead: "Repair the protected binding; never change the active session scope."}
	}
	if binding.Schema != "laneboss.binding.v2" || binding.Config != config || !bindingConfigName.MatchString(config) {
		return invalid()
	}
	if binding.Protocol != Protocol || binding.APISchema != SchemaVersion || binding.ContractRevision != ContractRevision || binding.ServiceVersion != version {
		return &Error{Code: CodeVersion, Message: "installed binding differs from the compiled release contract", Instead: "Install one matched service/helper/client generation."}
	}
	if binding.ServiceUID == 0 || binding.ServiceGID == 0 || binding.InstallationGeneration == 0 || binding.EndpointGeneration == 0 || !bindingDigest.MatchString(string(binding.ArtifactSHA256)) {
		return invalid()
	}
	if !filepath.IsAbs(binding.Socket) || filepath.Clean(binding.Socket) != binding.Socket || binding.Socket == "/" {
		return invalid()
	}
	if binding.Backend != "linux-bwrap-landlock" && binding.Backend != "darwin-seatbelt" {
		return invalid()
	}
	switch binding.Class {
	case EndpointHuman:
		if binding.LaunchID != "" || binding.Target != nil || binding.WorkerLeaseID != "" {
			return invalid()
		}
	case EndpointLane:
		if binding.LaunchID == "" || binding.Target == nil || binding.Target.LifeID == "" || binding.Target.Run == 0 || binding.WorkerLeaseID != "" {
			return invalid()
		}
	case EndpointWorker:
		if binding.LaunchID == "" || binding.Target == nil || binding.Target.LifeID == "" || binding.Target.Run == 0 || binding.WorkerLeaseID == "" {
			return invalid()
		}
	default:
		return invalid()
	}
	return nil
}

// ValidateTransactionShape is only a structural preflight. The store still
// performs current authorization, replay, proof/ticket/counter/CAS validation
// and the atomic state/event/outbox commit under its transaction boundary.
func ValidateTransactionShape(transaction Transaction) error {
	return validateTransactionShape(transaction, false)
}

func validateTransactionShape(transaction Transaction, cleanup bool) error {
	invalid := func() error {
		return &Error{Code: CodeInvalid, Message: "invalid typed transaction shape", Instead: "Use the closed transaction, guard, comparison and effect catalogs."}
	}
	if transaction.Internal == nil {
		spec, exists := Methods[transaction.Scope.Request.Method]
		if !exists || spec.Mutation && transaction.Reply == nil && transaction.Deferred == nil {
			return invalid()
		}
		if transaction.Deferred != nil && (!spec.Mutation || transaction.Reply != nil) {
			return invalid()
		}
		if !spec.Mutation && (!reflect.ValueOf(transaction.Writes).IsZero() || len(transaction.Effects)+len(transaction.Events)+len(transaction.Guards) != 0) {
			return invalid()
		}
		if !validPublicWrites(transaction) {
			return invalid()
		}
	} else {
		if transaction.Deferred != nil || transaction.Reply != nil {
			return invalid()
		}
		if transaction.Scope.Request.Method != "" || transaction.Internal.Config != transaction.Scope.Config || transaction.Internal.ID == "" {
			return invalid()
		}
		if !validInternalKind(transaction.Internal.Kind) || !validInternalWrites(transaction) {
			return invalid()
		}
		if !validPreparedPlanBindings(transaction) {
			return invalid()
		}
		if !validLaunchPolicyFence(transaction) {
			return invalid()
		}
		if !validPolicyRefresh(transaction) {
			return invalid()
		}
	}
	for _, event := range transaction.Events {
		if event.Kind == "lane.turn" && !launchID(event.LogicalTurnID) {
			return invalid()
		}
	}
	if !validLoopTurnWrites(transaction) {
		return invalid()
	}
	for _, compare := range transaction.Compare {
		if compare.ID == "" {
			return invalid()
		}
		switch compare.Kind {
		case CompareLane, CompareGrants, CompareOrg, CompareChange, CompareApproval, CompareRecord,
			CompareMail, CompareGuidance, CompareContinuation, CompareEndpoint, CompareUpgrade, CompareLaunchPlan:
		default:
			return invalid()
		}
	}
	for _, guard := range transaction.Guards {
		count := 0
		for _, present := range []bool{guard.Proof != nil, guard.Ticket != nil, guard.Approval != nil, guard.Cancellation != nil} {
			if present {
				count++
			}
		}
		if count != 1 {
			return invalid()
		}
	}
	for _, effect := range transaction.Effects {
		if effect.ID == "" || effect.OperationID == "" || effect.Context == nil ||
			effect.Context.ID == "" || effect.Context.Config != transaction.Scope.Config ||
			effect.Context.EffectID != effect.ID || effect.Context.CauseOperationID != effect.OperationID ||
			!validInternalKind(effect.Context.Kind) || !validEffectContext(effect) {
			return invalid()
		}
		count := 0
		for _, present := range []bool{effect.PlanLaunch != nil, effect.Launch != nil, effect.Stop != nil, effect.Deliver != nil,
			effect.Clean != nil, effect.Swap != nil, effect.Worker != nil, effect.ApplyChange != nil,
			effect.Migration != nil, effect.Upgrade != nil, effect.Rebuild != nil, effect.Bootstrap != nil, effect.Channel != nil,
			effect.HelperAllocate != nil, effect.HelperPrepare != nil, effect.HelperRelease != nil, effect.HelperAbort != nil} {
			if present {
				count++
			}
		}
		if count != 1 {
			return invalid()
		}
	}
	for _, selection := range transaction.Writes.Guidance {
		if !validGuidanceSelection(transaction, selection) {
			return invalid()
		}
	}
	for _, record := range transaction.Writes.LaunchPlans {
		if err := ValidateLaunchPlanRecord(record); err != nil {
			return err
		}
		if !validLaunchPlanWriteMode(transaction, record, cleanup) {
			return invalid()
		}
	}
	if transaction.Reply != nil {
		reply := transaction.Reply
		if (reply.Error == nil) == (len(reply.Result) == 0) {
			return invalid()
		}
		if reply.Error == nil {
			spec := Methods[transaction.Scope.Request.Method]
			if err := DecodeObject(reply.Result, reflect.New(spec.Response).Interface()); err != nil {
				return err
			}
		}
	}
	return nil
}

func validInternalKind(kind InternalKind) bool {
	switch kind {
	case InternalHelperAllocate, InternalHelperRegister, InternalHelperPrepare,
		InternalHelperOpen, InternalHelperStop, InternalHelperRelease, InternalHelperAbort,
		InternalEffectComplete, InternalMailDeliver, InternalGuidanceComplete, InternalGuidanceRecover,
		InternalProfileContinue, InternalProfileCancel, InternalOrgPublish, InternalOrgBootstrap,
		InternalUpgradeApply, InternalMigrationApply, InternalCaptureAppend, InternalObjectRetain,
		InternalJudgeEvaluate, InternalLifecycleEffect, InternalChannelReceive, InternalAdminEnroll, InternalLaunchPlan, InternalPolicyRefresh:
		return true
	}
	return false
}

func validEffectContext(effect Effect) bool {
	kind := effect.Context.Kind
	switch {
	case effect.PlanLaunch != nil:
		return kind == InternalLaunchPlan && launchID(effect.PlanLaunch.ReservationID) &&
			launchID(effect.Context.Target.LifeID) && effect.Context.Target.Run > 0
	case effect.HelperAllocate != nil:
		return kind == InternalHelperAllocate && reflect.DeepEqual(*effect.Context, effect.HelperAllocate.Cause)
	case effect.HelperPrepare != nil:
		return kind == InternalHelperPrepare && reflect.DeepEqual(*effect.Context, effect.HelperPrepare.Cause)
	case effect.HelperRelease != nil:
		return kind == InternalHelperRelease && reflect.DeepEqual(*effect.Context, effect.HelperRelease.Cause)
	case effect.HelperAbort != nil:
		request := effect.HelperAbort
		return kind == InternalHelperAbort && reflect.DeepEqual(*effect.Context, request.Cause) && request.EffectID == effect.ID && request.OperationID == effect.OperationID
	case effect.Launch != nil, effect.Stop != nil, effect.Clean != nil:
		return kind == InternalLifecycleEffect
	case effect.Swap != nil:
		return kind == InternalProfileContinue
	case effect.Deliver != nil, effect.Channel != nil:
		return kind == InternalMailDeliver
	case effect.Worker != nil:
		return kind == InternalLifecycleEffect || kind == InternalObjectRetain || kind == InternalChannelReceive
	case effect.ApplyChange != nil:
		return kind == InternalOrgPublish
	case effect.Bootstrap != nil:
		return kind == InternalOrgBootstrap
	case effect.Migration != nil, effect.Rebuild != nil:
		return kind == InternalMigrationApply
	case effect.Upgrade != nil:
		return kind == InternalUpgradeApply
	}
	return false
}

// ValidateReleaseReceipt checks the helper's measured shape. The helper/store
// must also authenticate its channel and correlate the pinned lease, operation,
// effect and caller observation; a well-formed value alone is not proof.
func ValidateReleaseReceipt(receipt ReleaseReceipt) error {
	if receipt.ID == "" || receipt.LeaseID == "" || receipt.ContainmentID == "" || receipt.OperationID == "" || receipt.EffectID == "" || receipt.ObservedAt == "" ||
		receipt.Quiescence.Handle.ContainmentID != receipt.ContainmentID ||
		receipt.Backend != "linux-bwrap-landlock" && receipt.Backend != "darwin-seatbelt" {
		return &Error{Code: CodeInvalid, Message: "release receipt lacks its measured lease binding", Instead: "Retain the lease and reconcile through the authenticated helper."}
	}
	for _, count := range []*uint64{receipt.Quiescence.Survivors, receipt.LiveConnections, receipt.QueuedJobs, receipt.WritableExports} {
		if count == nil || *count != 0 {
			return &Error{Code: CodeContainmentUnknown, Message: "release quiescence is unknown or nonzero", Instead: "Retain the lease and resolve every process, connection, job and writable export."}
		}
	}
	if receipt.Quiescence.State != "exited" {
		return &Error{Code: CodeContainmentUnknown, Message: "release containment is not measured exited", Instead: "Retain the lease and re-observe its registered containment."}
	}
	return nil
}
