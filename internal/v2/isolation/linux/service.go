// Package linux implements the Linux isolation boundary.
//
// The installed root helper owns UID/cgroup/gate state and invokes the fixed
// unprivileged namespace/Landlock bootstrap. ControlSource supplies protected
// service context; opaque IDs are never reinterpreted as host paths.
package linux

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Helper          api.HelperControl
	RuntimeManifest api.BlobRef
	Controls        ControlSource
}

type Service struct{ deps Dependencies }

const backendName = "linux-bwrap-landlock"

func New(deps Dependencies) (*Service, error) {
	if deps.Helper == nil {
		return nil, failure(api.CodePrerequisite, "the installed UID/cgroup helper is required")
	}
	if err := validateBlob(deps.RuntimeManifest); err != nil {
		return nil, failure(api.CodeIntegrity, "a pinned runtime manifest is required")
	}
	return &Service{deps: deps}, nil
}

var _ api.Launcher = (*Service)(nil)

func failure(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-linux",
		Instead: "Retain the failed evidence and repair the installed isolation prerequisites."}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		code := api.CodeCancelled
		if err == context.DeadlineExceeded {
			code = api.CodeDeadline
		}
		return failure(code, "isolation operation cancelled before release")
	}
	return nil
}

func missingControl(operation string) error {
	return api.NotImplemented("lb-v2-integrate", "isolation/linux."+operation+
		" (protected service ControlSource binding)")
}

func (s *Service) controls(operation string) (ControlSource, error) {
	if s == nil || s.deps.Controls == nil {
		return nil, missingControl(operation)
	}
	return s.deps.Controls, nil
}

func (s *Service) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := contextError(ctx); err != nil {
		return api.IsolationCapabilities{Backend: backendName}, err
	}
	host, err := probeHost(ctx)
	var typed *api.Error
	if err != nil && (!errors.As(err, &typed) || typed.Code != api.CodeNotImplemented) {
		return host, err
	}
	source, sourceErr := s.controls("Probe")
	if sourceErr != nil {
		return host, sourceErr
	}
	measured, err := source.Probe(ctx)
	if err != nil {
		return host, err
	}
	if err := validateInstalledProbe(host, measured); err != nil {
		return host, err
	}
	return mergeInstalledProbe(host, measured), nil
}

func (s *Service) Prepare(ctx context.Context, spec api.LaunchSpec) (_ api.PreparedLaunch, resultErr error) {
	if err := contextError(ctx); err != nil {
		return api.PreparedLaunch{}, err
	}
	if s == nil {
		return api.PreparedLaunch{}, failure(api.CodePrerequisite, "Linux launcher is not initialized")
	}
	check := "linux_spec"
	defer func() { api.ObserveHelperReason(ctx, resultErr, check) }()
	if err := validateSpec(spec, s.deps.RuntimeManifest, time.Now()); err != nil {
		return api.PreparedLaunch{}, err
	}
	if len(spec.Grants.Network) != 0 && s.deps.Controls == nil {
		return api.PreparedLaunch{}, &PrerequisiteError{Check: "controlled_egress", Err: errEgressLease}
	}
	source, err := s.controls("Prepare")
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	check = "linux_handoff"
	handoff, err := source.Handoff(ctx, spec)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	check = "linux_original"
	original, err := source.Original(ctx, handoff.Original)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := validateHandoff(spec, handoff, original); err != nil {
		return api.PreparedLaunch{}, err
	}
	var plan api.LaunchPlanRecord
	if spec.Kind == "agent" {
		check = "linux_plan"
		plan, err = readAgentPlan(ctx, source, spec.PlanID)
		if err != nil {
			return api.PreparedLaunch{}, err
		}
		if err := validateAgentHandoff(spec, handoff, original, plan); err != nil {
			return api.PreparedLaunch{}, err
		}
		if err := validatePreparePhase(plan); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	check = "linux_register"
	registered, err := s.deps.Helper.RegisterSpec(ctx, handoff)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := validateRegistration(handoff, registered); err != nil {
		return api.PreparedLaunch{}, err
	}
	check = "linux_runtime"
	runtime, err := s.deps.Helper.ResolveRuntime(ctx, handoff)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := validateRuntime(handoff, runtime); err != nil {
		return api.PreparedLaunch{}, err
	}
	if spec.Kind == "worker" && spec.Worker.Kind == "channel" {
		if err := validateChannelRuntime(spec, runtime); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	if materializeWorker(spec) {
		if err := validateMaterializeRuntime(spec, runtime); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	if spec.Kind == "agent" {
		if err := validateAgentRuntime(*plan.Plan, runtime); err != nil {
			return api.PreparedLaunch{}, err
		}
	}
	check = "linux_prepare_cause"
	cause, err := source.PrepareIntent(ctx, handoff)
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := validateStageCause(ctx, cause, api.InternalHelperPrepare, handoff); err != nil {
		return api.PreparedLaunch{}, err
	}
	prepareCtx := ctx
	if child, ok := api.PrepareLeaseFromContext(ctx); ok {
		prepareCtx = api.WithEffectLease(ctx, child)
	}
	check = "linux_prepare"
	prepared, err := s.deps.Helper.Prepare(prepareCtx, api.HelperLaunchRequest{
		Cause: cause, LeaseID: registered.LeaseID, PreparedSpecID: registered.SpecID,
		SpecSHA256: registered.SpecSHA256})
	if err != nil {
		return api.PreparedLaunch{}, err
	}
	check = "linux_prepared_tuple"
	if !validPrepared(prepared) || prepared.Target != spec.Target || prepared.SpecSHA256 != handoff.SpecSHA256 ||
		prepared.EndpointGeneration != spec.EndpointGeneration || prepared.ID == spec.LaunchID ||
		spec.Kind == "agent" && prepared.ContainmentID != plan.Plan.Lease.ContainmentID {
		// Preserve a mismatched helper receipt for recovery; never invent an
		// abort/exit or open its gate to make a malformed prepare usable.
		return prepared, failure(api.CodeIntegrity, "helper prepared gate differs from registered spec")
	}
	return prepared, nil
}

func (s *Service) Launch(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	if err := contextError(ctx); err != nil {
		return api.ProcessHandle{}, err
	}
	if !validPrepared(prepared) || permit.PreparedID != prepared.ID || permit.LaunchID == "" ||
		permit.CommittedSeq == 0 || !validDigest(permit.RecordSHA256) {
		return api.ProcessHandle{}, failure(api.CodeInvalid, "incomplete or mismatched launch permit")
	}
	source, err := s.controls("Launch")
	if err != nil {
		return api.ProcessHandle{}, err
	}
	binding, err := source.Binding(ctx, permit.LaunchID)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateIdentity(prepared, permit, binding); err != nil {
		return api.ProcessHandle{}, err
	}
	// Worker jobs have a separate authenticated worker lease. Every other
	// binding must recover its agent plan; missing recovery is never legacy.
	if binding.Record.Kind == "agent" {
		if binding.Recovery == nil {
			return api.ProcessHandle{}, failure(api.CodeIntegrity, "agent binding is missing retained recovery")
		}
		plan, err := readAgentPlan(ctx, source, binding.Recovery.PlanID)
		if err != nil {
			return api.ProcessHandle{}, err
		}
		if err := validateAgentBinding(binding, plan, s.deps.RuntimeManifest); err != nil {
			return api.ProcessHandle{}, err
		}
		handoff := binding.Recovery.Handoff
		original, err := source.Original(ctx, handoff.Original)
		if err != nil {
			return api.ProcessHandle{}, err
		}
		if err := validateAgentHandoff(handoff.Spec, handoff, original, plan); err != nil {
			return api.ProcessHandle{}, err
		}
	}
	request, err := source.Open(ctx, prepared, permit)
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateCause(request.Cause, api.InternalHelperOpen, prepared.Target); err != nil {
		return api.ProcessHandle{}, err
	}
	if request.Prepared != prepared || request.Permit != permit || request.Cause.Config != binding.Record.Config ||
		request.OperationID != request.Cause.CauseOperationID || request.EffectID != request.Cause.EffectID {
		return api.ProcessHandle{}, failure(api.CodeIntegrity, "open request differs from committed gate context")
	}
	if binding.Recovery != nil {
		if err := validateStageCause(ctx, request.Cause, api.InternalHelperOpen, binding.Recovery.Handoff); err != nil {
			return api.ProcessHandle{}, err
		}
	}
	reconciled, err := s.deps.Helper.ReconcileGate(ctx, api.HelperReconcileRequest{
		LeaseID: binding.Record.UIDLeaseID, LaunchID: permit.LaunchID,
		PreparedID: prepared.ID, OperationID: request.OperationID})
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if reconciled.Prepared == nil || *reconciled.Prepared != prepared {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "reconciliation did not resolve the original gate")
	}
	if reconciled.GateState == "" || reconciled.GateState == "unknown" {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "reconciled gate state is unknown")
	}
	if reconciled.Process != nil || reconciled.ConsumedPermit != nil {
		if reconciled.Process == nil || reconciled.ConsumedPermit == nil || *reconciled.ConsumedPermit != permit ||
			validateOpened(prepared, *reconciled.Process) != nil ||
			validateObservation(*reconciled.Process, reconciled.Observation, false) != nil {
			return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "consumed gate reconciliation is unknown or mismatched")
		}
		return *reconciled.Process, nil
	}
	if reconciled.GateState != "prepared" {
		return api.ProcessHandle{}, failure(api.CodeContainmentUnknown, "gate is not known prepared; another gate is refused")
	}
	handle, err := s.deps.Helper.OpenGate(ctx, request)
	if err != nil {
		// No local retry or replacement. The next attempt must reconcile the
		// same prepared ID/permit through the helper's durable journal.
		return api.ProcessHandle{}, err
	}
	if err := validateOpened(prepared, handle); err != nil {
		return api.ProcessHandle{}, err
	}
	observed, err := s.deps.Helper.ObserveGate(ctx, api.HelperObserveRequest{
		LeaseID: binding.Record.UIDLeaseID, Handle: handle})
	if err != nil {
		return api.ProcessHandle{}, err
	}
	if err := validateObservation(handle, observed, false); err != nil {
		return api.ProcessHandle{}, err
	}
	return handle, nil
}

func validateOpened(prepared api.PreparedLaunch, handle api.ProcessHandle) error {
	if validateProcess(handle) != nil || handle.Target != prepared.Target ||
		handle.ContainmentID != prepared.ContainmentID || handle.Generation != prepared.ProcessGeneration {
		return failure(api.CodeContainmentUnknown, "opened process differs from the committed containment")
	}
	return nil
}

func unknown(process api.ProcessHandle) api.ProcessObservation {
	return api.ProcessObservation{Handle: process, State: "unknown",
		PromptStatus: "unknown", ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
}

func (s *Service) Observe(ctx context.Context, process api.ProcessHandle) (api.ProcessObservation, error) {
	result := unknown(process)
	if err := contextError(ctx); err != nil {
		return result, err
	}
	source, err := s.controls("Observe")
	if err != nil {
		return result, err
	}
	request, err := source.Observe(ctx, process)
	if err != nil {
		return result, err
	}
	if request.LeaseID == "" || request.Handle != process || validateProcess(process) != nil {
		return result, failure(api.CodeContainmentUnknown, "observe context does not bind the original lease")
	}
	observed, err := s.deps.Helper.ObserveGate(ctx, request)
	if err != nil {
		return result, err
	}
	if err := validateObservation(process, observed, false); err != nil {
		return result, err
	}
	return observed, nil
}

func (s *Service) Stop(ctx context.Context, process api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	result := unknown(process)
	if err := contextError(ctx); err != nil {
		return result, err
	}
	if reason == "" {
		return result, failure(api.CodeInvalid, "a stop reason is required")
	}
	source, err := s.controls("Stop")
	if err != nil {
		return result, err
	}
	request, err := source.Stop(ctx, process, reason)
	if err != nil {
		return result, err
	}
	if err := validateCause(request.Cause, api.InternalHelperStop, process.Target); err != nil {
		return result, err
	}
	lease, err := source.Observe(ctx, process)
	if err != nil {
		return result, err
	}
	if request.Target.LeaseID == "" || request.Target != lease || request.Target.Handle != process ||
		request.Reason != reason || request.OperationID != request.Cause.CauseOperationID ||
		request.EffectID != request.Cause.EffectID {
		return result, failure(api.CodeIntegrity, "stop cause or containment context differs")
	}
	observed, err := s.deps.Helper.StopGate(ctx, request)
	if err != nil {
		return result, err
	}
	if err := validateObservation(process, observed, true); err != nil {
		return observed, err
	}
	return observed, nil
}

func (s *Service) Abort(ctx context.Context, prepared api.PreparedLaunch) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	source, err := s.controls("Abort")
	if err != nil {
		return err
	}
	if !validPrepared(prepared) {
		return failure(api.CodeInvalid, "abort requires the original prepared gate")
	}
	request, err := source.Abort(ctx, prepared)
	if err != nil {
		return err
	}
	if err := validateCause(request.Cause, api.InternalHelperAbort, prepared.Target); err != nil {
		return err
	}
	if request.LeaseID == "" || request.PreparedID != prepared.ID || request.SpecSHA256 != prepared.SpecSHA256 ||
		request.OperationID != request.Cause.CauseOperationID || request.EffectID != request.Cause.EffectID {
		return failure(api.CodeIntegrity, "abort cause or prepared spec differs")
	}
	receipt, err := s.deps.Helper.AbortGate(ctx, request)
	if err != nil {
		return err
	}
	if err := validateAborted(request, prepared, receipt); err != nil {
		return err
	}
	return source.RecordAbort(ctx, request, receipt)
}

func validateAborted(request api.HelperAbortRequest, prepared api.PreparedLaunch, receipt api.AbortReceipt) error {
	if receipt.ID == "" || receipt.LeaseID != request.LeaseID || receipt.PreparedID != prepared.ID ||
		receipt.AgentExecuted || !validTime(receipt.ObservedAt) || receipt.Quiescence.Survivors == nil ||
		*receipt.Quiescence.Survivors != 0 || receipt.Quiescence.Handle.Target != prepared.Target ||
		receipt.Quiescence.Handle.ContainmentID != prepared.ContainmentID ||
		receipt.Quiescence.Handle.Generation != prepared.ProcessGeneration ||
		receipt.Quiescence.State != "prepared" || receipt.Quiescence.ExitCode != nil || receipt.Quiescence.Signal != nil ||
		!validTime(receipt.Quiescence.ObservedAt) || !validPromptStatus(receipt.Quiescence.PromptStatus) {
		return failure(api.CodeContainmentUnknown, "abort lacks a measured nonexecuting quiescence receipt")
	}
	return nil
}

func (s *Service) Collect(ctx context.Context, leaseID api.ID, observation api.ProcessObservation) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if leaseID == "" || observation.State != "exited" || observation.Survivors == nil ||
		*observation.Survivors != 0 || observation.Handle.ContainmentID == "" || observation.Handle.Generation == "" {
		return failure(api.CodeContainmentUnknown, "collection requires a known quiescent containment")
	}
	source, err := s.controls("Collect")
	if err != nil {
		return err
	}
	if err := validateObservation(observation.Handle, observation, true); err != nil {
		return err
	}
	request, err := source.Release(ctx, leaseID, observation)
	if err != nil {
		return err
	}
	if err := validateCause(request.Cause, api.InternalHelperRelease, observation.Handle.Target); err != nil {
		return err
	}
	if request.LeaseID != leaseID || !sameObservation(request.Observation, observation) {
		return failure(api.CodeIntegrity, "collection request differs from current causal lease")
	}
	observeRequest, err := source.Observe(ctx, observation.Handle)
	if err != nil {
		return err
	}
	if observeRequest.LeaseID != leaseID || observeRequest.Handle != observation.Handle {
		return failure(api.CodeContainmentUnknown, "collection observation resolved another lease")
	}
	fresh, err := s.deps.Helper.ObserveGate(ctx, observeRequest)
	if err != nil {
		return err
	}
	if validateObservation(observation.Handle, fresh, true) != nil ||
		!sameObservation(fresh, observation) {
		return failure(api.CodeContainmentUnknown, "fresh containment disagrees with collection claim")
	}
	receipt, err := s.deps.Helper.Release(ctx, request)
	if err != nil {
		return err
	}
	if err := validateReleased(request, receipt); err != nil {
		return err
	}
	// Only the exact helper-measured receipt goes to EffectOutcome.Release.
	// The source owns the durable effect claim; no caller zero is promoted.
	return source.RecordRelease(ctx, request, receipt)
}

func validateInstalledProbe(host, measured api.IsolationCapabilities) error {
	if !measured.Available || measured.Backend != backendName || measured.Kernel != host.Kernel ||
		measured.LandlockABI != host.LandlockABI {
		return failure(api.CodePrerequisite, "installed helper probe is unavailable or differs from host")
	}
	for _, check := range host.Checks {
		if !check.Available && !installedBoundary(check.Name) {
			return failure(api.CodePrerequisite, "a current host prerequisite failed")
		}
	}
	checks := make(map[string]api.Capability)
	for _, check := range measured.Checks {
		if _, exists := checks[check.Name]; exists || !check.Available {
			return failure(api.CodePrerequisite, "installed helper probe has duplicate or failed checks")
		}
		checks[check.Name] = check
	}
	for _, name := range []string{"bwrap_options", "namespace_boundary", "seccomp_deny_filter", "uid_pool",
		"cgroup_containment", "controlled_egress", "runtime_projection", "capture_pipes", "launch_gate"} {
		check, exists := checks[name]
		if !exists || check.Evidence == nil || validateBlob(*check.Evidence) != nil || check.Evidence.Bytes == 0 {
			return failure(api.CodePrerequisite, "installed helper probe lacks retained boundary evidence")
		}
	}
	return nil
}

func installedBoundary(name string) bool {
	switch name {
	case "bwrap_options", "namespace_boundary", "seccomp_deny_filter", "uid_pool", "cgroup_containment",
		"controlled_egress", "runtime_projection", "capture_pipes", "launch_gate":
		return true
	}
	return false
}

func mergeInstalledProbe(host, measured api.IsolationCapabilities) api.IsolationCapabilities {
	result := measured
	result.Checks = nil
	seen := map[string]bool{}
	for _, check := range host.Checks {
		if !installedBoundary(check.Name) {
			result.Checks = append(result.Checks, check)
			seen[check.Name] = true
		}
	}
	for _, check := range measured.Checks {
		if !seen[check.Name] {
			result.Checks = append(result.Checks, check)
		}
	}
	return result
}
