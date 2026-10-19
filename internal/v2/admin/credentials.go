package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

var _ api.CredentialProjectionControl = (*Service)(nil)
var _ api.CredentialProjectionBinder = (*Service)(nil)

type credentialBindingResult struct {
	Bound   bool
	Unbound bool
	Failure *api.Error `json:"Failure,omitempty"`
}

type credentialBindingStatus struct {
	Bound   bool
	Fresh   bool
	Failure *api.Error `json:"Failure,omitempty"`
}

type credentialJournal struct {
	State   string
	Record  *api.CredentialProjectionRecord  `json:"Record,omitempty"`
	Refresh *api.CredentialSourceVersion     `json:"Refresh,omitempty"`
	Request *api.CredentialProjectionRequest `json:"request,omitempty"`
	Stop    *credentialStop                  `json:"local_stop,omitempty"`
}

type credentialPrepare struct {
	Request api.HelperLaunchRequest
	Claim   api.EffectLease
}

// Prepared before the one-use permit is consumed. These temporary exports
// remain owned until the handoff finishes or an earlier journal write fails.
type credentialExecDelivery struct {
	data    []byte
	exports []*os.File
}

func (d *credentialExecDelivery) close() error {
	if d == nil {
		return nil
	}
	err := closeCredentialFiles(d.exports)
	d.exports = nil
	clear(d.data)
	d.data = nil
	return err
}

type credentialRuntime struct {
	manager  *leaseManager
	broker   api.CredentialProjectionBroker
	identity api.CredentialProjectionIdentity
	peer     api.VerifiedPeer
	held     map[api.ID]*heldCredentials
}

type heldCredentials struct {
	record        api.CredentialProjectionRecord
	home          *os.File
	files         []*os.File
	sources       []string
	export        *os.File
	refresh       *api.CredentialRefresh
	sourceHandles []*os.File
	inventory     []storageInode
	destinations  []storageInode
	cleanup       *api.CredentialWithdrawalReceipt
	releaseScan   *rscan.NativeReleaseScan
}

func nonnilCredentialClient(value any) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return !v.IsNil()
	}
	return true
}

// Only metadata clients live in the service process. Binding the native
// receiver is a separate, authenticated root-helper operation.
func (s *Service) BindCredentialProjection(broker api.CredentialProjectionBroker, identity api.CredentialProjectionIdentity) error {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()
	if s.credentialAttempted {
		return failure(api.CodeConflict, "credential projection binding is one-use")
	}
	s.credentialAttempted = true
	if !nonnilCredentialClient(broker) || !nonnilCredentialClient(identity) {
		return failure(api.CodeInvalid, "credential projection needs both native owner clients")
	}
	if !validConfig(s.deps.Config) {
		return api.NotImplemented(owner, "admin.BindCredentialProjection")
	}
	// A new service process may attach to the same native helper owner. This
	// read-only query neither repeats binding nor resets a partial attempt.
	var status credentialBindingStatus
	if err := s.call(context.Background(), "credential_binding", api.Empty{}, &status); err != nil {
		return err
	}
	if status.Failure != nil {
		return status.Failure
	}
	if status.Bound == status.Fresh {
		return failure(api.CodeIntegrity, "helper returned contradictory credential attachment state")
	}
	if status.Bound {
		return s.completeCredentialBinding(credentialBindingResult{Bound: true}, broker, identity)
	}
	var result credentialBindingResult
	if err := s.call(context.Background(), "credential_bind", api.Empty{}, &result); err != nil {
		return err // transport uncertainty never certifies Unbound
	}
	return s.completeCredentialBinding(result, broker, identity)
}

func (m *leaseManager) credentialBinding(ctx context.Context) credentialBindingStatus {
	if m.credentials == nil {
		if m.credentialBindAttempted {
			return credentialBindingStatus{Failure: failure(api.CodeConflict, "native credential binding has a retained failed attempt")}
		}
		return credentialBindingStatus{Fresh: true}
	}
	if !m.credentialBindAttempted || m.credentials.manager != m {
		return credentialBindingStatus{Failure: failure(api.CodeIntegrity, "credential receiver lost its original helper owner")}
	}
	if err := m.credentials.checkBinding(ctx); err != nil {
		return credentialBindingStatus{Failure: failure(api.CodeUnauthenticated, "retained native credential owners are unavailable")}
	}
	return credentialBindingStatus{Bound: true}
}

func (s *Service) completeCredentialBinding(result credentialBindingResult, broker api.CredentialProjectionBroker, identity api.CredentialProjectionIdentity) error {
	if !result.Bound {
		if result.Failure == nil {
			return failure(api.CodeIntegrity, "helper did not certify its binding outcome")
		}
		err := &api.CredentialBindingFailure{Cause: result.Failure, Unbound: result.Unbound}
		if api.CredentialBindingRetryable(err) {
			s.credentialAttempted = false
		}
		return err
	}
	if result.Unbound || result.Failure != nil {
		return failure(api.CodeIntegrity, "helper returned contradictory binding evidence")
	}
	s.credentialBroker, s.credentialIdentity = broker, identity
	return nil
}

func closeCredentialFiles(files []*os.File) error {
	var failures []error
	for _, file := range files {
		if file != nil {
			failures = append(failures, file.Close())
		}
	}
	return errors.Join(failures...)
}

func (s *Service) credentialControl() (*credentialRuntime, error) {
	if s.nativeCredentials == nil {
		return nil, failure(api.CodeForbidden, "credential descriptors belong only to the root helper receiver")
	}
	return s.nativeCredentials, nil
}

func (s *Service) InspectCredentialTransfer(ctx context.Context, transfer api.CredentialTransfer) ([]api.CredentialDescriptorFact, error) {
	runtime, err := s.credentialControl()
	if err != nil {
		return nil, errors.Join(err, closeCredentialFiles(transfer.Files))
	}
	return runtime.inspect(ctx, transfer)
}
func (s *Service) ProjectCredentials(ctx context.Context, transfer api.CredentialTransfer) (api.CredentialProjectionReceipt, error) {
	runtime, err := s.credentialControl()
	if err != nil {
		return api.CredentialProjectionReceipt{}, errors.Join(err, closeCredentialFiles(transfer.Files))
	}
	return runtime.project(ctx, transfer)
}
func (s *Service) ObserveCredentials(ctx context.Context, id api.ID) (api.CredentialProjectionReceipt, error) {
	if s.nativeCredentials == nil {
		var observed api.CredentialProjectionReceipt
		if err := s.call(ctx, "credential_projection_observe_id", struct{ ProjectionID api.ID }{id}, &observed); err != nil {
			return observed, err
		}
		if observed.ProjectionID != id {
			return api.CredentialProjectionReceipt{}, failure(api.CodeIntegrity, "native credential observation changed projection identity")
		}
		return observed, nil
	}
	runtime, err := s.credentialControl()
	if err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	return runtime.observe(ctx, id)
}
func (s *Service) WithdrawCredentials(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	runtime, err := s.credentialControl()
	if err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	return runtime.withdraw(ctx, record)
}

// This reads an already completed helper measurement. It cannot close a gate,
// unlink a credential or manufacture resource counters from the caller's DTO.
func (s *Service) ReadCredentialWithdrawal(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	var receipt api.CredentialWithdrawalReceipt
	if err := s.call(ctx, "credential_withdrawal_observe", record, &receipt); err != nil {
		return receipt, err
	}
	if err := api.ValidateCredentialWithdrawalHelper(record, receipt); err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	return receipt, nil
}

func (m *leaseManager) credentialWithdrawalObservation(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	if m.credentials == nil {
		return api.CredentialWithdrawalReceipt{}, failure(api.CodePrerequisite, "credential native receiver is not bound")
	}
	if err := m.credentials.checkBinding(ctx); err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	held := m.credentials.held[record.Authority.ID]
	if held == nil || held.cleanup == nil || !reflect.DeepEqual(held.record, record) {
		return api.CredentialWithdrawalReceipt{}, failure(api.CodeContainmentUnknown, "credential withdrawal has no original completed native measurement")
	}
	if err := api.ValidateCredentialWithdrawalHelper(record, *held.cleanup); err != nil {
		return api.CredentialWithdrawalReceipt{}, err
	}
	return *held.cleanup, nil
}
func (s *Service) CollectCredentialRefresh(ctx context.Context, record api.CredentialProjectionRecord) (api.CredentialRefresh, error) {
	runtime, err := s.credentialControl()
	if err != nil {
		return api.CredentialRefresh{}, err
	}
	return runtime.collectRefresh(ctx, record)
}

func credentialRequired(spec api.LaunchSpec) bool {
	return spec.Runner != nil || len(spec.Injection.SlotIDs)+len(spec.Injection.GrantIDs)+len(spec.Injection.SourceVersions)+len(spec.Injection.TaskSecretNames)+len(spec.Injection.TaskSecretFileNames) != 0
}

func (m *leaseManager) ensureCredentialsWithdrawn(record leaseRecord) error {
	if record.Credentials != nil && record.Credentials.State != "withdrawn" {
		return failure(api.CodeContainmentUnknown, "credential projection must be withdrawn before lease collection")
	}
	return nil
}

// Expiration fences acquisition, but must never erase retained ownership or
// make cleanup impossible. Native observations remain separate from this DTO.
func validateCredentialJournal(record leaseRecord) error {
	j := record.Credentials
	if j == nil {
		return nil
	}
	if record.Spec == nil || record.Gate == nil || record.Storage == nil || !credentialRequired(record.Spec.Handoff.Spec) {
		return failure(api.CodeIntegrity, "credential journal lost its launch or storage")
	}
	if j.Stop != nil {
		cause := j.Stop.Cause
		if !record.Revoked && !releaseStop(record) || j.Stop.Note != "" && !releaseStop(record) || validateCause(cause, record.Request.Config, cause.Kind) != nil || cause.Target != record.Gate.Prepared.Target || cause.Kind != api.InternalHelperStop && cause.Kind != api.InternalHelperAbort && cause.Kind != api.InternalHelperRelease || j.Stop.Reason != "revoked" && j.Stop.Reason != "refused" && j.Stop.Reason != "release" && j.Stop.Reason != api.CredentialStopReason {
			return failure(api.CodeIntegrity, "credential local stop fence lost its revoked containment")
		}
	}
	if j.Request != nil {
		q := *j.Request
		stamp, err := time.Parse(time.RFC3339Nano, string(record.IssuedAt))
		// The gate keeps the prepare request as Prepare accepted it: its cause may carry the live claimant
		// {service, ClaimantID} in place of the effect's author (currentStage); the retained effect keeps the author.
		for _, c := range []struct {
			name string
			bad  bool
		}{
			{"issued_at", err != nil}, {"lease", q.Lease != record.Lease}, {"prepared", q.Prepared != record.Gate.Prepared},
			{"home", q.Home != record.Storage.Binding.Home}, {"handoff", !reflect.DeepEqual(q.Handoff, record.Spec.Handoff)},
			{"helper_prepare", !retainedPrepare(q.Claim.Record.Effect.HelperPrepare, record.Gate.Request, q.Claim.Record.ClaimantID)},
		} {
			if c.bad {
				return failure(api.CodeIntegrity, "retained credential request differs from its original preparation ("+c.name+")")
			}
		}
		if err := api.ValidateCredentialProjectionRequest(q, stamp); err != nil {
			return err
		}
	}
	// Earlier receiving records may lack the newly retained request. They
	// remain owned and fenced; absence never authorizes another export.
	if j.State == "receiving" && j.Record == nil && j.Refresh == nil {
		return nil
	}
	if j.Record == nil {
		return failure(api.CodeIntegrity, "credential journal has no retained authority")
	}
	p := j.Record
	q := p.Authority.Request
	if j.Request != nil && !reflect.DeepEqual(*j.Request, q) {
		return failure(api.CodeIntegrity, "credential authority differs from the retained request")
	}
	if !validID(p.Authority.ID) || p.Authority.Generation == 0 || q.Lease != record.Lease || q.Prepared != record.Gate.Prepared || q.Home != record.Storage.Binding.Home || !reflect.DeepEqual(q.Handoff, record.Spec.Handoff) {
		return failure(api.CodeIntegrity, "credential journal changed its exact retained launch")
	}
	stamp, err := time.Parse(time.RFC3339Nano, string(record.IssuedAt))
	if err != nil {
		return failure(api.CodeIntegrity, "credential ownership has no retained issue time")
	}
	if err := api.ValidateCredentialProjectionRequest(q, stamp); err != nil {
		return err
	}
	targets, err := api.CredentialTargets(q, stamp)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(targets, p.Authority.Targets) || len(p.Authority.Sources) != len(targets) {
		return failure(api.CodeIntegrity, "credential journal changed its selected sources")
	}
	for i, target := range targets {
		source := p.Authority.Sources[i]
		if source.Key != target.Key || source.Generation == 0 || source.Version == "" || source.Revoked || target.SlotID == "" && source.Version != target.Version {
			return failure(api.CodeIntegrity, "credential journal changed its source inventory")
		}
	}
	if p.Receipt != nil {
		r := p.Receipt
		if r.ProjectionID != p.Authority.ID || r.Generation != p.Authority.Generation+1 || r.Prepared != q.Prepared || r.HelperLeaseID != q.Lease.ID || r.SpecSHA256 != q.Handoff.SpecSHA256 || r.Home != q.Home || r.CancellationEpoch != q.Cause.CancellationEpoch || !r.GateClosed || r.HeldDescriptors == nil || *r.HeldDescriptors != uint64(len(targets)) || r.InheritedSources == nil || *r.InheritedSources != 0 || len(r.Targets) != len(targets) {
			return failure(api.CodeIntegrity, "credential receipt changed its exact native holding")
		}
		objects := map[string]bool{}
		for i, target := range targets {
			held := r.Targets[i]
			if held.Target != target || held.SourceObjectID == "" || held.ObjectID == "" || held.SourceObjectID == held.ObjectID || objects[held.ObjectID] || held.RootID != q.Home.RootID || held.HomeGeneration != q.Home.Generation || held.WritableByOthers || target.Delivery == "file" && (held.Links != 1 || held.OwnerUID != q.Lease.UID || held.Mode != target.FileMode) || target.FileMode == 0400 && (!held.ReadOnlyView || held.ParentMode != 0500) || target.FileMode == 0600 && held.ParentMode != 0700 || target.SlotID != "" && target.Delivery == "file" && target.EnvironmentName != "" && !held.ReadOnlyView || target.Delivery == "env" && (held.OwnerUID != 0 || held.Mode != 0600 || held.ParentMode != 0700 || held.Links != 0) {
				return failure(api.CodeIntegrity, "credential receipt changed a retained destination")
			}
			objects[held.ObjectID] = true
		}
	}
	if j.Refresh != nil {
		runner := q.Handoff.Spec.Runner
		if p.Fence == nil || p.Fence.Reason != "release" || runner == nil || runner.Slot.Mode != "codex-file" || j.Refresh.Key != runner.Slot.ID || j.Refresh.Revoked || j.Refresh.Generation == 0 || j.Refresh.Version == "" {
			return failure(api.CodeIntegrity, "credential journal changed its refresh acknowledgement")
		}
	}
	if j.State == "receiving" && p.State == "reserved" && p.Generation == p.Authority.Generation && p.Fence == nil && p.Withdrawal == nil && j.Refresh == nil {
		return nil
	}
	if j.State == "held" && p.State == "held" && p.Generation == p.Authority.Generation+1 && p.Receipt != nil && p.Fence == nil && p.Withdrawal == nil && j.Refresh == nil {
		return nil
	}
	if p.PriorFence != nil {
		base := *p
		base.State, base.Generation, base.Fence, base.PriorFence, base.Withdrawal, base.Revoked = "reserved", p.Authority.Generation, nil, nil, nil, false
		if p.Receipt != nil {
			base.State, base.Generation = "held", base.Generation+1
		}
		if api.ValidateCredentialWithdrawalRequest(base, *p.PriorFence) != nil {
			return failure(api.CodeIntegrity, "credential escalation lost its first fence")
		}
		base.State, base.Generation, base.Fence = "withdrawing", base.Generation+1, p.PriorFence
		if !p.Revoked || p.Fence == nil || api.ValidateCredentialWithdrawalRequest(base, *p.Fence) != nil {
			return failure(api.CodeIntegrity, "credential escalation lost its revocation")
		}
	}
	if j.State == "withdrawing" && p.State == "withdrawing" && p.Fence != nil && p.Fence.ProjectionID == p.Authority.ID && p.Fence.ExpectedGeneration+1 == p.Generation && p.Withdrawal == nil {
		return nil
	}
	if j.State == "withdrawn" && p.State == "withdrawn" && p.Withdrawal != nil && p.Fence != nil {
		fenced := *p
		fenced.State = "withdrawing"
		fenced.Generation--
		fenced.Withdrawal = nil
		return api.ValidateCredentialWithdrawal(fenced, *p.Withdrawal)
	}
	return failure(api.CodeIntegrity, "credential journal has an invalid ownership transition")
}

func credentialRecoveryTransition(before, after *credentialJournal) error {
	if reflect.DeepEqual(before, after) {
		return nil
	}
	if credentialStopTransition(before, after) {
		return nil
	}
	if before == nil || after == nil || before.Record == nil || after.Record == nil || !reflect.DeepEqual(before.Stop, after.Stop) || !reflect.DeepEqual(before.Request, after.Request) || !reflect.DeepEqual(before.Record.Authority, after.Record.Authority) || !reflect.DeepEqual(before.Record.Receipt, after.Record.Receipt) {
		return failure(api.CodeIntegrity, "recovery cannot replace credential ownership")
	}
	if before.Record.Revoked && !after.Record.Revoked {
		return failure(api.CodeIntegrity, "recovery cannot weaken credential revocation")
	}
	// A late stop completes the same normal release, including its acknowledged
	// refresh. Recovery may append that receipt, never replace or remove it.
	if before.State == "withdrawing" && before.Record.Fence != nil && before.Record.Fence.Reason == "release" && before.Stop != nil && before.Stop.Reason == "release" && before.Stop.Note == stopAfterExit && before.Refresh == nil && after.Refresh != nil {
		copy := *before
		copy.Refresh = after.Refresh
		if reflect.DeepEqual(&copy, after) {
			return nil
		}
	}
	if after.State == "withdrawing" && (before.State == "held" || before.State == "receiving") && after.Record.Generation == before.Record.Generation+1 && after.Record.Fence != nil && api.ValidateCredentialWithdrawalRequest(*before.Record, *after.Record.Fence) == nil {
		return nil
	}
	if before.State == "withdrawing" && after.State == "withdrawing" && after.Record.Revoked &&
		after.Record.Generation == before.Record.Generation+1 && after.Record.Fence != nil &&
		reflect.DeepEqual(after.Record.PriorFence, before.Record.Fence) && api.ValidateCredentialWithdrawalRequest(*before.Record, *after.Record.Fence) == nil {
		return nil
	}
	if before.State == "withdrawing" && after.State == "withdrawn" && reflect.DeepEqual(before.Record.Fence, after.Record.Fence) && reflect.DeepEqual(before.Record.PriorFence, after.Record.PriorFence) && after.Record.Generation == before.Record.Generation+1 && after.Record.Withdrawal != nil && api.ValidateCredentialWithdrawal(*before.Record, *after.Record.Withdrawal) == nil {
		return nil
	}
	return failure(api.CodeIntegrity, "recovery cannot restore credential authority")
}

// retainedPrepare reports whether the gate's prepare request is the effect's retained one, where the gate's cause
// may carry the live claimant in place of the effect's author (api.RetainedCause).
func retainedPrepare(retained *api.HelperLaunchRequest, gate api.HelperLaunchRequest, claimant api.ID) bool {
	if retained == nil || !api.RetainedCause(&retained.Cause, gate.Cause, claimant) {
		return false
	}
	want := *retained
	want.Cause = gate.Cause
	return want == gate
}

// retainedAllocate, retainedRelease and retainedAbort are retainedPrepare for the other retained helper requests: the
// live request may differ from the effect's retained one only by its cause carrying the live claimant.
func retainedAllocate(retained *api.HelperLeaseRequest, live api.HelperLeaseRequest, claimant api.ID) bool {
	if retained == nil || !api.RetainedCause(&retained.Cause, live.Cause, claimant) {
		return false
	}
	want := *retained
	want.Cause = live.Cause
	return reflect.DeepEqual(want, live)
}

func retainedRelease(retained *api.HelperReleaseRequest, live api.HelperReleaseRequest, claimant api.ID) bool {
	if retained == nil || !api.RetainedCause(&retained.Cause, live.Cause, claimant) {
		return false
	}
	want := *retained
	want.Cause = live.Cause
	return reflect.DeepEqual(want, live)
}

func retainedAbort(retained *api.HelperAbortRequest, live api.HelperAbortRequest, claimant api.ID) bool {
	if retained == nil || !api.RetainedCause(&retained.Cause, live.Cause, claimant) {
		return false
	}
	want := *retained
	want.Cause = live.Cause
	return want == live
}

// attemptClaimant is the claimant of the explicit attempt the helper envelope carries for effect, or "" without one. A
// native journal replay compares with the retained* functions above: a retry of effect may carry this live claimant
// {service, ClaimantID} in place of the journal's actor, and nothing else may differ.
func attemptClaimant(ctx context.Context, effect api.ID) api.ID {
	attempt, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !api.EffectLeaseClaimed(attempt) || attempt.Record.Effect.ID != effect {
		return ""
	}
	return attempt.Record.ClaimantID
}
