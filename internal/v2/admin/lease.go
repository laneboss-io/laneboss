package admin

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

type leaseRecord struct {
	Claudock          *claudockHomeJournal `json:"claudock_home,omitempty"`
	Judges            []judgeNative        `json:"judges,omitempty"`
	Usages            []usageNative        `json:"usages,omitempty"`
	Reviews           []*archiveJournal    `json:"reviews,omitempty"`
	archivalOwner     *archiveJournal
	Channels          []channelNative           `json:"channels,omitempty"`
	Archive           *archiveJournal           `json:"archive,omitempty"`
	ArchiveEpoch      *archivejob.EpochFence    `json:"archive_epoch,omitempty"`
	Cleanup           *cleanupJournal           `json:"cleanup,omitempty"`
	Credentials       *credentialJournal        `json:"credential_projection,omitempty"`
	Revoked           bool                      `json:"revoked,omitempty"`
	DataJobs          []dataJob                 `json:"data_jobs,omitempty"`
	Exports           []exportJournal           `json:"exports,omitempty"`
	Network           *networkJournal           `json:"network,omitempty"`
	Gate              *gateJournal              `json:"gate,omitempty"`
	LaunchAllocations []launchAllocation        `json:"launch_allocations,omitempty"`
	Storage           *launchStorageRecord      `json:"launch_storage,omitempty"`
	Captures          []captureJournal          `json:"captures,omitempty"`
	Abort             *api.HelperAbortRequest   `json:"abort,omitempty"`
	AbortReceipt      *api.AbortReceipt         `json:"abort_receipt,omitempty"`
	Spec              *specRegistration         `json:"spec,omitempty"`
	SpecReceipt       *api.PreparedSpecReceipt  `json:"spec_receipt,omitempty"`
	Allocations       []api.HelperLeaseRequest  `json:"allocations,omitempty"`
	Receipt           *api.ReleaseReceipt       `json:"receipt,omitempty"`
	Release           *api.HelperReleaseRequest `json:"release,omitempty"`
	Schema            string                    `json:"schema"`
	BootID            string                    `json:"boot_id"`
	Request           api.HelperLeaseRequest    `json:"request"`
	Lease             api.HelperLease           `json:"lease"`
	Phase             string                    `json:"phase"`
	IssuedAt          api.Timestamp             `json:"issued_at"`
}

// Storage and kernel operations are separate so a crash retains a reservation
// before any resources are created. Runtime construction uses only Linux OS
// implementations; focused tests inject failures at these boundaries.
type leaseStorage interface {
	Records() ([]leaseRecord, error)
	Save(leaseRecord) error
}

type leaseResources interface {
	Ensure(context.Context, leaseRecord) error
	Quiescent(context.Context, leaseRecord) error
	ObserveRelease(context.Context, leaseRecord) (releaseFacts, error)
	Remove(context.Context, leaseRecord) error
}

type leaseManager struct {
	judgeRelays             map[api.ID]*judgeRelay
	reviewView              bool
	helperMu                sync.Mutex
	storeLock               *os.File
	workerLaunch            interface{ check(context.Context) error }
	operationMu             sync.Mutex
	openWaitMu              sync.Mutex
	openWait                map[api.ID]*gateOpenTransition
	credentials             *credentialRuntime
	credentialBindAttempted bool
	credentialLeaseMu       sync.Mutex
	activeCredentialGuard   api.CredentialGateGuard
	recovery                *journalRecovery
	prompts                 map[api.ID]*runnerPrompt
	dataPins                map[api.ID]*dataPins
	dataOpenMu              sync.Mutex
	networkMu               sync.Mutex
	networks                map[api.ID]*namespaceOwner
	exports                 map[api.ID]map[api.ID]*registeredExport
	networkResolver         egressResolver
	exportResolver          exportResolver
	gates                   map[api.ID]ownedGate
	captures                map[api.ID]ownedCapture
	binding                 installation
	bootID                  string
	store                   leaseStorage
	resources               leaseResources
	containmentSnapshot     *containmentRecordSnapshot
}

type gateOpenTransition struct {
	done     chan struct{}
	released api.PreparedLaunch
}

// beginGateOpenWait owns the pending open attempt until its durable transition
// completes or fails. Its successful native release is a separate comparison
// for authentication; it never substitutes for the credential exec proof.
func (m *leaseManager) beginGateOpenWait(id api.ID) func() {
	m.openWaitMu.Lock()
	if m.openWait == nil {
		m.openWait = make(map[api.ID]*gateOpenTransition)
	}
	transition := &gateOpenTransition{done: make(chan struct{})}
	m.openWait[id] = transition
	m.openWaitMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.openWaitMu.Lock()
			if m.openWait[id] == transition {
				delete(m.openWait, id)
			}
			close(transition.done)
			m.openWaitMu.Unlock()
		})
	}
}

// Only openGate calls this, after the one-use native release succeeds and
// before lending operationMu for the exec wait. The identity is process-local:
// a helper restart or a failed open cannot reconstruct release from a journal.
// Its transition cannot disappear while this open attempt owns helperMu.
func (m *leaseManager) recordGateRelease(record leaseRecord) error {
	m.openWaitMu.Lock()
	defer m.openWaitMu.Unlock()
	transition := m.openWait[record.Lease.ID]
	if transition == nil || record.Gate == nil || record.Gate.State != "opening" || record.Gate.Permit == nil || record.Gate.Open == nil {
		return failure(api.CodeContainmentUnknown, "native release has no live committed gate transition")
	}
	transition.released = record.Gate.Prepared
	return nil
}

// This predicate is used only by containment authentication. Every query still
// checks the current helper journal generation and pins the real cgroup. The
// service verifies the connecting peer's UID, pidfd, generation and membership.
func (m *leaseManager) releasedForAuthentication(ctx context.Context, record leaseRecord) bool {
	if record.Revoked || record.Gate == nil || record.Gate.State != "opening" || record.Gate.Permit == nil || record.Gate.Open == nil {
		return false
	}
	live := m.gates[record.Lease.ID]
	if live == nil || live.PID() != record.Gate.PID || live.Generation() != record.Gate.Prepared.ProcessGeneration {
		return false
	}
	wait := time.Now()
	m.openWaitMu.Lock()
	acquired := time.Now()
	defer func() {
		hold := time.Since(acquired)
		m.openWaitMu.Unlock()
		helperLockTiming(ctx, "open_wait_mu", acquired.Sub(wait), hold)
	}()
	transition := m.openWait[record.Lease.ID]
	return transition != nil && transition.released == record.Gate.Prepared
}

func (m *leaseManager) gateOpenNotifier(ctx context.Context, id api.ID) <-chan struct{} {
	wait := time.Now()
	m.openWaitMu.Lock()
	acquired := time.Now()
	defer func() {
		hold := time.Since(acquired)
		m.openWaitMu.Unlock()
		helperLockTiming(ctx, "open_wait_mu", acquired.Sub(wait), hold)
	}()
	if transition := m.openWait[id]; transition != nil {
		return transition.done
	}
	return nil
}

func (m *leaseManager) waitForGateOpen(ctx context.Context, channel <-chan struct{}) error {
	if channel == nil {
		return failure(api.CodeContainmentUnknown, "opening gate has no live transition owner")
	}
	select {
	case <-channel:
		return nil
	case <-ctx.Done():
		return contextError(ctx)
	}
}

// One pointer owns the locks and all live native state for a helper process.
// Service reconnects keep that pointer. A new helper constructs a fresh owner
// over the retained journal; it cannot reconstruct descriptors from its DTOs.
func newLeaseManager(binding installation, bootID string, store leaseStorage, resources leaseResources) *leaseManager {
	return &leaseManager{binding: binding, bootID: bootID, store: store, resources: resources}
}

func (m *leaseManager) records() (_ []leaseRecord, resultErr error) {
	return m.recordsContext(context.Background())
}

func (m *leaseManager) recordsContext(ctx context.Context) (_ []leaseRecord, resultErr error) {
	defer helperCheck(&resultErr, "lease_records")
	if m.recovery != nil {
		return m.recoveryRecords()
	}
	finishRead := helperStage(ctx, "journal_read")
	records, err := m.store.Records()
	finishRead()
	if err != nil {
		return nil, err
	}
	defer helperStage(ctx, "journal_validate")()
	return m.validateRecords(records)
}

func (m *leaseManager) validateRecords(records []leaseRecord) (_ []leaseRecord, resultErr error) {
	check := "lease_archive"
	defer func() { helperCheck(&resultErr, check) }()
	if !m.reviewView {
		if err := validateReviewOwners(records, m.binding); err != nil {
			return nil, err
		}
	}
	if err := validateArchiveOwners(records, m.binding); err != nil {
		return nil, err
	}
	if err := validateChannelOwners(records, m.binding); err != nil {
		return nil, err
	}
	if err := validateJudgeOwners(records, m.binding); err != nil {
		return nil, err
	}
	if err := validateUsageOwners(records, m.binding); err != nil {
		return nil, err
	}
	projections := map[api.ID]bool{}
	for _, record := range records {
		check = "lease_archive_epoch"
		if err := validateArchiveEpoch(record); err != nil {
			return nil, err
		}
		check = "lease_claudock_home"
		if err := validateClaudockHomeJournal(record, m.binding); err != nil {
			return nil, err
		}
		check = "lease_capture_drain"
		if err := validateCaptureDrainJournal(record); err != nil {
			return nil, err
		}
		check = "lease_cleanup"
		if err := validateCleanupRecord(record); err != nil {
			return nil, err
		}
		check = "lease_credentials"
		if err := validateCredentialJournal(record); err != nil {
			return nil, err
		}
		if record.Credentials != nil && record.Credentials.Record != nil {
			check = "lease_projection_alias"
			id := record.Credentials.Record.Authority.ID
			if projections[id] {
				return nil, failure(api.CodeIntegrity, "credential projection aliases another lease")
			}
			projections[id] = true
		}
		check = "lease_network"
		if err := validateNetworkJournal(record); err != nil {
			return nil, err
		}
		check = "lease_exports"
		if err := validateExportJournals(record); err != nil {
			return nil, err
		}
		check = "lease_gate"
		if err := validateGateJournal(record); err != nil {
			return nil, err
		}
		check = "lease_launch"
		if err := validateLaunchJournal(record); err != nil {
			return nil, err
		}
		check = "lease_identity"
		if record.Schema != "laneboss.helper-lease.v2" ||
			record.BootID == "" ||
			validateAllocation(record.Request, m.binding.Config) != nil ||
			validateLease(record.Lease, m.binding) != nil {
			return nil, failure(api.CodeIntegrity, "invalid, duplicate or prior-boot helper lease; retain it for administrator recovery")
		}
		check = "lease_phase"
		if record.Phase != "reserved" && record.Phase != "active" && record.Phase != "releasing" && record.Phase != "released" && record.Phase != "aborting" && record.Phase != "aborted" {
			return nil, failure(api.CodeIntegrity, "unknown helper lease phase")
		}
		aborting := record.Phase == "aborting" || record.Phase == "aborted"
		check = "lease_abort_state"
		if aborting != (record.Abort != nil && record.AbortReceipt != nil) || (record.Abort == nil) != (record.AbortReceipt == nil) {
			return nil, failure(api.CodeIntegrity, "incomplete nonexecuting abort state")
		}
		check = "lease_abort_receipt"
		if record.AbortReceipt != nil && (validateAbort(*record.Abort, m.binding.Config) != nil || validateAbortReceipt(record, *record.Abort, *record.AbortReceipt) != nil) {
			return nil, failure(api.CodeIntegrity, "invalid nonexecuting abort receipt")
		}
		effects := map[api.ID]bool{record.Request.Cause.EffectID: true}
		check = "lease_allocation_history"
		for _, allocation := range record.Allocations {
			if validateAllocation(allocation, m.binding.Config) != nil || !sameLeasePolicy(allocation, record.Request) || effects[allocation.Cause.EffectID] {
				return nil, failure(api.CodeIntegrity, "invalid helper life allocation history")
			}
			effects[allocation.Cause.EffectID] = true
		}
		check = "lease_spec_state"
		if (record.Spec == nil) != (record.SpecReceipt == nil) {
			return nil, failure(api.CodeIntegrity, "incomplete registered helper spec")
		}
		if record.Spec != nil {
			check = "lease_spec"
			if validateSpecEnvelope(*record.Spec, m.binding.Config) != nil || record.Spec.Handoff.Spec.UIDLeaseID != record.Lease.ID ||
				record.SpecReceipt.LeaseID != record.Lease.ID || record.SpecReceipt.SpecID != record.Spec.Handoff.Spec.ID ||
				record.SpecReceipt.SpecSHA256 != record.Spec.Handoff.SpecSHA256 {
				return nil, failure(api.CodeIntegrity, "registered helper spec or receipt differs")
			}
		}
		collecting := record.Phase == "releasing" || record.Phase == "released"
		check = "lease_release_state"
		if collecting != (record.Release != nil) {
			return nil, failure(api.CodeIntegrity, "helper lease phase and release receipt differ")
		}
		check = "lease_receipt_state"
		if collecting != (record.Receipt != nil) {
			return nil, failure(api.CodeIntegrity, "helper release phase has no measured receipt")
		}
		check = "lease_release"
		if record.Release != nil && (record.Release.LeaseID != record.Lease.ID ||
			validateRelease(*record.Release, m.binding.Config) != nil ||
			validateObservation(record, record.Release.Observation) != nil) {
			return nil, failure(api.CodeIntegrity, "helper release receipt has invalid causal or observation facts")
		}
		check = "lease_receipt"
		if record.Receipt != nil && validateReceipt(record, *record.Release, *record.Receipt) != nil {
			return nil, failure(api.CodeIntegrity, "persisted helper measurement is invalid")
		}
	}
	check = "lease_data_identity"
	if err := validateDataIdentities(records); err != nil {
		return nil, err
	}
	for _, record := range records {
		check = "lease_data_job"
		for _, job := range record.DataJobs {
			if err := validateDataJob(record, job, m.binding); err != nil {
				return nil, err
			}
		}
		for _, capture := range record.Captures {
			check = "lease_capture_identity"
			if capture.Native == nil {
				continue
			}
			lease := capture.Native.Lease
			if validateLease(lease, m.binding) != nil || lease.ID != capture.Native.BindingID || lease.UID == record.Lease.UID ||
				lease.ContainmentID == record.Lease.ContainmentID {
				return nil, failure(api.CodeIntegrity, "outside capture UID or containment overlaps another live owner")
			}
		}
	}
	return records, nil
}

func (m *leaseManager) allocate(ctx context.Context, request api.HelperLeaseRequest) (_ api.HelperLease, resultErr error) {
	defer helperCheck(&resultErr, "lease_allocation")
	if err := contextError(ctx); err != nil {
		return api.HelperLease{}, err
	}
	if err := validateAllocation(request, m.binding.Config); err != nil {
		return api.HelperLease{}, err
	}
	records, err := m.records()
	if err != nil {
		return api.HelperLease{}, err
	}
	used := map[uint32]bool{}
	reserveArchiveUIDs(records, used)
	for _, record := range records {
		if record.Request.LifeID == request.LifeID {
			if record.BootID != m.bootID {
				return api.HelperLease{}, failure(api.CodeContainmentUnknown, "prior-boot lease requires measured reconciliation or nonexecuting abort")
			}
			if record.Phase == "released" || record.Phase == "releasing" || record.Phase == "aborting" || record.Phase == "aborted" {
				return api.HelperLease{}, failure(api.CodeConflict, "a collected or collecting life cannot reacquire its helper lease")
			}
			if err := m.requireAllocation(record); err != nil {
				return api.HelperLease{}, err
			}
			if record.Request.Cause.EffectID == request.Cause.EffectID {
				if !reflect.DeepEqual(record.Request, request) {
					return api.HelperLease{}, failure(api.CodeIdempotencyConflict, "helper life allocation was retried with changed input")
				}
				return m.activate(ctx, record)
			}
			for _, previous := range record.Allocations {
				if previous.Cause.EffectID == request.Cause.EffectID {
					if !reflect.DeepEqual(previous, request) {
						return api.HelperLease{}, failure(api.CodeIdempotencyConflict, "changed helper allocation replay")
					}
					return m.activate(ctx, record)
				}
			}
			if !sameLeasePolicy(record.Request, request) {
				return api.HelperLease{}, failure(api.CodeConflict, "a life lease cannot silently change its runtime or resource envelope")
			}
			record.Allocations = append(record.Allocations, request)
			if err := m.save(record); err != nil {
				return api.HelperLease{}, err
			}
			return m.activate(ctx, record)
		}
		if record.Phase != "released" && record.Phase != "aborted" {
			used[record.Lease.UID] = true
		}
		for _, capture := range record.Captures {
			if captureReservesUID(capture) {
				used[capture.Native.Lease.UID] = true
			}
		}
		for _, job := range record.DataJobs {
			if job.State != "collected" {
				used[job.Lease.UID] = true
			}
		}
	}
	for _, account := range m.binding.Lanes {
		if used[account.UID] {
			continue
		}
		id, err := randomID("lease-")
		if err != nil {
			return api.HelperLease{}, err
		}
		containment, err := randomID("cg-")
		if err != nil {
			return api.HelperLease{}, err
		}
		record := leaseRecord{
			Schema: "laneboss.helper-lease.v2", BootID: m.bootID, Request: request,
			Lease: api.HelperLease{ID: id, UID: account.UID, GID: account.GID,
				ContainmentID: containment, EndpointGeneration: m.binding.Generation},
			Phase: "reserved", IssuedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)),
		}
		if err := m.save(record); err != nil {
			return api.HelperLease{}, err
		}
		return m.activate(ctx, record)
	}
	return api.HelperLease{}, failure(api.CodeUnavailable, "the installed lane UID pool has no free account")
}

func sameLeasePolicy(left, right api.HelperLeaseRequest) bool {
	left.Cause, right.Cause = api.InternalIntent{}, api.InternalIntent{}
	left.ReservationID, right.ReservationID = "", ""
	return reflect.DeepEqual(left, right)
}

func (m *leaseManager) activate(ctx context.Context, record leaseRecord) (_ api.HelperLease, resultErr error) {
	defer helperCheck(&resultErr, "lease_activation")
	if err := m.requireAllocation(record); err != nil {
		return api.HelperLease{}, err
	}
	if record.Revoked {
		return api.HelperLease{}, failure(api.CodeForbidden, "revoked helper allocation cannot reactivate")
	}
	if err := m.resources.Ensure(ctx, record); err != nil {
		return api.HelperLease{}, err
	}
	if record.Phase != "active" {
		record.Phase = "active"
		if err := m.save(record); err != nil {
			return api.HelperLease{}, err
		}
	}
	return record.Lease, nil
}

func (m *leaseManager) find(id api.ID) (leaseRecord, error) {
	records, err := m.records()
	if err != nil {
		return leaseRecord{}, err
	}
	for _, record := range records {
		if record.Lease.ID == id {
			return record, nil
		}
	}
	return leaseRecord{}, failure(api.CodeNotFound, "unknown helper lease")
}

func (m *leaseManager) prepare(ctx context.Context, request api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	if err := contextError(ctx); err != nil {
		return api.PreparedLaunch{}, err
	}
	return m.prepareGate(ctx, request)
}

func validateObservation(record leaseRecord, observation api.ProcessObservation) error {
	if observation.Handle.ContainmentID != record.Lease.ContainmentID ||
		observation.Handle.Target.LifeID != record.Request.LifeID ||
		observation.Handle.Target.Run == 0 || observation.Handle.Target.Run > 1<<53-1 || !validID(observation.Handle.ID) ||
		observation.Handle.Generation == "" || observation.Survivors == nil || *observation.Survivors != 0 ||
		observation.State != "exited" {
		return failure(api.CodeContainmentUnknown, "release requires a matching terminal observation with explicit zero survivors")
	}
	stamp, err := time.Parse(time.RFC3339Nano, string(observation.ObservedAt))
	issued, issuedErr := time.Parse(time.RFC3339Nano, string(record.IssuedAt))
	if err != nil || issuedErr != nil || !strings.HasSuffix(string(observation.ObservedAt), "Z") ||
		stamp.IsZero() || stamp.Before(issued) || stamp.After(time.Now().UTC().Add(time.Second)) {
		return failure(api.CodeInvalid, "release observation requires a valid UTC timestamp")
	}
	if (observation.ExitCode == nil) == (observation.Signal == nil) {
		return failure(api.CodeContainmentUnknown, "release observation has no actual exit or signal")
	}
	if observation.ExitCode != nil && (int64(*observation.ExitCode) < -1<<31 || int64(*observation.ExitCode) > 1<<31-1) ||
		observation.Signal != nil && (*observation.Signal <= 0 || *observation.Signal > 64) {
		return failure(api.CodeInvalid, "release observation exit or signal is out of range")
	}
	switch observation.PromptStatus {
	case "not_written", "written", "cut", "unknown", "completed":
	default:
		return failure(api.CodeInvalid, "release observation prompt status is invalid")
	}
	return nil
}

func (m *leaseManager) release(ctx context.Context, request api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	if err := contextError(ctx); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := validateRelease(request, m.binding.Config); err != nil {
		return api.ReleaseReceipt{}, err
	}
	record, err := m.find(request.LeaseID)
	if err != nil {
		return api.ReleaseReceipt{}, err
	}
	if record.Phase != "active" && record.Phase != "releasing" && record.Phase != "released" {
		return api.ReleaseReceipt{}, failure(api.CodeConflict, "release cannot replace a nonexecuting abort")
	}
	if err := validateObservation(record, request.Observation); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if record.Release != nil && !retainedRelease(record.Release, request, attemptClaimant(ctx, request.Cause.EffectID)) {
		return api.ReleaseReceipt{}, failure(api.CodeIdempotencyConflict, "helper release was retried with changed cause or observation")
	}
	if err := m.commitExitForRelease(ctx, &record, request.Observation); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := m.withdrawProjection(ctx, &record, request.Cause, "release"); err != nil {
		return api.ReleaseReceipt{}, err
	}
	// Recheck independent containment even for an identical completed replay.
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	facts, err := m.resources.ObserveRelease(ctx, record)
	if err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := compareRelease(record, request.Observation, facts); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if record.Gate != nil {
		record.Gate.Observation = &facts.Observation
		record.Gate.State = "ended"
	}
	if record.Phase == "released" {
		return *record.Receipt, nil
	}
	if record.Receipt == nil {
		id, err := randomID("release-")
		if err != nil {
			return api.ReleaseReceipt{}, err
		}
		record.Receipt = &api.ReleaseReceipt{ID: id, LeaseID: record.Lease.ID, ContainmentID: record.Lease.ContainmentID,
			Backend: record.Request.Backend, OperationID: request.Cause.CauseOperationID, EffectID: request.Cause.EffectID,
			Quiescence: facts.Observation, LiveConnections: facts.LiveConnections, QueuedJobs: facts.QueuedJobs,
			WritableExports: facts.WritableExports, ObservedAt: facts.Observation.ObservedAt}
	}
	record.Phase, record.Release = "releasing", &request
	if err := m.save(record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := m.retainPrivateStorage(ctx, &record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := m.collectNetwork(ctx, &record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	if err := m.resources.Remove(ctx, record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	record.Phase = "released"
	if err := m.save(record); err != nil {
		return api.ReleaseReceipt{}, err
	}
	return *record.Receipt, nil
}

func (m *leaseManager) dispatch(ctx context.Context, method string, params json.RawMessage) (_ any, resultErr error) {
	defer func() {
		check := "operation"
		if frame, _ := api.JSONFailureFacts(resultErr); frame != "" {
			check = "operation_input"
		}
		helperCheck(&resultErr, check)
	}()
	switch method {
	case "claudock_bootstrap", "claudock_home":
		var request claudockNativePlanning
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.claudockPlanning(ctx, method, request)
	case "org_render":
		var stage orgrender.Stage
		if err := decodeStrict(params, &stage); err != nil {
			return nil, err
		}
		return m.renderOrg(ctx, stage)
	case "credential_peer_verify":
		var query CredentialPeerVerification
		if err := decodeStrict(params, &query); err != nil {
			return nil, err
		}
		return m.verifyCredentialNativePeer(ctx, query)
	case "credential_withdrawal_observe":
		var record api.CredentialProjectionRecord
		if err := decodeStrict(params, &record); err != nil {
			return nil, err
		}
		return m.credentialWithdrawalObservation(ctx, record)
	case "credential_projection_source":
		var query credentialSourceQuery
		if err := decodeStrict(params, &query); err != nil {
			return nil, err
		}
		return m.credentialSource(ctx, query)
	case "credential_projection_observe":
		var authority api.CredentialProjectionAuthority
		if err := decodeStrict(params, &authority); err != nil {
			return nil, err
		}
		return m.credentialObservation(ctx, authority)
	case "credential_projection_observe_id":
		var q struct{ ProjectionID api.ID }
		if err := decodeStrict(params, &q); err != nil {
			return nil, err
		}
		if m.credentials == nil {
			return nil, failure(api.CodePrerequisite, "credential native receiver is not bound")
		}
		if err := m.credentials.checkBinding(ctx); err != nil {
			return nil, err
		}
		return m.credentials.observe(ctx, q.ProjectionID)
	case "capture_drain_snapshot", "capture_drain_read", "capture_drain_ack":
		return m.dispatchCaptureDrain(ctx, method, params)
	case "archive_freeze", "archive_check", "archive_bytes":
		return m.dispatchArchiveStorage(ctx, method, params)
	case "judge_lease", "judge_register", "judge_prepare", "judge_open", "judge_observe", "judge_collect":
		return m.dispatchJudge(ctx, method, params)
	case "review_freeze", "review_check", "review_bytes", "review_lease", "review_register", "review_prepare", "review_open", "review_observe", "review_reconcile", "review_retire":
		return m.dispatchReview(ctx, method, params)
	case "channel_lease", "channel_register", "channel_prepare", "channel_reconcile", "channel_collect":
		return m.dispatchChannel(ctx, method, params)
	case "usage_lease", "usage_register", "usage_prepare", "usage_reconcile", "usage_collect", "usage_observe":
		return m.dispatchUsage(ctx, method, params)
	case "archive_lease", "archive_register", "archive_prepare", "archive_open", "archive_observe", "archive_reconcile":
		return m.dispatchArchiveWorker(ctx, method, params)
	case "archive_retire":
		var q archiveRetireQuery
		if err := decodeStrict(params, &q); err != nil {
			return nil, err
		}
		return m.retireArchive(ctx, q)
	case "cleanup_resolve", "cleanup_inspect", "cleanup_remove", "cleanup_journal", "cleanup_read":
		return m.dispatchCleanup(ctx, method, params)
	case "data_open", "data_query", "data_selector", "data_lease", "data_register", "data_prepare", "data_gate", "data_observe", "data_measure", "data_revoke", "data_collect", "data_native":
		return m.dispatchData(ctx, method, params)
	case "resolve_runtime":
		var request api.PreparedSpecHandoff
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.resolvePreparedRuntime(ctx, request)
	case "open_gate":
		var request gateOpenRegistration
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.openCredentialGate(ctx, request)
	case "observe_gate":
		var request api.HelperObserveRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.observeGate(ctx, request)
	case "credential_gate_observe":
		var request api.HelperObserveRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.credentialGateObservation(ctx, request)
	case "stop_gate":
		var request api.HelperStopRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.stopGate(ctx, request)
	case "reconcile_gate":
		var request api.HelperReconcileRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.reconcileGate(ctx, request)
	case "register_capture":
		var request captureRegistration
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.registerCapture(ctx, request)
	case "reconcile_capture":
		var request api.CaptureBinding
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.reconcileCapture(ctx, request)
	case "allocate_launch":
		var request launchAllocation
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.allocateLaunch(ctx, request)
	case "resolve_storage":
		var request launchStorageQuery
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.resolveStorage(ctx, request)
	case "allocate":
		var request api.HelperLeaseRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.allocate(ctx, request)
	case "prepare":
		var request credentialPrepare
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		prepared, err := m.prepare(ctx, request.Request)
		if err != nil {
			return nil, err
		}
		if err := m.prepareCredentials(ctx, request, prepared); err != nil {
			return nil, err
		}
		return prepared, nil
	case "credential_bind":
		var empty api.Empty
		if err := decodeStrict(params, &empty); err != nil {
			return nil, err
		}
		return m.bindCredentials(ctx), nil
	case "credential_binding":
		var empty api.Empty
		if err := decodeStrict(params, &empty); err != nil {
			return nil, err
		}
		return m.credentialBinding(ctx), nil
	case "register_spec":
		var request specRegistration
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.registerSpec(ctx, request)
	case "abort":
		var request api.HelperAbortRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.abort(ctx, request)
	case "plan_cleanup_native_read":
		var effect api.Effect
		if err := decodeStrict(params, &effect); err != nil {
			return nil, err
		}
		return m.readPlanCleanupNative(ctx, effect)
	case "containment", "containment_live":
		var request containmentQuery
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		if method == "containment_live" && !request.Opened {
			return nil, failure(api.CodeForbidden, "live containment metadata requires an opened gate")
		}
		return m.containment(ctx, request)
	case "containment_revoke":
		var request struct {
			ID api.ID `json:"id"`
		}
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.revokeNativeContainment(ctx, request.ID)
	case "release":
		var request api.HelperReleaseRequest
		if err := decodeStrict(params, &request); err != nil {
			return nil, err
		}
		return m.release(ctx, request)
	default:
		return nil, failure(api.CodeForbidden, "unknown helper operation; arbitrary root commands are not supported")
	}
}
