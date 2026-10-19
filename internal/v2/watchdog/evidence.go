package watchdog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

const (
	maxCaptureBytes = int64(16 * 1024 * 1024)
	maxRoomBytes    = int64(1024 * 1024)
	maxRoomAge      = time.Minute
	maxEventPages   = 512
	maxRunEvents    = 100000
)

// assessment is planning data, not a receipt or launch authority. Fresh work
// may first advance the live policy projection through its protected store CAS.
// Swap=nil means checked eligible room was exhausted, not a committed wait.
type assessment struct {
	Signal      api.LimitSignal
	Lane        api.Lane
	Grants      api.GrantSet
	Cause       api.Event
	Quiescence  api.ProcessObservation
	Rooms       []api.Room
	Eligibility *api.ProfileEligibility
	Swap        *api.ProfileSwap
}

func (s *Service) assess(ctx context.Context, signal api.LimitSignal) (assessment, error) {
	return s.assessFresh(ctx, signal, false)
}

func (s *Service) assessFresh(ctx context.Context, signal api.LimitSignal, refreshUsage bool) (assessment, error) {
	result := assessment{Signal: signal}
	if err := checkSignal(signal); err != nil {
		return result, err
	}
	lane, err := s.currentLane(ctx, signal.Target)
	if err != nil {
		return result, err
	}
	if err := eligibleLane(lane, signal.Target); err != nil {
		return result, err
	}
	events, err := s.events(ctx, lane.LifeID)
	if err != nil {
		return result, err
	}
	run, err := runEvidence(events, signal, lane.LogicalTurnID)
	if err != nil {
		return result, err
	}
	result.Lane = lane
	if err := s.liveTurn(ctx, lane, signal.Target); err != nil {
		return result, err
	}
	result.Cause = run.cause
	launch, err := s.deps.Store.Launch(ctx, run.launchID)
	if err != nil {
		return result, err
	}
	if launch.Config != s.deps.Config || launch.Target != signal.Target ||
		launch.ID != run.launchID || launch.ID != lane.LaunchID || launch.Revoked || launch.GrantSetID != lane.GrantSetID ||
		launch.ContainmentID != run.handle.ContainmentID ||
		launch.ProcessGeneration != run.handle.Generation ||
		launch.PolicyGeneration > lane.PolicyGeneration {
		return result, problem(api.CodeIntegrity, "process observation does not match its bound launch")
	}
	captureBinding, err := s.launchContext(ctx, lane, launch)
	if err != nil {
		return result, err
	}
	for _, capture := range run.captures {
		if capture.BindingID != captureBinding.ID {
			return result, problem(api.CodeIntegrity, "live capture has no matching registered binding")
		}
	}
	observeStarted := s.deps.Clock.Now()
	observation, err := s.deps.Launcher.Observe(ctx, run.handle)
	if err != nil {
		return result, err
	}
	observationNow := s.deps.Clock.Now()
	if observationNow.Before(observeStarted) {
		return result, problem(api.CodeIntegrity, "clock moved backwards during process observation")
	}
	if err := quiescent(observation, run.handle, signal, observationNow); err != nil {
		return result, err
	}
	result.Quiescence = observation
	if err := s.verifyCapture(ctx, run.captures, signal, observation); err != nil {
		return result, err
	}
	grants, err := s.deps.Store.Grants(ctx, lane.GrantSetID)
	if err != nil {
		return result, err
	}
	if err := currentGrants(grants, lane, launch, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	checked, err := s.deps.Grants.Revalidate(ctx, grants)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(checked, grants) {
		return result, problem(api.CodeConflict, "effective grants changed during watchdog assessment")
	}
	result.Grants = grants
	policy, err := s.policyForLane(ctx, lane)
	if err != nil {
		return result, err
	}
	if policy.Generation != lane.PolicyGeneration {
		if err := s.liveTurnAtPolicy(ctx, lane, signal.Target, policy.Generation); err != nil {
			return result, err
		}
	}
	active, err := activeProfile(grants, lane, signal, s.deps.Clock.Now())
	if err != nil {
		return result, err
	}
	room, err := s.room(ctx, active)
	if err != nil {
		return result, err
	}
	result.Rooms = append(result.Rooms, room)
	if room.Available {
		return result, problem(api.CodeConflict, "outside usage does not corroborate exhausted current profile")
	}
	usage, err := s.usageEvidence(ctx, signal, lane, run.cause.OperationID, observation, refreshUsage)
	if err != nil {
		return result, err
	}
	result.Signal.UsageEvidence = &usage
	// Retain delegation order. Do not discover logins, widen scope or switch
	// provider/driver. Paid profiles must already be granted and budgeted;
	// draft.4 also forbids a free-to-paid automatic transition.
	for _, grant := range grants.Profiles {
		if grant.ProfileID == active.ProfileID || grant.Driver != active.Driver ||
			grant.Provider != active.Provider || (grant.Paid && !active.Paid) || excluded(policy, grant.ProfileID) {
			continue
		}
		expires, err := timestamp(grant.ExpiresAt)
		if err != nil {
			return result, err
		}
		if !expires.After(s.deps.Clock.Now()) || (grant.Paid && lane.BudgetRemaining.SpendMicros <= 0) {
			continue
		}
		room, err := s.room(ctx, grant)
		if err != nil {
			// A worker failure is not exhausted room or permission to fall back.
			return result, err
		}
		result.Rooms = append(result.Rooms, room)
		if room.Available {
			request := api.ProfileEligibilityRequest{
				Target: signal.Target, GrantSetID: grants.ID, FromGrantID: active.ID, ToGrantID: grant.ID,
				Driver: lane.Session.Driver, Model: lane.Model, Session: lane.Session, HistoryID: lane.Session.HistoryID,
			}
			eligibility, err := s.deps.Credentials.Eligibility(ctx, request)
			if err != nil {
				return result, err
			}
			if err := validateEligibility(eligibility, request, s.deps.Clock.Now()); err != nil {
				return result, err
			}
			if _, err := s.blob(ctx, eligibility.Evidence, maxRoomBytes); err != nil {
				return result, err
			}
			if err := validateEligibility(eligibility, request, s.deps.Clock.Now()); err != nil {
				return result, err
			}
			if !eligibility.Compatible {
				continue
			}
			result.Eligibility = &eligibility
			result.Swap = &api.ProfileSwap{
				ProfileGrantID: grant.ID, EligibilityID: eligibility.ID,
				ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch,
				FromProfileID: active.ProfileID, ToProfileID: grant.ProfileID,
				CausingRun: lane.Run, ContinuationRun: lane.Run + 1,
				LogicalTurnID: lane.LogicalTurnID, Limit: result.Signal, Room: room,
			}
			// The store stamps the real operation when this plan is committed.
			break
		}
	}
	// No life write is justified by a quoted, uncorroborated or failed limit.
	// Advance policy only after the outside limit/room/usage checks succeeded,
	// pinning the policy used for this selection before taking new fences.
	lane, err = s.freshPolicy(ctx, lane, policy)
	if err != nil {
		return result, err
	}
	result.Lane = lane
	if result.Swap != nil {
		result.Swap.ExpectedGeneration = lane.Generation
	}
	current, err := s.currentLane(ctx, signal.Target)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(current, lane) {
		return result, problem(api.CodeConflict, "life changed during watchdog assessment")
	}
	// Dependency calls may advance the clock. A receipt issued after a call
	// began is not future evidence, and a receipt/grant that expired during
	// later reads must not escape as an eligible proposal.
	currentPolicy, err := s.policyForLane(ctx, lane)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(currentPolicy, policy) {
		return result, problem(api.CodeConflict, "profile exclusions changed during assessment")
	}
	now := s.deps.Clock.Now()
	if err := currentGrants(grants, lane, launch, now); err != nil {
		return result, err
	}
	if err := profileLive(active, now); err != nil {
		return result, err
	}
	if result.Swap != nil {
		for _, grant := range grants.Profiles {
			if grant.ID == result.Swap.ProfileGrantID {
				if err := profileLive(grant, now); err != nil {
					return result, err
				}
				if err := validateRoom(result.Swap.Room, grant, now); err != nil {
					return result, err
				}
			}
		}
	}
	if result.Eligibility != nil {
		if err := validateEligibility(*result.Eligibility, result.Eligibility.Request, now); err != nil {
			return result, err
		}
	}
	if _, err := s.usageEvidence(ctx, result.Signal, lane, run.cause.OperationID, observation, false); err != nil {
		return result, err
	}
	// This final read is useful for stale evidence, but is deliberately not
	// claimed to serialize a later launch with manual control.
	return result, nil
}

func checkSignal(signal api.LimitSignal) error {
	if err := checkTarget(signal.Target); err != nil {
		return err
	}
	if signal.Kind != string(UsageLimit) && signal.Kind != string(SessionLimit) {
		return problem(api.CodeInvalid, "only a validated usage or session limit is eligible")
	}
	if !validID.MatchString(string(signal.ProfileID)) ||
		!validID.MatchString(string(signal.CaptureID)) ||
		!validDigest.MatchString(string(signal.CaptureSHA256)) ||
		signal.Provider == "" || len(signal.Provider) > 128 ||
		signal.AdapterVersion == "" || len(signal.AdapterVersion) > 128 ||
		signal.ExitCode == nil || *signal.ExitCode < 0 || int64(*signal.ExitCode) > 1<<31-1 {
		return problem(api.CodeInvalid, "limit is missing bounded profile, capture, adapter or real exit evidence")
	}
	if signal.UsageEvidence == nil || signal.UsageEvidence.Class != "usage_window" ||
		!validID.MatchString(string(signal.UsageEvidence.ID)) || !validDigest.MatchString(string(signal.UsageEvidence.SHA256)) ||
		signal.UsageEvidence.Bytes <= 0 || signal.UsageEvidence.Bytes > api.MaxFrameBytes {
		return problem(api.CodeInvalid, "limit is missing committed outside usage-window evidence")
	}
	_, err := timestamp(signal.ObservedAt)
	return err
}

func eligibleLane(lane api.Lane, target api.LifeRef) error {
	if lane.LifeID != target.LifeID || lane.Run != target.Run {
		return problem(api.CodeConflict, "limit belongs to a stale life or run")
	}
	if lane.Cleaned {
		return problem(api.CodeCancelled, "cleaned life cannot continue")
	}
	switch lane.State {
	case "running", "verifying", "profile_wait":
	case "stopping", "abandoned", "merged", "accepted":
		return problem(api.CodeCancelled, "life is stopped or closed to automatic continuation")
	default:
		return problem(api.CodeConflict, "life is not eligible for quota continuation")
	}
	if lane.Run >= api.RunNumber(maxExactInteger) || lane.Generation == 0 ||
		uint64(lane.Generation) >= maxExactInteger || uint64(lane.CancellationEpoch) >= maxExactInteger ||
		!validID.MatchString(string(lane.LogicalTurnID)) ||
		lane.Session.Driver != api.DriverClaudock || lane.Session.VendorID == "" ||
		!validID.MatchString(string(lane.Session.ID)) || !validID.MatchString(string(lane.Session.HomeID)) ||
		!validID.MatchString(string(lane.Session.HistoryID)) || lane.Model == "" || len(lane.Model) > 256 ||
		!validID.MatchString(string(lane.Task.ID)) || !validDigest.MatchString(string(lane.Task.SHA256)) || lane.Task.Bytes <= 0 || lane.Task.Class != "task" ||
		lane.Session.LogicalCWD == "" || lane.Session.LogicalCWD != lane.Workspace.LogicalCWD ||
		!validID.MatchString(string(lane.Workspace.ID)) {
		return problem(api.CodeUnsupported, "quota continuation requires the recorded Claudock session and private workspace")
	}
	b := lane.BudgetRemaining
	if b.WallMS <= 0 || b.SpendMicros < 0 || b.MemoryBytes == 0 || b.DiskBytes == 0 || b.Processes == 0 {
		return problem(api.CodeBudget, "remaining quota-continuation budget is exhausted or invalid")
	}
	return nil
}

func currentGrants(grants api.GrantSet, lane api.Lane, launch api.LaunchRecord, now time.Time) error {
	if grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID ||
		grants.SHA256 != launch.GrantsSHA256 || !validDigest.MatchString(string(grants.SHA256)) ||
		grants.PolicyGeneration != launch.PolicyGeneration || grants.PolicyGeneration > lane.PolicyGeneration || grants.Generation == 0 {
		return problem(api.CodeIntegrity, "effective grant receipt does not match the current launch")
	}
	expires, err := timestamp(grants.ExpiresAt)
	if err != nil {
		return err
	}
	if grants.Revoked || !expires.After(now) {
		return problem(api.CodeForbidden, "effective grants are revoked or expired")
	}
	return nil
}

func activeProfile(grants api.GrantSet, lane api.Lane, signal api.LimitSignal, now time.Time) (api.ProfileGrant, error) {
	var active api.ProfileGrant
	ids := map[api.ID]bool{}
	profiles := map[api.ID]bool{}
	for _, grant := range grants.Profiles {
		if !validID.MatchString(string(grant.ID)) || !validID.MatchString(string(grant.ProfileID)) ||
			ids[grant.ID] || profiles[grant.ProfileID] {
			return active, problem(api.CodeIntegrity, "profile delegation is ambiguous or malformed")
		}
		ids[grant.ID], profiles[grant.ProfileID] = true, true
		if grant.ID == lane.ProfileGrantID {
			active = grant
		}
	}
	if active.ID == "" || active.ProfileID != signal.ProfileID ||
		active.Provider != signal.Provider || active.Driver != api.DriverClaudock {
		return active, problem(api.CodeForbidden, "limit profile is not the active delegated Claudock profile")
	}
	expires, err := timestamp(active.ExpiresAt)
	if err != nil {
		return active, err
	}
	if !expires.After(now) {
		return active, problem(api.CodeForbidden, "active profile grant expired")
	}
	return active, nil
}

type observedRun struct {
	launchID api.ID
	cause    api.Event
	handle   api.ProcessHandle
	captures []api.CaptureRecord
}

func runEvidence(events []api.Event, signal api.LimitSignal, turn api.ID) (observedRun, error) {
	var run observedRun
	if err := controlError(events, signal.Target, turn); err != nil {
		return run, err
	}
	for _, event := range events {
		if event.Run != signal.Target.Run || event.Origin != "service" {
			continue
		}
		switch event.Kind {
		case "lane.started", "lane.resumed":
			var payload api.LaunchEvent
			if err := decodePayload(event.Payload, &payload); err != nil {
				return run, err
			}
			if run.launchID != "" && run.launchID != payload.LaunchID {
				return run, problem(api.CodeIntegrity, "run has conflicting launch identities")
			}
			run.launchID = payload.LaunchID
			if !outsideEvent(event, "service", "watchdog", "worker", "scheduler") ||
				!validID.MatchString(string(event.OperationID)) || !validID.MatchString(string(event.RequestID)) ||
				!validID.MatchString(string(event.RequestedBy.ID)) || event.RequestedBy.Kind == "" {
				return run, problem(api.CodeIntegrity, "causing launch has no authentic operation and requester")
			}
			run.cause = event
		case "run.observed":
			if outsideEvent(event, "service", "worker") {
				var observation api.ProcessObservation
				if err := decodePayload(event.Payload, &observation); err != nil {
					return run, err
				}
				if observation.Handle.Target != signal.Target {
					return run, problem(api.CodeIntegrity, "outside observation has a different target")
				}
				run.handle = observation.Handle
			}
		case "lane.ended":
			if !outsideEvent(event, "service", "worker") {
				continue
			}
			var payload api.RunEndEvent
			if err := decodePayload(event.Payload, &payload); err != nil {
				return run, err
			}
			if payload.Reason != "exit" && payload.Reason != "limit" {
				return run, problem(api.CodeCancelled, "run ended for a reason other than a provider quota exit")
			}
			if payload.Observation.Handle.Target != signal.Target ||
				(run.launchID != "" && payload.LaunchID != run.launchID) {
				return run, problem(api.CodeIntegrity, "run end does not match the causing launch")
			}
			run.handle = payload.Observation.Handle
		}
	}
	// Only committed service-origin capture records qualify.
	for _, event := range events {
		if event.Run != signal.Target.Run || !outsideEvent(event, "service", "worker") {
			continue
		}
		switch event.Kind {
		case "capture.gap":
			return run, problem(api.CodeIntegrity, "run capture contains an unresolved gap")
		case "capture.appended", "capture.framed":
			var capture api.CaptureRecord
			if err := decodePayload(event.Payload, &capture); err != nil {
				return run, err
			}
			if capture.Target != signal.Target {
				return run, problem(api.CodeIntegrity, "capture event target does not match the run")
			}
			if capture.ReplacementOf == signal.CaptureID {
				return run, problem(api.CodeIntegrity, "limit capture was replaced")
			}
			if capture.Primary && capture.ReplacementOf == "" && capture.Coverage == "complete" {
				run.captures = append(run.captures, capture)
			}
		}
	}
	if !validID.MatchString(string(run.launchID)) ||
		!validID.MatchString(string(run.handle.ID)) || run.handle.Target != signal.Target ||
		!validID.MatchString(string(run.handle.ContainmentID)) || run.handle.Generation == "" {
		return run, problem(api.CodeIntegrity, "run is missing an authentic launch or outside process handle")
	}
	return run, nil
}

func outsideEvent(event api.Event, kinds ...string) bool {
	if event.Origin != "service" {
		return false
	}
	for _, kind := range kinds {
		if event.Actor.Kind == kind && validID.MatchString(string(event.Actor.ID)) &&
			event.Actor.LifeID == "" && event.Actor.Level == 0 && event.Actor.Role == "" {
			return true
		}
	}
	return false
}

func quiescent(observation api.ProcessObservation, handle api.ProcessHandle, signal api.LimitSignal, now time.Time) error {
	if observation.Handle != handle {
		return problem(api.CodeIntegrity, "launcher observed a different process generation")
	}
	if observation.State != "exited" || observation.Survivors == nil || *observation.Survivors != 0 {
		return problem(api.CodeContainmentUnknown, "outside supervisor has not proved an exited run with zero survivors")
	}
	if observation.ExitCode == nil || signal.ExitCode == nil || *observation.ExitCode != *signal.ExitCode || observation.Signal != nil {
		return problem(api.CodeIntegrity, "real provider exit does not corroborate the limit signal")
	}
	observedAt, err := timestamp(observation.ObservedAt)
	if err != nil {
		return err
	}
	limitAt, err := timestamp(signal.ObservedAt)
	if err != nil {
		return err
	}
	if observedAt.Before(limitAt) || observedAt.After(now) {
		return problem(api.CodeIntegrity, "outside exit and limit times do not agree")
	}
	switch observation.PromptStatus {
	case "written", "completed":
		return nil
	case "cut", "unknown", "not_written":
		return problem(api.CodeConflict, "uncertain prompt requires explicit lifecycle recovery before continuation")
	default:
		return problem(api.CodeIntegrity, "outside observation has invalid prompt evidence")
	}
}

func (s *Service) room(ctx context.Context, grant api.ProfileGrant) (api.Room, error) {
	checkedFrom := s.deps.Clock.Now()
	room, err := s.deps.Credentials.Room(ctx, grant)
	if err != nil {
		return room, err
	}
	if err := profileLive(grant, s.deps.Clock.Now()); err != nil {
		return room, err
	}
	if err := validateRoom(room, grant, s.deps.Clock.Now()); err != nil {
		return room, err
	}
	if _, err := s.blob(ctx, room.Evidence, maxRoomBytes); err != nil {
		return room, err
	}
	now := s.deps.Clock.Now()
	if now.Before(checkedFrom) {
		return room, problem(api.CodeIntegrity, "clock moved backwards during room check")
	}
	if err := profileLive(grant, now); err != nil {
		return room, err
	}
	if err := validateRoom(room, grant, now); err != nil {
		return room, err
	}
	return room, nil
}

func profileLive(grant api.ProfileGrant, now time.Time) error {
	expires, err := timestamp(grant.ExpiresAt)
	if err != nil {
		return err
	}
	if !expires.After(now) {
		return problem(api.CodeForbidden, "profile grant expired during watchdog assessment")
	}
	return nil
}

var errReceiptStale = errors.New("watchdog receipt lifetime elapsed")

func validateRoom(room api.Room, grant api.ProfileGrant, now time.Time) error {
	checked, err := timestamp(room.CheckedAt)
	if err != nil {
		return err
	}
	expires, err := timestamp(room.ExpiresAt)
	if err != nil {
		return err
	}
	if room.ProfileID != grant.ProfileID || checked.After(now) ||
		now.Sub(checked) > maxRoomAge || !expires.After(now) || !expires.After(checked) {
		if room.ProfileID == grant.ProfileID && !checked.After(now) && expires.After(checked) &&
			(now.Sub(checked) > maxRoomAge || !expires.After(now)) {
			return errors.Join(problem(api.CodeIntegrity, "outside room receipt expired"), errReceiptStale)
		}
		return problem(api.CodeIntegrity, "outside room receipt is stale or belongs to another profile")
	}
	return nil
}

func validateEligibility(receipt api.ProfileEligibility, request api.ProfileEligibilityRequest, now time.Time) error {
	checked, err := timestamp(receipt.CheckedAt)
	if err != nil {
		return err
	}
	expires, err := timestamp(receipt.ExpiresAt)
	if err != nil {
		return err
	}
	if !validID.MatchString(string(receipt.ID)) || receipt.Request != request || checked.After(now) ||
		now.Sub(checked) > maxRoomAge || !expires.After(now) || !expires.After(checked) {
		if validID.MatchString(string(receipt.ID)) && receipt.Request == request && !checked.After(now) && expires.After(checked) &&
			(now.Sub(checked) > maxRoomAge || !expires.After(now)) {
			return errors.Join(problem(api.CodeIntegrity, "profile eligibility expired"), errReceiptStale)
		}
		return problem(api.CodeIntegrity, "profile eligibility is stale or differs from the exact model, session and grants")
	}
	return nil
}

func (s *Service) events(ctx context.Context, lifeID api.ID) ([]api.Event, error) {
	result := []api.Event{}
	cursor := ""
	seen := map[string]bool{}
	var last api.Sequence
	for pageNumber := 0; pageNumber < maxEventPages; pageNumber++ {
		page, err := s.deps.Store.Events(ctx, s.readScope(), api.EventTailRequest{LifeID: lifeID, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, event := range page.Events {
			if event.Schema != api.SchemaVersion || event.Config != s.deps.Config ||
				event.LifeID != lifeID || event.Seq <= last {
				return nil, problem(api.CodeIntegrity, "outside event page is unordered or crosses its scope")
			}
			last = event.Seq
			result = append(result, event)
			if len(result) > maxRunEvents {
				return nil, problem(api.CodeUnavailable, "watchdog event snapshot exceeds its bounded scan")
			}
		}
		if page.Complete {
			return result, nil
		}
		if page.Cursor == "" || seen[page.Cursor] {
			return nil, problem(api.CodeIntegrity, "outside event snapshot is incomplete or repeats a cursor")
		}
		cursor = page.Cursor
		seen[cursor] = true
	}
	return nil, problem(api.CodeUnavailable, "watchdog event snapshot exceeds its page bound")
}

func (s *Service) blob(ctx context.Context, ref api.BlobRef, bound int64) (data []byte, resultErr error) {
	if !validID.MatchString(string(ref.ID)) || !validDigest.MatchString(string(ref.SHA256)) ||
		!blobClass(ref.Class) || ref.Bytes <= 0 || ref.Bytes > bound {
		return nil, problem(api.CodeIntegrity, "outside evidence blob is missing or exceeds its bound")
	}
	scope, release, err := objectread.Bind(ctx, s.deps.Store, s.readScope())
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	result := make([]byte, 0, int(ref.Bytes))
	for offset := int64(0); offset < ref.Bytes; {
		limit := int64(api.MaxChunkBytes)
		if ref.Bytes-offset < limit {
			limit = ref.Bytes - offset
		}
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{
			ObjectID: ref.ID, Offset: offset, Limit: int(limit),
		})
		if err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) == 0 || int64(len(chunk.Data)) > limit ||
			digest(chunk.Data) != chunk.SHA256 {
			return nil, problem(api.CodeIntegrity, "outside evidence chunk failed identity, range or hash validation")
		}
		result = append(result, chunk.Data...)
		offset += int64(len(chunk.Data))
	}
	if int64(len(result)) != ref.Bytes || digest(result) != ref.SHA256 {
		return nil, problem(api.CodeIntegrity, "outside evidence blob failed exact byte verification")
	}
	return result, nil
}

func digest(data []byte) api.Digest {
	hash := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(hash[:]))
}

func decodePayload(data []byte, target any) error {
	if !utf8.Valid(data) {
		return problem(api.CodeIntegrity, "outside event payload is not valid UTF-8")
	}
	if _, err := decodeObject(data); err != nil {
		return problem(api.CodeIntegrity, "outside event payload is malformed or ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return problem(api.CodeIntegrity, "outside event payload does not match its typed schema")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return problem(api.CodeIntegrity, "outside event payload contains trailing data")
	}
	return nil
}

func (s *Service) verifyCapture(ctx context.Context, captures []api.CaptureRecord, signal api.LimitSignal, observation api.ProcessObservation) error {
	var selected *api.CaptureRecord
	seen := map[api.ID]api.CaptureRecord{}
	for _, capture := range captures {
		if prior, exists := seen[capture.ID]; exists && prior != capture {
			return problem(api.CodeIntegrity, "primary capture ID has conflicting bytes or metadata")
		}
		seen[capture.ID] = capture
		if capture.ID == signal.CaptureID {
			copy := capture
			selected = &copy
		}
	}
	if selected == nil || !selected.Primary || selected.ReplacementOf != "" || selected.Data.Class != "capture" ||
		selected.Data.SHA256 != signal.CaptureSHA256 || selected.Coverage != "complete" ||
		selected.ObservedAt != signal.ObservedAt ||
		(selected.Stream != "stdout" && selected.Stream != "structured") {
		return problem(api.CodeIntegrity, "limit does not identify complete original primary stdout capture")
	}
	stream := []api.CaptureRecord{}
	for _, capture := range seen {
		if capture.Stream == selected.Stream {
			stream = append(stream, capture)
		}
	}
	sort.Slice(stream, func(i, j int) bool { return stream[i].Offset < stream[j].Offset })
	data := []byte{}
	for _, capture := range stream {
		if capture.Offset != int64(len(data)) || capture.Coverage != "complete" || capture.Target != signal.Target ||
			capture.Data.Bytes > maxCaptureBytes-int64(len(data)) {
			return problem(api.CodeIntegrity, "primary stdout capture is partial, overlapping or exceeds its bound")
		}
		part, err := s.blob(ctx, capture.Data, maxCaptureBytes-int64(len(data)))
		if err != nil {
			return err
		}
		data = append(data, part...)
	}
	outcome, err := Classify(api.DriverClaudock, JSONLines, data, nil, *observation.ExitCode)
	if err != nil {
		return problem(api.CodeIntegrity, "primary provider capture cannot be classified")
	}
	matched := false
	for _, diagnostic := range outcome.Signals {
		if diagnostic.Structured && !diagnostic.Candidate && string(diagnostic.Kind) == signal.Kind &&
			diagnostic.Offset >= selected.Offset &&
			diagnostic.Offset+int64(diagnostic.Bytes) <= selected.Offset+selected.Data.Bytes {
			matched = true
		}
	}
	if !outcome.Complete || outcome.Format != JSONLines || !matched {
		return problem(api.CodeIntegrity, "capture contains no sourced structured provider quota outcome")
	}
	corroborated, err := s.deps.Claudock.LimitFromCapture(ctx, *selected, observation)
	if err != nil {
		return err
	}
	if corroborated == nil || !sameLimitCause(*corroborated, signal) {
		return problem(api.CodeIntegrity, "pinned adapter did not corroborate the exact limit signal")
	}
	return nil
}
