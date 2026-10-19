package api

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"reflect"
	"strings"
	"time"
)

// InstalledScheduler is returned only by the native private service producer.
// Serialized fields alone are not scheduler authority.
// ExpiresAt is fixed within CapabilityGeneration; renewal advances generation.
type InstalledScheduler struct {
	Config                 string     `json:"config"`
	Actor                  Actor      `json:"actor"`
	CapabilityID           ID         `json:"capability_id"`
	CapabilityGeneration   Generation `json:"capability_generation"`
	InstallationGeneration Generation `json:"installation_generation"`
	BootID                 string     `json:"boot_id"`
	PolicyGeneration       Generation `json:"policy_generation"`
	ExpiresAt              Timestamp  `json:"expires_at"`
}

type SchedulerIdentitySource interface {
	VerifyScheduler(context.Context) (InstalledScheduler, error)
}

type schedulerAuthority struct {
	identity InstalledScheduler
	source   SchedulerIdentitySource
}

func ValidateInstalledScheduler(p InstalledScheduler, now time.Time) error {
	expires, err := time.Parse(time.RFC3339Nano, string(p.ExpiresAt))
	if !validInstalledSchedulerShape(p) || err != nil || !now.Before(expires) {
		return launchInvalid("invalid installed scheduler identity")
	}
	return nil
}

func validInstalledSchedulerShape(p InstalledScheduler) bool {
	_, err := time.Parse(time.RFC3339Nano, string(p.ExpiresAt))
	return bindingConfigName.MatchString(p.Config) && p.Actor.Kind == "scheduler" && launchID(p.Actor.ID) &&
		p.Actor.LifeID == "" && p.Actor.Level == 0 && p.Actor.Role == "" && launchID(p.CapabilityID) &&
		launchGeneration(p.CapabilityGeneration) && launchGeneration(p.InstallationGeneration) && p.BootID != "" &&
		launchGeneration(p.PolicyGeneration) && err == nil
}

// Assembly installs the producer on a distinct private scheduler dependency.
// It must verify the actual native caller, installed capability and lifetime.
func BindSchedulerScope(ctx context.Context, source SchedulerIdentitySource, now time.Time) (Scope, error) {
	if source == nil {
		return Scope{}, NotImplemented("lb-v2-identity", "installed scheduler identity")
	}
	identity, err := source.VerifyScheduler(ctx)
	if err != nil {
		return Scope{}, err
	}
	if err := ValidateInstalledScheduler(identity, now); err != nil {
		return Scope{}, err
	}
	return Scope{Config: identity.Config, Actor: identity.Actor, PolicyGeneration: identity.PolicyGeneration,
		scheduler: &schedulerAuthority{identity: identity, source: source}}, nil
}

// The writer calls this again against its current protected capability/policy
// view before reservation/replay; a prior scope stamp cannot survive revocation.
func CheckSchedulerScope(ctx context.Context, scope Scope, now time.Time) error {
	if !validSchedulerScope(scope) {
		return launchInvalid("scheduler scope lacks its private producer binding")
	}
	current, err := scope.scheduler.source.VerifyScheduler(ctx)
	if err != nil {
		return err
	}
	if err := ValidateInstalledScheduler(current, now); err != nil {
		return err
	}
	if current != scope.scheduler.identity {
		return &Error{Code: CodeConflict, Owner: "lb-v2-service", Message: "installed scheduler authority changed"}
	}
	return nil
}

// SchedulerStamp reads the private producer binding after a live recheck.
// Its value is metadata, not a constructor for scheduler authority.
func SchedulerStamp(ctx context.Context, scope Scope, now time.Time) (InstalledScheduler, error) {
	if err := CheckSchedulerScope(ctx, scope, now); err != nil {
		return InstalledScheduler{}, err
	}
	return scope.scheduler.identity, nil
}

func validSchedulerScope(scope Scope) bool {
	return scope.scheduler != nil && scope.scheduler.source != nil && scope.scheduler.identity.Config == scope.Config &&
		scope.scheduler.identity.Actor == scope.Actor && scope.scheduler.identity.PolicyGeneration == scope.PolicyGeneration &&
		scope.Connection == nil && scope.Frame == nil && scope.LaunchID == "" && reflect.DeepEqual(scope.Request, Request{}) &&
		scope.EndpointGeneration == 0 && scope.ReadView == nil && scope.ReadAuthority == nil && scope.Source == "" &&
		validInstalledSchedulerShape(scope.scheduler.identity)
}

// Only protected selectors enter a loop reservation. The store derives every
// new ID, input, budget, role, grant and logical turn under its writer lock.
type LoopTurnSelector struct {
	Target             LifeRef    `json:"target"`
	SettingEventID     ID         `json:"setting_event_id"`
	SettingSeq         Sequence   `json:"setting_seq"`
	SettingOperationID ID         `json:"setting_operation_id"`
	EndEventID         ID         `json:"end_event_id"`
	EndSeq             Sequence   `json:"end_seq"`
	ExpectedGeneration Generation `json:"expected_generation"`
	CancellationEpoch  Generation `json:"cancellation_epoch"`
	PreviousLaunchID   ID         `json:"previous_launch_id"`
}

// This canonical immutable manifest replaces an original public frame only
// for this private branch. ConfiguredBy remains separate from the scheduler.
type LoopTurnCause struct {
	Schema                string             `json:"schema"`
	Scheduler             InstalledScheduler `json:"scheduler"`
	Selector              LoopTurnSelector   `json:"selector"`
	ConfiguredBy          Actor              `json:"configured_by"`
	Setting               LoopRequest        `json:"setting"`
	End                   RunEndEvent        `json:"end"`
	GrantGeneration       Generation         `json:"grant_generation"`
	PreviousSession       Session            `json:"previous_session"`
	PreviousHome          PrivateHomeBinding `json:"previous_home"`
	BudgetRemaining       Budget             `json:"budget_remaining"`
	DueAt                 Timestamp          `json:"due_at"`
	ReservedAt            Timestamp          `json:"reserved_at"`
	ReservationID         ID                 `json:"reservation_id"`
	OperationID           ID                 `json:"operation_id"`
	RequestID             ID                 `json:"request_id"`
	LaunchID              ID                 `json:"launch_id"`
	GrantSetID            ID                 `json:"grant_set_id"`
	LogicalTurnID         ID                 `json:"logical_turn_id"`
	PreviousLogicalTurnID ID                 `json:"previous_logical_turn_id"`
	PlanEffectID          ID                 `json:"plan_effect_id"`
}

func validLoopSelector(s LoopTurnSelector) bool {
	return launchID(s.Target.LifeID) && s.Target.Run > 0 && s.Target.Run < launchMaxInteger &&
		launchID(s.SettingEventID) && s.SettingSeq > 0 && s.SettingSeq <= launchMaxInteger && launchID(s.SettingOperationID) &&
		launchID(s.EndEventID) && s.EndEventID != s.SettingEventID && s.EndSeq > 0 && s.EndSeq != s.SettingSeq && s.EndSeq <= launchMaxInteger &&
		launchGeneration(s.ExpectedGeneration) && s.ExpectedGeneration < launchMaxInteger &&
		s.CancellationEpoch <= launchMaxInteger && launchID(s.PreviousLaunchID)
}

func validateLoopRequest(scope Scope, request LaunchReservationRequest) error {
	if !validSchedulerScope(scope) || request.Loop == nil || !validLoopSelector(*request.Loop) ||
		request.OperationID != "" || request.ContinuationID != "" || len(request.Guards) != 0 {
		return launchInvalid("loop reservation lacks exclusive installed scheduler authority")
	}
	return nil
}

func ValidateLoopTurnCause(c LoopTurnCause) error {
	s := c.Selector
	reserved, reserveErr := time.Parse(time.RFC3339Nano, string(c.ReservedAt))
	ended, endErr := time.Parse(time.RFC3339Nano, string(c.End.Observation.ObservedAt))
	due, dueErr := time.Parse(time.RFC3339Nano, string(c.DueAt))
	if c.Schema != "laneboss.loop-turn.v2" || !validLoopSelector(s) || reserveErr != nil || endErr != nil || dueErr != nil ||
		ValidateInstalledScheduler(c.Scheduler, reserved) != nil ||
		c.ConfiguredBy.Kind != "human" && c.ConfiguredBy.Kind != "lane" || !launchID(c.ConfiguredBy.ID) ||
		!c.Setting.Enabled || c.Setting.Target.LifeID != s.Target.LifeID || c.Setting.Target.Run == 0 || c.Setting.Target.Run > s.Target.Run ||
		!launchGeneration(c.Setting.ExpectedGeneration) || c.Setting.ExpectedGeneration > s.ExpectedGeneration ||
		c.Setting.IdleMessage == nil || !launchBlob(*c.Setting.IdleMessage, "task") ||
		c.Setting.BackoffMS < 1 || c.Setting.BackoffMS > int64((1<<63-1)/time.Millisecond) ||
		c.End.LaunchID != s.PreviousLaunchID || c.End.Reason == "" || c.End.Reason == "service_lost" || c.End.ProfileContinuation ||
		c.End.Observation.Handle.Target != s.Target || c.End.Observation.State != "exited" ||
		c.End.Observation.Survivors == nil || *c.End.Observation.Survivors != 0 ||
		!due.Equal(ended.Add(time.Duration(c.Setting.BackoffMS)*time.Millisecond)) || reserved.Before(due) ||
		!launchGeneration(c.GrantGeneration) || c.BudgetRemaining != c.End.BudgetRemaining ||
		c.BudgetRemaining.WallMS <= 0 || c.BudgetRemaining.SpendMicros < 0 ||
		!launchID(c.PreviousSession.ID) || !launchID(c.PreviousSession.HistoryID) || !launchID(c.PreviousSession.HomeID) ||
		c.PreviousSession.Driver != DriverCodex && c.PreviousSession.Driver != DriverClaudock ||
		c.PreviousSession.VendorVersion == "" || s.Target.Run > 1 && c.PreviousSession.VendorID == "" ||
		c.PreviousSession.LogicalCWD != "/work/main" || c.PreviousHome.LifeID != s.Target.LifeID ||
		c.PreviousHome.Home.ID != c.PreviousSession.HomeID || c.PreviousHome.Home.HistoryID != c.PreviousSession.HistoryID ||
		!launchID(c.PreviousHome.RootID) || !launchGeneration(c.PreviousHome.Generation) {
		return launchInvalid("loop turn lost its setting, quiescent end or retained input fences")
	}
	if !(c.ConfiguredBy.Kind == "human" && c.ConfiguredBy.LifeID == "" && c.ConfiguredBy.Level == 0 && c.ConfiguredBy.Role == "" ||
		c.ConfiguredBy.Kind == "lane" && launchID(c.ConfiguredBy.LifeID) && c.ConfiguredBy.Level >= 3 && c.ConfiguredBy.Level <= 6 && launchID(ID(c.ConfiguredBy.Role))) ||
		!launchID(c.End.Observation.Handle.ID) || !launchID(c.PreviousHome.Home.WorkspaceID) || c.PreviousHome.RootID == c.PreviousHome.Home.WorkspaceID ||
		c.PreviousHome.Home.VendorDirectory == "" || path.IsAbs(c.PreviousHome.Home.VendorDirectory) ||
		path.Clean(c.PreviousHome.Home.VendorDirectory) != c.PreviousHome.Home.VendorDirectory || c.PreviousHome.Home.VendorDirectory == "." ||
		c.PreviousHome.Home.VendorDirectory == ".." || strings.HasPrefix(c.PreviousHome.Home.VendorDirectory, "../") || strings.ContainsRune(c.PreviousHome.Home.VendorDirectory, 0) {
		return launchInvalid("loop turn contains partial configurator, process or private home metadata")
	}
	seen := map[ID]bool{s.PreviousLaunchID: true, s.SettingOperationID: true, s.SettingEventID: true, s.EndEventID: true}
	for _, id := range []ID{c.ReservationID, c.OperationID, c.RequestID, c.LaunchID, c.GrantSetID, c.LogicalTurnID, c.PlanEffectID} {
		if !launchID(id) || seen[id] {
			return launchInvalid("loop turn lacks its store-issued identities")
		}
		seen[id] = true
	}
	if !launchID(c.PreviousLogicalTurnID) || c.LogicalTurnID == c.PreviousLogicalTurnID {
		return launchInvalid("loop reused the previous logical turn")
	}
	return nil
}

func validLoopReservation(r LaunchReservation) bool {
	c := r.Loop
	if c == nil || ValidateLoopTurnCause(*c) != nil {
		return false
	}
	raw, digest, err := launchCanonical(*c)
	return err == nil && r.Mode == "turn" && r.Config == c.Scheduler.Config && r.RequestedBy == c.Scheduler.Actor &&
		r.ID == c.ReservationID && r.OperationID == c.OperationID && r.RequestID == c.RequestID && r.LaunchID == c.LaunchID &&
		r.GrantSetID == c.GrantSetID && r.PolicyGeneration == c.Scheduler.PolicyGeneration &&
		r.Target == (LifeRef{LifeID: c.Selector.Target.LifeID, Run: c.Selector.Target.Run + 1}) &&
		r.BaseGeneration == c.Selector.ExpectedGeneration && r.CancellationEpoch == c.Selector.CancellationEpoch &&
		r.PreviousLaunchID == c.Selector.PreviousLaunchID && r.Driver == c.PreviousSession.Driver &&
		r.Authority == (LaunchAuthority{Kind: "scheduler", ID: c.Scheduler.CapabilityID}) &&
		r.OriginalRequest.Class == "manifest" && r.OriginalRequest.Bytes == int64(len(raw)) &&
		r.OriginalRequest.SHA256 == digest && r.RequestSHA256 == digest
}

// CheckLoopInput checks bytes only. Execution still requires the actual
// service-owned effect claim and the store's live policy and epoch fences.
func CheckLoopInput(r LaunchReservation, raw []byte) error {
	if r.Loop == nil || ValidateLaunchReservation(r) != nil {
		return launchInvalid("loop input has no valid private reservation")
	}
	canonical, digest, err := launchCanonical(*r.Loop)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) || digest != r.RequestSHA256 || int64(len(raw)) != r.OriginalRequest.Bytes {
		return &Error{Code: CodeIntegrity, Owner: "lb-v2-service", Message: "loop input differs from its exact reserved cause"}
	}
	return nil
}

func validReservationOriginal(r LaunchReservation) bool {
	if r.Loop != nil {
		return launchBlob(r.OriginalRequest, "manifest") && validLoopReservation(r)
	}
	return launchBlob(r.OriginalRequest, "launch_request")
}

// Public transaction rows cannot emit this reservation event. The dedicated
// ReserveLaunch writer appends it with the manifest and PlanLaunch effect.
func ValidateLoopReservedEvent(event Event, r LaunchReservation) error {
	if !validLoopReservation(r) || event.Kind != "loop.reserved" || event.Config != r.Config ||
		event.Actor != r.RequestedBy || event.RequestedBy != r.RequestedBy || event.OperationID != r.OperationID ||
		event.RequestID != r.RequestID || event.LifeID != r.Target.LifeID || event.Run != r.Target.Run ||
		event.LogicalTurnID != r.Loop.LogicalTurnID {
		return launchInvalid("loop reservation event changed its scheduler or cause")
	}
	var cause LoopTurnCause
	if DecodeObject(event.Payload, &cause) != nil || !reflect.DeepEqual(cause, *r.Loop) {
		return launchInvalid("loop reservation event changed its immutable input")
	}
	return nil
}

// A loop launch uses the existing lane.turn payload and a loop trigger. Its
// actual scheduler remains the audit actor; helper/identity events keep their
// actual executor and the scheduler as RequestedBy.
func ValidateLoopTurnEvent(event Event, r LaunchReservation) error {
	if !validLoopReservation(r) || event.Kind != "lane.turn" || event.Config != r.Config ||
		event.Actor != r.RequestedBy || event.RequestedBy != r.RequestedBy || event.OperationID != r.OperationID ||
		event.RequestID != r.RequestID || event.LifeID != r.Target.LifeID || event.Run != r.Target.Run ||
		event.LogicalTurnID != r.Loop.LogicalTurnID {
		return launchInvalid("loop launch event changed its scheduler or cause")
	}
	var body TurnEvent
	if DecodeObject(event.Payload, &body) != nil || body.Task != *r.Loop.Setting.IdleMessage || !launchBlob(body.Prompt, "prompt") ||
		body.Status != "written" || len(body.MailIDs) != 0 || body.Trigger.Kind != "loop" || len(body.Trigger.MailIDs) != 0 ||
		body.Trigger.CausingRun != r.Loop.Selector.Target.Run ||
		!reflect.DeepEqual(body.Trigger.CausingSeqs, []Sequence{r.Loop.Selector.SettingSeq, r.Loop.Selector.EndSeq}) {
		return launchInvalid("loop launch event lost its exact input or causal events")
	}
	return nil
}

func validLoopTurnWrites(tx Transaction) bool {
	for _, record := range tx.Writes.LaunchPlans {
		if record.Reservation.Loop == nil || record.Phase != "opened" {
			continue
		}
		count := 0
		for _, event := range tx.Events {
			if event.Kind == "lane.turn" && event.LifeID == record.Reservation.Target.LifeID && event.Run == record.Reservation.Target.Run {
				if ValidateLoopTurnEvent(event, record.Reservation) != nil {
					return false
				}
				var body TurnEvent
				if DecodeObject(event.Payload, &body) != nil || record.Plan == nil || body.Prompt != record.Plan.Runner.Prompt {
					return false
				}
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	for _, event := range tx.Events {
		if event.Kind != "lane.turn" {
			continue
		}
		var body TurnEvent
		if len(event.Payload) != 0 && json.Unmarshal(event.Payload, &body) != nil {
			return false
		}
		if event.Actor.Kind != "scheduler" && event.RequestedBy.Kind != "scheduler" && body.Trigger.Kind != "loop" {
			continue
		}
		matched := false
		for _, record := range tx.Writes.LaunchPlans {
			matched = matched || record.Phase == "opened" && record.Reservation.Loop != nil &&
				ValidateLoopTurnEvent(event, record.Reservation) == nil
		}
		if !matched {
			return false
		}
	}
	return true
}
