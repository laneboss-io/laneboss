//go:build laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

const fixtureAdapter = "serve-fixture/1.0.0"

// A fixture replaces only the explicitly enrolled vendor executables in the
// dedicated test build. Missing enrollment uses the current real constructors.
func installedRunners(installed Installation, deps runnerDependencies) (api.Runner, api.Runner, error) {
	declared, err := loadFixture(installed)
	if err != nil {
		return nil, nil, err
	}
	if declared == nil {
		return realRunners(installed, deps)
	}
	fixtureClaude, fixtureCodex, err := installedFixtureRunners(declared, installed, deps)
	if err != nil {
		return nil, nil, err
	}
	for _, runner := range []api.Runner{fixtureClaude, fixtureCodex} {
		if err := bindEnrolledFixture(runner, deps); err != nil {
			return nil, nil, err
		}
	}
	real, err := loadRealRuntime(installed)
	if err != nil {
		return nil, nil, err
	}
	if real == nil {
		return fixtureClaude, fixtureCodex, nil
	}
	claude, _, err := realRunners(installed, deps)
	return claude, fixtureCodex, err
}

func installedFixtureRunners(declared *fixtureEnrollment, installed Installation, deps runnerDependencies) (api.Runner, api.Runner, error) {
	claude, codex, err := runnersForFixture(declared)
	if err != nil {
		return nil, nil, err
	}
	return &fixtureClaudockRunner{Runner: claude,
		reader: enrolledRunner{config: installed.Config, deps: deps}}, codex, nil
}

func runnersForFixture(declared *fixtureEnrollment) (api.Runner, api.Runner, error) {
	if declared != nil {
		seen := make(map[api.Driver]bool)
		for _, driver := range declared.Drivers {
			seen[driver] = true
		}
		if seen[api.DriverClaudock] && seen[api.DriverCodex] {
			return &enrolledFixtureRunner{enrollment: *declared, driver: api.DriverClaudock},
				&enrolledFixtureRunner{enrollment: *declared, driver: api.DriverCodex}, nil
		}
	}
	return nil, nil, api.NotImplemented("lb-v2-serve", "complete dual-driver fixture enrollment")
}

// Runtime enrollment constructs the fixture runner, not a replacement launch
// gate. Fix 9 must supply the durable run/workspace and outside capture ports.
type enrolledFixtureRunner struct {
	enrollment fixtureEnrollment
	driver     api.Driver
	ports      runnerDependencies
}

var _ api.Runner = (*enrolledFixtureRunner)(nil)

func (r *enrolledFixtureRunner) prepare(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if ctx == nil {
		return api.RunnerPlan{}, fixtureError(api.CodeInvalid, "fixture runner context is required")
	}
	if err := ctx.Err(); err != nil {
		return api.RunnerPlan{}, err
	}
	if request.Executable != r.enrollment.Executable || request.Session.Driver != r.driver {
		return api.RunnerPlan{}, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-serve",
			Message: "fixture request differs from runtime", Instead: "Use the enrolled fixture bytes."}
	}
	expires, err := time.Parse(time.RFC3339Nano, string(request.Slot.ExpiresAt))
	if !filepath.IsAbs(r.enrollment.executablePath) || request.Target.LifeID == "" || request.Target.Run == 0 ||
		request.Session.ID == "" || request.Session.HomeID != request.Home.ID || request.Home.ID == "" ||
		request.Home.WorkspaceID == "" || request.Session.HistoryID != request.Home.HistoryID || request.Home.HistoryID == "" ||
		request.Session.LogicalCWD != "/work/main" ||
		request.Prompt.ID == "" || request.Prompt.Class != "prompt" || request.Prompt.Bytes < 1 || !isDigest(request.Prompt.SHA256) ||
		request.Slot.ID == "" || request.Slot.LeaseID == "" || request.Slot.ProfileGrantID == "" || request.Slot.ProfileID == "" ||
		err != nil || !expires.After(time.Now()) || request.Budget.WallMS < 1 || request.Budget.WallMS > 1800000 ||
		request.Model == "" || request.Effort == "" {
		return api.RunnerPlan{}, api.NotImplemented("lb-v2-serve", "complete fixture launch inputs")
	}
	session := request.Session
	if r.driver == api.DriverClaudock && (session.VendorID == "" || session.VendorVersion == "") {
		return api.RunnerPlan{}, runError(api.CodePrerequisite, "fixture requires the planner's enrolled vendor session")
	}
	if session.VendorID == "" {
		session.VendorID = string(session.ID)
	}
	if session.VendorVersion != "" && session.VendorVersion != r.enrollment.Version {
		return api.RunnerPlan{}, installError("fixture session version differs")
	}
	session.VendorVersion = r.enrollment.Version
	mode := r.enrollment.Mode
	if mode == "" {
		mode = "state"
	}
	argv := []string{r.enrollment.executablePath, "--config", r.enrollment.Config, "--client", r.enrollment.ClientPath,
		"--binding", r.enrollment.BindingPath, "--challenge", r.enrollment.Challenge, "--life", string(request.Target.LifeID),
		"--run", strconv.FormatUint(uint64(request.Target.Run), 10), "--mode", mode, "--driver", string(r.driver),
		"--session", string(session.ID), "--home", string(session.HomeID), "--history", string(session.HistoryID),
		"--vendor-session", session.VendorID, "--wait-ms", strconv.FormatInt(request.Budget.WallMS, 10),
		"--model", request.Model, "--effort", request.Effort}
	return api.RunnerPlan{Driver: r.driver, Executable: request.Executable, Argv: argv, CWD: session.LogicalCWD,
		Prompt: request.Prompt, Home: request.Home, Slot: request.Slot, Session: session, InnerSandbox: "off",
		AdapterVersion: fixtureAdapter, EnvironmentNames: []string{}}, nil
}

func (r *enrolledFixtureRunner) Start(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return r.prepare(ctx, request)
}

func (r *enrolledFixtureRunner) Resume(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return r.retained(ctx, request)
}

func (r *enrolledFixtureRunner) Turn(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	return r.retained(ctx, request)
}

// Watchdog retained-plan hunk. The enclosing enrolledRunner verifies the
// durable reservation, previous session/home, selected slot and current claim.
// A continuation never manufactures a replacement vendor/history identity.
func (r *enrolledFixtureRunner) retained(ctx context.Context, request api.RunnerRequest) (api.RunnerPlan, error) {
	if request.Target.Run < 2 || request.Session.VendorID == "" || request.Session.VendorVersion == "" {
		return api.RunnerPlan{}, api.NotImplemented("lb-v2-serve", "complete fixture launch inputs")
	}
	return r.prepare(ctx, request)
}

// Watchdog outside-capture hunk. These ports are installed in-process; neither
// task bytes nor a public RPC can bind them. State is reread on every call so
// service reconstruction does not depend on an in-memory run/session map.
func (r *enrolledFixtureRunner) bindFixture(ports runnerDependencies) { r.ports = ports }

// The Claudock fixture is wrapped by its measured-home runner; bind the
// enrolled fixture inside it. Any other runner type is a refused enrollment.
func bindEnrolledFixture(runner api.Runner, ports runnerDependencies) error {
	if wrapped, ok := runner.(*fixtureClaudockRunner); ok {
		runner = wrapped.Runner
	}
	enrolled, ok := runner.(*enrolledFixtureRunner)
	if !ok {
		return fixtureError(api.CodeInvalid, "fixture runner is not an enrolled fixture")
	}
	enrolled.bindFixture(ports)
	return nil
}

func fixtureError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Owner: "lb-v2-serve", Message: message,
		Instead: "Retain the actual fixture inputs and repair the protected runtime dependency."}
}

func (r *enrolledFixtureRunner) fixtureScope() api.Scope {
	return api.Scope{Config: r.enrollment.Config, Source: "worker", Actor: api.Actor{Kind: "service", ID: "serve-fixture"}}
}

func (r *enrolledFixtureRunner) events(ctx context.Context, target api.LifeRef) ([]api.Event, error) {
	if ctx == nil {
		return nil, fixtureError(api.CodeInvalid, "fixture capture context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.ports.Store == nil || r.ports.Clock == nil || !r.enrollment.VendorStoodIn {
		return nil, api.NotImplemented("lb-v2-service", "attested fixture capture bindings")
	}
	q := api.EventTailRequest{LifeID: target.LifeID, Run: target.Run, DeadlineMS: 5000}
	var events []api.Event
	seen := map[string]bool{}
	var last api.Sequence
	for page := 0; page < 512; page++ {
		result, err := r.ports.Store.Events(ctx, r.fixtureScope(), q)
		if err != nil {
			return nil, err
		}
		for _, event := range result.Events {
			if event.Config != r.enrollment.Config || event.LifeID != target.LifeID || event.Run != target.Run || event.Seq <= last || len(events) >= 100000 {
				return nil, fixtureError(api.CodeIntegrity, "fixture event scope or sequence changed")
			}
			last = event.Seq
			events = append(events, event)
		}
		if result.Complete {
			return events, nil
		}
		if result.Cursor == "" || seen[result.Cursor] {
			return nil, fixtureError(api.CodeIntegrity, "fixture event cursor did not advance")
		}
		seen[result.Cursor], q.Cursor = true, result.Cursor
	}
	return nil, fixtureError(api.CodeIntegrity, "fixture event inventory exceeds its bound")
}

func fixtureOutside(event api.Event) bool {
	return event.Origin == "service" && (event.Actor.Kind == "service" || event.Actor.Kind == "worker") && event.Actor.ID != "" && event.Actor.LifeID == "" && event.Actor.Level == 0 && event.Actor.Role == ""
}

func (r *enrolledFixtureRunner) captured(ctx context.Context, record api.CaptureRecord) (api.LaunchPlanRecord, []api.Event, []byte, error) {
	var empty api.LaunchPlanRecord
	if record.ID == "" || record.BindingID == "" || !record.Primary || record.ReplacementOf != "" || record.Coverage != "complete" ||
		record.Target.LifeID == "" || record.Target.Run == 0 || record.Offset < 0 || record.Data.Class != "capture" || record.Data.Bytes < 1 || record.Data.Bytes > api.MaxChunkBytes || !isDigest(record.Data.SHA256) {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture is not complete original primary output")
	}
	events, err := r.events(ctx, record.Target)
	if err != nil {
		return empty, nil, nil, err
	}
	var launch api.LaunchRecord
	for _, event := range events {
		if event.Kind == "identity.bound" && fixtureOutside(event) {
			var candidate api.LaunchRecord
			if api.DecodeObject(event.Payload, &candidate) != nil {
				return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture launch identity is malformed")
			}
			if candidate.Kind == "worker" {
				continue // Materialization/capture workers share the target run.
			}
			if launch.ID != "" || candidate.Kind != "agent" || candidate.Target != record.Target || candidate.Config != r.enrollment.Config {
				return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture has ambiguous launch identity")
			}
			launch = candidate
		}
	}
	if launch.ID == "" {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture has no outside launch identity")
	}
	binding, err := r.ports.Store.LaunchBinding(ctx, launch.ID)
	if err != nil {
		return empty, nil, nil, err
	}
	if !reflect.DeepEqual(binding.Record, launch) || binding.Recovery == nil {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture launch recovery differs from its identity")
	}
	plan, err := r.ports.Store.LaunchPlan(ctx, r.fixtureScope(), binding.Recovery.PlanID)
	if err != nil {
		return empty, nil, nil, err
	}
	if api.ValidateLaunchPlanRecord(plan) != nil || plan.Phase != "opened" || plan.Plan == nil || api.ValidateLaunchBindingPlan(binding, *plan.Plan) != nil ||
		plan.Reservation.Target != record.Target || plan.Plan.Runner.Driver != r.driver || plan.Plan.Runner.Executable != r.enrollment.Executable ||
		plan.Plan.Runner.Session.VendorVersion != r.enrollment.Version || plan.Plan.Runner.Session.VendorID == "" || plan.Plan.Capture.ID != record.BindingID {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture lost its opened plan or executable pins")
	}
	state, err := r.ports.Store.CaptureState(ctx, r.fixtureScope(), record.BindingID)
	if err != nil {
		return empty, nil, nil, err
	}
	if !reflect.DeepEqual(state.Binding, plan.Plan.Capture) || state.Generation < state.Binding.Generation || state.LastSeq == 0 || r.ports.Capture == nil {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture is not acknowledged by its producer")
	}
	reconciled, err := r.ports.Capture.ReconcileCapture(ctx, state.Binding)
	if err != nil {
		return empty, nil, nil, err
	}
	if !reflect.DeepEqual(reconciled, state.Binding) {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture producer changed")
	}
	port, ok := r.ports.Store.(interface {
		CaptureFrame(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	})
	if !ok {
		return empty, nil, nil, api.NotImplemented("lb-v2-store", "CaptureFrame")
	}
	canonical, raw, err := port.CaptureFrame(ctx, record.ID)
	if err != nil {
		return empty, nil, nil, err
	}
	if canonical != record || int64(len(raw)) != record.Data.Bytes || runDigest(raw) != record.Data.SHA256 {
		return empty, nil, nil, fixtureError(api.CodeIntegrity, "fixture capture differs from exact protected frame bytes")
	}
	return plan, events, raw, nil
}

func fixtureRecords(raw []byte, session api.Session) ([]map[string]any, error) {
	var records []map[string]any
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), api.MaxChunkBytes)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		canonical, err := api.CanonicalJSON(scanner.Bytes())
		var record map[string]any
		if err != nil || json.Unmarshal(canonical, &record) != nil || record == nil {
			return nil, fixtureError(api.CodeIntegrity, "fixture structured frame is malformed or ambiguous")
		}
		if id, exists := record["session_id"]; exists && id != session.VendorID {
			return nil, fixtureError(api.CodeIntegrity, "fixture vendor frame belongs to another session")
		}
		records = append(records, record)
	}
	if scanner.Err() != nil || len(records) > 65536 {
		return nil, fixtureError(api.CodeIntegrity, "fixture structured frame is incomplete or oversized")
	}
	return records, nil
}

func (r *enrolledFixtureRunner) SessionFromCapture(ctx context.Context, record api.CaptureRecord) (api.Session, error) {
	plan, _, raw, err := r.captured(ctx, record)
	if err != nil {
		return api.Session{}, err
	}
	session := plan.Plan.Runner.Session
	if record.Stream != "stdout" && record.Stream != "structured" && record.Stream != "vendor" {
		return api.Session{}, fixtureError(api.CodeNotFound, "fixture diagnostic stream has no vendor session init")
	}
	frames, err := fixtureRecords(raw, session)
	if err != nil {
		return api.Session{}, err
	}
	found := false
	for _, frame := range frames {
		if frame["type"] == "system" && frame["subtype"] == "init" {
			if found || frame["session_id"] != session.VendorID || frame["cwd"] != session.LogicalCWD {
				return api.Session{}, fixtureError(api.CodeIntegrity, "fixture init changed or duplicated the retained session")
			}
			found = true
		}
	}
	if !found {
		return api.Session{}, fixtureError(api.CodeNotFound, "fixture primary capture has no vendor session init")
	}
	return session, nil
}

var fixtureQuota = regexp.MustCompile(`^(?:You['’]ve hit your (?:limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?|Usage limit reached(?: · limit resets [^\r\n]+)?)$`)

// Only fixed provider-envelope positions are candidates. Model/tool output,
// diagnostic markers, authentication errors and successful result envelopes
// cannot become quota authority, even when they quote identical quota text.
func fixtureLimit(frames []map[string]any, session string) (string, bool) {
	kind := ""
	for _, frame := range frames {
		if frame["type"] == "error" {
			return "", true
		}
		if frame["type"] == "rate_limit_event" {
			info, _ := frame["rate_limit_info"].(map[string]any)
			if info["status"] == "rejected" {
				if frame["session_id"] != session {
					return "", true
				}
				kind = "rate_limit"
			}
			continue
		}
		var messages []any
		switch frame["type"] {
		case "assistant":
			marker := frame["error"]
			if marker == nil || marker == "" {
				continue
			}
			message, _ := frame["message"].(map[string]any)
			content, _ := message["content"].([]any)
			if marker != "rate_limit" || frame["session_id"] != session || len(content) != 1 {
				return "", true
			}
			block, _ := content[0].(map[string]any)
			if block["type"] != "text" {
				return "", true
			}
			messages = []any{block["text"]}
		case "result":
			if frame["session_id"] != session || frame["is_error"] != true {
				return "", true
			}
			if subtype, exists := frame["subtype"]; exists && subtype != "" && subtype != "success" && subtype != "error_during_execution" {
				return "", true
			}
			if errors, exists := frame["errors"]; exists {
				var ok bool
				messages, ok = errors.([]any)
				if !ok || len(messages) == 0 {
					return "", true
				}
			}
			if result, exists := frame["result"]; exists && result != "" {
				messages = append(messages, result)
			}
		default:
			continue
		}
		if len(messages) == 0 {
			return "", true
		}
		for _, raw := range messages {
			message, ok := raw.(string)
			if !ok || !fixtureQuota.MatchString(message) || strings.ContainsAny(message, "\r\n\x00") {
				return "", true
			}
			candidate := "usage_limit"
			if strings.Contains(message, "session limit") {
				candidate = "session_limit"
			}
			if kind == "" || kind == "rate_limit" || candidate == "session_limit" {
				kind = candidate
			}
		}
	}
	return kind, false
}

func (r *enrolledFixtureRunner) LimitFromCapture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	return r.limitFromFixture(ctx, record, exit)
}

func (r *enrolledFixtureRunner) limitFromFixture(ctx context.Context, record api.CaptureRecord, exit api.ProcessObservation) (*api.LimitSignal, error) {
	plan, events, raw, err := r.captured(ctx, record)
	if err != nil {
		return nil, err
	}
	var actual *api.ProcessObservation
	for _, event := range events {
		if !fixtureOutside(event) {
			continue
		}
		if event.Kind == "lane.ended" {
			var end api.RunEndEvent
			if actual != nil || api.DecodeObject(event.Payload, &end) != nil || end.LaunchID != plan.Reservation.LaunchID {
				return nil, fixtureError(api.CodeIntegrity, "fixture has ambiguous terminal evidence")
			}
			actual = &end.Observation
		}
		if strings.Contains(string(event.Kind), "refus") || event.Kind == "capture.gap" {
			return nil, fixtureError(api.CodeForbidden, "fixture run contains a service refusal or capture gap")
		}
	}
	observed, timeErr := time.Parse(time.RFC3339Nano, string(exit.ObservedAt))
	captured, captureErr := time.Parse(time.RFC3339Nano, string(record.ObservedAt))
	if actual == nil || !reflect.DeepEqual(*actual, exit) || exit.Handle.Target != record.Target || exit.State != "exited" || exit.Survivors == nil || *exit.Survivors != 0 || exit.ExitCode == nil || exit.Signal != nil ||
		timeErr != nil || captureErr != nil || observed.Before(captured) || observed.After(r.ports.Clock.Now()) {
		return nil, fixtureError(api.CodeContainmentUnknown, "fixture limit requires its actual exited zero-survivor observation")
	}
	if r.driver != api.DriverClaudock || record.Stream == "stderr" {
		return nil, nil
	}
	frames, err := fixtureRecords(raw, plan.Plan.Runner.Session)
	if err != nil {
		return nil, err
	}
	kind, blocked := fixtureLimit(frames, plan.Plan.Runner.Session.VendorID)
	if blocked || kind == "" {
		return nil, nil
	}
	framer, ok := r.ports.Store.(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
		CaptureFrame(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	})
	if !ok {
		return nil, api.NotImplemented("lb-v2-store", "whole-run fixture framing")
	}
	all, err := framer.FrameCapture(ctx, r.fixtureScope(), record.BindingID)
	if err != nil {
		return nil, err
	}
	found := false
	for _, frame := range all {
		canonical, data, err := framer.CaptureFrame(ctx, frame.ID)
		if err != nil {
			return nil, err
		}
		if canonical != frame || frame.BindingID != record.BindingID || frame.Target != record.Target || !frame.Primary || frame.ReplacementOf != "" || frame.Coverage != "complete" || int64(len(data)) != frame.Data.Bytes || runDigest(data) != frame.Data.SHA256 {
			return nil, fixtureError(api.CodeIntegrity, "fixture whole-run frame provenance changed")
		}
		found = found || frame == record
		if frame.Stream == "stderr" && len(bytes.TrimSpace(data)) != 0 {
			return nil, nil // Diagnostic failure cannot be hidden by a stdout marker.
		}
		if frame.Stream != "stdout" && frame.Stream != "structured" && frame.Stream != "vendor" {
			continue
		}
		parsed, err := fixtureRecords(data, plan.Plan.Runner.Session)
		if err != nil {
			return nil, err
		}
		if _, blocked := fixtureLimit(parsed, plan.Plan.Runner.Session.VendorID); blocked {
			return nil, nil
		}
	}
	if !found {
		return nil, fixtureError(api.CodeIntegrity, "fixture limit is outside the whole-run inventory")
	}
	profile, usage, err := r.fixtureUsage(ctx, plan, exit)
	if err != nil {
		return nil, err
	}
	code := *exit.ExitCode
	return &api.LimitSignal{Target: record.Target, Kind: kind, ProfileID: profile.ProfileID, Provider: profile.Provider,
		CaptureID: record.ID, CaptureSHA256: record.Data.SHA256, ExitCode: &code, AdapterVersion: plan.Plan.Runner.AdapterVersion,
		ObservedAt: record.ObservedAt, UsageEvidence: &usage}, nil
}

// The fixture consumes the broker's real normalized output. It never writes a
// usage envelope or substitutes room=false for exhaustion/worker provenance.
func (r *enrolledFixtureRunner) fixtureUsage(ctx context.Context, plan api.LaunchPlanRecord, exit api.ProcessObservation) (api.ProfileGrant, api.BlobRef, error) {
	var profile api.ProfileGrant
	for _, grant := range plan.Inputs.Grants.Profiles {
		if grant.ID == plan.Plan.Runner.Slot.ProfileGrantID && grant.ProfileID == plan.Plan.Runner.Slot.ProfileID && grant.Driver == r.driver {
			if profile.ID != "" {
				return profile, api.BlobRef{}, fixtureError(api.CodeIntegrity, "fixture selected profile is ambiguous")
			}
			profile = grant
		}
	}
	if profile.ID == "" {
		return profile, api.BlobRef{}, fixtureError(api.CodeForbidden, "fixture selected profile is outside its retained delegation")
	}
	source := r.ports.UsageWindows
	provenance, ok := source.(api.UsageProvenanceSource)
	if source == nil || !ok {
		return profile, api.BlobRef{}, api.NotImplemented("lb-v2-secrets", "protected fixture outside usage worker")
	}
	query := api.UsageWindowRequest{Target: plan.Reservation.Target, LaunchID: plan.Reservation.LaunchID, OperationID: plan.Reservation.OperationID,
		ProfileGrantID: profile.ID, ProfileID: profile.ProfileID, Provider: profile.Provider, RunEndedAt: exit.ObservedAt,
		AdapterVersion: plan.Plan.Runner.AdapterVersion, Executable: plan.Plan.Runner.Executable, RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest}
	evidence, err := source.ReadUsageWindow(ctx, r.fixtureScope(), query)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	meta, err := r.ports.Store.ObjectMetadata(ctx, r.fixtureScope(), evidence.ID)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	producer, err := provenance.ReadUsageProvenance(ctx, r.fixtureScope(), meta.Ref)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	if producer.Evidence != meta.Ref || producer.Executable != query.Executable || producer.RuntimeManifest != query.RuntimeManifest || producer.Producer.Endpoint.Config != r.enrollment.Config {
		return profile, api.BlobRef{}, fixtureError(api.CodeIntegrity, "fixture usage provenance differs from the causing runtime")
	}
	bound, err := r.ports.Store.WorkerBinding(ctx, producer.Producer.Endpoint, producer.Producer.Peer)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	if !reflect.DeepEqual(bound, producer.Producer) {
		return profile, api.BlobRef{}, fixtureError(api.CodeIntegrity, "fixture usage worker differs from its native mapping")
	}
	if err := api.ValidateUsageWindow(evidence, query, bound, r.ports.Clock.Now()); err != nil {
		return profile, api.BlobRef{}, err
	}
	raw, err := r.fixtureUsageBytes(ctx, evidence.Raw, "usage_raw", query, bound)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	if err := api.ValidateUsageSource(evidence, raw, producer.VendorProfile); err != nil {
		return profile, api.BlobRef{}, err
	}
	data, err := r.fixtureUsageBytes(ctx, meta.Ref, "usage_window", query, bound)
	if err != nil {
		return profile, api.BlobRef{}, err
	}
	var committed api.UsageWindowEvidence
	reset, resetErr := time.Parse(time.RFC3339Nano, string(evidence.ResetsAt))
	if api.DecodeObject(data, &committed) != nil || !reflect.DeepEqual(committed, evidence) || resetErr != nil || !reset.After(r.ports.Clock.Now()) {
		return profile, api.BlobRef{}, fixtureError(api.CodeIntegrity, "fixture usage envelope differs from its retained current bytes")
	}
	return profile, meta.Ref, nil
}

func (r *enrolledFixtureRunner) fixtureUsageBytes(ctx context.Context, ref api.BlobRef, class string, cause api.UsageWindowRequest, producer api.WorkerPrincipal) (raw []byte, resultErr error) {
	if ref.Class != class || ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes || !isDigest(ref.SHA256) {
		return nil, fixtureError(api.CodeIntegrity, "fixture usage object has invalid bounds or class")
	}
	scope, release, err := objectread.Bind(ctx, r.ports.Store, r.fixtureScope())
	if err != nil {
		return nil, err
	}
	defer release(&resultErr)
	meta, err := r.ports.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return nil, err
	}
	if meta.Ref != ref || meta.ACL.Config != r.enrollment.Config || meta.ACL.LifeID != cause.Target.LifeID || meta.ACL.Audience != "service" || meta.ACL.Generation == 0 ||
		meta.ACL.Owner != producer.Record.Actor || len(meta.ACL.Participants) != 0 || meta.SourceOperationID != cause.OperationID || meta.Origin != "service" && meta.Origin != "worker" {
		return nil, fixtureError(api.CodeIntegrity, "fixture usage object lacks private worker provenance")
	}
	for int64(len(raw)) < ref.Bytes {
		q := api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(raw)), Limit: min(api.MaxChunkBytes, int(ref.Bytes-int64(len(raw))))}
		part, err := r.ports.Store.Blob(ctx, scope, q)
		if err != nil {
			return nil, err
		}
		if part.ObjectID != ref.ID || part.Offset != q.Offset || len(part.Data) == 0 || len(part.Data) > q.Limit || runDigest(part.Data) != part.SHA256 {
			return nil, fixtureError(api.CodeIntegrity, "fixture usage object range changed")
		}
		raw = append(raw, part.Data...)
	}
	if runDigest(raw) != ref.SHA256 {
		return nil, fixtureError(api.CodeIntegrity, "fixture usage object bytes changed")
	}
	return raw, nil
}
