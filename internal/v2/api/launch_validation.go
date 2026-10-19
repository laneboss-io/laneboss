package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

const launchMaxInteger = 1<<53 - 1

var launchObjectID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var launchGitBase = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)

func launchInvalid(message string) error {
	return &Error{Code: CodeInvalid, Owner: "lb-v2-integrate", Message: message,
		Instead: "Use the retained service-issued launch reservation, enrolled sources and exact recovery binding."}
}

func launchID(id ID) bool                { return launchObjectID.MatchString(string(id)) }
func launchGeneration(g Generation) bool { return g > 0 && g <= launchMaxInteger }
func launchBlob(ref BlobRef, class string) bool {
	return launchID(ref.ID) && bindingDigest.MatchString(string(ref.SHA256)) &&
		ref.Bytes > 0 && ref.Bytes <= MaxObjectBytes && ref.Class == class
}
func launchExecutable(executable Executable) bool {
	return launchID(executable.ID) && bindingDigest.MatchString(string(executable.SHA256)) && executable.Version != ""
}

func ValidateLaunchEnrollment(enrollment LaunchEnrollment, config string, manifest BlobRef) error {
	if enrollment.Schema != "laneboss.launch-enrollment.v2" || enrollment.Config != config || !bindingConfigName.MatchString(config) ||
		!launchGeneration(enrollment.Generation) || !launchBlob(manifest, "manifest") || len(enrollment.Projects) == 0 || len(enrollment.Runtimes) == 0 ||
		enrollment.Supervisor != nil && !launchExecutable(*enrollment.Supervisor) {
		return launchInvalid("invalid installed launch enrollment")
	}
	if len(enrollment.Network) > 1 {
		return launchInvalid("only the enrolled Anthropic API endpoint is supported")
	}
	for _, endpoint := range enrollment.Network {
		if endpoint.ID != "anthropic-api" || endpoint.Host != "api.anthropic.com" ||
			endpoint.Protocol != "tcp" || endpoint.Port != 443 || len(endpoint.HostAddresses) > 256 {
			return launchInvalid("network enrollment must name the exact Anthropic API endpoint")
		}
		for _, address := range endpoint.HostAddresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.Zone() != "" || ip.String() != address {
				return launchInvalid("invalid host address inventory")
			}
		}
	}
	ids, projects, drivers := map[ID]bool{}, map[ID]bool{}, map[Driver]bool{}
	for _, project := range enrollment.Projects {
		if !launchID(project.ID) || ids[project.ID] || !launchGeneration(project.Generation) || !launchID(project.ProjectID) ||
			projects[project.ProjectID] || !launchBlob(project.Object, "manifest") || !launchGitBase.MatchString(project.Base) ||
			project.HistoryScope != "tree" && project.HistoryScope != "reachable" {
			return launchInvalid("invalid or duplicate project enrollment")
		}
		ids[project.ID], projects[project.ProjectID] = true, true
	}
	for _, runtime := range enrollment.Runtimes {
		if !launchID(runtime.EnrollmentID) || ids[runtime.EnrollmentID] || !launchGeneration(runtime.Generation) || drivers[runtime.Driver] ||
			runtime.Driver != DriverClaudock && runtime.Driver != DriverCodex || !launchExecutable(runtime.Executable) || runtime.Manifest != manifest ||
			runtime.Backend != "linux-bwrap-landlock" && runtime.Backend != "darwin-seatbelt" {
			return launchInvalid("invalid or duplicate runtime enrollment")
		}
		ids[runtime.EnrollmentID], drivers[runtime.Driver] = true, true
	}
	return nil
}

// Shape checks never prove that a reservation was issued or an enrollment is
// current. Each consumer must reload those records under its real store claim.
func ValidateLaunchReservation(reservation LaunchReservation) error {
	r := reservation
	if !launchID(r.ID) || !bindingConfigName.MatchString(r.Config) || !launchID(r.Target.LifeID) ||
		r.Target.Run == 0 || r.Target.Run > launchMaxInteger || !launchID(r.LaunchID) || !launchID(r.SpecID) || !launchID(r.GrantSetID) ||
		r.ID == r.LaunchID || r.SpecID == r.LaunchID || r.ID == r.SpecID ||
		!launchGeneration(r.Generation) || !launchGeneration(r.PolicyGeneration) ||
		r.CancellationEpoch > launchMaxInteger || r.StarterEventSeq > launchMaxInteger ||
		!launchID(r.OperationID) || !launchID(r.RequestID) || !bindingDigest.MatchString(string(r.RequestSHA256)) ||
		!launchID(r.RequestedBy.ID) || !validReservationOriginal(r) || r.OriginalRequest.Bytes > MaxFrameBytes {
		return launchInvalid("invalid launch reservation shape")
	}
	switch r.Mode {
	case "start", "adopt":
		if r.Target.Run != 1 || r.BaseGeneration != 0 || r.Generation != 1 || r.PreviousLaunchID != "" ||
			r.RequestedBy.Kind != "human" && r.RequestedBy.Kind != "lane" {
			return launchInvalid("invalid new-life launch reservation")
		}
	case "resume", "turn", "continue":
		if r.Target.Run < 2 || !launchGeneration(r.BaseGeneration) || r.BaseGeneration >= launchMaxInteger ||
			r.Generation != r.BaseGeneration+1 || !launchID(r.PreviousLaunchID) || r.PreviousLaunchID == r.LaunchID ||
			r.RequestedBy.Kind != "human" && r.RequestedBy.Kind != "lane" && r.RequestedBy.Kind != "service" &&
				r.RequestedBy.Kind != "scheduler" && r.RequestedBy.Kind != "watchdog" {
			return launchInvalid("invalid retained-life launch reservation")
		}
	default:
		return launchInvalid("unknown launch reservation mode")
	}
	if r.Level < 3 || r.Level > 6 || !launchID(ID(r.Role)) || r.Driver != DriverClaudock && r.Driver != DriverCodex || !launchID(r.Authority.ID) {
		return launchInvalid("reservation lacks its child role or consumed authority")
	}
	if r.Loop != nil {
		if !validLoopReservation(r) {
			return launchInvalid("invalid scheduler loop reservation")
		}
	} else if r.RequestedBy.Kind == "scheduler" && r.Mode != "continue" {
		return launchInvalid("scheduler turn lacks its private loop cause")
	} else if r.Mode == "continue" {
		if r.Authority.Kind != "starter" || r.Authority.ID != r.PreviousLaunchID {
			return launchInvalid("continuation lacks its retained launch authority")
		}
	} else if r.RequestedBy.Kind == "human" {
		if r.Mode == "start" || r.Mode == "adopt" {
			if r.Authority.Kind != "ticket" || r.ParentLifeID != "" {
				return launchInvalid("human root reservation lacks its consumed ticket")
			}
		} else if r.Authority.Kind != "proof" {
			return launchInvalid("human reservation lacks its consumed proof")
		}
	} else if r.Authority.Kind != "starter" {
		return launchInvalid("lane reservation carries human authority")
	}
	if (r.Mode == "start" || r.Mode == "adopt") && r.RequestedBy.Kind == "lane" &&
		(r.RequestedBy.Level > 6 || r.Level >= r.RequestedBy.Level || r.ParentLifeID != r.RequestedBy.LifeID) {
		return launchInvalid("reserved child exceeds its authentic starter level")
	}
	if !launchID(r.RootLifeID) || r.ParentLifeID == "" && (r.RootLifeID != r.Target.LifeID || len(r.StarterChain) != 0 || r.StarterEventSeq != 0) ||
		r.ParentLifeID != "" && (!launchID(r.ParentLifeID) || r.StarterEventSeq == 0 || len(r.StarterChain) == 0 ||
			r.StarterChain[0] != r.RootLifeID || r.StarterChain[len(r.StarterChain)-1] != r.ParentLifeID) {
		return launchInvalid("invalid launch reservation ancestry")
	}
	seen := map[ID]bool{r.Target.LifeID: true}
	for _, ancestor := range r.StarterChain {
		if !launchID(ancestor) || seen[ancestor] {
			return launchInvalid("invalid launch reservation ancestry")
		}
		seen[ancestor] = true
	}
	return nil
}

func validateLaunchInputs(r LaunchReservation, inputs LaunchInputs) error {
	g, sources := inputs.Grants, inputs.Sources
	p, runtime := sources.Project, sources.Runtime
	if g.ID != r.GrantSetID || g.LifeID != r.Target.LifeID || g.ParentLifeID != r.ParentLifeID ||
		!launchGeneration(g.Generation) || g.PolicyGeneration != r.PolicyGeneration || g.Revoked || g.ExpiresAt == "" ||
		!bindingDigest.MatchString(string(g.SHA256)) || sources.ReservationID != r.ID ||
		r.Loop != nil && g.Generation != r.Loop.GrantGeneration {
		return launchInvalid("launch inputs differ from reserved child grants")
	}
	if !launchID(p.EnrollmentID) || !launchGeneration(p.Generation) || !launchID(p.ProjectID) || !launchID(p.GrantID) ||
		!launchBlob(p.Object, "manifest") || !launchGitBase.MatchString(p.Base) ||
		p.HistoryScope != "tree" && p.HistoryScope != "reachable" ||
		!launchID(runtime.EnrollmentID) || !launchGeneration(runtime.Generation) || !launchExecutable(runtime.Executable) ||
		!launchBlob(runtime.Manifest, "manifest") || runtime.Driver != DriverClaudock && runtime.Driver != DriverCodex ||
		runtime.Backend != "linux-bwrap-landlock" && runtime.Backend != "darwin-seatbelt" {
		return launchInvalid("invalid enrolled launch sources")
	}
	main := 0
	for _, grant := range g.Data {
		if grant.ID == p.GrantID && grant.SourceObjectID == p.Object.ID && grant.SourceSHA256 == p.Object.SHA256 &&
			grant.Destination == "/work/main" && grant.HistoryScope == p.HistoryScope {
			main++
		}
	}
	if main != 1 {
		return launchInvalid("project source is not the unique granted main workspace")
	}
	return nil
}

func ValidateLaunchPlan(plan LaunchPlan) (resultErr error) {
	check := "pv_reservation"
	defer func() { resultErr = WithHelperReason(resultErr, check) }()
	r, inputs, data := plan.Reservation, plan.Inputs, plan.Data
	if err := ValidateLaunchReservation(r); err != nil {
		return err
	}
	check = "pv_inputs"
	if err := validateLaunchInputs(r, inputs); err != nil {
		return err
	}
	check = "pv_lease"
	if !launchID(plan.Lease.ID) || plan.Lease.UID == 0 || plan.Lease.GID == 0 ||
		!launchID(plan.Lease.ContainmentID) || !launchGeneration(plan.Lease.EndpointGeneration) ||
		data.ReservationID != r.ID || data.Target != r.Target || data.LeaseID != plan.Lease.ID || data.Source != inputs.Sources.Project {
		return launchInvalid("launch data differs from reserved lease or source")
	}
	w, home := data.Workspace, data.Home
	check = "pv_storage"
	if !launchID(w.ID) || w.ProjectID != data.Source.ProjectID || w.Base != data.Source.Base ||
		w.Branch != "lane/"+string(r.Target.LifeID) || w.LogicalCWD != "/work/main" || !launchBlob(w.Snapshot, "manifest") ||
		home.LifeID != r.Target.LifeID || !launchID(home.RootID) || home.RootID == w.ID || !launchGeneration(home.Generation) ||
		!launchID(home.Home.ID) || home.Home.WorkspaceID != w.ID || !launchID(home.Home.HistoryID) ||
		home.Home.VendorDirectory == "" || path.IsAbs(home.Home.VendorDirectory) ||
		path.Clean(home.Home.VendorDirectory) != home.Home.VendorDirectory || home.Home.VendorDirectory == "." ||
		home.Home.VendorDirectory == ".." || strings.HasPrefix(home.Home.VendorDirectory, "../") || strings.ContainsRune(home.Home.VendorDirectory, 0) {
		return launchInvalid("invalid private workspace or home binding")
	}
	materialization := data.Materialization
	check = "pv_material"
	if materialization.GrantSetID != inputs.Grants.ID || !launchBlob(materialization.Manifest, "manifest") {
		return launchInvalid("materialization differs from launch grants")
	}
	main := 0
	check = "pv_receipt"
	for _, object := range materialization.Objects {
		if object.GrantID == data.Source.GrantID && object.WorkspaceID == w.ID &&
			object.SourceIdentity != "" && object.DestinationIdentity != "" && object.SnapshotSHA256 == w.Snapshot.SHA256 {
			main++
		}
	}
	if main != 1 {
		return launchInvalid("launch workspace has no unique materialization receipt")
	}
	runner := plan.Runner
	check = "pv_runner"
	if runner.Driver != r.Driver || runner.Driver != inputs.Sources.Runtime.Driver || runner.Executable != inputs.Sources.Runtime.Executable ||
		runner.Home != home.Home || runner.CWD != w.LogicalCWD || len(runner.Argv) == 0 || runner.AdapterVersion == "" ||
		!launchBlob(runner.Prompt, "prompt") || runner.Session.Driver != runner.Driver || !launchID(runner.Session.ID) ||
		runner.Session.HomeID != home.Home.ID || runner.Session.HistoryID != home.Home.HistoryID ||
		runner.Session.LogicalCWD != w.LogicalCWD || runner.Session.VendorVersion == "" ||
		r.Target.Run > 1 && runner.Session.VendorID == "" {
		return launchInvalid("runner differs from enrolled runtime or private session")
	}
	check = "pv_loop"
	if r.Loop != nil && (plan.Budget != r.Loop.BudgetRemaining ||
		home.RootID != r.Loop.PreviousHome.RootID || home.Home != r.Loop.PreviousHome.Home || home.Generation < r.Loop.PreviousHome.Generation ||
		runner.Session.ID != r.Loop.PreviousSession.ID || runner.Session.HistoryID != r.Loop.PreviousSession.HistoryID ||
		runner.Session.HomeID != r.Loop.PreviousSession.HomeID ||
		r.Loop.PreviousSession.VendorID != "" && runner.Session.VendorID != r.Loop.PreviousSession.VendorID) {
		return launchInvalid("loop launch plan differs from its retained loop cause")
	}
	selected := 0
	check = "pv_credentials"
	for _, grant := range inputs.Grants.Profiles {
		if grant.ID == runner.Slot.ProfileGrantID && grant.ProfileID == runner.Slot.ProfileID && grant.Driver == runner.Driver {
			selected++
		}
	}
	if selected != 1 || !launchID(runner.Slot.ID) || !launchID(runner.Slot.LeaseID) || runner.Slot.ExpiresAt == "" ||
		plan.Injection.Target != r.Target || !slices.Contains(plan.Injection.SlotIDs, runner.Slot.ID) {
		return launchInvalid("runner credentials differ from reserved profile grants")
	}
	check = "pv_capture"
	if err := ValidateCaptureBinding(plan.Capture); err != nil {
		return err
	}
	if plan.Capture.Status == "refused" {
		check = "pv_cap_policy"
		if plan.CapturePolicy == nil || plan.CapturePolicy.Generation != r.PolicyGeneration {
			return launchInvalid("launch capture refusal lacks its policy snapshot")
		}
		check = "pv_cap_rule"
		if err := ValidateCapturePolicy(plan.Capture, *plan.CapturePolicy); err != nil {
			return err
		}
	}
	capture := plan.Capture
	check = "pv_cap_binding"
	if capture.ReservationID != r.ID || capture.Config != r.Config || capture.Target != r.Target || capture.LaunchID != r.LaunchID ||
		capture.HelperLeaseID != plan.Lease.ID || capture.OperationID != r.OperationID || capture.RequestID != r.RequestID || capture.RequestedBy != r.RequestedBy {
		return launchInvalid("capture differs from the reserved launch")
	}
	return nil
}

func ValidateAgentLaunchSpec(spec LaunchSpec, plan LaunchPlan) error {
	if err := ValidateLaunchPlan(plan); err != nil {
		return err
	}
	r := plan.Reservation
	if spec.Kind != "agent" || spec.Worker != nil || spec.Runner == nil || spec.Capture == nil ||
		spec.PlanID != r.ID || spec.ID != r.SpecID || spec.LaunchID != r.LaunchID || spec.Target != r.Target ||
		spec.UIDLeaseID != plan.Lease.ID || spec.Backend != plan.Inputs.Sources.Runtime.Backend ||
		spec.EndpointGeneration != plan.Lease.EndpointGeneration || spec.PolicyGeneration != r.PolicyGeneration ||
		spec.RuntimeManifest != plan.Inputs.Sources.Runtime.Manifest || spec.Workspace != plan.Data.Workspace ||
		!reflect.DeepEqual(*spec.Runner, plan.Runner) || !reflect.DeepEqual(spec.Grants, plan.Inputs.Grants) ||
		!reflect.DeepEqual(spec.Materialization, plan.Data.Materialization) || !reflect.DeepEqual(spec.Injection, plan.Injection) ||
		spec.Budget != plan.Budget || !reflect.DeepEqual(*spec.Capture, plan.Capture) {
		return launchInvalid("agent spec differs from the retained launch plan")
	}
	return nil
}

func launchCanonical(value any) ([]byte, Digest, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return canonical, Digest(hex.EncodeToString(sum[:])), nil
}

func validateLaunchHandoff(handoff PreparedSpecHandoff, plan LaunchPlan) error {
	if err := ValidateAgentLaunchSpec(handoff.Spec, plan); err != nil {
		return err
	}
	r, cause := plan.Reservation, handoff.Cause
	canonical, digest, err := launchCanonical(handoff.Spec)
	if err != nil || handoff.Config != r.Config || handoff.OperationID != r.OperationID || handoff.RequestID != r.RequestID ||
		cause.Kind != InternalHelperRegister || !launchID(cause.ID) || cause.Config != r.Config ||
		cause.Actor.Kind != "service" || !launchID(cause.Actor.ID) || cause.RequestedBy != r.RequestedBy ||
		cause.Target != r.Target || cause.CauseOperationID != r.OperationID || cause.CauseRequestID != r.RequestID ||
		!launchID(cause.EffectID) || cause.CancellationEpoch != r.CancellationEpoch || handoff.SpecSHA256 != digest ||
		!launchBlob(handoff.Original, "launch_spec") || handoff.Original.SHA256 != digest || handoff.Original.Bytes != int64(len(canonical)) {
		return launchInvalid("launch handoff differs from retained spec or request")
	}
	return nil
}

func ValidateLaunchPlanRecord(record LaunchPlanRecord) error {
	if err := ValidateLaunchReservation(record.Reservation); err != nil {
		return err
	}
	if !launchGeneration(record.Generation) {
		return launchInvalid("invalid launch plan revision")
	}
	if record.Inputs != nil {
		if err := validateLaunchInputs(record.Reservation, *record.Inputs); err != nil {
			return err
		}
	}
	if record.Plan != nil {
		if record.Inputs == nil || !reflect.DeepEqual(record.Plan.Reservation, record.Reservation) || !reflect.DeepEqual(record.Plan.Inputs, *record.Inputs) {
			return launchInvalid("launch plan projection changed its reservation or inputs")
		}
		if err := ValidateLaunchPlan(*record.Plan); err != nil {
			return err
		}
	}
	if record.Handoff != nil {
		if record.Plan == nil {
			return launchInvalid("launch handoff has no retained plan")
		}
		if err := validateLaunchHandoff(*record.Handoff, *record.Plan); err != nil {
			return err
		}
	}
	valid := false
	switch record.Phase {
	case "reserved":
		valid = record.Inputs == nil && record.Plan == nil && record.Handoff == nil
	case "sourced":
		valid = record.Inputs != nil && record.Plan == nil && record.Handoff == nil
	case "planned":
		valid = record.Plan != nil && record.Handoff == nil
	case "spec_retained", "bound", "opened":
		valid = record.Handoff != nil
	case "failed":
		valid = record.Error != nil && record.Error.Code != "" && record.Error.Owner != ""
	}
	if !valid || record.Phase != "failed" && record.Error != nil {
		return launchInvalid("invalid launch plan phase")
	}
	return nil
}

func validLaunchPlanWrite(tx Transaction, record LaunchPlanRecord) bool {
	return validLaunchPlanWriteMode(tx, record, false)
}

// Only ValidateFailedPlanWrite enters cleanup mode and checks the whole batch.
// Ordinary Transact cannot publish a planner failure without that batch.
func validLaunchPlanWriteMode(tx Transaction, record LaunchPlanRecord, cleanup bool) bool {
	r, cause := record.Reservation, tx.Internal
	if cause == nil || cause.Config != r.Config || cause.Target != r.Target || cause.CauseOperationID != r.OperationID ||
		cause.CauseRequestID != r.RequestID || cause.RequestedBy != r.RequestedBy || cause.CancellationEpoch != r.CancellationEpoch ||
		cause.Actor.Kind != "service" || !launchID(cause.Actor.ID) || !launchID(cause.EffectID) {
		return false
	}
	if cause.Kind == InternalLaunchPlan && record.Phase == "failed" && !cleanup {
		return false
	}
	if r.Loop != nil && (cause.LogicalTurnID != r.Loop.LogicalTurnID ||
		cause.Kind == InternalLaunchPlan && cause.EffectID != r.Loop.PlanEffectID) {
		return false
	}
	allowed := cause.Kind == InternalLaunchPlan && (record.Phase == "sourced" || record.Phase == "planned" || record.Phase == "spec_retained" || record.Phase == "failed") ||
		cause.Kind == InternalHelperPrepare && record.Phase == "bound" ||
		cause.Kind == InternalHelperOpen && record.Phase == "opened" ||
		cause.Kind == InternalHelperAbort && record.Phase == "failed"
	cas, cancellation := false, false
	for _, compare := range tx.Compare {
		cas = cas || compare.Kind == CompareLaunchPlan && compare.ID == r.ID && launchGeneration(compare.Generation) &&
			compare.Generation < launchMaxInteger && record.Generation == compare.Generation+1
	}
	for _, guard := range tx.Guards {
		cancellation = cancellation || guard.Cancellation != nil && guard.Cancellation.LifeID == r.Target.LifeID && guard.Cancellation.Epoch == r.CancellationEpoch
	}
	if record.Phase == "bound" {
		bound, lane, lifeCAS := false, false, false
		for _, binding := range tx.Writes.IdentityBindings {
			bound = bound || binding.Record.ID == r.LaunchID && binding.Record.Target == r.Target && binding.Prepared.Target == r.Target &&
				binding.Recovery != nil && binding.Recovery.PlanID == r.ID && binding.Recovery.OriginalRequest == r.OriginalRequest &&
				reflect.DeepEqual(binding.Recovery.Handoff, *record.Handoff) && binding.Recovery.Home == record.Plan.Data.Home &&
				reflect.DeepEqual(binding.Recovery.Capture, record.Plan.Capture)
		}
		for _, projection := range tx.Writes.Lanes {
			lane = lane || projection.LifeID == r.Target.LifeID && projection.Run == r.Target.Run &&
				projection.Generation == r.Generation && projection.GrantSetID == r.GrantSetID && projection.LaunchID == r.LaunchID &&
				(r.Loop == nil || projection.LogicalTurnID == r.Loop.LogicalTurnID)
		}
		for _, compare := range tx.Compare {
			lifeCAS = lifeCAS || compare.Kind == CompareLane && compare.ID == r.Target.LifeID && compare.Generation == r.BaseGeneration
		}
		if !bound || !lane || !lifeCAS {
			return false
		}
	}
	return allowed && cas && cancellation
}

// The identity/helper consumers must additionally read back the exact tuple
// from LaunchBinding, check its committed event and recheck current authority.
func ValidateLaunchBindingPlan(binding LaunchBindingRequest, plan LaunchPlan) error {
	if binding.Recovery == nil {
		return launchInvalid("agent launch binding has no recovery record")
	}
	recovery, r := binding.Recovery, plan.Reservation
	if err := validateLaunchHandoff(recovery.Handoff, plan); err != nil {
		return err
	}
	record, prepared, identity := binding.Record, binding.Prepared, binding.Identity
	_, recordDigest, err := launchCanonical(record)
	if err != nil || recovery.PlanID != r.ID || recovery.OriginalRequest != r.OriginalRequest || recovery.Home != plan.Data.Home ||
		!reflect.DeepEqual(recovery.Capture, plan.Capture) || record.Kind != "agent" || record.ID != r.LaunchID || record.Config != r.Config || record.Target != r.Target ||
		record.ParentLifeID != r.ParentLifeID || record.RootLifeID != r.RootLifeID || !slices.Equal(record.StarterChain, r.StarterChain) ||
		record.StarterEventSeq != r.StarterEventSeq || record.Actor.Kind != "lane" || record.Actor.Level != r.Level || record.Actor.Role != r.Role ||
		record.Actor.LifeID != r.Target.LifeID || !launchID(record.Actor.ID) ||
		record.UIDLeaseID != plan.Lease.ID || record.HostUID != plan.Lease.UID || record.ContainmentID != plan.Lease.ContainmentID ||
		record.GrantSetID != plan.Inputs.Grants.ID || record.GrantsSHA256 != plan.Inputs.Grants.SHA256 || record.PolicyGeneration != r.PolicyGeneration ||
		record.EndpointGeneration != plan.Lease.EndpointGeneration || record.Revoked || !launchID(prepared.ID) || prepared.ID == record.ID ||
		prepared.Target != r.Target || prepared.SpecSHA256 != recovery.Handoff.SpecSHA256 || prepared.ContainmentID != record.ContainmentID ||
		prepared.EndpointGeneration != record.EndpointGeneration || !launchID(prepared.GateID) || prepared.ProcessGeneration == "" ||
		prepared.ProcessGeneration != record.ProcessGeneration || identity.LaunchID != record.ID || !launchID(identity.EventID) ||
		identity.CommittedSeq == 0 || identity.RecordSHA256 != recordDigest {
		return launchInvalid("launch recovery differs from its committed identity binding")
	}
	return nil
}
