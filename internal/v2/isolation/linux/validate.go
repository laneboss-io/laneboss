package linux

import (
	"encoding/hex"
	"path"
	"slices"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func validDigest(value api.Digest) bool {
	if len(value) != 64 || strings.ToLower(string(value)) != string(value) {
		return false
	}
	_, err := hex.DecodeString(string(value))
	return err == nil
}

func validateBlob(blob api.BlobRef) error {
	if blob.ID == "" || !validDigest(blob.SHA256) || blob.Bytes < 0 || blob.Class == "" {
		return failure(api.CodeInvalid, "invalid immutable blob reference")
	}
	return nil
}

func validLife(target api.LifeRef) bool { return target.LifeID != "" && target.Run > 0 }

func canonical(p string) bool {
	return path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

func within(p, root string) bool {
	return p == root || root == "/" || strings.HasPrefix(p, root+"/")
}

func overlaps(a, b string) bool { return within(a, b) || within(b, a) }

func notExpired(value api.Timestamp, now time.Time) bool {
	if value == "" {
		return true
	}
	expires, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && strings.HasSuffix(string(value), "Z") && expires.After(now)
}

func validateExecutable(executable api.Executable) error {
	if executable.ID == "" || executable.Version == "" || !validDigest(executable.SHA256) {
		return failure(api.CodeIntegrity, "runner executable must have a pinned identity, version and digest")
	}
	return nil
}

func validateSpec(spec api.LaunchSpec, runtime api.BlobRef, now time.Time) error {
	invalid := func(message string) error { return failure(api.CodeInvalid, message) }
	materialize := materializeWorker(spec)
	if spec.ID == "" || spec.LaunchID == "" || !validLife(spec.Target) ||
		spec.UIDLeaseID == "" || spec.EndpointGeneration == 0 || spec.PolicyGeneration == 0 {
		return invalid("launch requires immutable life, run, lease and generation identities")
	}
	if spec.Backend != backendName {
		return failure(api.CodeUnsupported, "the Linux launcher cannot launch another backend")
	}
	if spec.RuntimeManifest != runtime {
		allowAndLog("launch_runtime_manifest")
	}
	if spec.Workspace.ID == "" || !canonical(spec.Workspace.LogicalCWD) ||
		!within(spec.Workspace.LogicalCWD, "/work/main") {
		return invalid("launch requires an independent main workspace and logical cwd")
	}
	grants := spec.Grants
	if grants.ID == "" || grants.LifeID != spec.Target.LifeID || !validDigest(grants.SHA256) ||
		grants.Generation == 0 || grants.PolicyGeneration != spec.PolicyGeneration ||
		grants.Revoked || !notExpired(grants.ExpiresAt, now) {
		return failure(api.CodeForbidden, "launch grant authority is missing, stale or revoked")
	}
	if spec.Materialization.GrantSetID != grants.ID ||
		validateBlob(spec.Materialization.Manifest) != nil {
		return failure(api.CodeIntegrity, "launch materialization is not bound to the grant set")
	}
	seenIDs := map[api.ID]bool{}
	seenDest := []string{}
	for _, grant := range grants.Data {
		if grant.ID == "" || seenIDs[grant.ID] || grant.SourceObjectID == "" ||
			!validDigest(grant.SourceSHA256) || !notExpired(grant.ExpiresAt, now) ||
			(grant.Access != "ro" && grant.Access != "rw") ||
			(grant.Delivery != "copy" && grant.Delivery != "mount" && !(materialize && grant.Delivery == "bind_ro")) {
			return invalid("invalid, duplicate or expired data grant")
		}
		seenIDs[grant.ID] = true
		jobSource := materialize && grant.Destination == "/job/source"
		if !canonical(grant.Destination) || !jobSource &&
			(path.Dir(grant.Destination) != "/work" && path.Dir(grant.Destination) != "/data") {
			return invalid("grant destination must be a direct child of work or data")
		}
		for _, other := range seenDest {
			if overlaps(grant.Destination, other) {
				return invalid("ambiguous or overlapping grant destinations")
			}
		}
		seenDest = append(seenDest, grant.Destination)
		if grant.RelativePath == "" || path.IsAbs(grant.RelativePath) ||
			path.Clean(grant.RelativePath) != grant.RelativePath || grant.RelativePath == ".." ||
			strings.HasPrefix(grant.RelativePath, "../") || strings.ContainsRune(grant.RelativePath, 0) {
			return invalid("grant source path must remain beneath its registered object")
		}
	}
	materialized := map[api.ID]bool{}
	for _, object := range spec.Materialization.Objects {
		if !seenIDs[object.GrantID] || materialized[object.GrantID] ||
			object.WorkspaceID != spec.Workspace.ID || object.SourceIdentity == "" ||
			object.DestinationIdentity == "" || !validDigest(object.SnapshotSHA256) {
			return failure(api.CodeIntegrity, "materialization identities are incomplete or mismatched")
		}
		materialized[object.GrantID] = true
	}
	if len(materialized) != len(seenIDs) {
		return failure(api.CodeIntegrity, "not every data grant was materialized")
	}
	if spec.Budget.WallMS <= 0 || spec.Budget.Processes == 0 || spec.Budget.MemoryBytes == 0 ||
		spec.Budget.DiskBytes == 0 || spec.Budget.SpendMicros < 0 {
		return failure(api.CodeBudget, "bounded wall, process, memory, disk and nonnegative spend are required")
	}
	if err := validateNetworkGrants(grants.Network, now); err != nil {
		return err
	}
	var argv []string
	switch spec.Kind {
	case "agent":
		if spec.Runner == nil || spec.Worker != nil {
			return invalid("an agent requires exactly one runner plan")
		}
		runner := spec.Runner
		if runner.Driver != api.DriverCodex && runner.Driver != api.DriverClaudock {
			return failure(api.CodeForbidden, "only codex and claudock-cli are agent drivers")
		}
		if err := validateExecutable(runner.Executable); err != nil {
			return err
		}
		if runner.CWD != spec.Workspace.LogicalCWD || runner.AdapterVersion == "" ||
			runner.Home.ID == "" || runner.Home.WorkspaceID != spec.Workspace.ID ||
			runner.Home.HistoryID == "" || validateBlob(runner.Prompt) != nil {
			return invalid("runner cwd, private home, history and retained prompt are required")
		}
		if runner.InnerSandbox != "off" {
			return invalid("this launch path requires explicit inner sandbox off")
		}
		if runner.Session.ID != "" && (runner.Session.Driver != runner.Driver ||
			runner.Session.HomeID != runner.Home.ID || runner.Session.LogicalCWD != runner.CWD ||
			runner.Session.HistoryID != runner.Home.HistoryID) {
			return invalid("runner session does not match private home, history and cwd")
		}
		if runner.Slot.ID == "" || runner.Slot.LeaseID == "" || runner.Slot.ProfileGrantID == "" || runner.Slot.ProfileID == "" ||
			!notExpired(runner.Slot.ExpiresAt, now) {
			return failure(api.CodePrerequisite, "a live run-scoped credential slot is required")
		}
		profileFound := false
		for _, profile := range grants.Profiles {
			if profile.ID == runner.Slot.ProfileGrantID && profile.ProfileID == runner.Slot.ProfileID &&
				profile.Driver == runner.Driver && notExpired(profile.ExpiresAt, now) {
				profileFound = true
				if profile.Paid && spec.Budget.SpendMicros <= 0 {
					return failure(api.CodeBudget, "a paid profile requires a positive spend ceiling")
				}
			}
		}
		if !profileFound {
			return failure(api.CodeForbidden, "runner credential slot is outside this grant set")
		}
		if err := validateEnvironmentNames(runner.EnvironmentNames); err != nil {
			return err
		}
		argv = runner.Argv
	case "worker":
		if spec.Worker == nil || spec.Runner != nil || spec.Worker.Schema != "laneboss.worker-plan.v2" ||
			spec.Worker.GrantSetID != grants.ID || spec.Worker.Budget != spec.Budget || !workerKind(spec.Worker.Kind) {
			return invalid("a worker requires exactly one fixed leased worker plan")
		}
		if err := validateExecutable(spec.Worker.Executable); err != nil {
			return err
		}
		if err := validateBlob(spec.Worker.Input); err != nil {
			return err
		}
		argv = spec.Worker.Argv
	default:
		return invalid("unknown launch kind")
	}
	channel := spec.Kind == "worker" && spec.Worker.Kind == "channel"
	if channel {
		if _, err := validateChannelPlan(spec); err != nil {
			return err
		}
	}
	if materialize {
		if _, err := validateMaterializePlan(spec); err != nil {
			return err
		}
	}
	if len(argv) == 0 || !channel && !materialize && (!canonical(argv[0]) || argv[0] == "/") {
		return invalid("plan must name an absolute executable in the lane view")
	}
	for _, argument := range argv {
		if strings.ContainsRune(argument, 0) {
			return invalid("NUL in runner argument")
		}
	}
	return validateInjection(spec, now)
}

func validateInjection(spec api.LaunchSpec, now time.Time) error {
	injection := spec.Injection
	// The immutable agent spec precedes native projection. Readiness belongs
	// to the helper's acknowledged projection and live open guard, not this DTO.
	stage := "ready"
	if spec.Kind == "agent" {
		stage = "prepared"
	}
	if injection.Target != spec.Target || injection.Outcome != stage {
		return failure(api.CodePrerequisite, "a matching injection preparation receipt is required")
	}
	if err := validateEnvironmentNames(injection.TaskSecretNames); err != nil {
		return err
	}
	if len(injection.GrantIDs) != len(spec.Grants.Secrets) || len(injection.SourceVersions) != len(spec.Grants.Secrets) {
		return failure(api.CodeIntegrity, "injection grant/version inventory differs")
	}
	seen := map[api.ID]bool{}
	var environment, files []string
	for index, grant := range spec.Grants.Secrets {
		if grant.ID == "" || seen[grant.ID] || grant.Name == "" || grant.SourceHandle == "" || grant.Version == "" ||
			!notExpired(grant.ExpiresAt, now) || injection.GrantIDs[index] != grant.ID ||
			injection.SourceVersions[index] != grant.Version {
			return failure(api.CodeIntegrity, "injection is not bound to the current secret grant/version")
		}
		seen[grant.ID] = true
		switch grant.Delivery {
		case "env":
			environment = append(environment, grant.Target)
		case "file":
			if !relativeSecretFile(grant.Target) {
				return failure(api.CodeInvalid, "secret file target must remain beneath private runtime")
			}
			files = append(files, grant.Target)
		default:
			return failure(api.CodeInvalid, "unknown task secret delivery")
		}
	}
	if !slices.Equal(environment, injection.TaskSecretNames) || !slices.Equal(files, injection.TaskSecretFileNames) {
		return failure(api.CodeIntegrity, "injection delivery names differ from granted request order")
	}
	seenFiles := map[string]bool{}
	for _, name := range files {
		if seenFiles[name] {
			return failure(api.CodeInvalid, "duplicate secret file target")
		}
		seenFiles[name] = true
	}
	var slots []api.ID
	if spec.Runner != nil {
		slots = []api.ID{spec.Runner.Slot.ID}
		for _, grant := range spec.Grants.Secrets {
			task := api.AgentTaskSlotID(spec.PlanID, grant.ID)
			if task == "" {
				return failure(api.CodeIntegrity, "injection credential slots differ from the runner plan")
			}
			slots = append(slots, task)
		}
	}
	if !slices.Equal(slots, injection.SlotIDs) {
		return failure(api.CodeIntegrity, "injection credential slots differ from the runner plan")
	}
	return nil
}

func relativeSecretFile(name string) bool {
	return name != "" && name != "." && name != ".." && !path.IsAbs(name) &&
		path.Clean(name) == name && !strings.HasPrefix(name, "../") && !strings.ContainsRune(name, 0)
}

func validateNetworkGrants(grants []api.NetworkGrant, now time.Time) error {
	seen := map[api.ID]bool{}
	for _, grant := range grants {
		if grant.ID == "" || seen[grant.ID] || grant.EndpointID == "" || !notExpired(grant.ExpiresAt, now) ||
			grant.Mode != "internet" && grant.Mode != "service" && grant.Mode != "publish" {
			return failure(api.CodeForbidden, "network grant identity, mode or expiry is invalid")
		}
		seen[grant.ID] = true
	}
	return nil
}

// These are the frozen worker protocol kinds, not a command or syscall list.
func workerKind(kind string) bool {
	switch kind {
	case "test", "import", "export", "archive", "render", "box_run", "channel", "owner_sheet", "gateway",
		"capture", "usage", "materialize":
		return true
	}
	return false
}

func validateEnvironmentNames(names []string) error {
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] || reservedEnvironment(name) {
			return failure(api.CodeInvalid, "duplicate, reserved or empty environment name")
		}
		for index, c := range name {
			if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
				index > 0 && c >= '0' && c <= '9') {
				return failure(api.CodeInvalid, "invalid environment name")
			}
		}
		seen[name] = true
	}
	return nil
}

func reservedEnvironment(name string) bool {
	switch name {
	case "HOME", "PATH", "TMPDIR", "TMP", "TEMP", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME",
		"XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR",
		"CLAUDOCK_CREDENTIAL_STORE", "CLAUDOCK_REGISTRY_DIR", "BASH_ENV", "ENV":
		return true
	}
	for _, prefix := range []string{"LD_", "DYLD_", "LANEBOSS_"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
