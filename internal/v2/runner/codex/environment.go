package codex

import (
	"bytes"
	"slices"
	"sort"

	"laneboss.io/laneboss/internal/v2/api"
)

// FinalEnvironment is the native helper's final vendor-exec adapter. Values
// stay in its private buffers until the actual post-drop, post-isolation facts
// pass the shared gate. Never call it to build a helper/bootstrap/bwrap envp.
// The native owner supplies observations; this function measures no kernel fact
// and does not replace the one-use OpenGate/exec acknowledgement.
func FinalEnvironment(record api.CredentialProjectionRecord, observed api.CredentialExecEnvironment, home api.PrivateHome, searchPath string, task map[string][]byte) ([]string, error) {
	r := record.Authority.Request
	runner := r.Handoff.Spec.Runner
	if runner == nil || runner.Driver != api.DriverCodex || runner.Slot.Mode != "codex-file" ||
		runner.Home != r.Home.Home || home.ID != runner.Home.ID || home.HistoryID != runner.Home.HistoryID || home.WorkspaceID != runner.Home.WorkspaceID {
		return nil, problem(api.CodeIntegrity, "Codex final environment differs from its held private home")
	}
	fixed, err := Environment(home, searchPath)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, target := range record.Authority.Targets {
		if target.Delivery == "env" && target.SlotID == "" {
			selected[target.EnvironmentName] = true
		}
	}
	if len(task) != len(selected) {
		return nil, problem(api.CodeIntegrity, "Codex final environment changed the selected task values")
	}
	names := environmentNames()
	for name, value := range task {
		if !selected[name] || bytes.IndexByte(value, 0) >= 0 {
			return nil, problem(api.CodeIntegrity, "Codex final environment has an unselected or invalid task value")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	actual := slices.Clone(observed.VendorNames)
	sort.Strings(actual)
	if !slices.Equal(names, actual) {
		return nil, problem(api.CodeIntegrity, "Codex final environment differs from observed vendor names")
	}
	if err := api.ValidateCredentialEnvironment(record, observed); err != nil {
		return nil, dependencyError(err)
	}
	// This is the sole point at which task values enter an envp. The caller now
	// performs the existing final unprivileged execve, with no intervening exec.
	result := slices.Clone(fixed)
	for _, name := range names {
		if selected[name] {
			result = append(result, name+"="+string(task[name]))
		}
	}
	return result, nil
}
