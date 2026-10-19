package linux

import (
	"regexp"

	"laneboss.io/laneboss/internal/v2/api"
)

const workerIDPattern = `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`

var workerID = regexp.MustCompile(workerIDPattern)

// This is the fixed worker entry's protocol grammar, not an agent tool list.
// The helper must independently resolve the executable and the current lease.
func validateChannelPlan(spec api.LaunchSpec) (api.ID, error) {
	worker := spec.Worker
	if spec.Kind != "worker" || worker == nil || spec.Runner != nil ||
		worker.Kind != "channel" || worker.Schema != "laneboss.worker-plan.v2" ||
		spec.PlanID != "" || spec.Capture != nil {
		return "", failure(api.CodeInvalid, "channel requires the separate fixed worker plan")
	}
	argv := worker.Argv
	if len(argv) != 7 || argv[0] != "laneboss" || argv[1] != "internal" || argv[2] != "channel" ||
		argv[3] != "--binding" || argv[4] != "/runtime/laneboss-worker.json" || argv[5] != "--lease" ||
		!workerID.MatchString(argv[6]) {
		return "", failure(api.CodeInvalid, "channel worker argv differs from its fixed lease grammar")
	}
	input := worker.Input
	inputID, executableID := string(input.ID), string(worker.Executable.ID)
	if !workerID.MatchString(inputID) || !workerID.MatchString(executableID) ||
		validateBlob(input) != nil || input.Class != "channel_input" || input.Bytes <= 0 || input.Bytes > api.MaxFrameBytes {
		return "", failure(api.CodeIntegrity, "channel worker lacks its bounded sealed input reference")
	}
	return api.ID(argv[6]), nil
}

func validateChannelRuntime(spec api.LaunchSpec, runtime api.ResolvedRuntime) error {
	lease, err := validateChannelPlan(spec)
	if err != nil {
		return err
	}
	bindings := runtime.Manifest.Bindings
	if len(bindings) != 1 || bindings[0].Class != api.EndpointWorker || bindings[0].WorkerLeaseID != lease {
		return failure(api.CodeIntegrity, "channel runtime endpoint differs from the fixed worker lease")
	}
	executable := spec.Worker.Executable
	return validateEnrolledExecutable(executable, runtime)
}
