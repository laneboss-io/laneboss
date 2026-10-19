package linux

import "laneboss.io/laneboss/internal/v2/api"

func materializeWorker(spec api.LaunchSpec) bool {
	return spec.Kind == "worker" && spec.Worker != nil && spec.Worker.Kind == "materialize"
}

// No paths are resolved here. The helper must find the actual child stage,
// narrow grant set and held storage descriptors under this worker lease.
func validateMaterializePlan(spec api.LaunchSpec) (api.ID, error) {
	if !materializeWorker(spec) || spec.Runner != nil || spec.Capture != nil || spec.PlanID != "" {
		return "", failure(api.CodeInvalid, "materialization requires its separate worker plan")
	}
	worker := spec.Worker
	argv := worker.Argv
	if len(argv) != 7 || argv[0] != "laneboss" || argv[1] != "internal" || argv[2] != "worker" ||
		argv[3] != "--binding" || argv[4] != "/runtime/laneboss-worker.json" || argv[5] != "--lease" ||
		!workerID.MatchString(argv[6]) {
		return "", failure(api.CodeInvalid, "materialization argv differs from the fixed child worker")
	}
	input := worker.Input
	inputID, executableID := string(input.ID), string(worker.Executable.ID)
	if worker.Schema != "laneboss.worker-plan.v2" || !workerID.MatchString(inputID) || !workerID.MatchString(executableID) ||
		validateBlob(input) != nil || input.Class != "materialize_input" || input.Bytes <= 0 || input.Bytes > api.MaxFrameBytes {
		return "", failure(api.CodeIntegrity, "materialization requires its bounded sealed input")
	}
	if err := validateMaterializeGrants(spec.Grants); err != nil {
		return "", err
	}
	return api.ID(argv[6]), nil
}

func validateMaterializeGrants(grants api.GrantSet) error {
	capabilities := len(grants.Resources)
	capabilities += len(grants.Secrets)
	capabilities += len(grants.Profiles)
	capabilities += len(grants.Network)
	capabilities += len(grants.Channels)
	if capabilities != 0 || len(grants.Data) != 1 {
		return failure(api.CodeForbidden, "materialization has capabilities outside its narrow data job")
	}
	source := grants.Data[0]
	parent := string(source.ParentGrantID)
	if !workerID.MatchString(parent) || source.Destination != "/job/source" || source.Access != "ro" ||
		source.RelativePath != "." || source.Delivery != "bind_ro" || source.HistoryScope != "tree" && source.HistoryScope != "reachable" {
		return failure(api.CodeForbidden, "materialization source is not its exact read-only projection")
	}
	return nil
}

func validateMaterializeRuntime(spec api.LaunchSpec, runtime api.ResolvedRuntime) error {
	lease, err := validateMaterializePlan(spec)
	if err != nil {
		return err
	}
	bindings := runtime.Manifest.Bindings
	if len(bindings) != 1 || bindings[0].Class != api.EndpointWorker || bindings[0].WorkerLeaseID != lease {
		return failure(api.CodeIntegrity, "materialization endpoint differs from its child worker lease")
	}
	executable := spec.Worker.Executable
	return validateEnrolledExecutable(executable, runtime)
}
