package linux

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func channelArgv(lease string) []string {
	return []string{"laneboss", "internal", "channel", "--binding", "/runtime/laneboss-worker.json", "--lease", lease}
}

func channelSpec() api.LaunchSpec {
	spec := fixtureSpec()
	spec.Worker.Kind, spec.Worker.Argv = "channel", channelArgv("channel-lease")
	spec.Worker.Input.Class, spec.RuntimeManifest.Class = "channel_input", "manifest"
	return spec
}

func TestChannelSpecGrammar(t *testing.T) {
	spec := channelSpec()
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("fixed channel metadata control:", err)
	}
	for _, fault := range []string{"command", "entry", "binding", "flag", "lease", "extra", "input", "input_id", "exe_id", "empty", "large", "agent"} {
		spec := channelSpec()
		switch fault {
		case "command":
			spec.Worker.Argv[0] = "/caller/worker"
		case "entry":
			spec.Worker.Argv[2] = "other"
		case "binding":
			spec.Worker.Argv[4] = "/caller/binding.json"
		case "flag":
			spec.Worker.Argv[5] = "--command"
		case "lease":
			spec.Worker.Argv[6] = "../foreign"
		case "extra":
			spec.Worker.Argv = append(spec.Worker.Argv, "extra")
		case "input":
			spec.Worker.Input.Class = "upload"
		case "input_id":
			spec.Worker.Input.ID = "/caller/input"
		case "exe_id":
			spec.Worker.Executable.ID = "/caller/executable"
		case "empty":
			spec.Worker.Input.Bytes = 0
		case "large":
			spec.Worker.Input.Bytes = api.MaxFrameBytes + 1
		case "agent":
			spec.PlanID = "agent-reservation"
		}
		if _, err := validateChannelPlan(spec); err == nil {
			t.Fatal("channel worker escaped its fixed grammar or input")
		}
	}
	spec = channelSpec()
	spec.Worker.Kind = "test"
	if validateSpec(spec, spec.RuntimeManifest, time.Now()) == nil {
		t.Fatal("channel grammar widened another worker's executable rules")
	}
}

func channelRuntimeMeta(t *testing.T, spec api.LaunchSpec) (api.PreparedSpecHandoff, api.ResolvedRuntime) {
	t.Helper()
	r, _ := planMeta(t)
	runtime := runtimeMeta(r)
	kind := api.InternalHelperRegister
	cause := fixtureCause(kind, spec.Target)
	handoff, _ := metaHandoff(t, spec, cause)
	runtime.Workspace = spec.Workspace
	runtime.SpecReceipt = api.PreparedSpecReceipt{SpecID: spec.ID, Config: handoff.Config, Target: spec.Target,
		LeaseID: spec.UIDLeaseID, SpecSHA256: handoff.SpecSHA256, RuntimeManifest: spec.RuntimeManifest, OperationID: handoff.OperationID}
	binding := &runtime.Manifest.Bindings[0]
	target := spec.Target
	binding.Class, binding.WorkerLeaseID = api.EndpointWorker, "channel-lease"
	binding.Target, binding.LaunchID, binding.EndpointGeneration = &target, spec.LaunchID, spec.EndpointGeneration
	object := &runtime.Manifest.Objects[0]
	object.ID, object.Content = spec.Worker.Executable.ID, fixtureBlob("exe")
	object.RelativePath = "bin/laneboss"
	return handoff, runtime
}

func TestChannelRuntimeBinding(t *testing.T) {
	spec := channelSpec()
	handoff, runtime := channelRuntimeMeta(t, spec)
	if err := validateRuntime(handoff, runtime); err != nil {
		t.Fatal("channel runtime projection metadata control:", err)
	}
	if err := validateChannelRuntime(spec, runtime); err != nil {
		t.Fatal("channel executable/lease metadata control:", err)
	}
	for _, fault := range []string{"lease", "class", "missing", "executable", "bytes"} {
		_, runtime := channelRuntimeMeta(t, spec)
		binding := &runtime.Manifest.Bindings[0]
		object := &runtime.Manifest.Objects[0]
		switch fault {
		case "lease":
			binding.WorkerLeaseID = "foreign-lease"
		case "class":
			runtime.Manifest.Bindings[0].Class = api.EndpointLane
		case "missing":
			runtime.Manifest.Bindings = nil
		case "executable":
			runtime.Manifest.Objects[0].ID = "foreign-executable"
		case "bytes":
			object.Content.SHA256 = fixtureBlob("foreign").SHA256
		}
		if validateChannelRuntime(spec, runtime) == nil {
			t.Fatal("channel runtime admitted a foreign lease or executable")
		}
	}
}
