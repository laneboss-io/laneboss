package claudock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func refusedPlan(t *testing.T, plan api.RunnerPlan, err error, reason string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code == api.CodeNotImplemented || len(plan.Argv) != 0 {
		t.Fatal(reason, err)
	}
}

func launchReason(t *testing.T, err error, expected, assertion string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Message != expected {
		t.Fatal(assertion, err)
	}
}

func TestLaunchReservationGuards(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	selector, record, err := f.service.retainedLaunch(ctx, f.request.Target)
	if err != nil {
		t.Fatal(err)
	}
	if record.Reservation.Target != f.request.Target {
		t.Fatal("valid reserved lookup changed its child")
	}
	for _, field := range []string{"reservation", "config", "child", "scope"} {
		t.Run(field, func(t *testing.T) {
			r := record
			r.Phase, r.Plan, r.Handoff = "sourced", nil, nil
			inputs := *record.Inputs
			r.Inputs = &inputs
			s := selector
			switch field {
			case "reservation":
				r.Reservation.ID = "other-plan"
				r.Inputs.Sources.ReservationID = r.Reservation.ID
			case "config":
				r.Reservation.Config = "other"
			case "child":
				r.Reservation.Target.LifeID, r.Reservation.RootLifeID, r.Inputs.Grants.LifeID = "other-life", "other-life", "other-life"
			case "scope":
				s.Scope.Config = "other"
			}
			f.launch.write("plan-"+string(selector.ReservationID), r)
			f.launch.write("index-life-a-1", s)
			_, _, err := f.service.retainedLaunch(ctx, f.request.Target)
			if err == nil {
				t.Fatal("foreign launch reservation reached the adapter: " + field)
			}
			expected := "runner lookup returned a foreign reservation"
			if field == "scope" {
				expected = "runner lookup lacks its installed service scope"
			}
			launchReason(t, err, expected, "foreign reservation lost the deciding fence: "+field)
			f.launch.write("plan-"+string(selector.ReservationID), record)
			f.launch.write("index-life-a-1", selector)
		})
	}
}

func TestPlanningGuards(t *testing.T) {
	for _, field := range []string{"executable", "path", "claim", "epoch", "policy", "grants", "enrollment", "storage", "prompt", "original", "umask"} {
		t.Run(field, func(t *testing.T) {
			f := runnerSetup(t)
			ctx := context.Background()
			selector, record, err := f.service.retainedLaunch(ctx, f.request.Target)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "executable":
				f.request.Executable.ID = "caller-executable"
				f.launch.retainRun(f.request)
			case "path":
				f.request.Home.VendorDirectory = "../shared"
			case "claim", "epoch":
				effect, err := f.launch.Effect(ctx, selector.Scope, selector.EffectID)
				if err != nil {
					t.Fatal(err)
				}
				if field == "claim" {
					effect.ClaimID = "stale-claim"
				} else {
					effect.Effect.Context.CancellationEpoch++
				}
				f.launch.write("effect-"+string(selector.EffectID), effect)
			case "policy":
				policy := f.launch.policy
				policy.Generation++
				f.launch.write("policy", policy)
			case "grants":
				grants := record.Inputs.Grants
				grants.Revoked = true
				f.launch.write("grants-"+string(grants.ID), grants)
			case "enrollment":
				sources := record.Inputs.Sources
				sources.Runtime.Generation++
				f.launch.write("enrolled-"+string(selector.ReservationID), sources)
			case "storage":
				storage, err := f.launch.ResolveLaunchStorage(ctx, api.LaunchDataRequest{ReservationID: selector.ReservationID, GrantSetID: record.Reservation.GrantSetID, LeaseID: selector.HelperLeaseID})
				if err != nil {
					t.Fatal(err)
				}
				storage.Home.RootID = "caller-root"
				f.launch.write("storage-"+string(selector.ReservationID), storage)
			case "prompt":
				metadata, err := f.launch.ObjectMetadata(ctx, selector.Scope, f.request.Prompt.ID)
				if err != nil {
					t.Fatal(err)
				}
				metadata.Origin = "observation"
				f.launch.write("meta-"+string(metadata.Ref.ID), metadata)
			case "original":
				put(t, filepath.Join(f.launch.dir, string(record.Reservation.OriginalRequest.ID)+".bytes"), []byte("changed retained frame"))
			case "umask":
				f.launch.write("bootstrap", struct{ Umask uint32 }{0022})
			}
			plan, err := f.service.Start(ctx, f.request)
			refusedPlan(t, plan, err, "invalid planning input produced runner argv: "+field)
			expected := map[string]string{
				"executable": "run and pinned vendor identities differ",
				"path":       "runner identity, prompt, private home and explicit session are required",
				"claim":      "runner planning lost its current effect claim or cancellation fence",
				"epoch":      "runner planning lost its current effect claim or cancellation fence",
				"policy":     "runner policy or grants changed after reservation",
				"grants":     "runner policy or grants changed after reservation",
				"enrollment": "runner differs from its current enrolled runtime",
				"storage":    "runner storage changed after its plan was retained",
				"prompt":     "runner object lacks protected provenance",
				"original":   "runner object read changed its exact byte range",
				"umask":      "fixture bootstrap lacks private vendor umask",
			}[field]
			launchReason(t, err, expected, "planning lost the deciding fence: "+field)
		})
	}
}

func TestRunnerReplayAndRestart(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	first, err := f.service.Start(ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(f.service.deps)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Start(ctx, f.request)
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatal("restart did not replay the retained runner plan", err)
	}
	original := f.request
	f.request.Prompt = f.launch.object("changed-prompt", "prompt", []byte("changed retained prompt"), "operation-1", "life-a")
	f.launch.retainRun(f.request)
	plan, err := service.Start(ctx, f.request)
	refusedPlan(t, plan, err, "changed replay produced runner argv")
	launchReason(t, err, "launch replay changed its immutable inputs", "changed replay escaped its retained input seal")
	f.request = original
	f.launch.retainRun(original)
	f.history(t)
	f.request.Target.Run = 2
	f.sourceLaunch(t, "resume")
	if err := os.Remove(filepath.Join(f.launch.dir, "binding-launch-1.json")); err != nil {
		t.Fatal(err)
	}
	plan, err = service.Resume(ctx, f.request)
	refusedPlan(t, plan, err, "restart invented a missing previous launch binding")
	launchReason(t, err, "fixture retained object is absent", "restart did not read the retained previous binding")
}

func TestProducerBoundCapture(t *testing.T) {
	control := runnerSetup(t)
	control.installLimitGuard()
	for _, stream := range []string{"stdout", "vendor"} {
		capture := control.setCapture(encodeEvent(t, control.initEvent()), stream)
		if session, err := control.service.SessionFromCapture(context.Background(), capture); err != nil || session != control.request.Session {
			t.Fatal("registered vendor stream did not establish its retained session", stream, err)
		}
		capture = control.setCapture(encodeEvent(t, control.quotaEvent("Usage limit reached")), stream)
		if signal, err := control.service.LimitFromCapture(context.Background(), capture, control.observation); err != nil || signal == nil {
			t.Fatal("registered vendor stream lost corroborated quota", stream, err)
		}
	}
	for _, field := range []string{"binding", "unbound", "supplementary", "refused", "producer", "boot", "pipe", "offset", "source", "recovery"} {
		t.Run(field, func(t *testing.T) {
			var f *runnerFixture
			if field == "refused" {
				f = refusalFixture(t)
			} else {
				f = runnerSetup(t)
			}
			ctx := context.Background()
			capture := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
			if session, err := f.service.SessionFromCapture(ctx, capture); err != nil || session != f.request.Session {
				t.Fatal("registered capture control failed", err)
			}
			selector, record, err := f.service.retainedLaunch(ctx, capture.Target)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "binding":
				capture.BindingID = "foreign-binding"
			case "unbound":
				capture.BindingID = ""
			case "supplementary":
				capture.Primary = false
			case "refused":
				f.refuseCapture(t)
			case "producer", "boot", "pipe":
				binding := record.Plan.Capture
				if field == "producer" {
					binding.ProducerGeneration = "other-generation"
				}
				if field == "boot" {
					binding.BootID = "other-boot"
				}
				if field == "pipe" {
					binding.Streams = append([]api.CaptureStreamBinding{}, binding.Streams...)
					binding.Streams[0].PipeID = "other-pipe"
				}
				f.launch.write("producer-"+string(binding.ID), binding)
			case "offset":
				state, err := f.launch.CaptureState(ctx, selector.Scope, capture.BindingID)
				if err != nil {
					t.Fatal(err)
				}
				for i := range state.Positions {
					state.Positions[i].NextOffset = 0
				}
				f.launch.write("capture-"+string(capture.BindingID), state)
			case "source":
				metadata, err := f.launch.ObjectMetadata(ctx, selector.Scope, capture.Data.ID)
				if err != nil {
					t.Fatal(err)
				}
				metadata.Origin = "observation"
				f.launch.write("meta-"+string(metadata.Ref.ID), metadata)
			case "recovery":
				if err := os.Remove(filepath.Join(f.launch.dir, "binding-launch-1.json")); err != nil {
					t.Fatal(err)
				}
			}
			_, err = f.service.SessionFromCapture(ctx, capture)
			if err == nil {
				t.Fatal("unbound or supplementary capture established a session", field)
			}
			expected := map[string]string{
				"binding":       "capture belongs to a different registered producer",
				"unbound":       "live runner capture lacks its registered binding",
				"supplementary": "capture must be complete primary outside output",
				"refused":       "capture producer unavailable is not implemented",
				"producer":      "capture producer lifetime or pipes changed",
				"boot":          "capture producer lifetime or pipes changed",
				"pipe":          "capture producer lifetime or pipes changed",
				"offset":        "capture range has not been durably acknowledged",
				"source":        "runner object lacks protected provenance",
				"recovery":      "fixture retained object is absent",
			}[field]
			if field == "refused" {
				expected = api.NotImplemented("lb-v2-admin", "capture producer unavailable").Message
			}
			launchReason(t, err, expected, "capture lost the deciding fence: "+field)
			signal, err := f.service.LimitFromCapture(ctx, capture, f.observation)
			if signal != nil {
				t.Fatal("invalid producer established a quota signal", field)
			}
			launchReason(t, err, expected, "quota capture lost the deciding fence: "+field)
		})
	}
}

func TestOriginalBudgetGuards(t *testing.T) {
	for _, mode := range []string{"start", "resume", "turn"} {
		t.Run(mode, func(t *testing.T) {
			f := runnerSetup(t)
			operation := f.service.Start
			if mode != "start" {
				f.history(t)
				f.request.Target.Run = 2
				f.sourceLaunch(t, mode)
				operation = f.service.Resume
				if mode == "turn" {
					operation = f.service.Turn
				}
			}
			if _, err := operation(context.Background(), f.request); err != nil {
				t.Fatal("original budget control failed", err)
			}
			f.request.Budget.WallMS++
			f.launch.retainRun(f.request)
			plan, err := operation(context.Background(), f.request)
			refusedPlan(t, plan, err, "changed original budget produced argv: "+mode)
			launchReason(t, err, "runner inputs differ from the original "+mode+" intent", "budget lost the original intent fence: "+mode)
		})
	}
}

func TestContinuationBindingOrder(t *testing.T) {
	f := runnerSetup(t)
	f.request.Target.Run = 2
	f.sourceLaunch(t, "resume")
	if err := f.home.records.transaction(f.home.key, func(record *homeRecord) error {
		record.Model = "claude-opus-4-6"
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	_, err := f.service.Resume(context.Background(), f.request)
	launchReason(t, err, "continuation differs from the protected session, home or model", "continuation inspected history before its protected binding")
}

type unavailableLaunchPorts struct {
	api.StateStore
	api.GrantResolver
	api.CredentialBroker
	api.CaptureControl
	err error
}

func (p unavailableLaunchPorts) LaunchPlan(context.Context, api.Scope, api.ID) (api.LaunchPlanRecord, error) {
	return api.LaunchPlanRecord{}, p.err
}
func (p unavailableLaunchPorts) ResolveLaunchSources(context.Context, api.LaunchSourceRequest) (api.LaunchSources, error) {
	return api.LaunchSources{}, p.err
}
func (p unavailableLaunchPorts) ResolveLaunchStorage(context.Context, api.LaunchDataRequest) (api.LaunchStorage, error) {
	return api.LaunchStorage{}, p.err
}
func (p unavailableLaunchPorts) Revalidate(context.Context, api.GrantSet) (api.GrantSet, error) {
	return api.GrantSet{}, p.err
}
func (p unavailableLaunchPorts) Resolve(context.Context, api.Scope, api.GrantResolveRequest) (api.GrantSet, error) {
	return api.GrantSet{}, p.err
}
func (p unavailableLaunchPorts) ReadUsageWindow(context.Context, api.Scope, api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	return api.UsageWindowEvidence{}, p.err
}
func (p unavailableLaunchPorts) ReconcileCapture(context.Context, api.CaptureBinding) (api.CaptureBinding, error) {
	return api.CaptureBinding{}, p.err
}

func TestLaunchDependencyBarriers(t *testing.T) {
	for _, port := range []string{"state", "sources", "storage", "grants", "capture", "usage"} {
		t.Run(port, func(t *testing.T) {
			f := runnerSetup(t)
			f.installLimitGuard()
			capture := f.setCapture(encodeEvent(t, f.quotaEvent("Usage limit reached")), "stdout")
			refusal := api.NotImplemented("lb-v2-admin", "fixture unavailable "+port)
			barrier := unavailableLaunchPorts{err: refusal}
			switch port {
			case "state":
				f.service.deps.State = barrier
			case "sources":
				f.service.deps.Sources = barrier
			case "storage":
				f.service.deps.Storage = barrier
			case "grants":
				f.service.deps.Grants = barrier
			case "capture":
				f.service.deps.CaptureControl = barrier
			case "usage":
				f.service.deps.UsageWindows = barrier
			}
			var err error
			if port == "capture" || port == "usage" {
				var signal *api.LimitSignal
				signal, err = f.service.LimitFromCapture(context.Background(), capture, f.observation)
				if signal != nil {
					t.Fatal("unavailable dependency produced a limit signal")
				}
			} else {
				var plan api.RunnerPlan
				plan, err = f.service.Start(context.Background(), f.request)
				if len(plan.Argv) != 0 {
					t.Fatal("unavailable dependency produced runner argv")
				}
			}
			if err != refusal {
				t.Fatal("launch dependency barrier was changed or bypassed: "+port, err)
			}
		})
	}
}
