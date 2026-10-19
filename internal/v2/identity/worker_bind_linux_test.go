package identity

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

type workerSourceFunc func(context.Context, string, api.ID) (WorkerLaunchGuard, error)

func (f workerSourceFunc) AcquireWorkerLaunch(ctx context.Context, config string, id api.ID) (WorkerLaunchGuard, error) {
	return f(ctx, config, id)
}

// The metadata/peer/registry here are controlled projections. Files use real
// kernel memfds/seals; these unit fixtures do not establish installed handoff.
type workerGuardFixture struct {
	a                  WorkerLaunchAuthority
	input, endpoint    *os.File
	peer               api.VerifiedPeer
	checks, closes     int
	checkErr, closeErr error
	after              func(int)
}

func (g *workerGuardFixture) Authority() WorkerLaunchAuthority { return g.a }
func (g *workerGuardFixture) Input() *os.File                  { return g.input }
func (g *workerGuardFixture) Endpoint() *os.File               { return g.endpoint }
func (g *workerGuardFixture) Peer() api.VerifiedPeer           { return g.peer }
func (g *workerGuardFixture) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g.checks++
	if g.after != nil {
		g.after(g.checks)
	}
	return g.checkErr
}
func (g *workerGuardFixture) Close() error {
	if g.closes != 0 {
		return refusal(api.CodeIntegrity, "fixture guard closed twice")
	}
	g.closes++
	return errors.Join(g.closeErr, g.input.Close(), g.endpoint.Close())
}

func workerMemfd(t *testing.T, data []byte, sealed, readonly bool) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("worker-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatalf("fixture setup: memfd unavailable: %v", err)
	}
	file := os.NewFile(uintptr(fd), "worker-fixture")
	if n, err := file.Write(data); err != nil || n != len(data) {
		t.Fatalf("fixture setup: memfd write failed: %v", err)
	}
	if err := file.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if sealed {
		if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
			t.Fatal(err)
		}
	}
	if !readonly {
		return file
	}
	view, err := os.Open("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return view
}

func workerBindFixture(t *testing.T, rule string) (*Service, *fixtureStore, *workerGuardFixture, api.LaunchBindingRequest) {
	t.Helper()
	s, store, _ := workerConsumerFixture(t)
	p := *store.worker
	p.Record.ProcessGeneration = p.Peer.ProcessGeneration
	if rule == "bootstrap" {
		p.Peer.ProcessGeneration = p.BootID + ":57"
	}
	p.Endpoint.Socket = "/runtime/laneboss-worker.sock"
	p.Lease.RuntimeManifest = launchBlob(t, "worker-runtime", "manifest", "retained runtime")
	store.record = p.Record
	grants, err := store.Grants(context.Background(), p.Lease.GrantSetID)
	if err != nil {
		t.Fatal(err)
	}
	store.grants = &grants
	plan := api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "materialize", Input: p.Lease.Input, GrantSetID: grants.ID,
		Executable: api.Executable{ID: "worker-artifact", SHA256: p.Endpoint.ArtifactSHA256, Version: p.Endpoint.ServiceVersion},
		Argv:       []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(p.Lease.ID)}}
	p.Claim.Record.Effect.Worker = &plan
	cause := *p.Claim.Record.Effect.Context
	cause.Kind = api.InternalHelperRegister
	spec := api.LaunchSpec{ID: "worker-spec", Kind: "worker", Worker: &plan, LaunchID: p.Record.ID, Target: p.Record.Target,
		UIDLeaseID: p.Record.UIDLeaseID, Backend: p.Endpoint.Backend, EndpointGeneration: p.Record.EndpointGeneration,
		PolicyGeneration: p.Record.PolicyGeneration, RuntimeManifest: p.Lease.RuntimeManifest, Grants: grants,
		Injection: api.Injection{Target: p.Record.Target, Outcome: "prepared"}}
	if rule == "parent" || rule == "parent-stage" {
		spec.PlanID = "worker-parent-reservation"
		store.plan = &api.LaunchPlanRecord{Reservation: api.LaunchReservation{ID: spec.PlanID, Config: p.Record.Config, Target: p.Record.Target, Mode: "start", Generation: 1,
			OperationID: p.Lease.OperationID, RequestID: cause.CauseRequestID, RequestedBy: cause.RequestedBy, CancellationEpoch: p.CancellationEpoch}, Phase: "sourced", Generation: 1, DataStageID: p.StageID}
		if rule == "parent-stage" {
			store.plan.DataStageID = "foreign-parent-stage"
		}
	}
	if rule == "argv" {
		plan.Argv = append([]string(nil), plan.Argv...)
		plan.Argv[2] = "caller-selected"
	}
	specRef := launchBlob(t, "worker-spec-object", "launch_spec", spec)
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: p.Record.Config, Spec: spec, Original: specRef, SpecSHA256: specRef.SHA256, OperationID: p.Lease.OperationID, RequestID: cause.CauseRequestID}
	binding := api.LaunchBindingRequest{Record: p.Record, Prepared: api.PreparedLaunch{ID: "worker-prepared", GateID: "worker-gate", Target: p.Record.Target,
		ContainmentID: p.Record.ContainmentID, ProcessGeneration: p.Record.ProcessGeneration, EndpointGeneration: p.Record.EndpointGeneration, SpecSHA256: specRef.SHA256},
		Identity: api.IdentityCommit{LaunchID: p.Record.ID, EventID: "worker-bound", CommittedSeq: 9, RecordSHA256: launchBlob(t, "worker-record", "manifest", p.Record).SHA256}}
	store.worker, store.binding = &p, &binding
	effect := p.Claim.Record
	store.projectionEffect = &effect
	store.lane.CancellationEpoch = p.CancellationEpoch
	if rule == "parent" || rule == "parent-stage" {
		store.lane = api.Lane{}
	}
	store.events = &api.EventPage{Events: []api.Event{{Schema: api.SchemaVersion, Seq: 9, ID: binding.Identity.EventID, Kind: "identity.bound", Config: p.Record.Config,
		LifeID: p.Record.Target.LifeID, Run: p.Record.Target.Run, Actor: cause.Actor, RequestedBy: cause.RequestedBy, RequestID: handoff.RequestID,
		OperationID: handoff.OperationID, Payload: launchJSON(t, p.Record)}}}
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	s.deps.Registry.(*fixtureContainmentRegistry).binding.Directory = directory
	input := []byte("sealed fixture job")
	if rule == "input" {
		input = []byte("foreign fixture job")
	}
	endpoint := p.Endpoint
	if rule == "endpoint" {
		endpoint.EndpointGeneration++
	}
	g := &workerGuardFixture{a: WorkerLaunchAuthority{Binding: binding, Handoff: handoff, Principal: p},
		input: workerMemfd(t, input, rule != "seals", rule != "readonly"), endpoint: workerMemfd(t, launchJSON(t, endpoint), true, true),
		peer: &fixturePeer{facts: p.Peer}}
	t.Cleanup(func() {
		if g.closes == 0 {
			if err := g.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	s.deps.Workers = workerSourceFunc(func(_ context.Context, config string, prepared api.ID) (WorkerLaunchGuard, error) {
		if config != binding.Record.Config || prepared != binding.Prepared.ID {
			t.Fatal("fixture check: worker source received caller-selected authority")
		}
		return g, nil
	})
	return s, store, g, binding
}

func TestWorkerBind(t *testing.T) {
	for _, rule := range []string{"current", "bootstrap", "parent", "parent-stage", "request", "input", "endpoint", "seals", "readonly", "argv", "claim", "grants", "policy", "allocation", "cancel", "drift", "native", "guard", "close", "missing"} {
		t.Run(rule, func(t *testing.T) {
			s, store, guard, request := workerBindFixture(t, rule)
			want := api.CodeConflict
			sentinel := api.NotImplemented("lb-v2-admin", "fixture native guard failed")
			switch rule {
			case "input", "endpoint", "argv":
				want = api.CodeIntegrity
			case "parent-stage":
				want = api.CodeIntegrity
			case "seals", "readonly":
				want = api.CodeUnauthenticated
			case "allocation":
				s.deps.Registry.(*fixtureContainmentRegistry).binding.Generation++
				want = api.CodeContainmentUnknown
			case "request":
				request.Record.RootLifeID = "caller-root"
			case "claim":
				store.projectionEffect.Generation++
			case "grants":
				store.grants.ExpiresAt = timestamp(s.deps.Clock.Now().Add(-time.Second))
				want = api.CodeForbidden
			case "policy":
				store.policy = &api.EffectivePolicy{}
			case "cancel":
				store.lane.CancellationEpoch++
			case "drift":
				guard.after = func(n int) {
					if n == 2 {
						store.binding.Record.PolicyGeneration++
					}
				}
			case "native":
				want = api.CodeUnauthenticated
				guard.after = func(n int) {
					if n == 2 {
						guard.peer.(*fixturePeer).facts.ProcessGeneration = "boot:changed"
					}
				}
			case "guard":
				guard.checkErr = sentinel
			case "close":
				guard.closeErr = sentinel
			case "missing":
				s.deps.Workers = nil
				want = api.CodeNotImplemented
			}
			permit, err := s.BindLaunch(context.Background(), request)
			if rule == "current" || rule == "bootstrap" || rule == "parent" {
				if err != nil || permit.LaunchID != request.Record.ID || permit.PreparedID != request.Prepared.ID || permit.RecordSHA256 != request.Identity.RecordSHA256 ||
					permit.CommittedSeq != request.Identity.CommittedSeq || guard.checks != 2 || guard.closes != 1 || store.transaction != nil {
					t.Fatalf("fixture check: retained native worker handoff did not produce its exact permit: %v", err)
				}
				return
			}
			if rule == "guard" || rule == "close" {
				if !errors.Is(err, sentinel) {
					t.Fatalf("fixture check: worker guard refusal was lost: %v", err)
				}
			} else {
				fixtureCode(t, err, want)
				if rule == "missing" {
					var typed *api.Error
					if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Message != "retained fixed worker descriptor and native lease handoff is not implemented" {
						t.Fatal("unwired worker source changed its exact scaffold refusal", err)
					}
				}
			}
			if !reflect.DeepEqual(permit, api.LaunchPermit{}) || store.transaction != nil {
				t.Fatal("fixture check: refused worker received authority or ran in process")
			}
			if rule != "missing" && rule != "request" && guard.closes != 1 {
				t.Fatal("fixture check: worker guard was not collected exactly once")
			}
		})
	}
}

func TestWorkerReservedLifeFence(t *testing.T) {
	for _, mode := range []string{"start", "adopt", "resume", "turn", "continue"} {
		for _, fault := range []string{"", "missing", "run", "generation", "launch", "cancel", "cleaned"} {
			if (mode == "start" || mode == "adopt") && fault != "" && fault != "run" {
				continue
			}
			t.Run(mode+"/"+fault, func(t *testing.T) {
				s, store, guard, _ := workerBindFixture(t, "parent")
				p := guard.a.Principal
				r := &store.plan.Reservation
				r.Mode, r.Generation = mode, 1
				store.lane.Generation = 8
				if mode == "start" || mode == "adopt" {
					store.lane = api.Lane{}
					if fault == "run" {
						store.lane = api.Lane{LifeID: p.Lease.Target.LifeID, Run: 1}
					}
				} else {
					store.lane = api.Lane{LifeID: p.Lease.Target.LifeID, Run: p.Lease.Target.Run, Generation: 8, LaunchID: "previous-agent", CancellationEpoch: p.CancellationEpoch}
					p.Lease.Target.Run++
					p.Record.Target = p.Lease.Target
					p.Endpoint.Target = &p.Lease.Target
					p.Claim.Record.Effect.Context.Target = p.Lease.Target
					r.Target, r.BaseGeneration, r.Generation, r.PreviousLaunchID = p.Lease.Target, store.lane.Generation, store.lane.Generation+1, store.lane.LaunchID
					s.deps.Registry.(*fixtureContainmentRegistry).binding.Target = p.Lease.Target
					switch fault {
					case "missing":
						store.lane = api.Lane{}
					case "run":
						store.lane.Run++
					case "generation":
						store.lane.Generation++
					case "launch":
						store.lane.LaunchID = "another-launch"
					case "cancel":
						store.lane.CancellationEpoch++
					case "cleaned":
						store.lane.Cleaned = true
					}
				}
				store.worker, guard.a.Principal = &p, p
				store.projectionEffect = &p.Claim.Record
				err := s.checkWorkerLaunchState(context.Background(), guard.a, p.Peer)
				if fault == "" {
					if err != nil {
						t.Fatal("worker cannot use its reserved life before agent preparation", err)
					}
					return
				}
				var typed *api.Error
				if fault == "missing" {
					if !errors.As(err, &typed) || typed.Code != api.CodeNotFound || typed.Message != "fixture life absent" {
						t.Fatal("missing retained life lost its store refusal", err)
					}
					return
				}
				if !errors.As(err, &typed) || typed.Code != api.CodeConflict || typed.Message != "worker target differs from its reserved life boundary" {
					t.Fatal("worker missed the exact reserved life fence", err)
				}
			})
		}
	}
}

func TestWorkerEventWriter(t *testing.T) {
	for _, writer := range []string{"claimant", "original_author"} {
		t.Run(writer, func(t *testing.T) {
			s, store, guard, request := workerBindFixture(t, "current")
			claim := guard.a.Principal.Claim
			claim.Record.ClaimantID = "current-worker-writer"
			guard.a.Principal.Claim, store.worker.Claim = claim, claim
			*store.projectionEffect = claim.Record
			if writer == "claimant" {
				store.events.Events[0].Actor = api.Actor{Kind: "service", ID: claim.Record.ClaimantID}
			}
			permit, err := s.BindLaunch(context.Background(), request)
			if writer == "claimant" {
				if err != nil || permit.LaunchID != request.Record.ID || permit.CommittedSeq != request.Identity.CommittedSeq {
					t.Fatal("current claimant's committed worker event was rejected", err)
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "identity commit event differs from the retained launch" || permit != (api.LaunchPermit{}) {
					t.Fatal("worker event borrowed its original author's identity", err)
				}
			}
		})
	}
}
