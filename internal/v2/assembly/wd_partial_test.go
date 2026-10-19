//go:build linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestWDProfiles(t *testing.T) {
	for _, count := range []int{2, 3, 5, 9} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			runtime, installed, values := runtimeFixture(t)
			declared, err := fixtureFromRuntime(runtime, installed, func(o api.RuntimeObject) ([]byte, error) { return values[o.ID], nil })
			if err != nil {
				t.Fatal(err)
			}
			installed.RuntimeManifest = api.BlobRef{ID: fx.ID(t), Class: "manifest", SHA256: fx.Digest(fx.JSON(t, runtime)), Bytes: int64(len(fx.JSON(t, runtime)))}
			planner := &initialFixtureProfiles{installed: installed, fixture: *declared}
			root := api.RootGrantManifest{}
			for n := 0; n < count; n++ {
				driver := api.DriverClaudock
				if count > 2 && n == count-1 {
					driver = api.DriverCodex
				}
				root.Profiles = append(root.Profiles, api.ProfileGrant{ProfileID: fx.ID(t), Driver: driver, Provider: "serve-fixture", Delegate: true, ExpiresAt: fx.Expiry()})
			}
			initial := admin.InitialManifest{Config: installed.Config, Runtime: installed.RuntimeManifest}
			profiles, err := planner.PlanStandInProfiles(context.Background(), initial, root)
			if err != nil || len(profiles) != count {
				t.Fatalf("distinct same-driver fixture selectors were not enrolled: %v", err)
			}
			selectors := map[api.ID]bool{}
			for n, p := range profiles {
				g := root.Profiles[n]
				if p.ID != g.ProfileID || p.Driver != g.Driver || p.Provider != g.Provider || p.ExpiresAt != g.ExpiresAt || p.Runtime != declared.Executable || selectors[p.LoginID] || selectors[p.Source.SourceHandle] {
					t.Fatal("fixture profiles lost pins or share an authenticator selector")
				}
				selectors[p.LoginID], selectors[p.Source.SourceHandle] = true, true
				if p.Driver == api.DriverClaudock && (p.Usage == nil || p.Usage.VendorProfile != string(g.ProfileID) || p.Usage.Executable != declared.Executable || p.Usage.RuntimeManifest != installed.RuntimeManifest || p.Usage.AdapterVersion != "serve-fixture/1.0.0") {
					t.Fatal("fixture Claudock profile omitted its protected usage enrollment")
				}
			}
			root.Profiles[1].ProfileID = root.Profiles[0].ProfileID
			if _, err := planner.PlanStandInProfiles(context.Background(), initial, root); err == nil {
				t.Fatal("duplicate profile selector was enrolled twice")
			}
		})
	}
}

func TestWDRetainedPlans(t *testing.T) {
	runtime, installed, values := runtimeFixture(t)
	declared, err := fixtureFromRuntime(runtime, installed, func(o api.RuntimeObject) ([]byte, error) { return values[o.ID], nil })
	if err != nil {
		t.Fatal(err)
	}
	declared.executablePath, declared.Mode = "/runtime/serve-agent", "lifecycle"
	claude, codex, err := runnersForFixture(declared)
	if err != nil {
		t.Fatal(err)
	}
	for driver, runner := range map[api.Driver]api.Runner{api.DriverClaudock: claude, api.DriverCodex: codex} {
		for name, method := range map[string]func(context.Context, api.RunnerRequest) (api.RunnerPlan, error){"resume": runner.Resume, "turn": runner.Turn} {
			t.Run(string(driver)+"/"+name, func(t *testing.T) {
				q := api.RunnerRequest{Target: api.LifeRef{LifeID: fx.ID(t), Run: 2}, Executable: declared.Executable,
					Session: api.Session{ID: fx.ID(t), Driver: driver, VendorID: string(fx.ID(t)), VendorVersion: declared.Version, HomeID: "private-home", HistoryID: fx.ID(t), LogicalCWD: "/work/main"},
					Prompt:  api.BlobRef{ID: fx.ID(t), Class: "prompt", SHA256: runtime.Artifact.SHA256, Bytes: 37}, Model: "fixture-model-1", Effort: "high",
					Slot:   api.CredentialSlot{ID: fx.ID(t), LeaseID: fx.ID(t), ProfileGrantID: fx.ID(t), ProfileID: fx.ID(t), ExpiresAt: fx.Expiry()},
					Budget: api.Budget{WallMS: 45000, CPUSeconds: 11, Processes: 5, DiskBytes: 4096, MemoryBytes: 1 << 20, Currency: "USD"}}
				q.Home = api.PrivateHome{ID: q.Session.HomeID, WorkspaceID: fx.ID(t), HistoryID: q.Session.HistoryID}
				plan, err := method(context.Background(), q)
				if err != nil || plan.Session != q.Session || plan.Home != q.Home || plan.Slot != q.Slot || plan.Prompt != q.Prompt || plan.Driver != driver {
					t.Fatalf("retained fixture %s did not preserve the reserved inputs: %v", name, err)
				}
				for _, fault := range []string{"vendor", "version", "history", "first-run", "expired"} {
					bad := q
					switch fault {
					case "vendor":
						bad.Session.VendorID = ""
					case "version":
						bad.Session.VendorVersion = ""
					case "history":
						bad.Home.HistoryID = fx.ID(t)
					case "first-run":
						bad.Target.Run = 1
					case "expired":
						bad.Slot.ExpiresAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
					}
					if _, err := method(context.Background(), bad); err == nil {
						t.Fatalf("retained fixture accepted %s", fault)
					}
				}
			})
		}
	}
}

type wdCapture struct{ binding api.CaptureBinding }

func (p wdCapture) RegisterCapture(context.Context, api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	return api.CaptureBinding{}, errors.New("registration was not requested by this observer")
}
func (p wdCapture) ReconcileCapture(_ context.Context, b api.CaptureBinding) (api.CaptureBinding, error) {
	if !reflect.DeepEqual(b, p.binding) {
		return api.CaptureBinding{}, errors.New("foreign fixture capture")
	}
	return p.binding, nil
}

func wdFrames(t *testing.T, lines []map[string]any, drivers ...api.Driver) (*fx.Fixture, api.Runner, []api.CaptureRecord, api.ProcessObservation) {
	t.Helper()
	f := fx.New(t)
	driver := api.DriverCodex
	if len(drivers) == 1 {
		driver = drivers[0]
		f.Start.Driver, f.Ceiling.Profiles[0].Driver = driver, driver
		f.Ceiling.Profiles[0].Provider = "serve-fixture"
		f.Ceiling.SHA256 = ""
		canonical, err := api.CanonicalJSON(fx.JSON(t, f.Ceiling))
		if err != nil {
			t.Fatal(err)
		}
		f.Ceiling.SHA256 = fx.Digest(canonical)
		f.Replace(t, "grants", f.Ceiling.ID, 1, f.Ceiling)
	}
	vendor := string(fx.ID(t))
	f.PlanSetup = func(p *api.LaunchPlan) {
		p.Runner.Session.VendorID = vendor
		p.Runner.Driver, p.Runner.Session.Driver = driver, driver
		if driver == api.DriverClaudock {
			p.Runner.Slot.Mode = "claudock-headless"
			p.Data.Home.Home.VendorDirectory, p.Runner.Home.VendorDirectory = ".claude", ".claude"
		}
	}
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	input := f.SourceTransaction(t)
	input.Writes.LaunchPlans[0].Inputs.Sources.Runtime.Driver = driver
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	f.Record = input.Writes.LaunchPlans[0]
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	var raw []byte
	for _, line := range lines {
		line["session_id"] = vendor
		encoded, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, append(encoded, '\n')...)
	}
	ref := f.CaptureData(t, raw)
	q := f.AppendRequest(t, &ref, false)
	receipt, err := f.State.AppendCapture(context.Background(), f.Worker, q)
	if err != nil {
		t.Fatal(err)
	}
	generation := receipt.Generation
	for n, stream := range f.Plan.Capture.Streams {
		q := f.AppendRequest(t, nil, true)
		q.StreamID, q.ExpectedGeneration = stream.ID, generation
		if n == 0 {
			q.Offset = int64(len(raw))
		}
		receipt, err := f.State.AppendCapture(context.Background(), f.Worker, q)
		if err != nil {
			t.Fatal(err)
		}
		generation = receipt.Generation
	}
	f.Opened(t)
	f.Ended(t)
	port := any(f.State).(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
	})
	frames, err := port.FrameCapture(context.Background(), f.Execution, f.Plan.Capture.ID)
	if err != nil || len(frames) != len(lines) {
		t.Fatal("real-store framing failed", err)
	}
	r := &enrolledFixtureRunner{driver: driver, enrollment: fixtureEnrollment{Config: f.Deps.Config, Version: f.Plan.Runner.Session.VendorVersion, Executable: f.Plan.Runner.Executable, VendorStoodIn: true}}
	// The unchanged implementation has no outside bindings and returns its
	// typed not_implemented result. The baseline must compile and reach that
	// result, rather than count a missing test API as a killed regression.
	if bound, ok := any(r).(interface{ bindFixture(runnerDependencies) }); ok {
		bound.bindFixture(runnerDependencies{Store: f.State, Clock: f.Deps.Clock, Capture: wdCapture{f.Plan.Capture}})
	}
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: f.Lane.LifeID})
	if err != nil {
		t.Fatal(err)
	}
	var exit api.ProcessObservation
	for _, event := range page.Events {
		if event.Kind == "lane.ended" {
			var end api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				t.Fatal(err)
			}
			exit = end.Observation
		}
	}
	return f, r, frames, exit
}

func TestWDSessionCapture(t *testing.T) {
	f, runner, frames, _ := wdFrames(t, []map[string]any{{"type": "system", "subtype": "init", "cwd": "/work/main"}})
	session, err := runner.SessionFromCapture(context.Background(), frames[0])
	if err != nil || session != f.Plan.Runner.Session {
		t.Fatalf("exact primary init did not resolve the retained session: %v", err)
	}
	for _, fault := range []string{"hash", "binding", "replacement", "primary", "coverage", "run"} {
		bad := frames[0]
		switch fault {
		case "hash":
			bad.Data.SHA256 = fx.Digest([]byte(string(fx.ID(t))))
		case "binding":
			bad.BindingID = fx.ID(t)
		case "replacement":
			bad.ReplacementOf = fx.ID(t)
		case "primary":
			bad.Primary = false
		case "coverage":
			bad.Coverage = "partial"
		case "run":
			bad.Target.Run++
		}
		if _, err := runner.SessionFromCapture(context.Background(), bad); err == nil {
			t.Fatalf("session accepted changed %s", fault)
		}
	}
}

func TestWDNeutralCapture(t *testing.T) {
	_, runner, frames, exit := wdFrames(t, []map[string]any{{"type": "assistant", "message": map[string]any{"content": []any{map[string]any{"type": "text", "text": "Usage limit reached"}}}}})
	signal, err := runner.LimitFromCapture(context.Background(), frames[0], exit)
	if err != nil || signal != nil {
		t.Fatalf("quoted model text became a limit or an unavailable classifier: %v", err)
	}
	bad := exit
	bad.Handle.Generation = string(fx.ID(t))
	if _, err := runner.LimitFromCapture(context.Background(), frames[0], bad); err == nil {
		t.Fatal("capture accepted a foreign process observation")
	}
}

// These private synthetic usage records exercise the shared provenance and
// TSV validators. The capture frames/launch binding still use the real SQLite
// writer above. This fixture does not establish a native worker or vendor login.
type wdUsage struct {
	api.StateStore
	evidence api.UsageWindowEvidence
	producer api.UsageProvenance
	query    api.UsageWindowRequest
	meta     map[api.ID]api.ObjectMetadata
	data     map[api.ID][]byte
}

func (s *wdUsage) ReadUsageWindow(_ context.Context, scope api.Scope, q api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	if q != s.query || scope.Config != s.producer.Producer.Endpoint.Config {
		return api.UsageWindowEvidence{}, errors.New("foreign causing usage request")
	}
	return s.evidence, nil
}
func (s *wdUsage) ReadUsageProvenance(_ context.Context, _ api.Scope, ref api.BlobRef) (api.UsageProvenance, error) {
	if ref != s.producer.Evidence {
		return api.UsageProvenance{}, errors.New("foreign usage envelope")
	}
	return s.producer, nil
}
func (s *wdUsage) WorkerBinding(_ context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	if !reflect.DeepEqual(endpoint, s.producer.Producer.Endpoint) || peer != s.producer.Producer.Peer {
		return api.WorkerPrincipal{}, errors.New("foreign usage worker mapping")
	}
	return s.producer.Producer, nil
}
func (s *wdUsage) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	if value, ok := s.meta[id]; ok {
		return value, nil
	}
	return s.StateStore.ObjectMetadata(ctx, scope, id)
}
func (s *wdUsage) Blob(ctx context.Context, scope api.Scope, q api.BlobReadRequest) (api.BlobChunk, error) {
	if data, ok := s.data[q.ObjectID]; ok {
		if q.Offset < 0 || q.Offset >= int64(len(data)) {
			return api.BlobChunk{}, errors.New("usage chunk range differs")
		}
		part := data[q.Offset:min(len(data), int(q.Offset)+q.Limit)]
		return api.BlobChunk{ObjectID: q.ObjectID, Offset: q.Offset, Data: part, SHA256: fx.Digest(part)}, nil
	}
	return s.StateStore.Blob(ctx, scope, q)
}
func (s *wdUsage) FrameCapture(ctx context.Context, scope api.Scope, id api.ID) ([]api.CaptureRecord, error) {
	return s.StateStore.(interface {
		FrameCapture(context.Context, api.Scope, api.ID) ([]api.CaptureRecord, error)
	}).FrameCapture(ctx, scope, id)
}
func (s *wdUsage) CaptureFrame(ctx context.Context, id api.ID) (api.CaptureRecord, []byte, error) {
	return s.StateStore.(interface {
		CaptureFrame(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	}).CaptureFrame(ctx, id)
}

func wdOutsideUsage(t *testing.T, f *fx.Fixture, runner api.Runner, exit api.ProcessObservation) *wdUsage {
	t.Helper()
	p, r := f.Plan, f.Reservation
	profile := p.Inputs.Grants.Profiles[0]
	q := api.UsageWindowRequest{Target: r.Target, LaunchID: r.LaunchID, OperationID: r.OperationID, ProfileGrantID: profile.ID,
		ProfileID: profile.ProfileID, Provider: profile.Provider, RunEndedAt: exit.ObservedAt, AdapterVersion: p.Runner.AdapterVersion,
		Executable: p.Runner.Executable, RuntimeManifest: p.Inputs.Sources.Runtime.Manifest}
	lease := api.WorkerLease{ID: fx.ID(t), Kind: "usage", Target: r.Target, OperationID: r.OperationID, EffectID: fx.ID(t),
		Input:           api.BlobRef{ID: fx.ID(t), Class: "worker_input", SHA256: fx.Digest(fx.JSON(t, q)), Bytes: int64(len(fx.JSON(t, q)))},
		RuntimeManifest: q.RuntimeManifest, GrantSetID: fx.ID(t), Generation: 1, ExpiresAt: fx.Expiry(), ConsumedBy: fx.ID(t)}
	record := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: r.Config, Target: r.Target,
		Actor: api.Actor{Kind: "worker", ID: fx.ID(t), LifeID: r.Target.LifeID}, HostUID: 12002, UIDLeaseID: fx.ID(t),
		ContainmentID: fx.ID(t), ProcessGeneration: string(fx.ID(t)), GrantSetID: lease.GrantSetID, EndpointGeneration: 1,
		PolicyGeneration: 1, GrantsSHA256: fx.Digest([]byte(string(fx.ID(t))))}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol,
		APISchema: api.SchemaVersion, Config: r.Config, Class: api.EndpointWorker, InstallationGeneration: 1, EndpointGeneration: 1,
		ServiceUID: 11000, ServiceGID: 11000, Socket: "/runtime/usage.sock", ArtifactSHA256: q.RuntimeManifest.SHA256,
		ServiceVersion: "fixture", Backend: "linux-bwrap-landlock", LaunchID: record.ID, Target: &r.Target, WorkerLeaseID: lease.ID}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalObjectRetain, Config: r.Config, Actor: f.Execution.Actor,
		RequestedBy: r.RequestedBy, Target: r.Target, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID,
		EffectID: lease.EffectID, CancellationEpoch: r.CancellationEpoch}
	claimID := fx.ID(t)
	producer := api.WorkerPrincipal{StageID: fx.ID(t), Lease: lease, Record: record, Endpoint: endpoint,
		Peer:   api.PeerFacts{HostUID: record.HostUID, HostGID: 12002, HostPID: 100, ProcessGeneration: string(fx.ID(t)), ContainmentID: record.ContainmentID},
		BootID: string(fx.ID(t)), AllocationGeneration: 1, CancellationEpoch: r.CancellationEpoch,
		Claim: api.EffectLease{ClaimID: claimID, ExpiresAt: lease.ExpiresAt, Record: api.EffectRecord{State: "claimed", Generation: 1,
			ClaimID: claimID, ClaimantID: f.Execution.Actor.ID, ClaimExpiresAt: lease.ExpiresAt,
			Effect: api.Effect{ID: lease.EffectID, OperationID: r.OperationID, Context: &cause}}}}
	now := time.Now().UTC()
	reset := api.Timestamp(now.Add(time.Hour).Format(time.RFC3339Nano))
	raw := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nvendor-profile\tfixture\tcurrent\t100\t" + string(reset) + "\n")
	e := api.UsageWindowEvidence{Schema: "laneboss.usage-window.v2", ID: fx.ID(t), Target: r.Target, LaunchID: r.LaunchID,
		OperationID: r.OperationID, ProfileGrantID: q.ProfileGrantID, ProfileID: q.ProfileID, Provider: q.Provider,
		AdapterVersion: q.AdapterVersion, Executable: q.Executable, RuntimeManifest: q.RuntimeManifest, WorkerLeaseID: lease.ID,
		ProducerID: record.Actor.ID, ProducerGeneration: producer.Peer.ProcessGeneration, BootID: producer.BootID,
		ObservedAt: api.Timestamp(now.Format(time.RFC3339Nano)), Window: "current", UsedPercent: 100, ResetsAt: reset, Row: 1,
		Raw: api.BlobRef{ID: fx.ID(t), Class: "usage_raw", SHA256: fx.Digest(raw), Bytes: int64(len(raw))}}
	envelope := fx.JSON(t, e)
	ref := api.BlobRef{ID: e.ID, Class: "usage_window", SHA256: fx.Digest(envelope), Bytes: int64(len(envelope))}
	source := &wdUsage{StateStore: f.State, query: q, evidence: e,
		producer: api.UsageProvenance{Evidence: ref, Producer: producer, VendorProfile: "vendor-profile", Executable: q.Executable, RuntimeManifest: q.RuntimeManifest},
		data:     map[api.ID][]byte{e.Raw.ID: raw, e.ID: envelope}, meta: map[api.ID]api.ObjectMetadata{}}
	for _, object := range []api.BlobRef{e.Raw, ref} {
		source.meta[object.ID] = api.ObjectMetadata{Ref: object, Origin: "worker", SourceOperationID: r.OperationID, CommittedAt: e.ObservedAt,
			ACL: api.ObjectACL{Config: r.Config, Owner: record.Actor, LifeID: r.Target.LifeID, Audience: "service", Generation: 1}}
	}
	runner.(*enrolledFixtureRunner).bindFixture(runnerDependencies{Store: source, Clock: f.Deps.Clock, Capture: wdCapture{f.Plan.Capture}, UsageWindows: source})
	return source
}

func TestWDObservedLimit(t *testing.T) {
	f, runner, frames, exit := wdFrames(t, []map[string]any{{"type": "system", "subtype": "init", "cwd": "/work/main"},
		{"type": "result", "is_error": true, "result": "Usage limit reached"}}, api.DriverClaudock)
	source := wdOutsideUsage(t, f, runner, exit)
	signal, err := runner.LimitFromCapture(context.Background(), frames[1], exit)
	if err != nil || signal == nil || signal.Target != frames[1].Target || signal.CaptureID != frames[1].ID || signal.CaptureSHA256 != frames[1].Data.SHA256 ||
		signal.ProfileID != source.query.ProfileID || signal.Provider != source.query.Provider || signal.UsageEvidence == nil || *signal.UsageEvidence != source.producer.Evidence ||
		signal.ExitCode == nil || *signal.ExitCode != *exit.ExitCode || signal.Kind != "usage_limit" {
		t.Fatalf("observed primary limit lost its exact run/usage provenance: signal=%v err=%v", signal, err)
	}
	for _, fault := range []string{"bytes", "worker", "age", "from-profile", "row"} {
		t.Run(fault, func(t *testing.T) {
			original := source.evidence
			before := source.data[original.Raw.ID]
			switch fault {
			case "bytes":
				changed := append([]byte(nil), before...)
				if changed[len(changed)-1] != '\n' {
					t.Fatal("usage fixture has no trailing newline to mutate")
				}
				changed[len(changed)-1] = ' '
				source.data[original.Raw.ID] = changed
			case "worker":
				source.evidence.ProducerGeneration = string(fx.ID(t))
			case "age":
				source.evidence.ObservedAt = api.Timestamp(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano))
			case "from-profile":
				source.evidence.ProfileID = fx.ID(t)
			case "row":
				source.evidence.Row = 2
			}
			if signal, err := runner.LimitFromCapture(context.Background(), frames[1], exit); err == nil || signal != nil {
				t.Fatal("fixture limit accepted drifted outside " + fault)
			}
			source.evidence, source.data[original.Raw.ID] = original, before
		})
	}
}
