package claudock

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestUsageMeasurementIDs(t *testing.T) {
	f := runnerSetup(t)
	ctx := context.Background()
	type keptObject struct {
		scope    api.Scope
		metadata api.ObjectMetadata
		data     []byte
	}
	var objects []keptObject
	var producers []api.WorkerPrincipal
	seen := map[api.ID]bool{}
	remember := func() {
		t.Helper()
		selector, record := f.launchRecord(t)
		evidence, _ := f.retainedUsage(t)
		endpoint, peer, err := f.launch.usageWorker(ctx, selector.Scope, evidence.WorkerLeaseID)
		if err != nil {
			t.Fatal(err)
		}
		producer, err := f.launch.WorkerBinding(ctx, endpoint, peer)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []api.ID{producer.Lease.ID, producer.Lease.Input.ID, producer.Record.ID, producer.StageID, producer.Lease.EffectID, evidence.ID, evidence.Raw.ID} {
			if id == "" || seen[id] {
				t.Fatal("usage measurements reused an input or producer identity")
			}
			seen[id] = true
		}
		var query api.UsageWindowRequest
		if err := f.launch.read(usageKey("usage-query", record.Reservation.Target), &query); err != nil {
			t.Fatal(err)
		}
		if err := api.ValidateUsageWindow(evidence, query, producer, f.service.deps.Clock.Now()); err != nil {
			t.Fatal("measurement lost its producer or causing pins", err)
		}
		metadata, err := f.launch.ObjectMetadata(ctx, selector.Scope, evidence.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range []api.BlobRef{producer.Lease.Input, evidence.Raw, metadata.Ref} {
			retained, err := f.launch.ObjectMetadata(ctx, selector.Scope, ref.ID)
			if err != nil {
				t.Fatal(err)
			}
			data, err := f.service.objectBytes(ctx, selector.Scope, ref, ref.Class, record.Reservation.OperationID, record.Reservation.Target.LifeID)
			if err != nil {
				t.Fatal("measurement object lost its exact bytes or provenance", err)
			}
			objects = append(objects, keptObject{selector.Scope, retained, data})
		}
		producers = append(producers, producer)
	}
	remember()
	// Repeating the identical query must allocate another input. The old run-ID
	// control reaches the uniqueness assertion here, before any conflicting write.
	_, first := f.launchRecord(t)
	f.seedUsage(t, first.Reservation, first.Inputs.Sources)
	remember()
	f.history(t)
	f.request.Target.Run = 2
	for _, mode := range []string{"resume", "turn"} {
		// These two sourced jobs share a run but have different operations, as
		// the vendor-tree guard regression does. Exercise both actual adapters.
		f.sourceLaunch(t, mode)
		operation := f.service.Resume
		if mode == "turn" {
			operation = f.service.Turn
		}
		plan, err := operation(ctx, f.request)
		if err != nil || len(plan.Argv) == 0 {
			t.Fatal("usage fixture stopped before the continuation adapter", mode, err)
		}
		remember()
	}
	for _, object := range objects {
		metadata, err := f.launch.ObjectMetadata(ctx, object.scope, object.metadata.Ref.ID)
		if err != nil || !reflect.DeepEqual(metadata, object.metadata) {
			t.Fatal("later measurement replaced prior object provenance", err)
		}
		data, err := f.service.objectBytes(ctx, object.scope, metadata.Ref, metadata.Ref.Class, metadata.SourceOperationID, metadata.ACL.LifeID)
		if err != nil || !bytes.Equal(data, object.data) {
			t.Fatal("later measurement replaced prior object bytes", err)
		}
	}
	for _, producer := range producers {
		retained, err := f.launch.WorkerBinding(ctx, producer.Endpoint, producer.Peer)
		if err != nil || !reflect.DeepEqual(retained, producer) {
			t.Fatal("later measurement replaced prior producer records", err)
		}
	}
}

func usageReady(t *testing.T) (*runnerFixture, api.CaptureRecord) {
	t.Helper()
	f := runnerSetup(t)
	f.installLimitGuard()
	capture := f.setCapture(encodeEvent(t, f.quotaEvent("Usage limit reached")), "stdout")
	signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation)
	if err != nil || signal == nil || signal.UsageEvidence == nil {
		t.Fatal("outside usage positive control failed", err)
	}
	evidence, _ := f.retainedUsage(t)
	selected, record := f.launchRecord(t)
	data, err := f.service.objectBytes(context.Background(), selected.Scope, *signal.UsageEvidence, "usage_window", record.Reservation.OperationID, record.Reservation.Target.LifeID)
	var retained api.UsageWindowEvidence
	if err != nil || api.DecodeObject(data, &retained) != nil || !reflect.DeepEqual(evidence, retained) || signal.UsageEvidence.ID != evidence.ID {
		t.Fatal("limit signal lost the actual committed usage envelope", err)
	}
	return f, capture
}

func refuseUsage(t *testing.T, f *runnerFixture, capture api.CaptureRecord, message, assertion string) {
	t.Helper()
	signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation)
	var typed *api.Error
	if signal != nil || !errors.As(err, &typed) || typed.Message != message {
		t.Fatal(assertion, err)
	}
}

func TestUsagePercent(t *testing.T) {
	f, capture := usageReady(t)
	e, raw := f.retainedUsage(t)
	e.UsedPercent = 99
	raw = []byte(strings.Replace(string(raw), "\t100\t", "\t99\t", 1))
	f.retainUsage(t, e, raw)
	refuseUsage(t, f, capture, "usage limit lacks fresh outside from-profile exhaustion", "non-exhausted outside usage produced a limit")
}

func TestUsageFresh(t *testing.T) {
	f, capture := usageReady(t)
	// Still post-exit, so only the 30-second freshness bound decides.
	f.service.deps.Clock = fixedClock{instant: time.Date(2026, 10, 15, 12, 1, 0, 0, time.UTC)}
	refuseUsage(t, f, capture, "usage limit lacks fresh outside from-profile exhaustion", "stale post-exit outside usage produced a limit")
}

func TestUsageProfile(t *testing.T) {
	f, capture := usageReady(t)
	e, raw := f.retainedUsage(t)
	e.ProfileID = "profile-b"
	f.retainUsage(t, e, raw)
	refuseUsage(t, f, capture, "usage limit lacks fresh outside from-profile exhaustion", "destination profile usage produced a limit")
}

func TestUsageProducer(t *testing.T) {
	f, capture := usageReady(t)
	e, raw := f.retainedUsage(t)
	e.ProducerGeneration = "lane-writer"
	f.retainUsage(t, e, raw)
	refuseUsage(t, f, capture, "usage limit lacks fresh outside from-profile exhaustion", "foreign usage producer produced a limit")
}

func TestUsageSource(t *testing.T) {
	f, capture := usageReady(t)
	e, raw := f.retainedUsage(t)
	// Both raw and envelope are newly retained and rehashed. Hash validation
	// alone therefore passes; the actual selected TSV percent must decide.
	raw = []byte(strings.Replace(string(raw), "\t100\t", "\t99\t", 1))
	f.retainUsage(t, e, raw)
	refuseUsage(t, f, capture, "usage window fields differ from actual vendor row", "rehashed non-exhausted TSV produced a limit")
}

func TestUsageEnvelopeGuards(t *testing.T) {
	for _, field := range []string{"pre-exit", "future", "reset", "elapsed-reset", "failed", "grant", "provider", "launch", "operation", "target", "adapter", "binary", "runtime", "boot", "row", "missing-raw"} {
		t.Run(field, func(t *testing.T) {
			f, capture := usageReady(t)
			e, raw := f.retainedUsage(t)
			expected := "usage limit lacks fresh outside from-profile exhaustion"
			switch field {
			case "pre-exit":
				e.ObservedAt = "2026-10-15T12:00:01Z"
			case "future":
				e.ObservedAt = "2026-10-15T12:00:11Z"
			case "reset":
				e.ResetsAt = "unknown"
			case "elapsed-reset":
				e.ResetsAt = "2026-10-15T12:00:09Z"
				raw = []byte(strings.Replace(string(raw), "2026-10-15T13:00:00Z", string(e.ResetsAt), 1))
				expected = "usage window reset is no longer in the future"
			case "failed":
				e.ExitCode = 1
			case "grant":
				e.ProfileGrantID = "grant-b"
			case "provider":
				e.Provider = "other-provider"
			case "launch":
				e.LaunchID = "other-launch"
			case "operation":
				e.OperationID = "other-operation"
			case "target":
				e.Target.Run++
			case "adapter":
				e.AdapterVersion = "other-adapter"
			case "binary":
				e.Executable.SHA256 = contentDigest([]byte("other-binary"))
			case "runtime":
				e.RuntimeManifest.SHA256 = contentDigest([]byte("other-runtime"))
			case "boot":
				e.BootID = "old-boot"
			case "row":
				e.Row = 0
			case "missing-raw":
				e.Raw = api.BlobRef{}
			}
			if field == "missing-raw" {
				f.launch.write(usageKey("usage-result", f.request.Target), e)
			} else {
				f.retainUsage(t, e, raw)
			}
			refuseUsage(t, f, capture, expected, "usage envelope guard was bypassed: "+field)
		})
	}
}

func TestUsageTSVGuards(t *testing.T) {
	for _, field := range []string{"header", "profile", "plan", "reset", "partial", "nan"} {
		t.Run(field, func(t *testing.T) {
			f, capture := usageReady(t)
			e, raw := f.retainedUsage(t)
			text, expected := string(raw), "usage window fields differ from actual vendor row"
			switch field {
			case "header":
				text = strings.Replace(text, "USED_PERCENT", "USAGE", 1)
				expected = "usage source differs from pinned vendor TSV bytes"
			case "profile":
				text = strings.Replace(text, "fixture-profile", "foreign-profile", 1)
			case "plan":
				text += "fixture-profile\tconflicting\tother\t1\t2026-10-15T13:00:00Z\n"
				expected = "usage command contains invalid or conflicting vendor rows"
			case "reset":
				text = strings.Replace(text, "2026-10-15T13:00:00Z", "unknown", 1)
			case "partial":
				text = strings.TrimSuffix(text, "2026-10-15T13:00:00Z\n")
				expected = "usage window fields differ from actual vendor row"
			case "nan":
				text = strings.Replace(text, "\t100\t", "\tNaN\t", 1)
				expected = "usage command contains invalid or conflicting vendor rows"
			}
			f.retainUsage(t, e, []byte(text))
			refuseUsage(t, f, capture, expected, "actual TSV guard was bypassed: "+field)
		})
	}
}

func TestUsageRetention(t *testing.T) {
	for _, field := range []string{"raw-origin", "raw-operation", "raw-life", "raw-audience", "raw-bytes", "envelope-origin", "envelope-class", "envelope-bytes", "unretained"} {
		t.Run(field, func(t *testing.T) {
			f, capture := usageReady(t)
			e, raw := f.retainedUsage(t)
			id, expected := e.Raw.ID, "runner object lacks protected provenance"
			if strings.HasPrefix(field, "envelope") {
				id = e.ID
			}
			var metadata api.ObjectMetadata
			if err := f.launch.read("meta-"+string(id), &metadata); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "raw-origin", "envelope-origin":
				metadata.Origin = "observation"
			case "raw-operation":
				metadata.SourceOperationID = "other-operation"
			case "raw-life":
				metadata.ACL.LifeID = "other-life"
			case "raw-audience":
				metadata.ACL.Audience = "lane"
				expected = "usage object is not private service evidence"
			case "raw-bytes":
				raw[0] = 'X'
				put(t, f.launch.dir+"/"+string(id)+".bytes", raw)
				expected = "runner object digest changed"
			case "envelope-class":
				metadata.Ref.Class = "record"
				expected = "runner object has the wrong committed class"
			case "envelope-bytes":
				changed := e
				changed.Window = "different"
				data := mustJSON(t, changed)
				put(t, f.launch.dir+"/"+string(id)+".bytes", data)
				metadata.Ref.SHA256, metadata.Ref.Bytes = contentDigest(data), int64(len(data))
				expected = "usage envelope differs from its committed bytes"
			case "unretained":
				e.ID = "unretained-envelope"
				f.launch.write(usageKey("usage-result", f.request.Target), e)
				expected = "fixture retained object is absent"
			}
			f.launch.write("meta-"+string(id), metadata)
			refuseUsage(t, f, capture, expected, "usage retention guard was bypassed: "+field)
		})
	}
}

type usageStateBarrier struct {
	api.StateStore
	err error
}

func (b usageStateBarrier) WorkerBinding(context.Context, api.InstalledBinding, api.PeerFacts) (api.WorkerPrincipal, error) {
	return api.WorkerPrincipal{}, b.err
}

func TestUsageDependencies(t *testing.T) {
	for _, port := range []string{"source", "native", "worker", "enrollment", "nil-source", "nil-native", "nil-enrollment"} {
		t.Run(port, func(t *testing.T) {
			f, capture := usageReady(t)
			refusal := api.NotImplemented("lb-v2-secrets", "fixture usage "+port)
			switch port {
			case "source":
				f.service.deps.UsageWindows = unavailableLaunchPorts{err: refusal}
			case "native":
				f.service.deps.UsageWorker = func(context.Context, api.Scope, api.ID) (api.InstalledBinding, api.PeerFacts, error) {
					return api.InstalledBinding{}, api.PeerFacts{}, refusal
				}
			case "worker":
				f.service.deps.State = usageStateBarrier{StateStore: f.launch, err: refusal}
			case "enrollment":
				f.service.deps.UsageProfile = func(context.Context, api.ProfileGrant) (string, error) { return "", refusal }
			case "nil-source":
				f.service.deps.UsageWindows = nil
			case "nil-native":
				f.service.deps.UsageWorker = nil
			case "nil-enrollment":
				f.service.deps.UsageProfile = nil
			}
			signal, err := f.service.LimitFromCapture(context.Background(), capture, f.observation)
			if strings.HasPrefix(port, "nil-") {
				wantCode(t, err, api.CodeNotImplemented, "missing usage dependency succeeded: "+port)
			} else if err != refusal {
				t.Fatal("usage dependency refusal was changed: "+port, err)
			}
			if signal != nil {
				t.Fatal("unavailable usage dependency produced a limit: " + port)
			}
		})
	}
}
