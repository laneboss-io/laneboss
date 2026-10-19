package claudock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func readHomeRecord(t *testing.T, home *Home) (homeRecord, []byte) {
	t.Helper()
	data := get(t, filepath.Join(home.records.path, home.key+".json"))
	var record homeRecord
	if err := decodeExact(data, &record); err != nil {
		t.Fatal(err)
	}
	return record, data
}

func TestLaunchSealRetry(t *testing.T) {
	f := runnerReady(t, nil)
	inputs, err := f.service.planning(context.Background(), f.request, "start")
	if err != nil {
		t.Fatal(err)
	}
	id, digest := inputs.record.Reservation.ID, inputs.digest
	records := f.home.records
	publish := records.publish
	defer func() { records.publish = publish }()
	sealAttempts := 0
	var failedPublication error
	missing, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	records.publish = func(root *os.Root, name string, data []byte) error {
		var pending homeRecord
		if err := decodeExact(data, &pending); err != nil {
			return err
		}
		if pending.Launches[id] == digest {
			sealAttempts++
			if sealAttempts == 1 {
				if pending.Session != f.request.Session || pending.Home != f.request.Home || pending.Model != f.request.Model {
					t.Fatal("seal failure was injected before the start binding")
				}
				if _, err := root.Lstat(missing); !os.IsNotExist(err) {
					t.Fatal("seal fault needs an actually absent temporary parent", err)
				}
				// Use the actual private publisher and bytes. Its temporary-file
				// open fails on the absent parent; no fabricated errno or success.
				failedPublication = replacePrivate(root, missing, name, data, 0600)
				if failedPublication == nil {
					t.Fatal("seal fault did not fail a real publication")
				}
				return failedPublication
			}
		}
		return publish(root, name, data)
	}
	first, err := f.service.Start(context.Background(), f.request)
	if failedPublication == nil || !errors.Is(err, failedPublication) || len(first.Argv) != 0 || sealAttempts != 1 {
		t.Fatal("start did not reach the injected seal publication failure", err)
	}
	partial, _ := readHomeRecord(t, f.home)
	if partial.Session.ID != "" || partial.Home.ID != "" || partial.Model != "" || len(partial.Launches) != 0 {
		t.Fatal("failed atomic start left a partial binding or seal")
	}
	retried, err := f.service.Start(context.Background(), f.request)
	if err != nil || len(retried.Argv) == 0 {
		t.Fatal("failed seal stranded the same start reservation", err)
	}
	sealed, _ := readHomeRecord(t, f.home)
	if sealAttempts != 2 || sealed.Launches[id] != digest || len(sealed.Launches) != 1 || sealed.Session != f.request.Session || sealed.Home != f.request.Home || sealed.Model != f.request.Model {
		t.Fatal("retry did not publish the original reservation seal")
	}
}

func TestStartBindRetryIdentity(t *testing.T) {
	f := runnerReady(t, nil)
	id, digest := api.ID("retry-reservation"), contentDigest([]byte("retained retry inputs"))
	if err := f.home.bindAndSeal(f.request, id, digest); err != nil {
		t.Fatal(err)
	}
	_, before := readHomeRecord(t, f.home)
	if err := f.home.bindAndSeal(f.request, id, digest); err != nil {
		t.Fatal("identical sealed reservation retry was refused", err)
	}
	for _, field := range []string{"session", "home", "model"} {
		bad := f.request
		switch field {
		case "session":
			bad.Session.ID = "session-other"
		case "home":
			bad.Home.WorkspaceID = "workspace-other"
		case "model":
			bad.Model = "claude-opus-4-6"
		}
		wantCode(t, f.home.bindAndSeal(bad, id, digest), api.CodeConflict, "changed start binding was accepted: "+field)
	}
	wantCode(t, f.home.bindAndSeal(f.request, id, contentDigest([]byte("changed retry inputs"))), api.CodeIntegrity, "changed start seal digest was accepted")
	_, after := readHomeRecord(t, f.home)
	if !bytes.Equal(before, after) {
		t.Fatal("binding retry or refusal changed the protected input bytes")
	}
}

// A deliberately conflicting, separately retained reservation for the same
// home. All source/request/effect IDs and bytes are correlated so the adapter's
// home conflict, rather than an unrelated malformed fixture, decides the test.
func (f *runnerFixture) secondStart(t *testing.T) api.ID {
	t.Helper()
	selector, record := f.launchRecord(t)
	originalBytes, err := f.service.objectBytes(context.Background(), selector.Scope, record.Reservation.OriginalRequest, "launch_request", record.Reservation.OperationID, "")
	if err != nil {
		t.Fatal(err)
	}
	storage, err := f.launch.ResolveLaunchStorage(context.Background(), api.LaunchDataRequest{
		ReservationID: record.Reservation.ID, GrantSetID: record.Reservation.GrantSetID, LeaseID: selector.HelperLeaseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := f.launch.Effect(context.Background(), selector.Scope, selector.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	r := &record.Reservation
	r.ID, r.LaunchID, r.SpecID = api.ID("plan-"+uuid), api.ID("launch-"+uuid), api.ID("spec-"+uuid)
	r.OperationID, r.RequestID, r.Authority.ID = api.ID("operation-"+uuid), api.ID("request-"+uuid), api.ID("ticket-"+uuid)
	selector.ReservationID, selector.EffectID, selector.ClaimID, selector.HelperLeaseID = r.ID, api.ID("effect-"+uuid), api.ID("claim-"+uuid), api.ID("helper-"+uuid)
	var original api.Request
	if err := api.DecodeObject(originalBytes, &original); err != nil {
		t.Fatal(err)
	}
	var start api.StartRequest
	if err := api.DecodeObject(original.Params, &start); err != nil {
		t.Fatal(err)
	}
	f.request.Prompt = f.launch.object(api.ID("prompt-"+uuid), "prompt", []byte("kept brief\n"), r.OperationID, r.Target.LifeID)
	start.Task, start.RootTicketID = f.request.Prompt, r.Authority.ID
	original.RequestID, original.IdempotencyKey = r.RequestID, api.ID("key-"+uuid)
	original.Params, err = json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	original.RequestSHA256, err = api.RequestDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	r.RequestSHA256 = original.RequestSHA256
	r.OriginalRequest = f.launch.object(api.ID("original-"+uuid), "launch_request", frame, r.OperationID, "")
	record.Inputs.Sources.ReservationID = r.ID
	record.Phase, record.Plan, record.Handoff = "sourced", nil, nil
	storage.ReservationID, storage.LeaseID = r.ID, selector.HelperLeaseID
	effect.Effect.ID, effect.Effect.OperationID, effect.ClaimID = selector.EffectID, r.OperationID, selector.ClaimID
	effect.Effect.PlanLaunch.ReservationID = r.ID
	effect.Effect.Context.CauseOperationID, effect.Effect.Context.CauseRequestID, effect.Effect.Context.EffectID = r.OperationID, r.RequestID, selector.EffectID
	f.launch.write("plan-"+string(r.ID), record)
	f.launch.write("storage-"+string(r.ID), storage)
	f.launch.write("enrolled-"+string(r.ID), record.Inputs.Sources)
	f.launch.write("effect-"+string(selector.EffectID), effect)
	f.launch.write(fmt.Sprintf("index-%s-%d", r.Target.LifeID, r.Target.Run), selector)
	f.launch.retainRun(f.request)
	return r.ID
}

func TestSecondStartRejected(t *testing.T) {
	for _, history := range []bool{true, false} {
		t.Run(map[bool]string{true: "conversation", false: "binding"}[history], func(t *testing.T) {
			f := runnerReady(t, nil)
			// Seed the first binding and seal through the real record methods,
			// then exercise its actual Start replay. The all-ID replay mutant
			// must not turn this setup into an accidentally unbound first home.
			first, err := f.service.planning(context.Background(), f.request, "start")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.home.bindAndSeal(f.request, first.record.Reservation.ID, first.digest); err != nil {
				t.Fatal(err)
			}
			initial, err := f.service.Start(context.Background(), f.request)
			if err != nil {
				t.Fatal("first reservation replay control failed", err)
			}
			f.opened(t, initial)
			if history {
				f.history(t)
			}
			before, data := readHomeRecord(t, f.home)
			id := f.secondStart(t)
			if _, exists := before.Launches[id]; exists {
				t.Fatal("second start reused the first reservation")
			}
			replayed, err := f.home.checkLaunch(id, first.digest)
			if err != nil || replayed {
				t.Fatal("foreign reservation was classified as a retained replay", err)
			}
			if _, err := f.service.planning(context.Background(), f.request, "start"); err != nil {
				t.Fatal("second start failed before its home-conflict guard", err)
			}
			plan, err := f.service.Start(context.Background(), f.request)
			wantCode(t, err, api.CodeConflict, "different start reservation replaced the bound home")
			if len(plan.Argv) != 0 {
				t.Fatal("different start reservation returned runner argv")
			}
			after, bytesAfter := readHomeRecord(t, f.home)
			if !bytes.Equal(data, bytesAfter) || len(after.Launches) != 1 {
				t.Fatal("refused second start changed the existing binding or seal")
			}
		})
	}
}

// Clone a separately claimed reservation while preserving the identical
// durable request. Store CAS should prevent duplicate issuance in production;
// this canary exercises the adapter's independent home guard if it occurs.
func (f *runnerFixture) duplicateStart(t *testing.T) (LaunchSelector, LaunchSelector) {
	t.Helper()
	a, record := f.launchRecord(t)
	storage, err := f.launch.ResolveLaunchStorage(context.Background(), api.LaunchDataRequest{
		ReservationID: a.ReservationID, GrantSetID: record.Reservation.GrantSetID, LeaseID: a.HelperLeaseID,
	})
	if err != nil {
		t.Fatal(err)
	}
	effect, err := f.launch.Effect(context.Background(), a.Scope, a.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.ReservationID, b.EffectID, b.ClaimID, b.HelperLeaseID = "race-plan-b", "race-effect-b", "race-claim-b", "race-helper-b"
	record.Reservation.ID, record.Reservation.LaunchID, record.Reservation.SpecID = b.ReservationID, "race-launch-b", "race-spec-b"
	record.Inputs.Sources.ReservationID = b.ReservationID
	storage.ReservationID, storage.LeaseID = b.ReservationID, b.HelperLeaseID
	effect.Effect.ID, effect.ClaimID = b.EffectID, b.ClaimID
	effect.Effect.PlanLaunch.ReservationID = b.ReservationID
	effect.Effect.Context.EffectID = b.EffectID
	f.launch.write("plan-"+string(b.ReservationID), record)
	f.launch.write("storage-"+string(b.ReservationID), storage)
	f.launch.write("enrolled-"+string(b.ReservationID), record.Inputs.Sources)
	f.launch.write("effect-"+string(b.EffectID), effect)
	f.launch.write("race-selector-a", a)
	f.launch.write("race-selector-b", b)
	return a, b
}

func TestConcurrentStarts(t *testing.T) {
	f := runnerReady(t, nil)
	a, b := f.duplicateStart(t)
	otherRecords, err := NewRecords(f.home.records.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := otherRecords.Close(); err != nil {
			t.Error(err)
		}
	})
	services := []*Service{f.service, nil}
	deps := f.service.deps
	deps.Records = otherRecords
	services[1], err = New(deps)
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan int, 2)
	release := []chan struct{}{make(chan struct{}), make(chan struct{})}
	// Cleanup also unblocks a failed-test path; no goroutine is left parked.
	defer func() {
		for _, ch := range release {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}()
	type result struct {
		index int
		plan  api.RunnerPlan
		err   error
	}
	finished := make(chan result, 2)
	for index, service := range services {
		name := []string{"race-selector-a", "race-selector-b"}[index]
		service.deps.SelectLaunch = func(_ context.Context, target api.LifeRef) (LaunchSelector, error) {
			var selector LaunchSelector
			err := f.launch.read(name, &selector)
			if err == nil && target != f.request.Target {
				err = failure(api.CodeIntegrity, "race selector target changed")
			}
			return selector, err
		}
		service.beforeStartCommit = func() { arrived <- index; <-release[index] }
	}
	waitArrival := func(index int) {
		t.Helper()
		select {
		case actual := <-arrived:
			if actual != index {
				t.Fatal("start reached the wrong commit barrier")
			}
		case early := <-finished:
			t.Fatal("start did not reach the commit barrier", early.index, early.err)
		case <-time.After(10 * time.Second):
			t.Fatal("start commit barrier timed out")
		}
	}
	start := func(index int) {
		go func() {
			p, err := services[index].Start(context.Background(), f.request)
			finished <- result{index, p, err}
		}()
	}
	// A remains inside the actual Start call while B completes all its stale
	// preflight reads. Neither can commit until both calls are in flight.
	start(0)
	waitArrival(0)
	start(1)
	waitArrival(1)
	before, _ := readHomeRecord(t, f.home)
	if len(before.Launches) != 0 || before.Session.ID != "" {
		t.Fatal("start published before the atomic commit barrier")
	}
	// Park the actual publisher while its record flock is held. A second
	// Records handle must fail to acquire it, and disk still has no binding.
	publishing, publishRelease := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-publishRelease:
		default:
			close(publishRelease)
		}
	}()
	publish := f.home.records.publish
	f.home.records.publish = func(root *os.Root, name string, data []byte) error {
		close(publishing)
		<-publishRelease
		return publish(root, name, data)
	}
	close(release[0])
	select {
	case <-publishing:
	case <-time.After(10 * time.Second):
		t.Fatal("start did not reach real publication")
	}
	pending, _ := readHomeRecord(t, f.home)
	if pending.Session.ID != "" || len(pending.Launches) != 0 {
		t.Fatal("pending atomic publication exposed a partial start")
	}
	lockErr := otherRecords.transaction(f.home.key, func(*homeRecord) error { return nil }, nil)
	if !errors.Is(lockErr, ErrBusy) {
		t.Fatal("start publication did not hold the record flock", lockErr)
	}
	close(publishRelease)
	waitResult := func() result {
		t.Helper()
		select {
		case r := <-finished:
			return r
		case <-time.After(10 * time.Second):
			t.Fatal("concurrent start did not finish")
			return result{}
		}
	}
	first := waitResult()
	f.home.records.publish = publish
	close(release[1])
	second := waitResult()
	after, _ := readHomeRecord(t, f.home)
	if first.index != 0 || first.err != nil || len(first.plan.Argv) == 0 || second.index != 1 || second.err == nil || len(second.plan.Argv) != 0 || len(after.Launches) != 1 || after.Launches[a.ReservationID] == "" || after.Launches[b.ReservationID] != "" {
		t.Fatal("concurrent starts did not yield exactly one plan and one seal", first.err, second.err)
	}
	wantCode(t, second.err, api.CodeConflict, "foreign concurrent start did not conflict")
	launchReason(t, second.err, "private home is sealed for another start reservation", "concurrent start did not reach the foreign-seal refusal")
	replay, err := services[0].Start(context.Background(), f.request)
	if err != nil || !bytes.Equal(mustJSON(t, replay), mustJSON(t, first.plan)) {
		t.Fatal("winning reservation replay was not idempotent", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
