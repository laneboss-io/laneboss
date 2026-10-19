//go:build linux

package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This exercises the native stop path and its durable reason choice. Closing
// stdin lets the real descriptor canary exit normally, independently of Stop.
// The broker refuses at Begin; actual encrypted completion is covered by the
// ruling-B release and LB-304 cancel/revoke controls in the secrets package.
func TestObservedExitCredentialStop(t *testing.T) {
	for _, mode := range []string{"observed-exit", "unobserved-exit", "running", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			m, registration, g, store, owner, broker, held, hold := stopCredentialFixtureControl(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			target := api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)}
			if mode != "running" {
				if err := hold.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-g.done:
				case <-ctx.Done():
					t.Fatal("independent canary exit was not reaped")
				}
				if mode != "unobserved-exit" {
					record, err := m.find(target.LeaseID)
					if err != nil {
						t.Fatal(err)
					}
					if err := owner.WaitContainmentEmpty(ctx, record); err != nil {
						t.Fatal(err)
					}
					observed, err := m.observeGate(ctx, target)
					if err != nil || observed.State != "exited" || observed.ExitCode == nil || *observed.ExitCode != 0 || owner.kills != 0 {
						t.Fatal("natural exit was not independently measured before Stop", err)
					}
				}
			}
			want := api.CredentialStopReason
			if mode == "observed-exit" {
				want = "release"
			}
			if mode == "revoked" {
				matched, err := m.revokeNativeContainment(ctx, registration.Binding.Record.ID)
				if !matched || !errors.Is(err, broker.failure) || broker.request.Reason != "revoked" {
					t.Fatal("revocation control did not retain its actual quarantine", err)
				}
				want = "revoked"
			}
			first := registration.Request.Cause
			first.Kind = api.InternalHelperStop
			request := api.HelperStopRequest{Cause: first, Target: target, Reason: "committed stop intent",
				OperationID: first.CauseOperationID, EffectID: first.EffectID}
			for attempt := range 2 {
				_, err := m.stopGate(ctx, request)
				if mode == "running" && owner.kills == 0 {
					t.Fatal("running canary was never killed by Stop")
				}
				if !errors.Is(err, broker.failure) || !owner.waited || !broker.ordered {
					t.Fatal("Stop did not reach withdrawal after real kill/wait", err)
				}
				records, err := store.Records()
				if err != nil || len(records) != 1 || records[0].Gate.Stop == nil || records[0].Credentials.Stop == nil {
					t.Fatal("Stop lost its persisted native or credential fence", err)
				}
				record := records[0]
				if *record.Gate.Stop != first || record.Credentials.Stop.Reason != want || broker.request.Reason != want {
					t.Fatalf("observed exit reason choice changed: mode=%s attempt=%d want=%s local=%s broker=%s native_first=%t",
						mode, attempt+1, want, record.Credentials.Stop.Reason, broker.request.Reason, *record.Gate.Stop == first)
				}
				if mode != "revoked" && (record.Credentials.Stop.Cause != first || broker.request.Cause != first) {
					t.Fatal("reclaimed Stop replaced the first credential withdrawal cause")
				}
				if _, err := held.Stat(); err != nil || !reflect.DeepEqual(record.Credentials.Record.Receipt, m.credentials.held["stop-projection"].record.Receipt) {
					t.Fatal("broker refusal discarded the original credential holding", err)
				}
				if _, err := m.observeGate(ctx, target); err != nil {
					t.Fatal("retry could not observe the now-ended process", err)
				}
				request.Cause.ID += "-retry"
				request.Cause.Actor = api.Actor{Kind: "service", ID: "reclaimed-stop-owner"}
			}
		})
	}
}

type stopFenceFailStore struct {
	leaseStorage
	writes  int
	failAt  int
	failure error
}

func (s *stopFenceFailStore) Save(record leaseRecord) error {
	s.writes++
	if s.writes == s.failAt {
		return s.failure
	}
	return s.leaseStorage.Save(record)
}

func TestStopFencePrecedesKill(t *testing.T) {
	for _, stage := range []string{"native", "credential"} {
		t.Run(stage, func(t *testing.T) {
			m, registration, g, store, owner, broker, held := stopCredentialFixture(t, true)
			failed := &stopFenceFailStore{leaseStorage: store, failAt: 1, failure: errors.New("component stop fence save failed")}
			if stage == "credential" {
				failed.failAt = 2
			}
			m.store = failed
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first := registration.Request.Cause
			first.Kind = api.InternalHelperStop
			request := api.HelperStopRequest{Cause: first,
				Target: api.HelperObserveRequest{LeaseID: registration.Binding.Record.UIDLeaseID, Handle: gateHandleFrom(registration)},
				Reason: "committed stop intent", OperationID: first.CauseOperationID, EffectID: first.EffectID}
			_, err := m.stopGate(ctx, request)
			if !errors.Is(err, failed.failure) || failed.writes != failed.failAt || broker.calls != 0 {
				t.Fatal("Stop did not retain the selected fence-save failure", err)
			}
			observed, err := g.Observe(ctx, request.Target.Handle)
			if err != nil {
				t.Fatal("failed-fence canary lost its native observation", err)
			}
			if owner.kills != 0 || owner.waits != 0 || observed.State != "running" {
				t.Errorf("kill preceded durable stop fences: stage=%s kills=%d waits=%d state=%s", stage, owner.kills, owner.waits, observed.State)
			}
			retained, err := store.Records()
			if err != nil || len(retained) != 1 || (retained[0].Gate.Stop != nil) != (stage == "credential") || retained[0].Credentials.Stop != nil {
				t.Fatal("failed save changed which stop fence was durably retained", err)
			}
			if _, err := held.Stat(); err != nil {
				t.Fatal("failed fence discarded the original credential holding", err)
			}
			// Match the installed retry's Observe before Stop. On the broken
			// path this records its earlier SIGKILL as an unfenced natural end.
			if observed.State == "exited" {
				if _, err := m.observeGate(ctx, request.Target); err != nil {
					t.Fatal("retry could not retain the actual earlier exit", err)
				}
			}
			request.Cause.ID += "-retry"
			request.Cause.Actor = api.Actor{Kind: "service", ID: "retry-stop-owner"}
			_, err = m.stopGate(ctx, request)
			if !errors.Is(err, broker.failure) || broker.calls != 1 || owner.kills == 0 || !owner.waited {
				t.Fatal("retry did not kill/wait after its durable fences and reach the broker", err)
			}
			wantCause := request.Cause
			if stage == "credential" {
				wantCause = first
			}
			retained, err = store.Records()
			if err != nil || len(retained) != 1 || retained[0].Gate.Stop == nil || retained[0].Credentials.Stop == nil {
				t.Fatal("retry lost its actual native and credential fences", err)
			}
			if *retained[0].Gate.Stop != wantCause || retained[0].Credentials.Stop.Cause != wantCause || broker.request.Cause != wantCause ||
				retained[0].Credentials.Stop.Reason != api.CredentialStopReason || broker.request.Reason != api.CredentialStopReason {
				t.Fatal("fence-save retry relabelled cancellation or replaced its first durable cause", broker.request.Reason)
			}
		})
	}
}
