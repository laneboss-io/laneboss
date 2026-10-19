//go:build linux

package admin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type endWriteFault struct {
	*fileLeaseStore
	after bool
	hit   bool
	err   error
}

func (s *endWriteFault) Save(record leaseRecord) error {
	if !s.hit && committedExit(record) && record.Gate.Stop == nil {
		s.hit = true
		if s.after {
			if err := s.fileLeaseStore.Save(record); err != nil {
				return err
			}
		}
		return s.err
	}
	return s.fileLeaseStore.Save(record)
}

// This component owns one real process, not an installed cgroup/UID census.
// Restart gets only its numeric identity and independently checks /proc;
// neither the old gate, its done channel nor a wait result is copied.
type endedProcessResources struct {
	*observedResources
	pid int
}

func (r *endedProcessResources) Quiescent(ctx context.Context, record leaseRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if record.Gate == nil || record.Gate.PID != r.pid {
		return errors.New("terminal component changed its process identity")
	}
	_, err := os.Stat(fmt.Sprintf("/proc/%d", r.pid))
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("terminal component process is present or unknown")
	}
	return nil
}

func TestEndCommitBoundary(t *testing.T) {
	for _, after := range []bool{false, true} {
		name := "write-failed"
		if after {
			name = "crash-after-commit"
		}
		t.Run(name, func(t *testing.T) {
			m, reg, g, store, owner, broker, held := stopCredentialFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			naturalCanaryExit(t, ctx, owner)
			observation, err := g.Observe(ctx, owner.handle)
			if err != nil {
				t.Fatal(err)
			}
			zero := uint64(0) // The fixture's real wait above reaped its sole process.
			observation.Survivors = &zero
			fault := &endWriteFault{fileLeaseStore: store, after: after, err: errors.New("exit commit interrupted")}
			m.store = fault
			cause := reg.Request.Cause
			cause.Kind = api.InternalHelperRelease
			_, err = m.release(ctx, api.HelperReleaseRequest{Cause: cause,
				LeaseID: reg.Binding.Record.UIDLeaseID, Observation: observation})
			if !errors.Is(err, fault.err) || !fault.hit || broker.calls != 0 || len(owner.removed) != 0 {
				t.Fatal("exit commit did not precede credential cleanup and removal", err)
			}
			if _, err := held.Stat(); err != nil {
				t.Fatal("failed exit publication discarded credential ownership", err)
			}
			records, err := store.Records()
			if err != nil || len(records) != 1 || committedExit(records[0]) != after || records[0].Revoked || records[0].Credentials.Stop != nil {
				t.Fatal("interrupted exit changed the wrong durable state", err)
			}
			reopened, err := os.OpenRoot(store.root.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restart := newLeaseManager(m.binding, m.bootID, &fileLeaseStore{root: reopened, owner: store.owner},
				&endedProcessResources{observedResources: &observedResources{}, pid: g.PID()})
			target := api.HelperObserveRequest{LeaseID: records[0].Lease.ID, Handle: owner.handle}
			observed, err := restart.observeGate(ctx, target)
			if !after {
				requireCode(t, err, api.CodeContainmentUnknown)
				return
			}
			if err != nil || !reflect.DeepEqual(observed, *records[0].Gate.Observation) || stopWithdrawalReason(records[0]) != "release" || len(restart.gates) != 0 {
				t.Fatal("restart lost the committed exit or quarantined its disposition", err)
			}
			resources := restart.resources
			restart.resources = &observedResources{quietErr: failure(api.CodeContainmentUnknown, "fresh census refused")}
			_, err = restart.observeGate(ctx, target)
			requireCode(t, err, api.CodeContainmentUnknown)
			restart.resources = resources
			restart.bootID = "another-boot"
			_, err = restart.observeGate(ctx, target)
			requireCode(t, err, api.CodeContainmentUnknown)
		})
	}
}

func TestEndCommitRefusals(t *testing.T) {
	for _, mode := range []string{"owner", "claim", "boot", "running", "census"} {
		t.Run(mode, func(t *testing.T) {
			m, reg, g, store, owner, broker, _ := stopCredentialFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			zero, code := uint64(0), 0
			// In the running control this deliberately false caller claim must
			// never replace the native wait. Other cases use the actual exit.
			claim := api.ProcessObservation{Handle: owner.handle, State: "exited", PromptStatus: "unknown",
				ExitCode: &code, Survivors: &zero, ObservedAt: gateTimestamp()}
			if mode != "running" {
				naturalCanaryExit(t, ctx, owner)
				var err error
				claim, err = g.Observe(ctx, owner.handle)
				if err != nil {
					t.Fatal(err)
				}
				claim.Survivors = &zero
			}
			switch mode {
			case "owner":
				delete(m.gates, reg.Binding.Record.UIDLeaseID)
			case "claim":
				claim.Handle.ID = "foreign-process"
			case "boot":
				m.bootID = "another-boot"
			case "census":
				owner.quietErr = failure(api.CodeContainmentUnknown, "native census refused")
			}
			cause := reg.Request.Cause
			cause.Kind = api.InternalHelperRelease
			_, err := m.release(ctx, api.HelperReleaseRequest{Cause: cause,
				LeaseID: reg.Binding.Record.UIDLeaseID, Observation: claim})
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || broker.calls != 0 || len(owner.removed) != 0 {
				t.Fatal("normal release bypassed native refusal", err)
			}
			records, err := store.Records()
			if err != nil || len(records) != 1 || committedExit(records[0]) || records[0].Credentials.State != "held" ||
				stopWithdrawalReason(records[0]) != api.CredentialStopReason {
				t.Fatal("native refusal invented a durable exit or released ownership", err)
			}
		})
	}
}

type exitAtFence struct {
	leaseStorage
	t     *testing.T
	ctx   context.Context
	owner *stopCanaryOwner
	hit   bool
}

func (s *exitAtFence) Save(record leaseRecord) error {
	if !s.hit && record.Gate != nil && record.Gate.Stop != nil {
		s.hit = true
		naturalCanaryExit(s.t, s.ctx, s.owner)
	}
	return s.leaseStorage.Save(record)
}

// The process exits at the native fence publication boundary, after the
// disposition read. A later Observe and a reclaimed Stop must keep rotation.
func TestStopChoiceBeforeFence(t *testing.T) {
	m, reg, _, store, owner, broker, _ := stopCredentialFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fence := &exitAtFence{leaseStorage: store, t: t, ctx: ctx, owner: owner}
	m.store = fence
	request := stopExitRequest(reg)
	for attempt := range 2 {
		_, err := m.stopGate(ctx, request)
		if !errors.Is(err, broker.failure) || !fence.hit || broker.request.Reason != api.CredentialStopReason {
			t.Fatal("pre-exit Stop became a release at its native fence", err)
		}
		records, err := store.Records()
		if err != nil || len(records) != 1 || !records[0].Revoked || records[0].Credentials.Stop == nil ||
			records[0].Credentials.Stop.Reason != api.CredentialStopReason || records[0].Credentials.Stop.Note != "" {
			t.Fatal("pre-exit Stop lost its durable rotation choice", err)
		}
		if _, err := m.observeGate(ctx, request.Target); err != nil {
			t.Fatal(err)
		}
		request.Cause.ID += "-retry"
		request.Cause.Actor = api.Actor{Kind: "service", ID: api.ID(fmt.Sprintf("reclaimed-%d", attempt))}
	}
}
