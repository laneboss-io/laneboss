package identity_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	datafx "laneboss.io/laneboss/internal/v2/store/matfx"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type reservationSource func(context.Context, string, api.ID) (identity.WorkerLaunchGuard, error)

func (s reservationSource) AcquireWorkerLaunch(ctx context.Context, config string, id api.ID) (identity.WorkerLaunchGuard, error) {
	return s(ctx, config, id)
}

type reservationGuard struct {
	a               identity.WorkerLaunchAuthority
	input, endpoint *os.File
	peer            api.VerifiedPeer
	closes          int
}

func (g *reservationGuard) Authority() identity.WorkerLaunchAuthority { return g.a }
func (g *reservationGuard) Input() *os.File                           { return g.input }
func (g *reservationGuard) Endpoint() *os.File                        { return g.endpoint }
func (g *reservationGuard) Peer() api.VerifiedPeer                    { return g.peer }
func (g *reservationGuard) Check(ctx context.Context) error           { return g.peer.Alive(ctx) }
func (g *reservationGuard) Close() error {
	g.closes++
	return errors.Join(g.input.Close(), g.endpoint.Close())
}

type reservationRegistry struct {
	api.ContainmentRegistry
	binding api.ContainmentBinding
}

func (r *reservationRegistry) ResolveContainment(ctx context.Context, facts api.PeerFacts, endpoint api.InstalledBinding) (api.ContainmentBinding, error) {
	if err := ctx.Err(); err != nil {
		return api.ContainmentBinding{}, err
	}
	if facts.HostUID != r.binding.Lease.UID || facts.HostGID != r.binding.Lease.GID || facts.ContainmentID != r.binding.Lease.ContainmentID || endpoint.Config != r.binding.Config {
		return api.ContainmentBinding{}, &api.Error{Code: api.CodeForbidden, Message: "component containment selector changed"}
	}
	return r.binding, nil
}

type reservationPeers struct{}

func (reservationPeers) Verify(context.Context, net.Conn, api.InstalledBinding) (api.VerifiedPeer, error) {
	return nil, &api.Error{Code: api.CodeForbidden, Message: "component cannot authenticate a native connection"}
}

func reservationMemfd(t *testing.T, raw []byte) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("reservation-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "reservation-fixture")
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		t.Fatal("sealed component input write failed", err)
	}
	if err := file.Chmod(0444); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		t.Fatal(err)
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

// The store issues the real reservation, stage, child claim, spec and identity
// event. Native peer/containment are explicit component fixtures; the input
// and endpoint are actual read-only sealed memfds. No lane is fabricated.
func TestWorkerBindBeforeLaneCreated(t *testing.T) {
	ctx := context.Background()
	d := datafx.NewData(t)
	d.Seal(t)
	d.Prepared = api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: d.Stage.Reservation.Target,
		SpecSHA256: d.Handoff.SpecSHA256, ContainmentID: d.Allocation.ContainmentID,
		ProcessGeneration: "component-boot:" + string(fx.ID(t)), EndpointGeneration: d.Allocation.EndpointGeneration}
	var err error
	d.Binding, err = d.F.State.BindDataWorker(ctx, d.F.Execution, d.Stage.ID, d.Prepared)
	if err != nil {
		t.Fatal("real worker identity commit failed", err)
	}
	_, err = d.F.State.Lane(ctx, d.F.Execution, d.Stage.Reservation.Target)
	var missing *api.Error
	if !errors.As(err, &missing) || missing.Code != api.CodeNotFound {
		t.Fatal("first-launch control unexpectedly has a lane projection", err)
	}
	facts := api.PeerFacts{HostUID: d.Allocation.UID, HostGID: d.Allocation.GID, HostPID: os.Getpid(),
		ProcessGeneration: d.Prepared.ProcessGeneration, ContainmentID: d.Allocation.ContainmentID}
	principal, err := d.F.State.WorkerBinding(ctx, d.Endpoint, facts)
	if err != nil {
		t.Fatal("real pre-lane worker mapping failed", err)
	}
	input, err := d.F.State.Blob(ctx, d.F.Execution, api.BlobReadRequest{ObjectID: d.Stage.Worker.Input.ID, Limit: api.MaxChunkBytes})
	if err != nil || input.SHA256 != d.Stage.Worker.Input.SHA256 {
		t.Fatal("real retained input read failed", err)
	}
	guard := &reservationGuard{a: identity.WorkerLaunchAuthority{Binding: d.Binding, Handoff: d.Handoff, Principal: principal},
		input: reservationMemfd(t, input.Data), endpoint: reservationMemfd(t, fx.JSON(t, d.Endpoint)),
		peer: &fx.Peer{FactsValue: facts}}
	t.Cleanup(func() {
		if guard.closes == 0 {
			if err := guard.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := directory.Close(); err != nil {
			t.Error(err)
		}
	})
	registry := &reservationRegistry{binding: api.ContainmentBinding{Config: d.Endpoint.Config,
		Target: d.Stage.Reservation.Target, Backend: d.Endpoint.Backend, BootID: principal.BootID,
		Generation: principal.AllocationGeneration, Lease: d.Allocation, Directory: directory}}
	source := reservationSource(func(_ context.Context, config string, id api.ID) (identity.WorkerLaunchGuard, error) {
		if config != d.Endpoint.Config || id != d.Prepared.ID {
			t.Fatal("worker source received a foreign selector")
		}
		return guard, nil
	})
	s, err := identity.New(identity.Dependencies{Store: d.F.State, Clock: d.F.Deps.Clock, Peers: reservationPeers{}, Registry: registry, Workers: source})
	if err != nil {
		t.Fatal(err)
	}
	permit, err := s.BindLaunch(ctx, d.Binding)
	if err != nil || permit.LaunchID != d.Binding.Record.ID || permit.PreparedID != d.Prepared.ID ||
		permit.RecordSHA256 != d.Binding.Identity.RecordSHA256 || permit.CommittedSeq != d.Binding.Identity.CommittedSeq || guard.closes != 1 {
		page, readErr := d.F.State.Events(ctx, d.F.Execution, api.EventTailRequest{LifeID: d.Binding.Record.Target.LifeID, Run: d.Binding.Record.Target.Run, Since: d.Binding.Identity.CommittedSeq - 1})
		if readErr != nil {
			t.Fatal("identity event diagnostic read failed", readErr)
		}
		for _, event := range page.Events {
			if event.Seq == d.Binding.Identity.CommittedSeq {
				t.Logf("identity event metadata: author_matches=%t claimant_matches=%t requester_matches=%t request_matches=%t operation_matches=%t",
					event.Actor == d.Handoff.Cause.Actor, event.Actor == (api.Actor{Kind: "service", ID: principal.Claim.Record.ClaimantID}),
					event.RequestedBy == d.Handoff.Cause.RequestedBy, event.RequestID == d.Handoff.RequestID, event.OperationID == d.Handoff.OperationID)
			}
		}
		t.Fatalf("real sourced worker must bind before lane.created: %v", err)
	}
	if _, err := d.F.State.Lane(ctx, d.F.Execution, d.Stage.Reservation.Target); !errors.As(err, &missing) || missing.Code != api.CodeNotFound {
		t.Fatal("worker binding fabricated an agent lane", err)
	}
}
