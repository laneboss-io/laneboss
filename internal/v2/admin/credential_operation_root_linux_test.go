//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCodexContainmentLiveGateTransition(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("containment transition fixture requires the root Linux box build")
	}
	manager, registration, _, _, store := retainedGateFixture(t)
	leaseID := registration.Binding.Record.UIDLeaseID
	group := filepath.Join(manager.binding.cgroupPath(), string(registration.Binding.Record.ContainmentID))
	unit := filepath.Dir(manager.binding.cgroupPath())
	lanes := manager.binding.cgroupPath()
	for _, path := range []string{unit, lanes, group} {
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal("cannot create containment fixture cgroup", err)
		}
	}
	if err := os.Chmod(group, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(group)
		_ = os.Remove(lanes)
		_ = os.Remove(unit)
	})

	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("gate fixture did not retain one helper record", err)
	}
	record := records[0]
	permit := registration.Request.Permit
	record.Gate.State, record.Gate.Permit, record.Gate.Open = "opening", &permit, &registration
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	notifierDone := manager.beginGateOpenWait(leaseID)
	result := make(chan struct {
		ticket containmentTicket
		err    error
	}, 1)
	go func() {
		ticket, err := manager.containment(context.Background(), containmentQuery{LeaseID: leaseID, Opened: true})
		result <- struct {
			ticket containmentTicket
			err    error
		}{ticket, err}
	}()
	time.Sleep(20 * time.Millisecond)
	record.Gate.State = "opened"
	if err := store.Save(record); err != nil {
		notifierDone()
		t.Fatal(err)
	}
	notifierDone()
	select {
	case outcome := <-result:
		if outcome.err != nil || outcome.ticket.Lease.ID != leaseID {
			t.Fatal("live notifier did not return the durable opened containment ticket", outcome.err)
		}
	case <-time.After(time.Second):
		t.Fatal("containment_live waiter did not observe the opened transition")
	}

	record.Gate.State = "opening"
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	finished := manager.beginGateOpenWait(leaseID)
	result = make(chan struct {
		ticket containmentTicket
		err    error
	}, 1)
	go func() {
		ticket, err := manager.containment(context.Background(), containmentQuery{LeaseID: leaseID, Opened: true})
		result <- struct {
			ticket containmentTicket
			err    error
		}{ticket, err}
	}()
	time.Sleep(20 * time.Millisecond)
	finished()
	select {
	case outcome := <-result:
		if outcome.ticket != (containmentTicket{}) || outcome.err == nil {
			t.Fatal("a finished notifier without durable opened state returned a containment ticket", outcome.err)
		}
		requireCode(t, outcome.err, api.CodeUnauthenticated)
	case <-time.After(time.Second):
		t.Fatal("containment waiter did not observe the finished transition")
	}

	record.Gate.State = "opening"
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	ticket, err := manager.containment(context.Background(), containmentQuery{LeaseID: leaseID, Opened: true})
	if ticket != (containmentTicket{}) || err == nil {
		t.Fatal("an opening gate without a notifier was accepted", err)
	}
	requireCode(t, err, api.CodeContainmentUnknown)
}
