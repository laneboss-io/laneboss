//go:build linux

package admin

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/pollgate"
)

func TestContainmentReadFence(t *testing.T) {
	service, ticket := registryFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered := make(chan struct{})
	result := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		_, check, err := service.containmentProof(ctx, "cg-a", containmentQuery{LeaseID: ticket.Lease.ID, Opened: true}, nil,
			func(ctx context.Context, query containmentQuery) (containmentTicket, time.Time, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-ctx.Done()
					return containmentTicket{}, time.Time{}, ctx.Err()
				}
				return ticket, time.Now().Add(pollgate.VerdictAge), nil
			})
		if err == nil {
			err = check()
		}
		result <- err
	}()
	<-entered
	finish := service.beginContainment(ticket.Lease.ID)
	finish()
	select {
	case err := <-result:
		if err != nil || calls.Load() != 2 {
			t.Fatal("publication fence refused instead of taking a fresh observation", calls.Load(), err)
		}
	case <-ctx.Done():
		t.Fatal("publication fence left the request waiting")
	}
}

func TestLaneCacheFence(t *testing.T) {
	service, ticket := registryFixture(t)
	lane, worker := service.containments["cg-a"], service.containments["cg-b"]
	lane.Ticket.Kind, worker.Ticket.Kind = api.EndpointLane, api.EndpointWorker
	if err := service.revokeLanes(ticket.Lease.ID); err != nil {
		t.Fatal(err)
	}
	if !lane.Binding.Revoked {
		t.Fatal("known stopped lane retained its cached authority")
	}
	if worker.Binding.Revoked {
		t.Fatal("lane cache fence revoked the separate worker route")
	}
	if _, err := worker.Binding.Directory.Stat(); err != nil {
		t.Fatal("lane cache fence closed the worker's retained pin", err)
	}
}

func TestContainmentCache(t *testing.T) {
	for _, change := range []string{"expiry", "generation", "replacement", "revoked", "cancelled", "helper-error", "slow-reply", "wait-budget"} {
		t.Run(change, func(t *testing.T) {
			service, ticket := registryFixture(t)
			query := containmentQuery{LeaseID: ticket.Lease.ID, Opened: true}
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			calls := 0
			if change == "slow-reply" || change == "wait-budget" {
				if _, err := service.cachedContainment(ctx, "cg-a", query, func(context.Context, containmentQuery) (containmentTicket, error) {
					return ticket, nil
				}); err != nil {
					t.Fatal("cannot prime the steady-read control", err)
				}
				time.Sleep(120 * time.Millisecond)
			}
			helperErr := errors.New("helper observation failed")
			refresh := func(ctx context.Context, got containmentQuery) (containmentTicket, error) {
				calls++
				if !service.registryMu.TryLock() {
					t.Fatal("registry lock held over helper IPC")
				}
				service.registryMu.Unlock()
				if got != query {
					t.Fatal("helper read lost exact lease or opened gate", got)
				}
				if change == "helper-error" {
					return containmentTicket{}, helperErr
				}
				if change == "slow-reply" {
					time.Sleep(120 * time.Millisecond)
				}
				if change == "wait-budget" {
					<-ctx.Done()
					return containmentTicket{}, ctx.Err()
				}
				return ticket, nil
			}
			read := func() (containmentTicket, error) {
				return service.cachedContainment(ctx, "cg-a", query, refresh)
			}
			start := time.Now()
			got, err := read()
			if change == "helper-error" || change == "slow-reply" || change == "wait-budget" {
				if err == nil || change == "helper-error" && !errors.Is(err, helperErr) {
					t.Fatal("failed or expired observation became authority", err)
				}
				if _, nextErr := read(); nextErr == nil || calls != 2 {
					t.Fatal("negative observation was cached", calls, nextErr)
				}
				if change == "wait-budget" && time.Since(start) > 188*time.Millisecond {
					t.Fatal("expired helper refresh did not refuse within 188 ms", time.Since(start))
				}
				return
			}
			if err != nil || got != ticket {
				t.Fatal("cannot warm exact helper ticket", err)
			}
			for range 20 {
				if got, err := read(); err != nil || got != ticket {
					t.Fatal("unchanged short-lived observation lost", err)
				}
			}
			if calls != 1 {
				t.Fatal("repeated native checks did not share one helper observation", calls)
			}
			switch change {
			case "expiry":
				time.Sleep(120 * time.Millisecond)
			case "generation":
				ticket.Generation++
				ticket.Lease.EndpointGeneration++
				service.containments["cg-a"].Ticket = ticket
			case "replacement":
				old := service.containments["cg-a"]
				service.containments["cg-a"] = &containmentEntry{Binding: old.Binding, Ticket: old.Ticket}
			case "revoked":
				if err := service.revokeEntries(ticket.Lease.ID); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err = read()
			if change == "revoked" || change == "cancelled" {
				if err == nil || calls != 1 {
					t.Fatal("revoked or cancelled cache hit retained authority", calls, err)
				}
			} else if err != nil || got != ticket || calls != 2 {
				t.Fatal("expired or replaced generation reused old authority", calls, err)
			}
		})
	}
}

func TestContainmentCacheWait(t *testing.T) {
	for _, change := range []string{"coalesce", "cancelled", "revoked", "replacement"} {
		t.Run(change, func(t *testing.T) {
			service, ticket := registryFixture(t)
			query := containmentQuery{LeaseID: ticket.Lease.ID, Opened: true}
			started, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var calls atomic.Int32
			refresh := func(ctx context.Context, got containmentQuery) (containmentTicket, error) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				return ticket, nil
			}
			result := make(chan error, 21)
			go func() {
				_, err := service.cachedContainment(context.Background(), "cg-a", query, refresh)
				result <- err
			}()
			<-started
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for range 20 {
				go func() {
					_, err := service.cachedContainment(ctx, "cg-a", query, refresh)
					result <- err
				}()
			}
			if change == "cancelled" {
				cancel()
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("cancelled waiter reused authority")
					}
				case <-time.After(188 * time.Millisecond):
					t.Fatal("cancelled waiter waited on leader IPC")
				}
			} else if change == "revoked" {
				if err := service.revokeEntries(ticket.Lease.ID); err != nil {
					t.Fatal(err)
				}
			} else if change == "replacement" {
				service.registryMu.Lock()
				old := service.containments["cg-a"]
				old.Ticket.Generation++
				service.registryMu.Unlock()
			}
			close(release)
			count := 21
			if change == "cancelled" {
				count--
			}
			for range count {
				select {
				case err := <-result:
					if change == "coalesce" && err != nil || change == "revoked" && err == nil || change == "replacement" && err == nil {
						t.Fatal("concurrent refresh returned wrong authority", err)
					}
				case <-time.After(time.Second):
					t.Fatal("containment waiter leaked")
				}
			}
			if change == "coalesce" && calls.Load() != 1 {
				t.Fatal("identical concurrent helper reads were not coalesced", calls.Load())
			}
		})
	}
}
