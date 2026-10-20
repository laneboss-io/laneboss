//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type pollLoadJournal struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (j *pollLoadJournal) Write(data []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.data.Write(data)
}

// Exercise the production helper turn and actual journal generation/decoder.
// This isolates helper queue/store latency; native IPC and kernel containment
// retain their separate root canaries and installed-item measurements.
func TestPollRateLoad(t *testing.T) {
	root, err := os.OpenRoot(privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &fileLeaseStore{root: root, owner: uint32(os.Geteuid())}
	record := leaseRecord{Schema: "laneboss.helper-lease.v2", BootID: "poll-load-boot", Request: testAllocation(),
		Lease: api.HelperLease{ID: "poll-load-lease", UID: 61001, GID: 61001, ContainmentID: "poll-load-group", EndpointGeneration: 1},
		Phase: "active", IssuedAt: gateTimestamp()}
	if err := store.Save(record); err != nil {
		t.Fatal(err)
	}
	manager := newLeaseManager(testBinding(), record.BootID, store, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const workers, turns = 8, 32
	start := make(chan struct{})
	results := make(chan time.Duration, workers*turns)
	controls := make(chan time.Duration, turns)
	pollEnds := make(chan time.Time, workers)
	failures := make(chan error, workers*turns+turns)
	var group sync.WaitGroup
	journal := &pollLoadJournal{}
	params, err := json.Marshal(containmentQuery{LeaseID: record.Lease.ID, Opened: true})
	if err != nil {
		t.Fatal(err)
	}
	run := func(method string, count int, output chan<- time.Duration) {
		defer group.Done()
		if method == "containment_live" {
			defer func() { pollEnds <- time.Now() }()
		}
		<-start
		var cadence *time.Ticker
		if method != "containment_live" {
			// Sample ordinary operations throughout the metadata load, not
			// only in the initial burst before its queue has formed.
			cadence = time.NewTicker(64 * time.Millisecond)
			defer cadence.Stop()
		}
		for range count {
			if cadence != nil {
				select {
				case <-cadence.C:
				case <-ctx.Done():
					failures <- ctx.Err()
					return
				}
			}
			began := time.Now()
			trace := &helperRequestTrace{method: method, timing: journal}
			trace.stage("operation_wait")
			turnCtx := context.WithValue(ctx, helperTimingKey{}, trace)
			turn, finish, err := manager.beginHelperTurn(turnCtx, method == "containment_live", method, params, journal)
			if err != nil {
				failures <- err
				return
			}
			current, _, err := manager.containmentRecord(turn, record.Lease.ID, false)
			finish()
			trace.finishTiming()
			if err != nil {
				failures <- err
				return
			}
			if current.Lease != record.Lease {
				failures <- failure(api.CodeIntegrity, "helper returned another actual lease")
				return
			}
			output <- time.Since(began)
		}
	}
	for range workers {
		group.Add(1)
		go run("containment_live", turns, results)
	}
	group.Add(1)
	go run("containment", turns, controls)
	var before, after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	close(start)
	group.Wait()
	elapsed := time.Since(began)
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	close(results)
	close(controls)
	close(failures)
	close(pollEnds)
	for err := range failures {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	var metadataElapsed time.Duration
	for ended := range pollEnds {
		if duration := ended.Sub(began); duration > metadataElapsed {
			metadataElapsed = duration
		}
	}
	metadata, control := []time.Duration{}, []time.Duration{}
	for value := range results {
		metadata = append(metadata, value)
	}
	for value := range controls {
		control = append(control, value)
	}
	if len(metadata) != workers*turns || len(control) != turns {
		t.Fatal("helper load did not complete all actual reads")
	}
	sort.Slice(metadata, func(i, j int) bool { return metadata[i] < metadata[j] })
	sort.Slice(control, func(i, j int) bool { return control[i] < control[j] })
	cpu := time.Duration(after.Utime.Nano() + after.Stime.Nano() - before.Utime.Nano() - before.Stime.Nano())
	t.Logf("helper load polls=%d elapsed_ms=%d total_ms=%d rate=%.2f/s cpu_ms=%d producers=%d", len(metadata), metadataElapsed.Milliseconds(), elapsed.Milliseconds(), float64(len(metadata))/metadataElapsed.Seconds(), cpu.Milliseconds(), workers)
	t.Logf("containment_live p50_us=%d p99_us=%d; ordinary containment p50_us=%d p99_us=%d", metadata[len(metadata)/2].Microseconds(), metadata[len(metadata)*99/100].Microseconds(), control[len(control)/2].Microseconds(), control[len(control)*99/100].Microseconds())
	lines := bytes.Count(journal.data.Bytes(), []byte("\n"))
	t.Logf("routine helper journal lines=%d for %d fresh polls", lines, len(metadata))
	if lines > len(metadata)+workers {
		t.Fatal("routine containment timing regained its stage-log amplification")
	}
	// One initial permit plus at most 125 fresh metadata turns per second.
	if metadataElapsed < time.Duration(len(metadata)-1)*8*time.Millisecond {
		t.Fatal("containment_live rate exceeded the 125/s helper bound")
	}
	if control[len(control)-1] > time.Second || metadata[len(metadata)-1] > time.Second {
		t.Fatal("helper bound starved an actual ordinary or metadata read")
	}
}
