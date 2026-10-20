//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// These counters delegate every operation to the installed file backend.
// No helper result, native process observation or storage read is simulated.
type gateCostStore struct {
	*fileLeaseStore
	reads    int
	readTime time.Duration
}

func (s *gateCostStore) Records() ([]leaseRecord, error) {
	start := time.Now()
	defer func() { s.reads++; s.readTime += time.Since(start) }()
	return s.fileLeaseStore.Records()
}

type gateCostInput struct {
	Query    api.HelperReconcileRequest
	Allocate api.HelperLeaseRequest
}

type gateCostResult struct {
	Calls   int
	Elapsed time.Duration
	Busy    time.Duration
	Start   time.Duration
	Lease   api.HelperLease
}

type gateCostPhase struct {
	Ticket  containmentTicket
	Elapsed time.Duration
	Code    api.ErrorCode
}

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-gate-cost-client" {
		if err := gateCostClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(116)
		}
		os.Exit(0)
	}
}

func gateCostClient(config string) error {
	b, err := loadInstallation(config)
	if err != nil {
		return err
	}
	s, err := New(Dependencies{Config: b.Config, ServiceUID: b.Service.UID,
		ArtifactSHA256: b.Artifact.SHA256, Version: b.Release.Version,
		Protocol: api.Protocol, Schema: api.SchemaVersion})
	if err != nil {
		return err
	}
	var input gateCostInput
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceCallBudget)
	defer cancel()
	result := gateCostResult{}
	var observed time.Time
	start := time.Now()
	ticker := time.NewTicker(2 * time.Second / 3)
	defer ticker.Stop()
	for i := range 12 {
		began := time.Now()
		var group sync.WaitGroup
		var startErr error
		if i == 3 {
			// Race a real lane-start allocation with the recurring gate read.
			// Both use authenticated IPC and the same serialized main helper.
			group.Add(1)
			go func() {
				defer group.Done()
				began := time.Now()
				startErr = s.call(ctx, "allocate", input.Allocate, &result.Lease)
				result.Start = time.Since(began)
			}()
		}
		actual, err := s.ReconcileGate(ctx, input.Query)
		gateElapsed := time.Since(began)
		group.Wait()
		if err != nil {
			return err
		}
		if startErr != nil {
			return startErr
		}
		if actual.Prepared == nil || actual.Prepared.ID != input.Query.PreparedID ||
			actual.Process == nil || actual.ConsumedPermit == nil ||
			actual.Observation.State != "running" || actual.Observation.Survivors == nil ||
			*actual.Observation.Survivors == 0 {
			return errors.New("gate load lost its actual consumed native process")
		}
		stamp, err := time.Parse(time.RFC3339Nano, string(actual.Observation.ObservedAt))
		if err != nil || !stamp.After(observed) {
			return errors.New("gate load reused an old native observation")
		}
		observed = stamp
		result.Calls++
		result.Busy += gateElapsed
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	result.Elapsed = time.Since(start)
	if err := encoder.Encode(result); err != nil {
		return err
	}
	for _, stage := range []string{"warm", "revoked"} {
		var command string
		if err := decoder.Decode(&command); err != nil {
			return err
		}
		if command != stage {
			return errors.New("gate client received an unordered lifecycle phase")
		}
		began := time.Now()
		phase := gateCostPhase{}
		err := s.call(ctx, "containment_live", containmentQuery{LeaseID: input.Query.LeaseID, Opened: true}, &phase.Ticket)
		phase.Elapsed = time.Since(began)
		if err != nil {
			var typed *api.Error
			if !errors.As(err, &typed) {
				return err
			}
			phase.Code = typed.Code
		}
		if err := encoder.Encode(phase); err != nil {
			return err
		}
	}
	return nil
}

func TestGateCostRPC(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("gate cost requires the disposable Linux root step")
	}
	if os.Args[len(os.Args)-1] != "gate-cost-root" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.v", "-test.run=^TestGateCostRPC$", "--", "gate-cost-root")
		cmd.Env = []string{}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native gate cost failed: %v\n%s", err, out)
		}
		if !bytes.Contains(out, []byte("--- PASS: TestGateCostRPC ")) {
			t.Fatal("missing native gate cost result")
		}
		t.Log(string(out))
		return
	}
	privateContainmentMounts(t)
	m, open, gate, reader, store, hold := retainedGateFixtureControl(t)
	if _, err := m.openGate(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != gate.token {
		t.Fatal("native runner did not execute", err)
	}
	record, err := m.find(open.Binding.Record.UIDLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	// The same real, valid long-lived allocation history as the native
	// identity load fixture. No injected store delay or artificial lock hold.
	for i := range 900 {
		allocation := record.Request
		allocation.Cause.EffectID = api.ID("cost-history-" + strconv.Itoa(i))
		record.Allocations = append(record.Allocations, allocation)
	}
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	m.binding.Lanes[1] = workerCanaryAccounts(t)[0]
	unit := filepath.Dir(m.binding.cgroupPath())
	emptyGroup := func(path string) {
		t.Helper()
		if err := os.Mkdir(path, 0755); err != nil {
			if !errors.Is(err, os.ErrExist) {
				t.Fatal(err)
			}
			events, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
			if err != nil || !strings.Contains(string(events), "populated 0\n") {
				t.Fatal("prior cost fixture is still populated", err)
			}
		}
	}
	for _, path := range []string{unit, m.binding.cgroupPath()} {
		emptyGroup(path)
	}
	t.Cleanup(func() {
		if err := os.Remove(unit); err != nil {
			t.Error(err)
		}
	})
	endpoint := nativeContainmentEndpoint(t, m, true)
	if err := setupCgroups(m.binding); err != nil {
		t.Fatal(err)
	}
	groupPath := filepath.Join(m.binding.cgroupPath(), string(record.Lease.ContainmentID))
	emptyGroup(groupPath)
	if err := os.WriteFile(filepath.Join(groupPath, "cgroup.procs"), []byte(strconv.Itoa(gate.PID())), 0600); err != nil {
		t.Fatal(err)
	}
	resources := &linuxResources{binding: m.binding, manager: m}
	m.resources = resources
	counted := &gateCostStore{fileLeaseStore: store}
	m.store = counted
	began := time.Now()
	profile, err := store.Records()
	if err != nil {
		t.Fatal(err)
	}
	decodeTime := time.Since(began)
	began = time.Now()
	if _, err := m.validateRecords(profile); err != nil {
		t.Fatal(err)
	}
	validateTime := time.Since(began)
	began = time.Now()
	if _, err := gate.Observe(context.Background(), gateHandle(record)); err != nil {
		t.Fatal(err)
	}
	observeTime := time.Since(began)
	began = time.Now()
	if _, err := resources.Survivors(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	t.Logf("profile decode_us=%d validate_us=%d native_us=%d cgroup_us=%d",
		decodeTime.Microseconds(), validateTime.Microseconds(), observeTime.Microseconds(), time.Since(began).Microseconds())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.binding.socketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if err := os.Chown(m.binding.socketPath(), 0, int(m.binding.Service.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(m.binding.socketPath(), 0660); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if errors.Is(err, net.ErrClosed) {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
			if err := serveHelperConnectionWithJournal(context.Background(), conn, m.binding, m, endpoint.journal); err != nil {
				done <- err
				return
			}
		}
	}()
	joined := false
	t.Cleanup(func() {
		listener.Close()
		if !joined {
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	})
	input := gateCostInput{Query: api.HelperReconcileRequest{LeaseID: record.Lease.ID,
		LaunchID: record.Spec.Handoff.Spec.LaunchID, PreparedID: record.Gate.Prepared.ID,
		OperationID: record.Spec.Handoff.OperationID}, Allocate: testAllocation()}
	input.Allocate.LifeID, input.Allocate.Cause.Target.LifeID = "cost-start", "cost-start"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, endpoint.binding.binaryPath(), "admin-gate-cost-client", endpoint.binding.Config)
	cmd.Env = []string{}
	clientInput, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer clientInput.Close()
	clientOutput, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: endpoint.binding.Service.UID, Gid: endpoint.binding.Service.GID, Groups: []uint32{}},
		UseCgroupFD: true, CgroupFD: int(endpoint.group.Fd())}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	clientJoined := false
	defer func() {
		if !clientJoined {
			cancel()
			if err := cmd.Wait(); err != nil && ctx.Err() == nil {
				t.Error(err)
			}
		}
	}()
	encoder, decoder := json.NewEncoder(clientInput), json.NewDecoder(clientOutput)
	if err := encoder.Encode(input); err != nil {
		t.Fatal(err)
	}
	var result gateCostResult
	if err := decoder.Decode(&result); err != nil {
		clientInput.Close()
		waitErr := cmd.Wait()
		clientJoined = true
		t.Fatal("real helper load client failed", errors.Join(err, waitErr), diagnostic.String())
	}
	listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	joined = true
	t.Logf("calls=%d rate=%.2f/s busy_ms=%d share=%.4f start_ms=%d reads=%d decode_ms=%d",
		result.Calls, float64(result.Calls)/result.Elapsed.Seconds(), result.Busy.Milliseconds(),
		float64(result.Busy)/float64(result.Elapsed), result.Start.Milliseconds(), counted.reads, counted.readTime.Milliseconds())
	if result.Calls != 12 || result.Lease.ID == "" || result.Lease.UID == record.Lease.UID {
		t.Error("dirty load did not complete its independent lane-start allocation")
	}
	if result.Start >= serviceCallBudget {
		t.Error("lane-start allocation missed the unchanged service deadline")
	}
	if result.Busy > result.Elapsed/20 {
		t.Error("recurring gate reads occupy more than five percent of the helper")
	}
	gateCostInputs(t, m, store, record.Lease.ID)
	phase := func(name string) gateCostPhase {
		t.Helper()
		if err := encoder.Encode(name); err != nil {
			t.Fatal(err)
		}
		var value gateCostPhase
		if err := decoder.Decode(&value); err != nil {
			t.Fatal("resident service lost its lifecycle reply", err)
		}
		return value
	}
	if warm := phase("warm"); warm.Code != "" || warm.Ticket.Lease != record.Lease {
		t.Fatal("cannot warm actual live containment", warm.Code)
	}
	current, err := m.find(record.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.Revoked = true
	// An atomic writer outside manager.save must also invalidate every view.
	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}
	began = time.Now()
	refused := phase("revoked")
	if refused.Code != api.CodeContainmentUnknown {
		t.Fatal("real helper retained revoked containment", refused.Code)
	}
	if time.Since(began) > 188*time.Millisecond {
		t.Fatal("revoked helper containment exceeded 188 ms")
	}
	t.Logf("revoked_refusal_us=%d round_trip_us=%d bound_ms=188", refused.Elapsed.Microseconds(), time.Since(began).Microseconds())
	if err := cmd.Wait(); err != nil {
		t.Fatal("resident service failed", err, diagnostic.String())
	}
	clientJoined = true
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.done:
	case <-ctx.Done():
		t.Fatal("native cost runner did not end")
	}
	ended, err := m.reconcileGate(context.Background(), input.Query)
	if err != nil || ended.GateState != "consumed" || ended.Observation.State != "exited" ||
		ended.Observation.ExitCode == nil || *ended.Observation.ExitCode != 0 ||
		ended.Observation.Survivors == nil || *ended.Observation.Survivors != 0 ||
		ended.Process == nil || *ended.Process != gateHandle(current) ||
		ended.Prepared == nil || *ended.Prepared != open.Request.Prepared ||
		ended.ConsumedPermit == nil || *ended.ConsumedPermit != open.Request.Permit {
		t.Fatal("terminal reconciliation changed its measured result", err)
	}
	restarted := newLeaseManager(m.binding, m.bootID, store, resources)
	retained, err := restarted.reconcileGate(context.Background(), input.Query)
	if err != nil || !reflect.DeepEqual(retained, ended) {
		t.Fatal("helper restart changed the committed terminal result", err)
	}
	for _, id := range []api.ID{record.Lease.ID, result.Lease.ID} {
		r, err := m.find(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := resources.Remove(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(m.binding.cgroupPath()); err != nil {
		t.Fatal(err)
	}
}

func gateCostInputs(t *testing.T, m *leaseManager, store *fileLeaseStore, id api.ID) {
	t.Helper()
	name := string(id) + ".json"
	original, err := store.root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	write := func(data []byte) {
		t.Helper()
		file, err := store.root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatal(err)
		}
		count, err := file.Write(data)
		if err := errors.Join(err, file.Close()); err != nil || count != len(data) {
			t.Fatal("cannot write cache validation input", err)
		}
	}
	defer write(original)
	first, err := m.find(id)
	if err != nil {
		t.Fatal(err)
	}
	want := first.Gate.Prepared
	first.Gate.Prepared.ID = "foreign-prepared"
	first.Allocations[0].Budget.WallMS++
	second, err := m.find(id)
	if err != nil || second.Gate.Prepared != want ||
		second.Allocations[0].Budget == first.Allocations[0].Budget {
		t.Fatal("journal decode reused mutable result pointers", err)
	}
	for _, prefix := range []string{`{"unknown":0,`, `{"schema":"laneboss.helper-lease.v2",`, `{"Schema":"foreign",`} {
		bad := append([]byte(prefix), original[1:]...)
		var weak leaseRecord
		if err := json.Unmarshal(bad, &weak); err != nil {
			t.Fatal("strict-cache control does not reach the permissive decoder", err)
		}
		write(bad)
		_, err := store.Records()
		requireCode(t, err, api.CodeIntegrity)
		write(original)
		if _, err := m.find(id); err != nil {
			t.Fatal("cache input recovery failed", err)
		}
	}
}
