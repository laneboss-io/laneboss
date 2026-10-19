//go:build linux && laneboss_root_canary

package admin

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func retirementRuntime(t *testing.T, m *leaseManager) {
	t.Helper()
	var created []string
	t.Cleanup(func() {
		for index := len(created) - 1; index >= 0; index-- {
			if err := os.Remove(created[index]); err != nil {
				t.Error(err)
			}
		}
	})
	workers := filepath.Join(m.binding.runtimePath(), "workers")
	for _, name := range []string{filepath.Dir(m.binding.runtimePath()), m.binding.runtimePath(), workers} {
		mode := os.FileMode(0750)
		if name == workers {
			mode = 0700
		}
		if err := os.Mkdir(name, mode); err == nil {
			created = append(created, name)
			if name == workers {
				if err := os.Chown(name, int(m.binding.Service.UID), int(m.binding.Service.GID)); err != nil {
					t.Fatal(err)
				}
			}
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	// Archive socket inventory now uses the actual protected service binding,
	// rather than accepting this lease's basename anywhere in the network NS.
	for _, name := range []string{"/etc/laneboss-v2", "/etc/laneboss-v2/bindings"} {
		if err := os.Mkdir(name, 0755); err == nil {
			created = append(created, name)
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	service := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: m.binding.Config, Class: api.EndpointHuman,
		InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation,
		ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID,
		MappedServiceUID: m.binding.Service.UID, MappedServiceGID: m.binding.Service.GID,
		Socket:         filepath.Join("/run/laneboss-v2-service", m.binding.Config, "control.sock"),
		ArtifactSHA256: m.binding.Artifact.SHA256, ServiceVersion: m.binding.Release.Version, Backend: "linux-bwrap-landlock"}
	raw, err := json.Marshal(service)
	if err != nil || api.ValidateBinding(service, m.binding.Config, m.binding.Release.Version) != nil {
		t.Fatal("retirement fixture has an invalid service binding", err)
	}
	name := filepath.Join("/etc/laneboss-v2/bindings", m.binding.Config+".json")
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err == nil {
		created = append(created, name)
		n, writeErr := file.Write(raw)
		if closeErr := file.Close(); writeErr != nil || closeErr != nil || n != len(raw) {
			t.Fatal("retirement fixture could not retain its service binding", errors.Join(writeErr, closeErr))
		}
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	actual, err := workerServiceBinding(m.binding)
	if err != nil || !reflect.DeepEqual(actual, service) {
		t.Fatal("retirement fixture must preserve an existing foreign binding", err)
	}
}

func retirementSocket(t *testing.T, m *leaseManager, id api.ID) *net.UnixListener {
	t.Helper()
	path := filepath.Join(m.binding.runtimePath(), "workers", string(id)+".sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chown(path, int(m.binding.Service.UID), int(m.binding.Service.GID)); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	return listener
}

func retirementLiveGate(t *testing.T, p leaseRecord, w *archiveWorker, path string, opened bool) (*nativeGate, *os.File) {
	t.Helper()
	command, hold, generation := cleanupHolder(t, path, w.Lease, p.BootID)
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		unix.Close(pidfd)
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(pair[0]), "native-retire-control")
	connection, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		unix.Close(pair[1])
		unix.Close(pidfd)
		t.Fatal("native retirement control socket setup failed")
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		unix.Close(pair[1])
		unix.Close(pidfd)
		t.Fatal("retirement control socket is not native Unix")
	}
	g := &nativeGate{command: command, pidfd: pidfd, generation: generation, done: make(chan struct{}), released: opened, control: control, innerFD: -1}
	w.State = "prepared"
	w.Gate = &dataGate{Prepared: api.PreparedLaunch{ID: "archive-prepared", GateID: "archive-gate", Target: w.Reg.Job.Lease.Target, ContainmentID: w.Lease.ContainmentID, ProcessGeneration: generation, EndpointGeneration: w.Lease.EndpointGeneration, SpecSHA256: w.Spec.Handoff.SpecSHA256}, PID: command.Process.Pid, State: "prepared"}
	if opened {
		w.State, w.Gate.State = "opened", "opened"
		w.Gate.Permit = &api.LaunchPermit{LaunchID: w.Reg.LaunchID, PreparedID: w.Gate.Prepared.ID, RecordSHA256: testDigest("component committed archive binding"), CommittedSeq: 1}
	}
	go func() {
		err := command.Wait()
		g.mu.Lock()
		g.waitErr, g.state = err, command.ProcessState
		close(g.done)
		g.mu.Unlock()
	}()
	t.Cleanup(func() {
		select {
		case <-g.done:
		default:
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			select {
			case <-g.done:
			case <-time.After(5 * time.Second):
				t.Error("retirement fixture failed to reap its original process")
			}
		}
		if err := g.Close(); err != nil {
			t.Error(err)
		}
		if err := unix.Close(pair[1]); err != nil {
			t.Error(err)
		}
		if err := unix.Close(pidfd); err != nil {
			t.Error(err)
		}
	})
	return g, hold
}

func retirementFixture(t *testing.T, mode string) (*leaseManager, cleanupEnrollment, archiveRetireQuery, string, *nativeGate, *os.File) {
	t.Helper()
	var worker *archiveWorker
	var live *nativeGate
	var hold *os.File
	factory := func(t *testing.T, b installation, p leaseRecord, group api.ID, path string) *archiveWorker {
		worker = cleanupWorkerSeal(t, b, p, group)
		if mode == "expired-worker" {
			deadline := api.Timestamp(time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339Nano))
			worker.Reg.Job.Lease.ExpiresAt = deadline
			worker.Reg.Claim.ExpiresAt, worker.Reg.Claim.Record.ClaimExpiresAt = deadline, deadline
			if err := validateArchiveSeal(archiveSeal{Reg: worker.Reg, Spec: *worker.Spec, Endpoint: *worker.Endpoint, Input: worker.Input}, b, true); err != nil {
				t.Fatal(err)
			}
		}
		switch mode {
		case "absent":
			if err := unix.Rmdir(path); err != nil {
				t.Fatal(err)
			}
			return nil
		case "unopened":
			worker.Spec, worker.Endpoint, worker.Input = nil, nil, nil
			worker.State = "allocated"
			return worker
		}
		live, hold = retirementLiveGate(t, p, worker, path, mode != "prepared")
		return worker
	}
	m, e, _, group := cleanupPathWorker(t, false, false, factory)
	retirementRuntime(t, m)
	q := archiveRetireQuery{Job: worker.Reg.Job, Claim: worker.Reg.Claim}
	if mode != "absent" {
		q.Allocation, q.Handoff = worker.Lease, worker.Spec != nil
		if live != nil {
			m.gates = map[api.ID]ownedGate{worker.Lease.ID: live}
			if mode != "prepared" {
				q.Process = archiveHandle(*worker)
			}
		}
	}
	return m, e, q, group, live, hold
}
