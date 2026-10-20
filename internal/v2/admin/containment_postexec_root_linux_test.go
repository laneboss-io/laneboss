//go:build linux && laneboss_root_canary

package admin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestContainmentLivePostExec(t *testing.T) {
	for _, phase := range []string{"during-hash", "after-opened"} {
		t.Run(phase, func(t *testing.T) { postExecAuthentication(t, phase, false) })
	}
}

func TestCredentialProofFailureRevokes(t *testing.T) {
	postExecAuthentication(t, "during-hash", true)
}

func TestContainmentLivePostOpenJournal(t *testing.T) {
	postExecAuthentication(t, "after-opened-journal", false)
}

func TestContainmentJournalIDs(t *testing.T) {
	postExecAuthentication(t, "after-opened-journal-ids", false)
}

type containmentBlockedJournal struct {
	writer  io.Writer
	entered chan struct{}
	once    sync.Once
}

func (j *containmentBlockedJournal) Write(data []byte) (int, error) {
	j.once.Do(func() { close(j.entered) })
	return j.writer.Write(data)
}

func postExecAuthentication(t *testing.T, phase string, failProof bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("post-exec authentication requires the disposable Linux root box")
	}
	if os.Args[len(os.Args)-1] != "containment-postexec-root" {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/proc/self/exe", "-test.v", "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "--", "containment-postexec-root")
		command.Env = []string{}
		command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: "+strings.Split(t.Name(), "/")[0]+" ")) {
			t.Fatalf("isolated native containment canary failed: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	privateContainmentMounts(t)
	id, err := randomID("lb-v2-cx-auth2-post-")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join("/run", string(id))
	if err := os.Mkdir(stage, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(stage); err != nil {
			t.Error(err)
		}
	})
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(stage, "runner")
	if err := os.WriteFile(binary, self, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(binary); err != nil {
			t.Error(err)
		}
	})
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(stage, "lane.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	control, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := control.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	}); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if err := os.Chmod(filepath.Join(stage, "lane.sock"), 0666); err != nil {
		t.Fatal(err)
	}
	var group, lanes, unit string
	t.Cleanup(func() {
		for _, path := range []string{group, lanes, unit} {
			if path != "" {
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}
		}
	})
	gate, reader, boot, uid, gid, input := descriptorGateAuthenticationMode(t, [2]*os.File{}, filepath.Join(stage, "lane.sock"), phase, binary)
	expected := digestBytes(self)
	if failProof {
		expected = digestBytes(append(append([]byte{}, self...), 0))
	}
	manager, registration, _, _, store := retainedGateFromNativeHash(t, gate, reader, boot, uid, gid, expected)
	manager, registration, _, _, _, _, _ = stopCredentialsForGate(t, false, manager, registration, gate, reader, store)
	records, err := manager.records()
	if err != nil || len(records) != 1 {
		t.Fatal("post-exec fixture has no exact retained credentialed gate", err)
	}
	record := records[0]
	concurrent := strings.HasPrefix(phase, "after-opened-concurrent")
	if concurrent {
		// A long-lived lease can retain many valid allocation attempts. Exercise
		// actual bounded journal decoding/validation, never an injected delay.
		for i := range 900 {
			allocation := record.Request
			allocation.Cause.EffectID = api.ID("history-" + strconv.Itoa(i))
			record.Allocations = append(record.Allocations, allocation)
		}
		if err := manager.save(record); err != nil {
			t.Fatal("cannot retain real allocation history", err)
		}
	}
	lanes, unit = manager.binding.cgroupPath(), filepath.Dir(manager.binding.cgroupPath())
	group = filepath.Join(lanes, string(record.Lease.ContainmentID))
	for _, path := range []string{unit, lanes, group} {
		if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	mode := os.FileMode(0700)
	if concurrent {
		mode = 0755 // The real service UID must pin the cgroup directory itself.
	}
	if err := os.Chmod(group, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(gate.PID())), 0600); err != nil {
		t.Fatal(err)
	}
	manager.resources = &linuxResources{binding: manager.binding, manager: manager}
	ctx, cancel := context.WithTimeout(context.Background(), helperCallTimeout)
	t.Cleanup(cancel)
	hashEntered, finishHash := make(chan struct{}), make(chan struct{})
	journalPhase := phase == "after-opened-journal"
	var firstRead, releaseHash sync.Once
	resumeHash := func() { releaseHash.Do(func() { close(finishHash) }) }
	if phase == "during-hash" || journalPhase {
		gate.execHashRead = func(n int) {
			firstRead.Do(func() {
				if n <= 0 {
					return
				}
				close(hashEntered)
				select {
				case <-finishHash:
				case <-ctx.Done():
				}
			})
		}
	}
	var endpoint containmentEndpoint
	var metadata func(api.ID) (containmentTicket, error)
	if concurrent || phase == "after-opened-journal-ids" {
		endpoint = nativeContainmentEndpoint(t, manager, true)
		metadata = endpoint.query
	} else {
		metadata = nativeContainmentRPC(t, manager)
	}
	t.Cleanup(resumeHash)
	var turnJournal io.Writer = io.Discard
	var journalRead *io.PipeReader
	var journalEntered chan struct{}
	if journalPhase {
		var write *io.PipeWriter
		journalRead, write = io.Pipe()
		journalEntered = make(chan struct{})
		turnJournal = &containmentBlockedJournal{writer: write, entered: journalEntered}
		t.Cleanup(func() { write.Close(); journalRead.Close() })
	}
	type completion struct {
		handle api.ProcessHandle
		err    error
	}
	opened := make(chan completion, 1)
	go func() {
		openCtx, finishTurn, err := manager.beginHelperTurn(ctx, false, "open_gate", nil, turnJournal)
		if err != nil {
			opened <- completion{err: err}
			return
		}
		defer finishTurn()
		handle, err := manager.withCredentialGuard(openCtx, &credentialGuardFixture{}, func() (api.ProcessHandle, error) {
			return manager.openGate(openCtx, registration)
		})
		opened <- completion{handle, err}
	}()
	if phase == "during-hash" {
		select {
		case <-hashEntered:
			t.Log("runner exec EOF observed; actual executable bytes are being hashed before opened save")
		case result := <-opened:
			t.Fatal("openGate finished without entering the real post-exec hash proof", result.err)
		case <-ctx.Done():
			t.Fatal("real post-exec hash proof was not reached")
		}
	} else {
		if journalPhase {
			select {
			case <-hashEntered:
			case <-ctx.Done():
				t.Fatal("journal canary did not enter the real executable hash proof")
			}
			// Exercise the slow-turn diagnostic taken by the installed 1.7 s
			// launch, without changing either native or authentication deadline.
			timer := time.NewTimer(helperSlowTurn)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("journal canary ended before its slow helper turn")
			}
			resumeHash()
		}
		select {
		case result := <-opened:
			if result.err != nil {
				t.Fatal("real openGate failed before its opened save", result.err)
			}
		case <-ctx.Done():
			t.Fatal("real openGate did not finish its opened save")
		}
		if journalPhase {
			select {
			case <-journalEntered:
			case <-ctx.Done():
				t.Fatal("opened helper turn did not reach the real blocked journal pipe")
			}
			retained, err := store.Records()
			if err != nil || len(retained) != 1 || !openedContainment(retained[0]) {
				t.Fatal("journal backpressure canary did not retain the real opened save", err)
			}
			available := manager.operationMu.TryLock()
			if available {
				manager.operationMu.Unlock()
			}
			t.Logf("real opened save retained; journal pipe blocked; operation_mu_available=%t", available)
		}
		if concurrent {
			concurrentIdentityAuthentication(t, manager, registration, endpoint, listener, gate, reader, input, phase)
			return
		}
		if n, err := input.Write([]byte{'a'}); err != nil || n != 1 {
			t.Fatal(err)
		}
	}
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("execed runner did not start its real CLI child", err)
	}
	defer connection.Close()
	peer, err := pinPeer(connection, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer closePeer(peer)
	if int(peer.credentials.Pid) == gate.PID() {
		t.Fatal("post-exec authentication did not come from the runner's CLI child")
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := readUnixFrame(connection, peer)
	if err != nil {
		t.Fatal(err)
	}
	var query containmentQuery
	if err := decodeStrict(raw, &query); err != nil || query.LeaseID != record.Lease.ID || !query.Opened {
		t.Fatal("post-exec CLI did not ask for its real live containment", err)
	}
	start := time.Now()
	ticket, err := metadata(query.LeaseID)
	if err != nil {
		t.Fatal("post-exec containment_live did not reply before the unchanged frame deadline", err)
	}
	if ticket.Lease != record.Lease || ticket.Target != record.SpecReceipt.Target {
		t.Fatal("post-exec RPC returned another registered containment")
	}
	if phase == "after-opened-journal-ids" {
		found := false
		var helperNonce, callNonce api.ID
		for _, line := range strings.Split(endpoint.journal.snapshot(), "\n") {
			var row struct {
				Event  string        `json:"event"`
				Method string        `json:"method"`
				Life   api.ID        `json:"life_id"`
				Run    api.RunNumber `json:"run"`
				Launch api.ID        `json:"launch_id"`
				Lease  api.ID        `json:"lease_id"`
				Nonce  api.ID        `json:"helper_nonce"`
			}
			if json.Unmarshal([]byte(line), &row) == nil && row.Event == "helper_request" && row.Method == "containment_live" &&
				row.Life == ticket.Target.LifeID && row.Run == ticket.Target.Run && row.Launch == ticket.LaunchID && row.Lease == ticket.Lease.ID && row.Nonce != "" {
				found = true
				helperNonce = row.Nonce
			}
			if row.Event == "helper_call_end" && row.Method == "containment_live" {
				callNonce = row.Nonce
			}
		}
		if !found {
			t.Fatal("real helper observation has no lane/lease/request correlation")
		}
		if callNonce == "" || callNonce != helperNonce {
			t.Fatal("service call cannot join the real helper nonce")
		}
	}
	var registry *Service
	if failProof {
		directory, err := os.Open(group)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { directory.Close() })
		registry = &Service{containments: map[api.ID]*containmentEntry{record.Lease.ContainmentID: {
			Ticket: ticket, Binding: api.ContainmentBinding{Config: ticket.Config, Lease: ticket.Lease, Target: ticket.Target,
				BootID: ticket.BootID, Generation: ticket.Generation, Backend: "linux-bwrap-landlock", Directory: directory},
		}}}
		bound, _, err := registry.refreshContainment(record.Lease.ContainmentID, func(query containmentQuery) (containmentTicket, error) {
			return metadata(query.LeaseID)
		})
		if err != nil || bound.Directory == nil {
			t.Fatal("real authenticated containment binding could not be refreshed before proof failure", err)
		}
		if err := bound.Directory.Close(); err != nil {
			t.Fatal(err)
		}
	}
	generation, err := processGeneration(int(peer.credentials.Pid), boot)
	if err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostPID: int(peer.credentials.Pid), HostUID: uid, HostGID: gid, ProcessGeneration: generation}
	if err := verifyContainedProcess(ctx, facts, boot, strings.TrimPrefix(group, "/sys/fs/cgroup")); err != nil {
		t.Fatal("post-exec native peer did not match the actual cgroup", err)
	}
	current, err := store.Records()
	if err != nil || len(current) != 1 || phase == "during-hash" && (current[0].Gate.State != "opening" || openedContainment(current[0])) ||
		strings.HasPrefix(phase, "after-opened") && !openedContainment(current[0]) {
		t.Fatal("authentication changed or bypassed the real gate transition", err)
	}
	if err := writeFrame(connection, ticket); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(gate.token))
	if _, err := io.ReadFull(reader, actual); err != nil || string(actual) != gate.token {
		t.Fatal("execed runner did not observe its CLI's real successful authentication", err)
	}
	t.Logf("post-exec phase=%s authentication_ms=%d", phase, time.Since(start).Milliseconds())
	if journalPhase {
		line, err := bufio.NewReader(journalRead).ReadString('\n')
		var timing struct {
			Event     string `json:"event"`
			Operation string `json:"operation"`
			HoldMS    int64  `json:"hold_ms"`
		}
		if err != nil || json.Unmarshal([]byte(line), &timing) != nil || timing.Event != "helper_timing" || timing.Operation != "open_gate" ||
			timing.HoldMS < helperSlowTurn.Milliseconds() {
			t.Fatal("real blocked helper journal lost its measured slow-turn event", err)
		}
		t.Log("post-open authentication completed while the actual helper journal pipe remained blocked")
	}
	if phase == "during-hash" {
		resumeHash()
		var result completion
		select {
		case result = <-opened:
		case <-ctx.Done():
			t.Fatal("real openGate did not finish after post-exec authentication")
		}
		if failProof {
			requireCode(t, result.err, api.CodeIntegrity)
			current, err = manager.records()
			if err != nil || len(current) != 1 || !current[0].Revoked || current[0].Credentials.Stop == nil {
				t.Fatal("failed executable proof left the authenticated containment unfenced", err)
			}
			bound, _, err := registry.refreshContainment(record.Lease.ContainmentID, func(query containmentQuery) (containmentTicket, error) {
				return metadata(query.LeaseID)
			})
			if bound.Directory != nil {
				bound.Directory.Close()
				t.Fatal("failed executable proof returned its prior live binding")
			}
			if err == nil || !strings.Contains(err.Error(), string(api.CodeContainmentUnknown)+":") {
				t.Fatal("failed executable proof did not refuse the existing binding through live containment revocation", err)
			}
			if err := manager.waitContainmentEmpty(ctx, current[0]); err != nil {
				t.Fatal("failed executable proof left a real process in the containment", err)
			}
			observation, err := gate.Observe(ctx, gateHandle(current[0]))
			if err != nil || observation.State != "exited" {
				t.Fatal("failed proof did not reap its original native runner", err)
			}
		} else if result.err != nil {
			t.Fatal("post-exec authentication did not complete the valid real proof", result.err)
		}
	}
}

// Overlay only this isolated process's installation view. An existing host
// artifact is never replaced or removed by the fixture.
func privateContainmentMounts(t *testing.T) {
	t.Helper()
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/usr/lib/laneboss-v2", "/etc/laneboss-v2", "/run/laneboss-v2"} {
		if err := os.Mkdir(target, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		original, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		view := t.TempDir()
		if err := os.Chmod(view, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(view, target, "", unix.MS_BIND, ""); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			// The isolated child owns this bind. Native descriptors may pin
			// its old view until process exit; detach it from this namespace
			// and verify that the original host directory is visible again.
			if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
				t.Error(err)
				return
			}
			current, err := os.Stat(target)
			if err != nil || !os.SameFile(original, current) {
				t.Error("private containment view did not restore its original directory", err)
			}
		})
	}
}
