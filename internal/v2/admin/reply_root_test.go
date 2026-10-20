//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Hold only the scheduling of a real journal generation check. Every byte,
// cgroup observation, peer check and helper reply uses production code.
type replyStore struct {
	*fileLeaseStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *replyStore) ContainmentGeneration() ([32]byte, error) {
	s.once.Do(func() { close(s.entered); <-s.release })
	return s.fileLeaseStore.ContainmentGeneration()
}

type replyInput struct {
	Ticket  containmentTicket
	Mode    string
	PeerPID int
}

type replyEvent struct {
	Event        string        `json:"event"`
	Method       string        `json:"method"`
	Nonce        api.ID        `json:"helper_nonce"`
	Lease        api.ID        `json:"lease_id"`
	Life         api.ID        `json:"life_id"`
	Launch       api.ID        `json:"launch_id"`
	Caller       int           `json:"caller_pid"`
	Code         api.ErrorCode `json:"code"`
	Reason       string        `json:"reason"`
	CallState    string        `json:"call_state"`
	RequestState string        `json:"request_state"`
}

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-reply-client" {
		if err := replyClient(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(117)
		}
		os.Exit(0)
	}
}

func replyClient(config string) error {
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
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	var input replyInput
	if err := decoder.Decode(&input); err != nil {
		return err
	}
	ticket := input.Ticket
	directory := os.NewFile(3, "reply-containment")
	defer directory.Close()
	s.containments = map[api.ID]*containmentEntry{ticket.Lease.ContainmentID: {
		Ticket: ticket, Binding: api.ContainmentBinding{Config: ticket.Config,
			Lease: ticket.Lease, Target: ticket.Target, BootID: ticket.BootID,
			Generation: ticket.Generation, Backend: "linux-bwrap-landlock", Directory: directory},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = s.containmentCallContext(ctx, ticket.Lease.ContainmentID, input.PeerPID)
	result := make(chan error, 1)
	go func() {
		got, err := s.liveContainment(ctx, ticket.Lease.ContainmentID,
			containmentQuery{LeaseID: ticket.Lease.ID, Opened: true})
		if err == nil && got != ticket {
			err = errors.New("reply changed the actual containment")
		}
		result <- err
	}()
	var command string
	if err := decoder.Decode(&command); err != nil || command != input.Mode {
		return errors.New("missing reply lifecycle command")
	}
	if input.Mode == "fence" {
		finish := s.beginContainment(ticket.Lease.ID)
		finish()
		// Let the transport cancellation run before the helper can reply.
		// A publication fence must leave this request-owned socket open.
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		if err := encoder.Encode("changed"); err != nil {
			return err
		}
		if err := <-result; err != nil {
			return err
		}
	} else if input.Mode == "cancel" {
		began := time.Now()
		cancel()
		err := <-result
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeCancelled || time.Since(began) > 188*time.Millisecond {
			return errors.New("real requester cancellation lost its bounded refusal")
		}
		if err := encoder.Encode("changed"); err != nil {
			return err
		}
	} else {
		return errors.New("unknown reply lifecycle mode")
	}
	if err := encoder.Encode("complete"); err != nil {
		return err
	}
	// Stay alive while the helper journals its actual response. A dead peer
	// would test caller_lifetime instead of the closed response transport.
	if err := decoder.Decode(&command); err != nil || command != "retired" {
		return errors.New("missing helper journal completion")
	}
	return nil
}

func TestReplyDrain(t *testing.T) {
	for _, mode := range []string{"fence", "cancel"} {
		t.Run(mode, func(t *testing.T) { replyDrain(t, mode) })
	}
}

func replyDrain(t *testing.T, mode string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("reply canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] != "reply-drain-root" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.v", "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "--", "reply-drain-root")
		cmd.Env = []string{}
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("real helper reply canary failed: %v\n%s", err, out)
		}
		writes := bytes.Count(out, []byte(`"stage":"response_write"`))
		if mode == "fence" && writes != 0 || mode == "cancel" && writes != 1 {
			t.Fatalf("actual response_write diagnostic count=%d mode=%s\n%s", writes, mode, out)
		}
		t.Log(string(out))
		return
	}
	privateContainmentMounts(t)
	var groups []string
	t.Cleanup(func() {
		for i := len(groups) - 1; i >= 0; i-- {
			if err := os.Remove(groups[i]); err != nil {
				t.Error(err)
			}
		}
	})
	m, open, gate, reader, store, _ := retainedGateFixtureControl(t)
	if _, err := m.openGate(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	token := make([]byte, len(gate.token))
	if _, err := io.ReadFull(reader, token); err != nil || string(token) != gate.token {
		t.Fatal("real runner did not execute", err)
	}
	record, err := m.find(open.Binding.Record.UIDLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	group := filepath.Join(m.binding.cgroupPath(), string(record.Lease.ContainmentID))
	for _, path := range []string{filepath.Dir(m.binding.cgroupPath()), m.binding.cgroupPath(), group} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		groups = append(groups, path)
	}
	if err := os.WriteFile(filepath.Join(group, "cgroup.procs"), []byte(strconv.Itoa(gate.PID())), 0600); err != nil {
		t.Fatal(err)
	}
	m.resources = &linuxResources{binding: m.binding, manager: m}
	endpoint := nativeContainmentEndpoint(t, m, true)
	ticket, err := m.containment(context.Background(), containmentQuery{LeaseID: record.Lease.ID, Opened: true})
	if err != nil {
		t.Fatal(err)
	}
	blocked := &replyStore{fileLeaseStore: store, entered: make(chan struct{}), release: make(chan struct{})}
	m.store = blocked
	var release sync.Once
	unblock := func() { release.Do(func() { close(blocked.release) }) }
	t.Cleanup(unblock)
	directory, err := os.Open(group)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, endpoint.binding.binaryPath(), "admin-reply-client", endpoint.binding.Config)
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{directory}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: endpoint.binding.Service.UID, Gid: endpoint.binding.Service.GID, Groups: []uint32{}},
		UseCgroupFD: true, CgroupFD: int(endpoint.group.Fd())}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			cancel()
			if err := cmd.Wait(); err != nil && !t.Failed() {
				t.Error(err)
			}
		}
	}()
	encoder, decoder := json.NewEncoder(input), json.NewDecoder(output)
	if err := encoder.Encode(replyInput{Ticket: ticket, Mode: mode, PeerPID: gate.PID()}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.entered:
	case <-ctx.Done():
		t.Fatal("helper did not enter its real journal read")
	}
	if err := encoder.Encode(mode); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := decoder.Decode(&state); err != nil || state != "changed" {
		t.Fatal("client did not change its lifecycle", err)
	}
	unblock()
	if err := decoder.Decode(&state); err != nil || state != "complete" {
		t.Fatal("client did not finish its bounded request", err)
	}
	want := 2
	if mode == "cancel" {
		want = 1
	}
	var replies []replyEvent
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for len(replies) < want {
		replies = nil
		for _, line := range strings.Split(endpoint.journal.snapshot(), "\n") {
			var event replyEvent
			if json.Unmarshal([]byte(line), &event) == nil && event.Event == "helper_request" && event.Method == "containment_live" {
				replies = append(replies, event)
			}
		}
		if len(replies) >= want {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("actual helper reply was not journalled")
		}
	}
	if err := encoder.Encode("retired"); err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	joined = true
	if waitErr != nil {
		t.Fatal("service client failed", waitErr, diagnostic.String())
	}
	ends := map[api.ID]replyEvent{}
	for _, line := range strings.Split(diagnostic.String(), "\n") {
		var event replyEvent
		if json.Unmarshal([]byte(line), &event) == nil && event.Event == "helper_call_end" {
			ends[event.Nonce] = event
		}
	}
	refused := 0
	for _, event := range replies {
		call, ok := ends[event.Nonce]
		if !ok || event.Nonce == "" || event.Caller != cmd.Process.Pid || call.Caller != event.Caller ||
			event.Lease != record.Lease.ID || call.Lease != event.Lease || event.Life != ticket.Target.LifeID ||
			call.Life != event.Life || event.Launch != ticket.LaunchID || call.Launch != event.Launch {
			t.Fatal("helper nonce, lease, life or caller correlation was lost")
		}
		if event.Code != "ok" && event.Reason == "reply_transport" {
			refused++
			t.Logf("reply refusal correlated=true call_state=%s request_state=%s", call.CallState, call.RequestState)
		}
		if mode == "fence" && (event.Code != "ok" || call.CallState != "live" || call.RequestState != "live") {
			t.Error("normal lifecycle fence abandoned an authenticated helper reply")
		}
		if mode == "cancel" && (event.Reason != "reply_transport" || event.Code != api.CodeUnavailable || call.RequestState != "cancelled") {
			t.Error("real requester cancellation lost its helper refusal journal")
		}
	}
	t.Logf("mode=%s helper_requests=%d response_write=%d nonce_joins=%d", mode, len(replies), refused, len(ends))
}
