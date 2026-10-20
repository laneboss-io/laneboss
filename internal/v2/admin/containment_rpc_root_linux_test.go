//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 4 && os.Args[1] == "admin-containment-service-client" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b, err := loadInstallation(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(111)
		}
		service, err := New(Dependencies{Config: b.Config, ServiceUID: b.Service.UID, ArtifactSHA256: b.Artifact.SHA256,
			Version: b.Release.Version, Protocol: api.Protocol, Schema: api.SchemaVersion})
		var ticket containmentTicket
		if err == nil {
			err = service.call(ctx, "containment_live", containmentQuery{LeaseID: api.ID(os.Args[3]), Opened: true}, &ticket)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(112)
		}
		if json.NewEncoder(os.Stdout).Encode(ticket) != nil {
			os.Exit(113)
		}
		os.Exit(0)
	}
}

type containmentRPCJournal struct {
	mu sync.Mutex
	bytes.Buffer
}

func (j *containmentRPCJournal) Write(data []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Buffer.Write(data)
}

func (j *containmentRPCJournal) snapshot() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Buffer.String()
}

// Install only the protected helper binding and this test executable. The
// caller and listener use the production authenticated IPC, with actual
// distinct UIDs, cgroups, pidfds and installed-executable identity checks.
// No account database, real vendor credential or model service is used.
func nativeContainmentRPC(t *testing.T, manager *leaseManager) func(api.ID) (containmentTicket, error) {
	return nativeContainmentEndpoint(t, manager, false).query
}

type containmentEndpoint struct {
	binding installation
	group   *os.File
	journal *containmentRPCJournal
	query   func(api.ID) (containmentTicket, error)
}

func nativeContainmentEndpoint(t *testing.T, manager *leaseManager, compact bool) containmentEndpoint {
	t.Helper()
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	b := manager.binding
	b.Artifact.Bytes, b.Artifact.SHA256 = int64(len(self)), digestBytes(self)
	b.Release.Artifacts = []api.ReleaseArtifact{b.Artifact}
	manager.binding = b
	var directories, files []string
	var stop func() error
	journal := &containmentRPCJournal{}
	logged := 0
	emitJournal := func() {
		data := journal.snapshot()
		if compact {
			turns, reads := 0, 0
			var readMS, holdMS int64
			for _, line := range strings.Split(data, "\n") {
				var timing struct {
					Operation string `json:"operation"`
					Stage     string `json:"stage"`
					HoldMS    int64  `json:"hold_ms"`
				}
				if json.Unmarshal([]byte(line), &timing) != nil || timing.Operation != "containment_live" {
					continue
				}
				if timing.Stage == "turn" {
					turns++
					holdMS += timing.HoldMS
				}
				if timing.Stage == "journal_read" {
					reads++
					readMS += timing.HoldMS
				}
			}
			t.Logf("containment_live turns=%d journal_reads=%d journal_read_ms=%d turn_hold_ms=%d", turns, reads, readMS, holdMS)
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(data[logged:]), "\n") {
			if line != "" {
				var timing struct {
					Event  string `json:"event"`
					Stage  string `json:"stage"`
					WaitMS int64  `json:"wait_ms"`
					HoldMS int64  `json:"hold_ms"`
				}
				if json.Unmarshal([]byte(line), &timing) == nil && timing.Event == "helper_timing" && timing.WaitMS == 0 && timing.HoldMS == 0 &&
					timing.Stage != "operation_mu" && timing.Stage != "helper_mu" && timing.Stage != "open_wait_mu" && timing.Stage != "turn" {
					continue // Keep the bounded box result focused on locks and measured work.
				}
				t.Log(line)
			}
		}
		logged = len(data)
	}
	original, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(filepath.Dir(b.cgroupPath()), "control")
	serviceGroup := filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-service@"+b.Config+".service")
	moved := false
	t.Cleanup(func() {
		if stop != nil {
			if err := stop(); err != nil {
				t.Error(err)
			}
		}
		emitJournal()
		if moved {
			if err := os.WriteFile(filepath.Join("/sys/fs/cgroup", original, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				t.Error("cannot restore the root canary's original cgroup", err)
				return
			}
		}
		for index := len(files) - 1; index >= 0; index-- {
			if err := os.Remove(files[index]); err != nil {
				t.Error(err)
			}
		}
		for index := len(directories) - 1; index >= 0; index-- {
			if err := os.Remove(directories[index]); err != nil {
				t.Error(err)
			}
		}
	})
	for _, directory := range []string{"/usr/lib/laneboss-v2", filepath.Dir(b.binaryPath()), "/etc/laneboss-v2", "/etc/laneboss-v2/admin", "/run/laneboss-v2", b.runtimePath(), control, serviceGroup} {
		if err := os.Mkdir(directory, 0755); err == nil {
			directories = append(directories, directory)
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			t.Fatal("native metadata fixture refuses to overwrite an installed file", err)
		}
		files = append(files, path)
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			t.Fatal(err)
		}
	}
	write(b.binaryPath(), self, 0555)
	encoded, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	write(bindingPath(b.Config), encoded, 0644)
	if err := os.WriteFile(filepath.Join(control, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	moved = true
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	requestDone := make(chan error, 2048)
	stop, err = startCredentialMetadataReader(ctx, b, func(ctx context.Context, connection *net.UnixConn) error {
		err := serveHelperConnectionWithJournal(ctx, connection, b, manager, journal, true)
		if !compact {
			requestDone <- err
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	serviceDirectory, err := os.Open(serviceGroup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serviceDirectory.Close() })
	query := func(lease api.ID) (containmentTicket, error) {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		command := exec.CommandContext(bounded, b.binaryPath(), "admin-containment-service-client", b.Config, string(lease))
		command.Env = []string{}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: b.Service.UID, Gid: b.Service.GID, Groups: []uint32{}},
			UseCgroupFD: true, CgroupFD: int(serviceDirectory.Fd())}
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		start := time.Now()
		err := command.Run()
		if _, err := journal.Write(diagnostic.Bytes()); err != nil {
			t.Fatal("cannot retain service-side helper call correlation", err)
		}
		if compact {
			// Concurrent calls cannot be matched to a shared completion queue.
			// The process result carries this call's actual authenticated reply;
			// endpoint cleanup joins every helper reader before the final summary.
			t.Logf("native metadata RPC elapsed_ms=%d client_refused=%t", time.Since(start).Milliseconds(), err != nil)
		} else {
			select {
			case helperErr := <-requestDone:
				t.Logf("native metadata RPC elapsed_ms=%d helper_refused=%t", time.Since(start).Milliseconds(), helperErr != nil)
			case <-time.After(helperReplyTimeout):
				t.Logf("native metadata RPC elapsed_ms=%d helper_pending=true", time.Since(start).Milliseconds())
				t.Error("native metadata helper did not finish its actual request")
			}
		}
		emitJournal()
		var ticket containmentTicket
		if err != nil {
			return ticket, fmt.Errorf("installed metadata client failed: %w: %s", err, diagnostic.String())
		}
		if err := decodeStrict(output.Bytes(), &ticket); err != nil {
			return ticket, err
		}
		return ticket, nil
	}
	return containmentEndpoint{binding: b, group: serviceDirectory, journal: journal, query: query}
}
