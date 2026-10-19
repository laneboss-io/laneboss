//go:build linux && laneboss_gate_integration

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 3 && os.Args[1] == "admin-credential-exec-vendor" {
		if os.Getenv("TASK_ACCESS") != os.Args[2] {
			os.Exit(86)
		}
		entries, err := os.ReadDir("/proc/1/fd")
		if err != nil || len(entries) != 3 {
			os.Exit(87)
		}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil || fd < 0 || fd > 2 {
				os.Exit(87)
			}
		}
		entries, err = os.ReadDir("/proc/self/fd")
		if err != nil {
			os.Exit(88)
		}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil {
				os.Exit(88)
			}
			if fd <= 2 {
				continue
			}
			var info unix.Stat_t
			if err := unix.Stat("/proc/self/fd/"+entry.Name(), &info); errors.Is(err, unix.ENOENT) {
				continue // ReadDir's own descriptor has already closed.
			} else if err != nil {
				os.Exit(88)
			}
			switch info.Mode & unix.S_IFMT {
			case unix.S_IFREG, unix.S_IFDIR, unix.S_IFSOCK, unix.S_IFIFO:
				os.Exit(88) // No retained input/socket is selected in this canary.
			}
		}
		if err := os.WriteFile("/work/main/executed", []byte(os.Args[2]), 0600); err != nil {
			os.Exit(89)
		}
		if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
			os.Exit(90)
		}
		var hold [1]byte
		if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
			os.Exit(91)
		}
		os.Exit(0)
	}
}

// Source authority is explicitly a synthetic fixture. The actual staged files,
// sealed environment export, bwrap gate, final credential receiver, vendor exec,
// pidfd/hash proof and in-lane descriptor observations are production paths.
func credentialExecCanary(t *testing.T, m *leaseManager, record *leaseRecord, payload *gatePayload, work string) *os.File {
	t.Helper()
	ctx := context.Background()
	input, _ := credentialCanary(t)
	if err := input.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if n, err := input.WriteAt([]byte(payload.Token), 0); err != nil || n != len(payload.Token) {
		t.Fatal(err)
	}
	sourceID, _, err := credentialObject(input)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(work, ".codex")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(parent, "auth.json")
	if err := os.WriteFile(auth, []byte(payload.Token), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(auth, int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	environment, err := anonymousCredential(ctx, input, int64(len(payload.Token)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Close(); err != nil {
			t.Error(err)
		}
	})
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	pin := api.Executable{ID: "credential-canary-vendor", Version: "fixture", SHA256: digestBytes(self)}
	expires := api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	slot := api.CredentialSlot{ID: "canary-slot", ProfileGrantID: "canary-profile-grant", ProfileID: "canary-profile",
		Mode: "codex-file", LeaseID: "canary-slot-lease", ExpiresAt: expires}
	home := api.PrivateHomeBinding{LifeID: record.Request.Cause.Target.LifeID, RootID: "canary-home-root", Generation: 1,
		Home: api.PrivateHome{ID: "canary-home", VendorDirectory: ".codex"}}
	spec := api.LaunchSpec{Kind: "agent", Backend: "linux-bwrap-landlock", Runner: &api.RunnerPlan{Driver: api.DriverCodex, Slot: slot, Home: home.Home, Executable: pin,
		Argv: []string{}, EnvironmentNames: []string{}}, Materialization: api.Materialization{Objects: []api.MaterializedObject{}},
		Grants: api.GrantSet{Resources: []api.ResourceGrant{}, Data: []api.DataGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
			Profiles: []api.ProfileGrant{{ID: slot.ProfileGrantID, ProfileID: slot.ProfileID, Driver: api.DriverCodex, ExpiresAt: expires}},
			Secrets:  []api.SecretGrant{{ID: "canary-env", Name: "access", SourceHandle: "canary-env-source", Version: "v1", Delivery: "env", Target: "TASK_ACCESS", ExpiresAt: expires}}},
		Injection: api.Injection{SlotIDs: []api.ID{slot.ID}, GrantIDs: []api.ID{"canary-env"}, SourceVersions: []string{"v1"}, TaskSecretNames: []string{"TASK_ACCESS"}, TaskSecretFileNames: []string{}}}
	payload.CredentialRequired, payload.PreparedID, payload.SpecSHA256 = true, "canary-prepared", digestBytes([]byte("synthetic canary spec correlation"))
	payload.Argv = []string{"/runtime/native-canary", "admin-credential-exec-vendor", payload.Token}
	request := api.CredentialProjectionRequest{Lease: record.Lease, Home: home, Prepared: api.PreparedLaunch{ID: payload.PreparedID, GateID: payload.GateID},
		Handoff: api.PreparedSpecHandoff{Spec: spec, SpecSHA256: payload.SpecSHA256}}
	targets, err := api.CredentialTargets(request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	authority := api.CredentialProjectionAuthority{ID: "canary-projection", Generation: 1, Request: request, Targets: targets}
	receipt := api.CredentialProjectionReceipt{ProjectionID: authority.ID, Generation: 2, Prepared: request.Prepared, HelperLeaseID: record.Lease.ID,
		SpecSHA256: request.Handoff.SpecSHA256, Home: home, GateClosed: true, ObservedAt: gateTimestamp()}
	files := []*os.File{file, environment}
	state, err := dataParent(m.binding.statePath())
	if err != nil {
		t.Fatal(err)
	}
	var nativeParent, helperParent unix.Stat_t
	if err := errors.Join(unix.Stat(parent, &nativeParent), unix.Fstat(int(state.Fd()), &helperParent), state.Close()); err != nil {
		t.Fatal(err)
	}
	for index, target := range targets {
		fact, err := credentialDescriptor(files[index], target.Delivery == "env")
		if err != nil {
			t.Fatal(err)
		}
		authority.Sources = append(authority.Sources, api.CredentialSourceVersion{Key: target.Key, Generation: 1, Version: "v1"})
		parentMode := nativeParent.Mode & 07777
		if target.Delivery == "env" {
			parentMode = helperParent.Mode & 07777
		}
		receipt.Targets = append(receipt.Targets, api.CredentialHeldTarget{Target: target, SourceObjectID: sourceID, ObjectID: fact.ObjectID,
			RootID: home.RootID, HomeGeneration: home.Generation, OwnerUID: fact.OwnerUID, Mode: fact.Mode, Links: fact.Links, ParentMode: parentMode,
			WritableByOthers: fact.Mode&0077 != 0})
	}
	count, zero := uint64(len(files)), uint64(0)
	receipt.HeldDescriptors, receipt.InheritedSources = &count, &zero
	projection := api.CredentialProjectionRecord{Authority: authority, Generation: 2, State: "held", Receipt: &receipt}
	raw, err := json.Marshal(credentialExecPacket{Record: projection, Objects: []credentialExecObject{}})
	var checked credentialExecPacket
	if err != nil || decodeStrict(raw, &checked) != nil {
		t.Fatal("credential canary packet did not survive the production strict reader", err)
	}
	// Typed fixture preflight only. The real bootstrap independently observes
	// UID, capabilities and isolation in credentialExecFacts before using data.
	if err := api.ValidateCredentialEnvironment(projection, api.CredentialExecEnvironment{PreparedID: request.Prepared.ID, Stage: "vendor_exec",
		UID: record.Lease.UID, GID: record.Lease.GID, Capabilities: &zero, Backend: spec.Backend, IsolationReady: true,
		ObservedAt: gateTimestamp(), EarlierNames: []string{}, VendorNames: []string{"TASK_ACCESS"}}); err != nil {
		t.Fatal("credential canary did not retain valid actual destination facts", err)
	}
	m.credentials = &credentialRuntime{manager: m, held: map[api.ID]*heldCredentials{authority.ID: {record: projection, files: files}}}
	record.Credentials = &credentialJournal{State: "held", Record: &projection}
	record.Spec = &specRegistration{Handoff: request.Handoff}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, file := range []*os.File{read, write} {
			if err := file.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error(err)
			}
		}
	})
	payload.stdin = read
	return write
}

func observeCredentialCanary(t *testing.T, ctx context.Context, manager *leaseManager, record leaseRecord) {
	t.Helper()
	gate := manager.gates[record.Lease.ID].(*nativeGate)
	// The vendor has emitted its measured success marker and remains alive on
	// its input pipe. This old-channel observation classifies the review claim;
	// it supplies no exec acceptance. The independent EOF/hash proof follows.
	if err := gate.control.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	n, err := gate.control.Read(data[:])
	if n == 0 && errors.Is(err, io.EOF) {
		t.Log("monitor-control-eof=observed")
	} else if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
		t.Log("monitor-control-eof=retained")
	} else {
		t.Fatal("native inherited-channel observation is uncertain")
	}
	if err := manager.awaitCredentialGate(ctx, record); err != nil {
		t.Fatal("acceptance: credentialed native gate lacked EOF and exact live vendor exec", err)
	}
	t.Log("bootstrap-exec-eof=observed; pid1-stdio-only=observed; helper-descriptors=unreachable")
}
