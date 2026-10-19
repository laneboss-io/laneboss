//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func init() {
	if len(os.Args) != 4 || os.Args[1] != "claudock-settings-canary" {
		return
	}
	for _, path := range []string{"/home/lane/.claude/settings.json", "/home/lane/.config/claudock/profiles.json",
		"/home/lane/.config/claudock/" + "preferences.json"} {
		if err := os.Chmod(path, 0600); !errors.Is(err, unix.EROFS) {
			os.Exit(181)
		}
		if err := os.WriteFile(path, []byte("unauthorized settings replacement"), 0600); err == nil {
			os.Exit(182)
		}
	}
	if _, err := os.ReadDir(os.Args[3]); err == nil {
		os.Exit(183)
	}
	if err := os.WriteFile("/home/lane/owned-write", []byte(os.Args[2]), 0600); err != nil {
		os.Exit(184)
	}
	if _, err := os.Stdout.WriteString(os.Args[2]); err != nil {
		os.Exit(185)
	}
	var hold [1]byte
	if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
		os.Exit(186)
	}
	os.Exit(0)
}

// Admission metadata is declared component input, as in the native delivery
// canary. The shipped helper confinement, actual bootstrap, kernel observations,
// lane-owned home, root-owned records and complete home transaction are real.
func TestClaudockNativePlanning(t *testing.T) {
	workerLaunchCanary(t, false, claudockNativePlanningCanary)
}

func claudockNativePlanningCanary(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	// The actual bootstrap must establish privacy rather than inherit the
	// helper unit's 0077 setting. This changes only this isolated test process.
	previous := unix.Umask(0022)
	defer unix.Umask(previous)
	record, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	reserved := record
	reserved.Phase = "reserved"
	if err := m.resources.Ensure(ctx, reserved); err != nil {
		t.Fatal(err)
	}
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	record.Storage.Binding.Home.Home.VendorDirectory = ".claude"
	record.Request.Budget.Currency = "USD"
	record.LaunchAllocations[0].Request.Budget.Currency = "USD"
	projection := keyPlan(t, &record, runtime, executable)
	record.LaunchAllocations[0].Inputs.Sources.Runtime.SessionExecutable = executable
	r := record.LaunchAllocations[0].Reservation
	home := filepath.Join(storageBase(m.binding, record), string(record.Storage.Binding.Home.RootID))
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(home, ".claude"), int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	expires := api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	cause := record.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "claudock-planning", api.InternalLaunchPlan, "claudock-plan-effect"
	lease := api.EffectLease{ClaimID: "claudock-plan-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1,
		ClaimID: "claudock-plan-claim", ClaimantID: cause.Actor.ID, ClaimExpiresAt: expires, Effect: api.Effect{ID: cause.EffectID, OperationID: r.OperationID,
			Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}}}
	ctx = api.WithEffectLease(ctx, lease)
	runner := projection.Handoff.Spec.Runner
	session := runner.Session
	session.VendorID = "00000000-0000-4000-8000-000000000001"
	request := api.RunnerRequest{Target: r.Target, LogicalTurnID: "claudock-native-turn", Session: session, Home: runner.Home, Slot: runner.Slot,
		Executable: executable, Prompt: runner.Prompt, Model: "claude-sonnet-4-6", Effort: "high", Budget: record.Request.Budget}
	q := claudockNativePlanning{Reservation: r, Input: ClaudockPlanningRequest{Claim: api.PlanningClaim(r.ID, lease), LeaseID: record.Lease.ID,
		Home: projection.Home, Request: request, RequiredUmask: claudock.RequiredUmask}}
	homePlan := claudock.HomePlanRequest{Request: request, Home: q.Input.Home, ReservationID: r.ID,
		InputsSHA256: testDigest("native component retained plan inputs"), Start: true,
		Claude: executable, ClaudePath: "/runtime/" + string(executable.ID)}
	q.Input.Plan = &homePlan
	_, err = claudockNativeWireCall(ctx, m, "claudock_home", q)
	claudockNativeRefusal(t, err, "credential home has no matching measured bootstrap proof", "unmeasured credential bootstrap authorized a home transaction")
	q.Input.Plan = nil
	if _, err := claudockNativeWireCall(ctx, m, "claudock_bootstrap", q); err != nil {
		t.Fatal("actual installed credential bootstrap could not be measured", err)
	}
	measured, err := m.find(record.Lease.ID)
	if err != nil || measured.Claudock == nil || measured.Claudock.Umask == nil || *measured.Claudock.Umask != claudock.RequiredUmask {
		t.Fatal("bootstrap did not retain its actual kernel measurement", err)
	}
	q.Input.Plan = &homePlan
	for _, fault := range []string{"path", "digest"} {
		altered := homePlan
		if fault == "path" {
			altered.ClaudePath = "/usr/bin/claude"
		} else {
			altered.Claude.SHA256 = testDigest("another vendor")
		}
		bad := q
		bad.Input.Plan = &altered
		_, err := claudockNativeWireCall(ctx, m, "claudock_home", bad)
		claudockNativeRefusal(t, err, "credential home CLI pin differs from its enrolled runtime", "credential worker accepted another CLI path or digest")
	}
	bad := q
	bad.Input.Home.RootID = "outside-credential-home"
	_, err = claudockNativeWireCall(ctx, m, "claudock_home", bad)
	claudockNativeRefusal(t, err, "credential worker home is outside its lane confinement", "credential worker accepted a home outside lane confinement")
	if _, err := claudockNativeWireCall(ctx, m, "claudock_home", q); err != nil {
		t.Fatal("credential worker could not plan the actual lane-owned home", err)
	}
	if _, err := claudockNativeWireCall(ctx, m, "claudock_home", q); err != nil {
		t.Fatal("identical credential home transaction could not replay", err)
	}
	if err := os.Chown(filepath.Join(home, ".claude"), 0, 0); err != nil {
		t.Fatal(err)
	}
	_, err = claudockNativeWireCall(ctx, m, "claudock_home", q)
	claudockNativeRefusal(t, err, "credential owned-entry owner differs from its lane allocation", "credential worker accepted a foreign owner in its private vendor home")
	if err := os.Chown(filepath.Join(home, ".claude"), int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	measured, err = m.find(record.Lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := m.appendClaudockSettings(ctx, measured, nil)
	if err != nil || len(mounts) != 3 {
		t.Fatal("credential home did not supply all pinned read-only projections", err)
	}
	for _, mount := range mounts {
		if mount.writable || mount.directory || mount.executable || mount.target != "/home/lane/.claude/settings.json" &&
			mount.target != "/home/lane/.config/claudock/profiles.json" && mount.target != "/home/lane/.config/claudock/"+"preferences.json" {
			t.Fatal("credential generated projection changed its target or write authority")
		}
		if err := mount.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	claudockProjectionCanary(t, ctx, m, measured)
	var owner unix.Stat_t
	if unix.Lstat(filepath.Join(home, ".claude/settings.json"), &owner) != nil || owner.Uid != record.Lease.UID || owner.Gid != record.Lease.GID || owner.Mode&07777 != 0400 {
		t.Fatal("credential worker changed lane ownership or protected settings mode")
	}
	if unix.Lstat(filepath.Join(m.binding.statePath(), "claudock"), &owner) != nil || owner.Uid != 0 || owner.Mode&07777 != 0700 {
		t.Fatal("credential records were exposed outside the root worker")
	}
	// Same owner and mode on a replacement cannot replace the journaled inode.
	old := home + "-retained"
	if err := os.Rename(home, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	_, err = claudockNativeWireCall(ctx, m, "claudock_home", q)
	claudockNativeRefusal(t, err, "credential home inode owner or mode differs from its lane confinement", "credential worker accepted an inode replacement inside lane confinement")
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, home); err != nil {
		t.Fatal(err)
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := m.resources.Quiescent(cleanup, record); err != nil {
		t.Fatal(err)
	}
	if err := m.resources.Remove(cleanup, record); err != nil {
		t.Fatal(err)
	}
	t.Log("credential native planning: installed bootstrap umask measured; confined lane home initialized and sealed; missing proof, foreign home and inode replacement refused")
}

func claudockNativeWireCall(ctx context.Context, m *leaseManager, method string, q claudockNativePlanning) (any, error) {
	input, err := EncodeWire(q)
	if err != nil {
		return nil, err
	}
	return m.dispatch(ctx, method, input)
}

func claudockProjectionCanary(t *testing.T, ctx context.Context, m *leaseManager, record leaseRecord) {
	t.Helper()
	_, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	mounts, err = m.appendClaudockSettings(ctx, record, mounts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, mount := range mounts {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	file, err := os.Open(m.binding.binaryPath())
	if err != nil {
		t.Fatal(err)
	}
	mounts = append(mounts, &nativeMount{file: file, target: "/runtime/claudock-settings-canary", executable: true})
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	stdin, finish, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer finish.Close()
	discard, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer discard.Close()
	token, err := randomID("settings-canary-")
	if err != nil {
		t.Fatal(err)
	}
	payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: token, Token: string(token), UID: record.Lease.UID, GID: record.Lease.GID,
		Argv: []string{"/runtime/claudock-settings-canary", "claudock-settings-canary", string(token), filepath.Join(m.binding.statePath(), "claudock")},
		CWD:  "/work/main", Budget: record.Request.Budget, Environment: []string{}, stdin: stdin}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, write, discard, nil, nil, m.bootID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := gate.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := gate.Release(); err != nil {
		t.Fatal(err)
	}
	if err := read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(token))
	if _, err := io.ReadFull(read, actual); err != nil || string(actual) != string(token) {
		t.Fatal("confined credential settings were writable or protected records were visible", err)
	}
	if err := finish.Close(); err != nil {
		t.Fatal(err)
	}
	observation, err := gate.Stop(ctx, api.ProcessHandle{})
	if err != nil || observation.ExitCode == nil || *observation.ExitCode != 0 {
		t.Fatal("credential projection canary did not exit cleanly", err)
	}
	if err := m.waitContainmentEmpty(ctx, record); err != nil {
		t.Fatal(err)
	}
	t.Log("credential projections: native read-only settings and registry refused chmod/write; protected records absent; ordinary home writable")
}

func claudockNativeRefusal(t *testing.T, err error, expected, assertion string) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != expected {
		t.Fatal(assertion, err)
	}
}
