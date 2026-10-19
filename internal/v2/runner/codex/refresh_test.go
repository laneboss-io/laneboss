package codex

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Real synthetic descriptor bytes; native root ownership/peer/seal facts below
// model the owning broker's input. This is not a native transfer or root test.
func refreshFixture(t *testing.T, f *runnerFixture, data []byte) (api.CredentialProjectionRecord, api.CredentialRefresh) {
	t.Helper()
	file := refreshFile(t, data, false, false)
	zero := uint64(0)
	request := api.CredentialProjectionRequest{Prepared: api.PreparedLaunch{ID: "refresh_prepared", Target: f.request.Target,
		ContainmentID: "containment_one", ProcessGeneration: "generation_one"},
		Home: api.PrivateHomeBinding{Home: f.request.Home}, Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{Kind: "agent", Runner: &api.RunnerPlan{Driver: api.DriverCodex, Slot: f.request.Slot}}}}
	record := api.CredentialProjectionRecord{Authority: api.CredentialProjectionAuthority{ID: "refresh_projection", Request: request,
		Sources: []api.CredentialSourceVersion{{Key: f.request.Slot.ID, Generation: 1, Version: "login_revision_one"}}},
		Generation: 3, State: "withdrawing", Receipt: &api.CredentialProjectionReceipt{}, Fence: &api.CredentialWithdrawalRequest{Reason: "release"}}
	refresh := api.CredentialRefresh{ProjectionID: record.Authority.ID, ExpectedGeneration: record.Generation, SlotID: f.request.Slot.ID,
		ExpectedSourceGeneration: 1, Observation: observation(f.request.Target, 0), File: file,
		Fact: api.CredentialDescriptorFact{ObjectID: "anonymous_refresh", OwnerUID: 0, Mode: 0600, Size: int64(len(data)),
			Regular: true, ReadOnly: true, CloseOnExec: true, WritableHandles: &zero}}
	return record, refresh
}

func refreshFile(t *testing.T, data []byte, linked, writable bool) *os.File {
	t.Helper()
	name := filepath.Join(canonicalTemp(t), "synthetic-refresh")
	putFile(t, name, data, 0600)
	flags := os.O_RDONLY
	if writable {
		flags = os.O_RDWR
	}
	file, err := os.OpenFile(name, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		if err := os.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	return file
}

func receiveRefresh(t *testing.T, f *runnerFixture, data []byte) (Credential, error) {
	t.Helper()
	record, refresh := refreshFixture(t, f, data)
	return f.slot.Refreshed(record, refresh, f.clock.Now())
}

func TestRefreshSource(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.home.path, ".codex/auth.json")
	laneBytes := syntheticAuthFor(t, "on_lane_", "synthetic_account_login_one")
	putFile(t, path, laneBytes, 0600)
	returned := syntheticAuthFor(t, "returned", "synthetic_account_login_one")
	if len(laneBytes) != len(returned) || bytes.Equal(laneBytes, returned) {
		t.Fatal("refresh source fixture did not isolate equal-size bytes")
	}
	record, refresh := refreshFixture(t, f, returned)
	if _, err := refresh.File.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	credential, err := f.slot.Refreshed(record, refresh, f.clock.Now())
	if err != nil || !bytes.Equal(credential.payload, returned) {
		t.Fatal("refresh did not consume exact received bytes", err)
	}
	if _, err := refresh.File.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("refresh received duplicate remained open")
	}
	if !bytes.Equal(getFile(t, path), laneBytes) {
		t.Fatal("refresh consumer wrote back into the lane")
	}
	claim, err := f.slot.locks.acquire("login", "login_one")
	if claim != nil {
		if closeErr := claim.close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	wantCode(t, err, api.CodeConflict)
}

func TestRefreshFD(t *testing.T) {
	for _, fault := range []string{"linked", "writable", "cloexec"} {
		t.Run(fault, func(t *testing.T) {
			data := syntheticAuth(t, "descriptor")
			control := refreshFile(t, data, false, false)
			actual, err := readRefreshDescriptor(control)
			if closeErr := control.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil || !bytes.Equal(actual, data) {
				t.Fatal("valid anonymous refresh descriptor refused", err)
			}
			file := refreshFile(t, data, fault == "linked", fault == "writable")
			if fault == "cloexec" {
				if _, _, err := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_SETFD, 0); err != 0 {
					t.Fatal(err)
				}
			}
			_, err = readRefreshDescriptor(file)
			if closeErr := file.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			wantCode(t, err, api.CodeIntegrity)
		})
	}
}

func TestRefreshProof(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	data := syntheticAuthFor(t, "returned", "synthetic_account_login_one")
	if _, err := receiveRefresh(t, f, data); err != nil {
		t.Fatal("valid reverse handoff refused", err)
	}
	record, refresh := refreshFixture(t, f, data)
	refresh.ExpectedSourceGeneration++
	_, err := f.slot.Refreshed(record, refresh, f.clock.Now())
	wantCode(t, err, api.CodeInvalid)
	if _, err := refresh.File.Stat(); err == nil {
		t.Fatal("refused refresh duplicate remained open")
	}
}

func TestNativeDestination(t *testing.T) {
	home, _ := newTestHome(t)
	locks, err := NewLeases(canonicalTemp(t))
	if err != nil {
		t.Fatal(err)
	}
	defer locks.Close()
	slot, err := NewSlot(home, locks)
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	data := syntheticAuth(t, "returned_native")
	file := refreshFile(t, data, false, false)
	returned, err := readRefreshDescriptor(file)
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredential("native_profile", "native_login", hashBytes([]byte("synthetic_account_returned_native")), returned)
	if err != nil {
		t.Fatal(err)
	}
	selected := api.CredentialSlot{ID: "native_slot", Mode: "codex-file", ProfileGrantID: "native_grant", ProfileID: credential.profile, LeaseID: "native_lease", ExpiresAt: "2100-01-01T00:00:00Z"}
	if err := slot.Install(api.LifeRef{LifeID: "native_life", Run: 1}, selected, credential); err != nil {
		t.Fatal(err)
	}
	actual, err := readPrivate(home.root, ".codex/auth.json", maxAuthBytes)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("credential missed the fixed native destination", err)
	}
	if history := getFile(t, filepath.Join(home.path, ".codex/history.jsonl")); len(history) != 0 {
		t.Fatal("credential publication changed conversation history")
	}
}
