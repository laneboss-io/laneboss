package codex

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This fixture-only cleanup closes real synthetic file descriptors. It does not
// claim that a production login was rotated or that a process was quiescent.
func closeFixtureHandles(t *testing.T, slot *Slot) {
	t.Helper()
	if err := slot.root.Close(); err != nil {
		t.Error(err)
	}
	for _, claim := range slot.logins {
		if err := claim.close(); err != nil {
			t.Error(err)
		}
	}
	if err := slot.homeLease.close(); err != nil {
		t.Error(err)
	}
	slot.closed = true
}

// Fails if a second lane gets the same canonical login through a profile alias,
// or if an independent login is unnecessarily blocked. Actual flock is used.
func TestCanonicalLoginSerialization(t *testing.T) {
	f := newFixture(t)
	home, _ := newTestHome(t)
	second := testSlot(t, home, f.slot.locks)
	target := api.LifeRef{LifeID: "life_two", Run: 1}
	reference := f.request.Slot
	reference.ID = "slot_two"
	reference.ProfileID = "alias_profile"
	reference.ProfileGrantID = "alias_grant"
	err := second.Install(target, reference, credentialFor(t, reference.ProfileID, "login_one"))
	wantCode(t, err, api.CodeConflict)
	if _, err := os.Stat(filepath.Join(home.path, ".codex/auth.json")); !os.IsNotExist(err) {
		t.Fatal("busy login was copied before acquiring its lease")
	}
	if err := second.Install(target, reference, credentialFor(t, reference.ProfileID, "login_two")); err != nil {
		t.Fatal("independent login blocked", err)
	}
	if _, err := f.slot.Revoke(); err != nil {
		t.Fatal(err)
	}
	if err := second.Install(target, reference, credentialFor(t, reference.ProfileID, "login_one")); err != nil {
		t.Fatal("released canonical login still blocked", err)
	}
}

// Fails if active refresh/swaps, unknown survivors or a different run can pass
// quiescence. Refreshed imports only auth bytes and keeps all history unchanged.
func TestRefreshRequiresQuiescence(t *testing.T) {
	f := newFixture(t)
	history := filepath.Join(f.home.path, ".codex/history.jsonl")
	putFile(t, history, []byte(t.Name()), 0600)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	err := f.slot.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_two"))
	wantCode(t, err, api.CodeConflict)
	if _, err := receiveRefresh(t, f, syntheticAuthFor(t, "active", "synthetic_account_login_one")); err == nil {
		t.Fatal("active refresh imported")
	}
	for _, shape := range []string{"not-exited", "unknown-survivors", "survivor", "wrong-run", "two-outcomes", "missing-time"} {
		exit := observation(f.request.Target, 0)
		switch shape {
		case "not-exited":
			exit.State = "running"
		case "unknown-survivors":
			exit.Survivors = nil
		case "survivor":
			one := uint64(1)
			exit.Survivors = &one
		case "wrong-run":
			exit.Handle.Target.Run++
		case "two-outcomes":
			signal := 15
			exit.Signal = &signal
		case "missing-time":
			exit.ObservedAt = ""
		}
		wantCode(t, f.slot.Quiesce(exit), api.CodeContainmentUnknown)
	}
	refreshed := syntheticAuthFor(t, "refreshed", "synthetic_account_login_one")
	putFile(t, filepath.Join(f.home.path, ".codex/auth.json"), refreshed, 0600)
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	credential, err := receiveRefresh(t, f, refreshed)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := credential.WriteTo(&output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), refreshed) || !bytes.Equal(getFile(t, history), []byte(t.Name())) {
		t.Fatal("refresh changed bytes or imported history")
	}
}

// H3: even owned-prefix directories/symlinks and unrelated runtime files cannot
// prevent native auth removal. Only ordinary owned-prefix files are removed.
func TestRevokeRemovesAuthFirst(t *testing.T) {
	f := newFixture(t)
	runtime := filepath.Join(f.home.path, ".runnerhome-runtime")
	putFile(t, filepath.Join(runtime, ".runnerhome-file"), []byte("synthetic_transient"), 0600)
	putFile(t, filepath.Join(runtime, "ordinary"), []byte("keep_ordinary"), 0600)
	canonicalTemp(t, filepath.Join(runtime, ".runnerhome-directory"))
	if err := os.Symlink("ordinary", filepath.Join(runtime, ".runnerhome-link")); err != nil {
		t.Fatal(err)
	}
	report, err := f.slot.Revoke()
	if _, statErr := os.Lstat(filepath.Join(f.home.path, ".codex/auth.json")); !os.IsNotExist(statErr) {
		t.Fatal("native auth name remains after revocation")
	}
	if err != nil {
		t.Fatal(err)
	}
	if !report.AuthRemoved || report.RotateLogin || len(report.Observations) < 3 {
		t.Fatal("revocation omitted its observations or did not finish")
	}
	for _, name := range []string{".codex/auth.json", ".runnerhome-runtime/.runnerhome-file"} {
		if _, err := os.Lstat(filepath.Join(f.home.path, name)); !os.IsNotExist(err) {
			t.Fatal("known credential file remained")
		}
	}
	for _, name := range []string{"ordinary", ".runnerhome-directory", ".runnerhome-link"} {
		if _, err := os.Lstat(filepath.Join(runtime, name)); err != nil {
			t.Fatal("nonregular or unrelated entry was removed", err)
		}
	}
}

// H3: prove the harmless synthetic copy exists, then require native removal,
// a retained refresh lease and a persistent rotation flag for a hardlinked auth.
func TestRevokeCopiedAuthNeedsRotation(t *testing.T) {
	f := newFixture(t)
	copyPath := filepath.Join(canonicalTemp(t), "copied-auth")
	authPath := filepath.Join(f.home.path, ".codex/auth.json")
	if err := os.Link(authPath, copyPath); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(getFile(t, authPath), getFile(t, copyPath)) {
		t.Fatal("hardlink canary did not copy synthetic auth")
	}
	t.Cleanup(func() {
		if !f.slot.closed {
			closeFixtureHandles(t, f.slot)
		}
	})
	report, err := f.slot.Revoke()
	if err != nil {
		t.Fatal(err)
	}
	if !report.AuthRemoved || !report.RotateLogin {
		t.Fatal("copied auth was not removed and marked for rotation")
	}
	if _, err := os.Lstat(authPath); !os.IsNotExist(err) {
		t.Fatal("native hardlinked auth name remains")
	}
	claim, err := f.slot.locks.acquire("login", "login_one")
	if err == nil {
		claim.close()
		t.Fatal("copied login's refresh lease was released")
	}
	wantCode(t, err, api.CodeConflict)
	wantCode(t, f.slot.Close(), api.CodeIntegrity)
	opened, err := Open(f.home.path, f.home.records)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if !opened.record.Slot.Rotate {
		t.Fatal("rotation obligation disappeared on reopen")
	}
}

// H4: the real root is closed, then a reported close error is injected. The home
// lease must still be released so a fresh controller can acquire the same inode.
func TestCloseFinishesAfterRootError(t *testing.T) {
	f := newFixture(t)
	f.slot.closeRoot = func() error {
		if err := f.slot.root.Close(); err != nil {
			return err
		}
		return fs.ErrClosed
	}
	wantCode(t, f.slot.Close(), api.CodeUnavailable)
	if !f.slot.closed {
		t.Fatal("slot cleanup stopped at the root-close error")
	}
	next, err := NewSlot(f.home, f.slot.locks)
	if err != nil {
		t.Fatal("home claim leaked after root close failure", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

// H6: this test is portable (no Linux-only build tag). Closing only the slot's
// root induces a real post-lease publication failure, retaining BOTH logins.
func TestPartialSwapRetainsBothLeases(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.root.Close(); err != nil {
		t.Fatal(err)
	}
	reference := f.request.Slot
	reference.ID = "slot_next"
	reference.ProfileID = "profile_next"
	err := f.slot.Install(f.request.Target, reference, credentialFor(t, reference.ProfileID, "login_two"))
	if err == nil {
		t.Fatal("closed root falsely published a credential")
	}
	if !f.home.record.Slot.Poisoned || f.home.record.Slot.Ready {
		t.Fatal("partial publication left the slot usable")
	}
	for _, login := range []string{"login_one", "login_two"} {
		claim, err := f.slot.locks.acquire("login", login)
		if err == nil {
			claim.close()
			t.Fatal("partial swap released a login lease")
		}
		wantCode(t, err, api.CodeConflict)
	}
	root, err := os.OpenRoot(f.home.path)
	if err != nil {
		t.Fatal(err)
	}
	f.slot.root = root
	f.slot.closeRoot = root.Close
	if _, err := f.slot.Revoke(); err != nil {
		t.Fatal("recovered removal did not release retained material", err)
	}
}

// C1/H2: an inactive empty binding survives worker reconstruction and can bind
// from outside capture. A lane-side forgery and a conflicting replay cannot win.
func TestBindAfterInactiveRestart(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	// The real plan/recovery tuple predates loss of the credential worker.
	f.sealCapture()
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.Close(); err != nil {
		t.Fatal(err)
	}
	putFile(t, filepath.Join(f.home.path, ".runnerhome-conversation.json"), []byte("forged_vendor_binding"), 0600)
	opened, err := Open(f.home.path, f.home.records)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	next, err := NewSlot(opened, f.slot.locks)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	}()
	line := []byte(`{"type":"thread.started","thread_id":"` + testVendorID + `"}`)
	record := f.capture(line, 0)
	if err := next.BindCodexSession(context.Background(), f.service, record); err != nil {
		t.Fatal("inactive recovered binding could not complete", err)
	}
	if err := next.BindCodexSession(context.Background(), f.service, record); err != nil {
		t.Fatal("identical replay refused", err)
	}
	bad := record
	bad.ID = "not_captured"
	wantCode(t, next.BindCodexSession(context.Background(), f.service, bad), api.CodeIntegrity)
	request := f.request
	request.Target.Run = 2
	request.Slot.ID = "slot_next"
	request.Session.VendorID = testVendorID
	if err := next.Install(request.Target, request.Slot, credentialFor(t, request.Slot.ProfileID, "login_one")); err != nil {
		t.Fatal(err)
	}
	if err := next.Reserve(request); err != nil {
		t.Fatal("recovered explicit continuation failed", err)
	}
	if err := next.Quiesce(observation(request.Target, 0)); err != nil {
		t.Fatal(err)
	}
}

// Reopening a valid protected record preserves history; changing only its
// session history must fail rather than adopting a new history on restart.
func TestReopenHistoryBinding(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	if err := f.slot.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(f.home.path, f.home.records)
	if err != nil {
		t.Fatal("unchanged protected history control failed", err)
	}
	if opened.record.Session != f.request.Session {
		t.Fatal("reopening changed the protected session")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	f.home.record.Session.HistoryID = "another_history"
	if err := f.home.save(); err != nil {
		t.Fatal(err)
	}
	opened, err = Open(f.home.path, f.home.records)
	if opened != nil {
		if closeErr := opened.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	wantCode(t, err, api.CodeIntegrity)
}

// Recovery may release a kernel flock without stopping a process. Persisted
// active state must still prevent another install until outside observation.
func TestRestartRetainsActiveState(t *testing.T) {
	f := newFixture(t)
	if err := f.slot.Reserve(f.request); err != nil {
		t.Fatal(err)
	}
	closeFixtureHandles(t, f.slot)
	opened, err := Open(f.home.path, f.home.records)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	next, err := NewSlot(opened, f.slot.locks)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, next.Install(f.request.Target, f.request.Slot, credentialFor(t, f.request.Slot.ProfileID, "login_one")), api.CodeConflict)
	if err := next.Quiesce(observation(f.request.Target, 0)); err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

// H6: synthetic values are constructed at runtime; formatting/JSON never expose
// them, exact credential bytes survive handoff, and incomplete writes fail.
func TestCredentialBytesAndRedaction(t *testing.T) {
	input := syntheticAuth(t, "hand_off")
	original := append([]byte{}, input...)
	credential, err := NewCredential("profile_one", "login_one", hashBytes([]byte("synthetic_account_hand_off")), input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = 'x'
	var output bytes.Buffer
	n, err := credential.WriteTo(&output)
	if err != nil || n != int64(len(original)) || !bytes.Equal(output.Bytes(), original) {
		t.Fatal("credential bytes were aliased or changed", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		text := fmt.Sprintf(format, credential)
		if bytes.Contains([]byte(text), []byte("hand_off")) {
			t.Fatal("credential formatting exposed payload")
		}
	}
	encoded, err := json.Marshal(credential)
	if err != nil || bytes.Contains(encoded, []byte("hand_off")) {
		t.Fatal("credential JSON exposed payload", err)
	}
	if _, err := credential.WriteTo(shortWriter{}); err == nil {
		t.Fatal("short credential handoff accepted")
	}
	for _, bad := range [][]byte{[]byte(`{"tokens":null}`), []byte(`{"tokens":{},"tokens":{}}`), []byte(`{"auth_mode":"api"}`)} {
		if _, err := NewCredential("profile_one", "login_one", hashBytes([]byte("synthetic_account_hand_off")), bad); err == nil {
			t.Fatal("invalid or paid credential fallback accepted")
		}
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }

// A schema-valid sibling auth document cannot replace the selected projection
// before a run. Restoring the exact leased bytes must restore the valid control.
func TestBorrowedAuthProjection(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.home.path, ".codex/auth.json")
	original := getFile(t, path)
	putFile(t, path, syntheticAuth(t, "sibling"), 0600)
	wantCode(t, f.slot.Matches(f.request.Target, f.request.Home, f.request.Slot), api.CodeIntegrity)
	wantCode(t, f.slot.Reserve(f.request), api.CodeIntegrity)
	putFile(t, path, original, 0600)
	if err := f.slot.Matches(f.request.Target, f.request.Home, f.request.Slot); err != nil {
		t.Fatal("restored native projection refused", err)
	}
}
