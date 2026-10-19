package claudock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func testSlot(t *testing.T, home *Home) *Slot {
	t.Helper()
	s, err := NewSlot(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func testCredential(t *testing.T, profile, login string) Credential {
	t.Helper()
	// Synthetic bytes are built at runtime; no secret-assignment fixture or
	// token-shaped string literal belongs in the published source.
	token := []byte(strings.Join([]string{"synthetic", profile, login}, "_"))
	c, err := NewCredential(profile, login, token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func fixtureExit(target api.LifeRef) api.ProcessObservation {
	code, survivors := 0, uint64(0)
	return api.ProcessObservation{Handle: api.ProcessHandle{ID: "process-a", Target: target,
		ContainmentID: "containment-a", Generation: "generation-a"}, State: "exited",
		ExitCode: &code, Survivors: &survivors, PromptStatus: "completed", ObservedAt: "2026-10-15T12:00:02Z"}
}

// H6/port: fails on changed input bytes, caller-buffer aliasing, broad token
// documents or accidental value exposure in formatting/JSON. Short writes fail.
func TestCredentialBytesAndRedaction(t *testing.T) {
	input := []byte(strings.Join([]string{"synthetic", t.Name()}, "_"))
	credential, err := NewCredential("profile", "login", input)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(input)
	input[0] = 'x'
	var output bytes.Buffer
	if n, err := credential.WriteTo(&output); err != nil || n != int64(len(want)) || !bytes.Equal(want, output.Bytes()) {
		t.Fatal("credential input bytes were lost", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(format, credential), string(want)) {
			t.Fatal("credential formatting leaked bytes")
		}
	}
	encoded, err := json.Marshal(credential)
	if err != nil || bytes.Contains(encoded, want) {
		t.Fatal("credential JSON leaked bytes", err)
	}
	for _, invalid := range [][]byte{nil, []byte("two words"), {0xff}, []byte("line\nbreak")} {
		if _, err := NewCredential("profile", "login", invalid); err == nil {
			t.Fatal("invalid token bytes were accepted")
		}
	}
	if _, err := credential.WriteTo(shortWriter{}); err == nil {
		t.Fatal("partial credential handoff passed")
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }

// Port: one canonical login cannot refresh in two homes, even through different
// profile labels. Swap changes the token, preserving all history bytes.
func TestSlotOwnershipAndSwap(t *testing.T) {
	r := testRecords(t)
	a, b := testSlot(t, testHome(t, r)), testSlot(t, testHome(t, r))
	first := testCredential(t, "first", "login-a")
	if err := a.Install(first); err != nil {
		t.Fatal(err)
	}
	alias := testCredential(t, "alias", "login-a")
	if err := b.Install(alias); !errors.Is(err, ErrBusy) {
		t.Fatal("alias acquired a concurrent login", err)
	}
	history := filepath.Join(a.home.path, ".claude/history.jsonl")
	put(t, history, []byte(t.Name()))
	target := api.LifeRef{LifeID: "life-a", Run: 1}
	if err := a.Reserve(target); err != nil {
		t.Fatal(err)
	}
	if err := a.Install(testCredential(t, "second", "login-b")); !errors.Is(err, ErrActive) {
		t.Fatal("active slot changed login")
	}
	unknown := fixtureExit(target)
	unknown.Survivors = nil
	if err := a.Quiesce(unknown); !errors.Is(err, ErrActive) {
		t.Fatal("unknown survivors released the active run")
	}
	if _, err := a.Revoke(); !errors.Is(err, ErrActive) {
		t.Fatal("active slot was revoked")
	}
	if err := a.Quiesce(fixtureExit(target)); err != nil {
		t.Fatal(err)
	}
	second := testCredential(t, "second", "login-b")
	if err := a.Install(second); err != nil {
		t.Fatal(err)
	}
	actual, err := a.Token()
	if err != nil || !bytes.Equal(actual.token, second.token) {
		t.Fatal("slot token did not change exactly", err)
	}
	if !bytes.Equal(get(t, history), []byte(t.Name())) {
		t.Fatal("swap changed history")
	}
	if err := b.Install(alias); err != nil {
		t.Fatal("successful swap retained the old lease", err)
	}
}

// H6: deliberately platform-independent. A publication-phase close of the real
// directory handle fails AFTER the token write; both login leases must stay.
func TestPartialSwapKeepsBothLeases(t *testing.T) {
	r := testRecords(t)
	a, b := testSlot(t, testHome(t, r)), testSlot(t, testHome(t, r))
	if err := a.Install(testCredential(t, "old", "old-login")); err != nil {
		t.Fatal(err)
	}
	a.project = func(record *homeRecord) error {
		if err := a.registry.Close(); err != nil {
			return err
		}
		return a.publishProjection(record)
	}
	newCredential := testCredential(t, "new", "new-login")
	if err := a.Install(newCredential); err == nil {
		t.Fatal("partial swap passed")
	}
	if !bytes.Equal(get(t, filepath.Join(a.home.path, ".runnerhome-runtime/.runnerhome-token")), newCredential.token) {
		t.Fatal("publication failure was not reached after the token write")
	}
	for _, login := range []string{"old-login", "new-login"} {
		if err := b.Install(testCredential(t, "alias", login)); !errors.Is(err, ErrBusy) {
			t.Fatal("partial swap released a login", err)
		}
	}
	if _, err := a.Token(); err == nil {
		t.Fatal("poisoned slot exported a token")
	}
	var err error
	a.registry, err = a.root.OpenRoot(".config/claudock")
	if err != nil {
		t.Fatal(err)
	}
	a.closers[1] = a.registry
	if _, err := a.Revoke(); err != nil {
		t.Fatal(err)
	}
	if err := b.Install(testCredential(t, "recovered", "new-login")); err != nil {
		t.Fatal("recovered revocation retained the login", err)
	}
}

// H3: junk and nonregular .runnerhome-* entries are reported after credentials
// disappear. Only regular prefixed files are collected; arbitrary data remains.
func TestRevokeDespiteRuntimeJunk(t *testing.T) {
	r := testRecords(t)
	s := testSlot(t, testHome(t, r))
	if err := s.Install(testCredential(t, "selected", "login")); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(s.home.path, ".claude/.credentials.json"), []byte("synthetic_auth"))
	directory := filepath.Join(s.home.path, ".runnerhome-runtime")
	put(t, filepath.Join(directory, "ordinary"), []byte("ordinary_data"))
	put(t, filepath.Join(directory, ".runnerhome-staging"), []byte("synthetic_staging"))
	if err := os.Mkdir(filepath.Join(directory, ".runnerhome-directory"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(directory, ".runnerhome-link")); err != nil {
		t.Fatal(err)
	}
	report, err := s.Revoke()
	if err != nil || len(report.Findings) != 3 {
		t.Fatal("unexpected runtime state blocked revocation or was lost", err)
	}
	for _, name := range []string{".claude/.credentials.json", ".config/claudock/profiles.json",
		".config/claudock/credential-store.json", ".runnerhome-runtime/.runnerhome-token", ".runnerhome-runtime/.runnerhome-staging"} {
		if _, err := os.Lstat(filepath.Join(s.home.path, name)); !os.IsNotExist(err) {
			t.Fatal("known credential/staging name survived revocation")
		}
	}
	if !bytes.Equal(get(t, filepath.Join(directory, "ordinary")), []byte("ordinary_data")) {
		t.Fatal("revocation removed ordinary data")
	}
	other := testSlot(t, testHome(t, r))
	if err := other.Install(testCredential(t, "alias", "login")); err != nil {
		t.Fatal("junk retained an otherwise safe login lease", err)
	}
}

// H3: the hardlink canary proves that removing our name cannot retract a copy.
// Revoke must still remove it, persist rotation, and block alias reuse.
func TestCopiedCredentialNeedsRotation(t *testing.T) {
	for _, name := range []string{".claude/.credentials.json", ".runnerhome-runtime/.runnerhome-token"} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			r := testRecords(t)
			s := testSlot(t, testHome(t, r))
			credential := testCredential(t, "selected", "canonical-login")
			if err := s.Install(credential); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.home.path, name)
			if name == ".claude/.credentials.json" {
				put(t, path, credential.token)
			}
			copyPath := filepath.Join(temporary(t), "copy")
			if err := os.Link(path, copyPath); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(get(t, copyPath), credential.token) {
				t.Fatal("hardlink canary did not copy the selected bytes")
			}
			report, err := s.Revoke()
			if err != nil || !reflect.DeepEqual(report.RotateLogins, []string{"canonical-login"}) {
				t.Fatal("copied credential was not marked for rotation", err)
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("copied credential's original name survived")
			}
			if !bytes.Equal(get(t, copyPath), credential.token) {
				t.Fatal("revocation falsely implied a copied credential was retracted")
			}
			other := testSlot(t, testHome(t, r))
			var typed *api.Error
			if err := other.Install(testCredential(t, "alias", "canonical-login")); !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
				t.Fatal("copied login could be reused without rotation", err)
			}
		})
	}
}

// H3/H4: moving the native container must not hide its original credential from
// the retained descriptor. The replacement copy is also removed and reported.
func TestRevokeMovedContainer(t *testing.T) {
	s := testSlot(t, testHome(t, testRecords(t)))
	if err := s.Install(testCredential(t, "selected", "login")); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(s.home.path, ".claude")
	moved := old + "-moved"
	put(t, filepath.Join(old, ".credentials.json"), []byte("synthetic_old"))
	if err := os.Rename(old, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(old, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(old, ".credentials.json"), []byte("synthetic_new"))
	report, err := s.Revoke()
	if err != nil || len(report.RotateLogins) != 1 {
		t.Fatal("moved container was not collected and marked", err)
	}
	for _, directory := range []string{old, moved} {
		if _, err := os.Lstat(filepath.Join(directory, ".credentials.json")); !os.IsNotExist(err) {
			t.Fatal("renamed credential survived revocation")
		}
	}
}

// H4: a close-result fault must not retain the home lease. Go 1.26's os.Root
// deliberately hides close errno, so this is an explicit unit fault after
// closing a real root, not a claimed observed kernel failure.
func TestCloseFinishesAfterRootError(t *testing.T) {
	r := testRecords(t)
	s := testSlot(t, testHome(t, r))
	if err := s.Install(testCredential(t, "selected", "login")); err != nil {
		t.Fatal(err)
	}
	s.closers[3] = closeFault{Closer: s.root}
	if _, err := s.Close(); err == nil || !s.closed {
		t.Fatal("root close failure was swallowed or cleanup did not finish")
	}
	claim, err := acquire(r.root, "home/"+s.home.key)
	if err != nil {
		t.Fatal("failed root close retained the home lease", err)
	}
	if err := claim.close(); err != nil {
		t.Fatal(err)
	}
}

type closeFault struct{ io.Closer }

func (c closeFault) Close() error {
	if err := c.Closer.Close(); err != nil {
		return err
	}
	return errors.New("injected close result")
}
