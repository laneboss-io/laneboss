package claudock

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

// Slot owns one home's private projection and the canonical login refresh
// lease. Lifecycle must reconcile surviving processes before reconstructing it;
// a released kernel lock is not proof that a previous runner is dead.
type Slot struct {
	mu            sync.Mutex
	home          *Home
	root          *os.Root
	claude        *os.Root
	registry      *os.Root
	runtime       *os.Root
	closers       []io.Closer
	homeLease     *lease
	logins        map[string]*lease
	profile       string
	login         string
	ready         bool
	poisoned      bool
	rotatePending bool
	active        bool
	closed        bool
	target        api.LifeRef
	project       func(*homeRecord) error
	claimLogin    func(string) (*lease, error)
}

// ErrContainerChanged means a retained credential directory no longer matches
// its current private path. Revocation can still collect the retained object.
var ErrContainerChanged = errors.New("credential container identity changed")

type Revocation struct {
	Removed      []string  `json:"removed"`
	Findings     []Finding `json:"findings"`
	RotateLogins []string  `json:"rotate_login_handles"`
}

func (s *Slot) Format(state fmt.State, verb rune) {
	io.WriteString(state, "credential-slot(values withheld)")
}
func (s *Slot) MarshalJSON() ([]byte, error) { return []byte(`{"credential_slot":"withheld"}`), nil }

func NewSlot(home *Home) (*Slot, error) {
	if home == nil {
		return nil, failure(api.CodeInvalid, "private home is required")
	}
	if err := home.AuditOwned(); err != nil {
		return nil, err
	}
	r, err := home.open()
	if err != nil {
		return nil, err
	}
	claim, err := home.records.acquireLease("home/" + home.key)
	if err != nil {
		r.Close()
		return nil, err
	}
	s := &Slot{home: home, root: r, homeLease: claim, logins: map[string]*lease{}}
	s.claude, err = r.OpenRoot(".claude")
	if err == nil {
		s.registry, err = r.OpenRoot(".config/claudock")
	}
	if err == nil {
		s.runtime, err = r.OpenRoot(".runnerhome-runtime")
	}
	if err != nil {
		for _, root := range []*os.Root{s.claude, s.registry, s.runtime, r} {
			if root != nil {
				root.Close()
			}
		}
		claim.close()
		return nil, ownedError(ErrOwnedRead)
	}
	if err := s.audit(); err != nil {
		for _, root := range []*os.Root{s.claude, s.registry, s.runtime, r} {
			root.Close()
		}
		claim.close()
		return nil, err
	}
	s.project = s.publishProjection
	s.claimLogin = func(login string) (*lease, error) { return home.records.acquireLease("login/claudock-cli/" + login) }
	s.closers = []io.Closer{s.claude, s.registry, s.runtime, s.root}
	return s, nil
}

func (s *Slot) Install(credential Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return activeError()
	}
	if s.closed || s.poisoned {
		return failure(api.CodeConflict, "credential slot is closed or incomplete")
	}
	if _, err := NewCredential(credential.profile, credential.login, credential.token); err != nil {
		return err
	}
	if err := s.audit(); err != nil {
		return err
	}
	if err := s.home.verifyGenerated(); err != nil {
		return err
	}
	if err := s.home.records.rotationAbsent(credential.login); err != nil {
		return err
	}
	var newClaim *lease
	if s.logins[credential.login] == nil {
		if s.claimLogin == nil {
			return failure(api.CodePrerequisite, "canonical login lease provider is unavailable")
		}
		claim, err := s.claimLogin(credential.login)
		if err != nil {
			return err
		}
		newClaim = claim
	}
	// Recheck under the canonical login lock. Another worker may have marked
	// rotation between the first lookup and our acquisition of the old lease.
	if err := s.home.records.rotationAbsent(credential.login); err != nil {
		return errors.Join(err, newClaim.close())
	}
	if newClaim != nil {
		s.logins[credential.login] = newClaim
	}
	s.ready, s.poisoned = false, true
	if err := replacePrivate(s.runtime, ".", ".runnerhome-token", credential.token, 0600); err != nil {
		return err
	}
	// The private alias stays constant across a swap. Restore only the exact
	// protected registry generation, never a profile's global history/settings.
	if s.project == nil {
		return failure(api.CodePrerequisite, "private credential projection writer is unavailable")
	}
	if err := s.home.records.transaction(s.home.key, s.project, nil); err != nil {
		return err
	}
	for login, claim := range s.logins {
		if login != credential.login {
			if err := claim.close(); err != nil {
				return err
			}
			delete(s.logins, login)
		}
	}
	s.profile, s.login = credential.profile, credential.login
	s.ready, s.poisoned = true, false
	return nil
}

// Token is a trusted injection handoff before Reserve, never an environment
// snapshot. It does not produce argv or expose a general secret lookup.
func (s *Slot) Token() (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return Credential{}, activeError()
	}
	if !s.ready || s.closed || s.poisoned {
		return Credential{}, failure(api.CodeConflict, "credential slot is unavailable")
	}
	if err := s.audit(); err != nil {
		return Credential{}, err
	}
	data, err := readPrivate(s.runtime, ".runnerhome-token", 65536)
	if err != nil {
		return Credential{}, err
	}
	return NewCredential(s.profile, s.login, data)
}

func (s *Slot) Reserve(target api.LifeRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return activeError()
	}
	if s.closed || s.poisoned || !s.ready || !identifier(target.LifeID) || target.Run == 0 || uint64(target.Run) > 1<<53-1 {
		return failure(api.CodeConflict, "credential slot cannot reserve this run")
	}
	if err := s.audit(); err != nil {
		return err
	}
	if err := s.home.verifyGenerated(); err != nil {
		return err
	}
	s.active, s.target = true, target
	return nil
}

// The caller is the outside supervisor. A model/tool claim cannot call this
// internal utility. Unknown survivors retain all credential and home leases.
func (s *Slot) Quiesce(observation api.ProcessObservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return failure(api.CodeConflict, "credential slot is closed")
	}
	if !s.active || observation.Handle.Target != s.target || !terminalObservation(observation) {
		return activeError()
	}
	s.active = false
	return nil
}

// The controller holds these directory handles through a run and revocation.
// Checking only the names would permit a private replacement with copied bytes
// while writes/token reads still target the renamed predecessor.
func (s *Slot) audit() error {
	if err := s.home.auditRoot(s.root); err != nil {
		return err
	}
	for _, container := range []struct {
		name string
		root *os.Root
	}{
		{".claude", s.claude}, {".config/claudock", s.registry}, {".runnerhome-runtime", s.runtime},
	} {
		if container.root == nil || !sameContainer(s.root, container.name, container.root) {
			return ownedError(ErrContainerChanged)
		}
	}
	return nil
}

func (s *Slot) publishProjection(record *homeRecord) error {
	if err := replacePrivate(s.registry, ".", "profiles.json", record.Registry, 0400); err != nil {
		return err
	}
	return replacePrivate(s.registry, ".", "credential-store.json", []byte("{}\n"), 0600)
}

func rotationName(login string) string {
	return "rotate-" + string(contentDigest([]byte(login))) + ".json"
}

func (s *Slot) Revoke() (Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoke()
}

func (s *Slot) revoke() (Revocation, error) {
	report := Revocation{Removed: []string{}, Findings: []Finding{}, RotateLogins: []string{}}
	if s.active {
		return report, activeError()
	}
	if s.closed {
		return report, nil
	}
	s.ready, s.poisoned = false, true
	var failures []error
	rotate := s.rotatePending
	currentHome, pathErr := os.Lstat(s.home.path)
	anchoredHome, rootErr := s.root.Stat(".")
	if pathErr != nil || rootErr != nil || !currentHome.IsDir() || !os.SameFile(currentHome, anchoredHome) {
		report.Findings = append(report.Findings, Finding{Path: ".", Kind: "home-replaced-or-unavailable"})
		rotate = true
	}
	// Do this BEFORE enumerating runtime junk. Use retained directory handles
	// so a lane cannot hide the real slot by renaming its parent directory.
	for _, entry := range []struct {
		root         *os.Root
		parent, name string
	}{
		{s.claude, ".claude", ".credentials.json"},
		{s.registry, ".config/claudock", "profiles.json"},
		{s.registry, ".config/claudock", "credential-store.json"},
		{s.runtime, ".runnerhome-runtime", ".runnerhome-token"},
	} {
		changed := !sameContainer(s.root, entry.parent, entry.root)
		if changed {
			report.Findings = append(report.Findings, Finding{Path: entry.parent, Kind: "container-replaced"})
			rotate = true
		}
		copied, err := removeCredential(entry.root, entry.name, filepath.Join(entry.parent, entry.name), &report)
		rotate = rotate || copied
		if err != nil {
			failures = append(failures, err)
		}
		if changed {
			// Also collect a replacement ordinary private directory, without
			// following a substituted intermediate symlink.
			if err := ownedDirectory(s.root, entry.parent); err == nil {
				current, openErr := s.root.OpenRoot(entry.parent)
				if openErr == nil {
					copied, removeErr := removeCredential(current, entry.name, filepath.Join(entry.parent, entry.name), &report)
					rotate = rotate || copied
					if removeErr != nil {
						failures = append(failures, removeErr)
					}
					if err := current.Close(); err != nil {
						failures = append(failures, ownedError(ErrOwnedRead))
					}
				} else {
					failures = append(failures, ownedError(ErrOwnedRead))
				}
			}
		}
	}
	directory, err := s.runtime.Open(".")
	if err != nil {
		failures = append(failures, ownedError(ErrOwnedRead))
	} else {
		entries, readErr := directory.ReadDir(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			failures = append(failures, ownedError(ErrOwnedRead))
		}
		for _, entry := range entries {
			name := filepath.Join(".runnerhome-runtime", entry.Name())
			info, err := s.runtime.Lstat(entry.Name())
			if err != nil {
				failures = append(failures, ownedError(ErrOwnedRead))
				continue
			}
			if !strings.HasPrefix(entry.Name(), ".runnerhome-") || !info.Mode().IsRegular() {
				report.Findings = append(report.Findings, Finding{Path: name, Kind: "unexpected-runtime"})
				continue
			}
			copied, err := removeCredential(s.runtime, entry.Name(), name, &report)
			rotate = rotate || copied
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := s.home.records.check(); err != nil {
		failures = append(failures, err)
	}
	s.rotatePending = rotate || len(failures) != 0
	if s.rotatePending {
		for login := range s.logins {
			if err := s.home.records.markRotation(login); err != nil {
				failures = append(failures, err)
			}
			report.RotateLogins = append(report.RotateLogins, login)
		}
	}
	if len(failures) != 0 {
		return report, errors.Join(failures...)
	}
	for login, claim := range s.logins {
		if err := claim.close(); err != nil {
			failures = append(failures, err)
		}
		delete(s.logins, login)
	}
	s.login, s.profile, s.poisoned = "", "", false
	s.rotatePending = false
	return report, errors.Join(failures...)
}

func sameContainer(root *os.Root, name string, anchored *os.Root) bool {
	if err := ownedDirectory(root, name); err != nil {
		return false
	}
	current, err := root.Lstat(name)
	after, anchorErr := anchored.Stat(".")
	return err == nil && anchorErr == nil && os.SameFile(current, after)
}

func removeCredential(root *os.Root, name, logicalName string, report *Revocation) (bool, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return true, ownedError(ErrOwnedRead)
	}
	copied := !info.Mode().IsRegular() || linked(info)
	if copied {
		report.Findings = append(report.Findings, Finding{Path: logicalName, Kind: "credential-copy-or-type"})
	}
	if err := root.Remove(name); err != nil {
		return true, failure(api.CodeIntegrity, "credential removal incomplete; retain the login lease")
	}
	report.Removed = append(report.Removed, logicalName)
	return copied, nil
}

func (s *Slot) Close() (Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	report, err := s.revoke()
	if err != nil {
		return report, err
	}
	if s.closed {
		return report, nil
	}
	var failures []error
	for _, closer := range s.closers {
		if err := closer.Close(); err != nil {
			failures = append(failures, failure(api.CodeIntegrity, "credential root close failed"))
		}
	}
	// A root.Close error must not prevent the home lease from being released.
	if err := s.homeLease.close(); err != nil {
		failures = append(failures, err)
	}
	s.closed = true
	return report, errors.Join(failures...)
}
