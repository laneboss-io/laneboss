package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type slotRecord struct {
	AuthSHA256    api.Digest         `json:"auth_sha256"`
	AccountSHA256 api.Digest         `json:"account_sha256"`
	LastQuiesced  api.LifeRef        `json:"last_quiesced"`
	Target        api.LifeRef        `json:"target"`
	Slot          api.CredentialSlot `json:"slot"`
	Login         api.ID             `json:"login"`
	Logins        []api.ID           `json:"logins"`
	Active        bool               `json:"active"`
	Ready         bool               `json:"ready"`
	Poisoned      bool               `json:"poisoned"`
	Rotate        bool               `json:"rotate"`
}

// Slot holds the canonical-login refresh lease in the outside credential worker.
// Nothing here authenticates a user, swaps a paid provider, or launches a process.
// All methods use the Home lock; several handles cannot race its protected state.
type Slot struct {
	mu        sync.Mutex
	home      *Home
	root      *os.Root
	locks     *Leases
	homeLease *lease
	logins    map[api.ID]*lease
	closed    bool
	closeRoot func() error
}

func (s *Slot) Format(state fmt.State, verb rune) {
	io.WriteString(state, "codex-slot(values withheld)")
}
func (s *Slot) MarshalJSON() ([]byte, error) {
	return []byte(`{"credential_slot":"values withheld"}`), nil
}

func NewSlot(home *Home, locks *Leases) (*Slot, error) {
	if home == nil || locks == nil || within(home.path, locks.path) || within(locks.path, home.path) {
		return nil, problem(api.CodeIntegrity, "Codex lease directory must be separate from its home")
	}
	home.mu.Lock()
	defer home.mu.Unlock()
	if _, err := home.audit(); err != nil {
		return nil, err
	}
	claim, err := locks.acquire("home", home.key)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(home.path)
	if err != nil {
		closeErr := claim.close()
		return nil, errors.Join(problem(api.CodeUnavailable, "Codex credential home cannot be opened"), closeErr)
	}
	if err := sameRoot(home.path, root); err != nil {
		return nil, errors.Join(err, closeResult(root.Close()), claim.close())
	}
	if err := home.reload(); err != nil {
		return nil, errors.Join(err, closeResult(root.Close()), claim.close())
	}
	s := &Slot{home: home, root: root, locks: locks, homeLease: claim, logins: map[api.ID]*lease{}, closeRoot: root.Close}
	for _, login := range home.record.Slot.Logins {
		if !id(login) || s.logins[login] != nil {
			return nil, s.closeOnOpenFailure(problem(api.CodeIntegrity, "Codex retained login record is invalid"))
		}
		lock, err := locks.acquire("login", string(login))
		if err != nil {
			return nil, s.closeOnOpenFailure(err)
		}
		s.logins[login] = lock
	}
	// Persisted Active/Poisoned are deliberately preserved on recovery. Flock
	// release after a worker crash says nothing about a surviving vendor process.
	return s, nil
}

func (s *Slot) closeOnOpenFailure(cause error) error {
	errs := []error{cause, closeResult(s.closeRoot()), s.homeLease.close()}
	for _, lock := range s.logins {
		errs = append(errs, lock.close())
	}
	return errors.Join(errs...)
}

// Install acquires the new login before publication and holds the old login on
// every partial failure. Only a validated, delegated worker supplies credentials.
func (s *Slot) Install(target api.LifeRef, slot api.CredentialSlot, credential Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	state := &s.home.record.Slot
	if s.closed || state.Active || state.Rotate || state.Poisoned {
		return problem(api.CodeConflict, "Codex slot is active, incomplete or pending login rotation")
	}
	if !id(target.LifeID) || target.Run == 0 || !id(slot.ID) || !id(slot.ProfileGrantID) || !id(slot.ProfileID) || !id(slot.LeaseID) || slot.Mode != "codex-file" || slot.ProfileID != credential.profile || !id(credential.login) {
		return problem(api.CodeForbidden, "Codex credential and run slot identities do not match")
	}
	if _, err := NewCredential(credential.profile, credential.login, credential.account, credential.payload); err != nil {
		return err
	}
	if _, err := s.home.audit(); err != nil {
		return err
	}
	if s.logins[credential.login] == nil {
		claim, err := s.locks.acquire("login", string(credential.login))
		if err != nil {
			return err
		}
		s.logins[credential.login] = claim
		state.Logins = append(state.Logins, credential.login)
	}
	state.Ready = false
	state.Poisoned = true
	if err := s.home.save(); err != nil {
		return wrap("reserve Codex credential publication", err)
	}
	if err := writePrivate(s.root, ".codex/auth.json", ".runnerhome-runtime", credential.payload, 0600); err != nil {
		return wrap("install Codex native auth slot", err)
	}
	state.Target = target
	state.Slot = slot
	state.Login = credential.login
	state.AccountSHA256 = credential.account
	hash := sha256.Sum256(credential.payload)
	state.AuthSHA256 = api.Digest(hex.EncodeToString(hash[:]))
	state.Ready = true
	state.Poisoned = false
	// Keep every acquired login in the crash record until the corresponding
	// kernel lease has actually closed. A failed close prevents future prepares.
	if err := s.home.save(); err != nil {
		state.Ready = false
		state.Poisoned = true
		return err
	}
	for login, claim := range s.logins {
		if login == credential.login {
			continue
		}
		if err := claim.close(); err != nil {
			state.Ready = false
			state.Poisoned = true
			return err
		}
		delete(s.logins, login)
		state.Logins = slices.DeleteFunc(state.Logins, func(value api.ID) bool { return value == login })
	}
	return s.home.save()
}

// Reserve seals the logical conversation in protected records before launch.
// A failed launcher must reconcile this reservation, never start a new thread.
// Project configuration is checked separately against physical materialization
// by CheckProjectConfig in the service's plan/pre-release path.
func (s *Slot) Reserve(request api.RunnerRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	state := &s.home.record.Slot
	if s.closed || state.Active || !state.Ready || state.Poisoned || state.Rotate {
		return problem(api.CodeConflict, "Codex credential slot cannot reserve another active or incomplete run")
	}
	if err := validateRequest(request); err != nil {
		return err
	}
	if state.Target != request.Target || state.Slot != request.Slot || request.Home != s.home.record.Home {
		return problem(api.CodeIntegrity, "Codex reservation differs from the selected home and run slot")
	}
	if _, err := s.home.audit(); err != nil {
		return err
	}
	auth, err := readPrivate(s.root, ".codex/auth.json", maxAuthBytes)
	if err != nil {
		return err
	}
	if err := validateAuth(auth); err != nil {
		return err
	}
	if hash := sha256.Sum256(auth); api.Digest(hex.EncodeToString(hash[:])) != state.AuthSHA256 {
		return problem(api.CodeIntegrity, "Codex native auth projection changed before reservation")
	}
	prior := s.home.record.Session
	if prior.ID == "" {
		if request.Target.Run != 1 || request.Session.VendorID != "" {
			return problem(api.CodeIntegrity, "Codex initial reservation cannot invent a vendor session")
		}
		s.home.record.Session = request.Session
		s.home.record.Model = request.Model
	} else if prior != request.Session || request.Model != s.home.record.Model {
		return problem(api.CodeIntegrity, "Codex continuation must preserve the captured session, model and cwd")
	} else if prior.VendorID == "" && request.Target.Run > 1 && (state.LastQuiesced.LifeID != request.Target.LifeID ||
		state.LastQuiesced.Run+1 != request.Target.Run) {
		return problem(api.CodeContainmentUnknown, "Codex unmapped startup retry needs the preceding quiescent run")
	}
	state.Active = true
	if err := s.home.save(); err != nil {
		state.Poisoned = true
		return err
	}
	return nil
}

// BindCodexSession verifies the original primary record through the configured
// outside capture reader. Raw vendor/home bytes are never binding authority.
// An inactive recovered reservation can still consume that verified capture.
func (s *Slot) BindCodexSession(ctx context.Context, runner *Service, record api.CaptureRecord) error {
	if runner == nil {
		return problem(api.CodePrerequisite, "Codex session binding needs the outside capture reader")
	}
	session, err := runner.SessionFromCapture(ctx, record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	if s.closed || s.home.record.Session.ID == "" {
		return problem(api.CodeConflict, "Codex has no reserved logical session to bind")
	}
	prior := s.home.record.Session
	claim := session
	claim.VendorID = prior.VendorID
	if claim != prior || record.Target != s.home.record.Slot.Target ||
		(prior.VendorID != "" && prior.VendorID != session.VendorID) {
		return problem(api.CodeIntegrity, "Codex outside capture differs from its protected session binding")
	}
	s.home.record.Session = session
	if err := s.home.save(); err != nil {
		s.home.record.Session = prior
		s.home.record.Slot.Poisoned = true
		return err
	}
	return nil
}

// Quiesce requires the exact outside run observation. Credentials and leases
// remain in place until the worker validates and persists only the refresh data.
func (s *Slot) Quiesce(observation api.ProcessObservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	if s.closed {
		return problem(api.CodeConflict, "Codex credential slot is closed")
	}
	if !quiescent(observation, s.home.record.Slot.Target) {
		return problem(api.CodeContainmentUnknown, "Codex credential operation requires observed exit and zero survivors")
	}
	state := &s.home.record.Slot
	priorActive, priorQuiesced := state.Active, state.LastQuiesced
	state.Active = false
	state.LastQuiesced = observation.Handle.Target
	if err := s.home.save(); err != nil {
		state.Active, state.LastQuiesced = priorActive, priorQuiesced
		state.Poisoned = true
		return err
	}
	return nil
}

// Refreshed consumes the received helper-to-broker duplicate, never a lane
// pathname. The outside broker must authenticate/remeasure that native transfer
// and resolve record from its protected withdrawal journal before this call.
// It retains the canonical refresh lease through its own exact-source CAS and
// durable acknowledgement; this schema consumer neither persists nor releases it.
func (s *Slot) Refreshed(record api.CredentialProjectionRecord, refresh api.CredentialRefresh, now time.Time) (credential Credential, err error) {
	if refresh.File != nil {
		defer func() {
			if closeErr := refresh.File.Close(); closeErr != nil {
				credential = Credential{}
				err = errors.Join(err, problem(api.CodeUnavailable, "Codex refresh duplicate could not close"))
			}
		}()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	state := s.home.record.Slot
	if s.closed || state.Active || !state.Ready || state.Poisoned || state.Rotate {
		return Credential{}, problem(api.CodeConflict, "Codex refresh material is active or unavailable")
	}
	if err := api.ValidateCredentialRefresh(record, refresh, now); err != nil {
		return Credential{}, dependencyError(err)
	}
	r := record.Authority.Request
	if r.Home.Home != s.home.record.Home || r.Handoff.Spec.Runner.Slot != state.Slot || r.Prepared.Target != state.Target ||
		state.LastQuiesced != state.Target || s.logins[state.Login] == nil || s.logins[state.Login].file == nil {
		return Credential{}, problem(api.CodeIntegrity, "Codex refresh differs from its quiescent leased slot")
	}
	if err := sameRoot(s.locks.path, s.locks.root); err != nil {
		return Credential{}, err
	}
	data, err := readRefreshDescriptor(refresh.File)
	if err != nil {
		return Credential{}, err
	}
	if int64(len(data)) != refresh.Fact.Size {
		return Credential{}, problem(api.CodeIntegrity, "Codex refresh differs from its native measured size")
	}
	return NewCredential(state.Slot.ProfileID, state.Login, state.AccountSHA256, data)
}

type Revocation struct {
	AuthRemoved  bool
	RotateLogin  bool
	Observations []Observation
}

func (s *Slot) Revoke() (Revocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	return s.revoke()
}

func (s *Slot) revoke() (Revocation, error) {
	report := Revocation{Observations: []Observation{}}
	state := &s.home.record.Slot
	if state.Active {
		return report, problem(api.CodeContainmentUnknown, "Codex active run retains its credentials and leases")
	}
	if s.closed {
		report.AuthRemoved = true
		return report, nil
	}
	state.Ready = false
	if err := sameRoot(s.home.path, s.root); err != nil {
		state.Rotate = true
		report.Observations = append(report.Observations, Observation{Path: ".", Kind: "changed-home-root"})
	}
	// Remove the native credential BEFORE inspecting any ancillary runtime
	// entries. A hard link may have copied it: unlink our name, keep the lease
	// and persist the mandatory rotation flag. Do not follow a linked leaf.
	info, err := s.root.Lstat(".codex/auth.json")
	if err == nil {
		if !info.Mode().IsRegular() || linked(info) {
			state.Rotate = true
			report.Observations = append(report.Observations, Observation{Path: ".codex/auth.json", Kind: "rotation-required"})
		}
		if err := ownedAncestors(s.root, ".codex/auth.json"); err != nil {
			state.Rotate = true
			report.Observations = append(report.Observations, Observation{Path: ".codex", Kind: "changed-auth-container"})
		}
		if err := s.root.Remove(".codex/auth.json"); err != nil {
			state.Rotate = true
			report.RotateLogin = true
			persistErr := s.home.save()
			return report, errors.Join(problem(api.CodeIntegrity, "Codex auth removal is incomplete; rotate the login and retain leases"), persistErr)
		}
	} else if !os.IsNotExist(err) {
		state.Rotate = true
		report.RotateLogin = true
		return report, errors.Join(problem(api.CodeIntegrity, "Codex auth slot cannot be inspected for removal; rotate the login"), s.home.save())
	}
	report.AuthRemoved = true
	// Unknown/special runtime entries never prevent the auth removal above.
	// Only regular files with our exact prefix are removed; everything else is
	// retained and reported, including directories and symlinks.
	var cleanupErr error
	if container, err := s.root.Lstat(".runnerhome-runtime"); err == nil && container.IsDir() {
		directory, err := s.root.Open(".runnerhome-runtime")
		if err == nil {
			entries, readErr := directory.ReadDir(-1)
			closeErr := directory.Close()
			if readErr != nil || closeErr != nil {
				cleanupErr = problem(api.CodeUnavailable, "Codex runtime cleanup could not enumerate every entry")
			}
			for _, entry := range entries {
				name := filepath.Join(".runnerhome-runtime", entry.Name())
				info, statErr := s.root.Lstat(name)
				if statErr != nil || !info.Mode().IsRegular() || !strings.HasPrefix(entry.Name(), ".runnerhome-") {
					report.Observations = append(report.Observations, Observation{Path: name, Kind: "retained-runtime-entry"})
					continue
				}
				if linked(info) {
					state.Rotate = true
					report.Observations = append(report.Observations, Observation{Path: name, Kind: "rotation-required"})
				}
				if err := s.root.Remove(name); err != nil {
					cleanupErr = problem(api.CodeUnavailable, "Codex transient credential removal is incomplete")
				}
			}
		} else {
			cleanupErr = problem(api.CodeUnavailable, "Codex runtime cleanup directory cannot be opened")
		}
	} else {
		report.Observations = append(report.Observations, Observation{Path: ".runnerhome-runtime", Kind: "unavailable-runtime-directory"})
		if err != nil && !os.IsNotExist(err) {
			cleanupErr = problem(api.CodeUnavailable, "Codex runtime cleanup directory cannot be inspected")
		}
	}
	report.RotateLogin = state.Rotate
	state.Poisoned = cleanupErr != nil
	if err := s.home.save(); err != nil {
		return report, errors.Join(cleanupErr, err)
	}
	if cleanupErr != nil {
		return report, cleanupErr
	}
	if state.Rotate {
		return report, nil
	} // Explicit rotation report; leases stay held.
	for login, claim := range s.logins {
		if err := claim.close(); err != nil {
			state.Poisoned = true
			return report, err
		}
		delete(s.logins, login)
	}
	state.Login = ""
	state.Slot = api.CredentialSlot{}
	state.Logins = []api.ID{}
	state.AuthSHA256 = ""
	state.AccountSHA256 = ""
	if err := s.home.save(); err != nil {
		state.Poisoned = true
		return report, err
	}
	return report, nil
}

// Close finishes lease cleanup even if the root handle's close reports failure.
// Unknown containment, failed removal and required rotation intentionally retain
// ownership; the outside worker must repair/revoke the login first.
func (s *Slot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	if s.closed {
		return nil
	}
	report, err := s.revoke()
	if err != nil {
		return err
	}
	if report.RotateLogin {
		return problem(api.CodeIntegrity, "Codex login rotation is required before releasing its lease")
	}
	errs := []error{closeResult(s.closeRoot())}
	for login, claim := range s.logins {
		errs = append(errs, claim.close())
		delete(s.logins, login)
	}
	errs = append(errs, s.homeLease.close())
	s.closed = true
	return errors.Join(errs...)
}

// Matches is a worker-local identity check for the service's VerifySlot seam.
// The worker must also validate delegation/expiry, its issued lease ID and the
// actual mount/projection; this helper does not manufacture those attestations.
func (s *Slot) Matches(target api.LifeRef, home api.PrivateHome, slot api.CredentialSlot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home.mu.Lock()
	defer s.home.mu.Unlock()
	state := s.home.record.Slot
	if s.closed || !state.Ready || state.Poisoned || state.Rotate || state.Target != target || state.Slot != slot || s.home.record.Home != home || s.logins[state.Login] == nil {
		return problem(api.CodeForbidden, "Codex native auth projection is not leased to this run and home")
	}
	if err := s.home.records.check(); err != nil {
		return err
	}
	if err := sameRoot(s.locks.path, s.locks.root); err != nil {
		return err
	}
	if err := sameRoot(s.home.path, s.root); err != nil {
		return err
	}
	auth, err := readPrivate(s.root, ".codex/auth.json", maxAuthBytes)
	if err != nil {
		return err
	}
	account, err := authAccount(auth)
	if err != nil {
		return err
	}
	if account != state.AccountSHA256 {
		return problem(api.CodeIntegrity, "Codex native auth account differs from its enrolled slot")
	}
	if hash := sha256.Sum256(auth); api.Digest(hex.EncodeToString(hash[:])) != state.AuthSHA256 {
		return problem(api.CodeIntegrity, "Codex native auth projection differs from the selected slot")
	}
	return nil
}
