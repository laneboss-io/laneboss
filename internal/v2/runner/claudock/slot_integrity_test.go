package claudock

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Fails if a private replacement directory can pass a path-only audit while
// Token/Install/Reserve still use the descriptor for its renamed predecessor.
// Identical copied bytes make the ordinary type/digest checks a positive control.
func TestSlotPinsCredentialContainers(t *testing.T) {
	for _, name := range []string{".claude", ".config/claudock", ".runnerhome-runtime"} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			records := testRecords(t)
			home := testHome(t, records)
			slot := testSlot(t, home)
			old := testCredential(t, "selected", "old-login")
			if err := slot.Install(old); err != nil {
				t.Fatal(err)
			}
			if _, err := slot.Token(); err != nil {
				t.Fatal("unchanged container control failed", err)
			}
			path := filepath.Join(home.path, name)
			moved := path + "-saved"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if name == ".claude" {
				for _, directory := range []string{"projects", "sessions", "plugins", "agents", "skills", "hooks", "cache", "debug", "todos", "session-env"} {
					if err := os.Mkdir(filepath.Join(path, directory), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			files := []string{"settings.json", "history.jsonl"}
			if name == ".config/claudock" {
				files = []string{"profiles.json", "credential-store.json"}
			}
			if name == ".runnerhome-runtime" {
				files = []string{".runnerhome-token"}
			}
			for _, file := range files {
				source := filepath.Join(moved, file)
				info, err := os.Stat(source)
				if err != nil {
					t.Fatal(err)
				}
				put(t, filepath.Join(path, file), get(t, source))
				if err := os.Chmod(filepath.Join(path, file), info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
			}
			if err := home.AuditOwned(); err != nil {
				t.Fatal("private replacement control failed owned audit", err)
			}
			if err := home.verifyGenerated(); err != nil {
				t.Fatal("identical replacement control failed digest check", err)
			}
			_, err := slot.Token()
			if !errors.Is(err, ErrContainerChanged) {
				t.Fatal("replaced container still exported a token", err)
			}
			next := testCredential(t, "next", "new-login")
			if err := slot.Install(next); !errors.Is(err, ErrContainerChanged) {
				t.Fatal("replaced container still accepted a swap", err)
			}
			if err := slot.Reserve(api.LifeRef{LifeID: "life-a", Run: 1}); !errors.Is(err, ErrContainerChanged) {
				t.Fatal("replaced container still reserved a run", err)
			}
			if !bytes.Equal(get(t, filepath.Join(home.path, ".runnerhome-runtime/.runnerhome-token")), old.token) {
				t.Fatal("refused swap changed the selected credential")
			}
			other := testSlot(t, testHome(t, records))
			if err := other.Install(next); err != nil {
				t.Fatal("refused swap leaked the new login lease", err)
			}
			report, err := slot.Revoke()
			if err != nil || len(report.RotateLogins) != 1 {
				t.Fatal("container tamper blocked credential cleanup/rotation", err)
			}
		})
	}
}

// Fails if a syntactically incomplete/conflicting observation releases an
// active slot. Revoke must remain blocked until a valid outside terminal record.
func TestQuiesceRejectsMalformedExit(t *testing.T) {
	slot := testSlot(t, testHome(t, testRecords(t)))
	if err := slot.Install(testCredential(t, "selected", "login")); err != nil {
		t.Fatal(err)
	}
	target := api.LifeRef{LifeID: "life-a", Run: 1}
	if err := slot.Reserve(target); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "containment", "generation", "time", "zone", "both", "neither", "zero-signal", "prompt", "target", "survivors", "running"} {
		t.Run(field, func(t *testing.T) {
			observation := fixtureExit(target)
			switch field {
			case "id":
				observation.Handle.ID = ""
			case "containment":
				observation.Handle.ContainmentID = ""
			case "generation":
				observation.Handle.Generation = ""
			case "time":
				observation.ObservedAt = ""
			case "zone":
				observation.ObservedAt = "2026-10-15T12:00:02+00:00"
			case "both":
				signal := 15
				observation.Signal = &signal
			case "neither":
				observation.ExitCode = nil
			case "zero-signal":
				signal := 0
				observation.ExitCode, observation.Signal = nil, &signal
			case "prompt":
				observation.PromptStatus = "invalid"
			case "target":
				observation.Handle.Target.Run++
			case "survivors":
				observation.Survivors = nil
			case "running":
				observation.State = "running"
			}
			if err := slot.Quiesce(observation); !errors.Is(err, ErrActive) {
				t.Fatal("malformed observation released the active slot", err)
			}
			if _, err := slot.Revoke(); !errors.Is(err, ErrActive) {
				t.Fatal("malformed observation enabled revocation", err)
			}
		})
	}
	if err := slot.Quiesce(fixtureExit(target)); err != nil {
		t.Fatal("valid exited control failed", err)
	}
	if _, err := slot.Token(); err != nil {
		t.Fatal("valid observation did not release the reservation", err)
	}
	if err := slot.Reserve(api.LifeRef{LifeID: target.LifeID, Run: 2}); err != nil {
		t.Fatal(err)
	}
	signalled := fixtureExit(api.LifeRef{LifeID: target.LifeID, Run: 2})
	signal := 15
	signalled.ExitCode, signalled.Signal, signalled.PromptStatus = nil, &signal, "cut"
	if err := slot.Quiesce(signalled); err != nil {
		t.Fatal("known signal termination control failed", err)
	}
}

// Fails if Seed can rewrite a protected generation while a credential controller
// owns the home. A refused import must not poison or change the existing bytes.
func TestSeedNeedsExclusiveHome(t *testing.T) {
	home := testHome(t, testRecords(t))
	source := filepath.Join(temporary(t), "hook")
	put(t, source, []byte("first_generation"))
	if err := home.Seed(source, ".claude/hooks/check"); err != nil {
		t.Fatal("unclaimed home seed control failed", err)
	}
	target := filepath.Join(home.path, ".claude/hooks/check")
	slot := testSlot(t, home)
	if err := slot.Install(testCredential(t, "selected", "login")); err != nil {
		t.Fatal(err)
	}
	put(t, source, []byte("next_generation"))
	if err := home.Seed(source, ".claude/hooks/check"); !errors.Is(err, ErrBusy) {
		t.Fatal("owned home accepted generated-file seeding", err)
	}
	if !bytes.Equal(get(t, target), []byte("first_generation")) {
		t.Fatal("refused seed changed generated bytes")
	}
	if err := home.verifyGenerated(); err != nil {
		t.Fatal("refused seed poisoned the protected generation", err)
	}
	if _, err := slot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := home.Seed(source, ".claude/hooks/check"); err != nil {
		t.Fatal("released home could not be seeded", err)
	}
	if !bytes.Equal(get(t, target), []byte("next_generation")) {
		t.Fatal("released seed did not copy its actual input")
	}
}
