package linux

import (
	"context"
	"os"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRegistryRegistrationFixture(t *testing.T) {
	for _, input := range []string{"root", "ordinary-directory", "boot", "uninitialized"} {
		t.Run(input, func(t *testing.T) {
			registry, err := NewRegistry()
			if err != nil {
				t.Fatalf("fixture setup: cgroup registry unavailable: %v", err)
			}
			initialized := registry
			t.Cleanup(func() { closeFixture(t, initialized.Close) })
			path := "/sys/fs/cgroup"
			if input == "ordinary-directory" {
				path = t.TempDir()
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			directory, err := os.Open(path)
			if err != nil {
				t.Fatalf("fixture setup: directory unavailable: %v", err)
			}
			t.Cleanup(func() { closeFixture(t, directory.Close) })
			binding := api.ContainmentBinding{Config: "fixture", Backend: "linux-bwrap-landlock", BootID: registry.boot,
				Generation: 1, Target: api.LifeRef{LifeID: "life", Run: 1}, Directory: directory,
				Lease: api.HelperLease{ID: "lease", ContainmentID: "containment", UID: 1234, GID: 1234, EndpointGeneration: 1}}
			want := api.CodeInvalid
			if input == "ordinary-directory" {
				want = api.CodeContainmentUnknown
			}
			if input == "boot" {
				binding.BootID = "prior-boot"
			}
			if input == "uninitialized" {
				registry = &Registry{}
				want = api.CodePrerequisite
			}
			requireCode(t, registry.RegisterContainment(context.Background(), binding), want)
			if _, err := directory.Stat(); err != nil {
				t.Fatal("fixture check: rejected registration closed the caller's directory")
			}
		})
	}
}

// This isolates registry revocation bookkeeping; it does not enroll the
// ordinary test directory as a real containment or claim helper allocation.
func TestRegistryRevocationFixture(t *testing.T) {
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatalf("fixture setup: revocation pin unavailable: %v", err)
	}
	entry := api.ContainmentBinding{Directory: directory, Lease: api.HelperLease{ID: "lease", UID: 1234, ContainmentID: "containment"}}
	registry := &Registry{entries: map[api.ID]api.ContainmentBinding{"containment": entry},
		leases: map[api.ID]bool{"lease": true}, uids: map[uint32]api.ID{1234: "containment"}}
	t.Cleanup(func() { closeFixture(t, registry.Close) })
	if err := registry.RevokeContainment(context.Background(), "containment"); err != nil {
		t.Fatalf("fixture check: registered containment could not be revoked: %v", err)
	}
	if !registry.entries["containment"].Revoked || registry.uids[entry.Lease.UID] != "containment" || !registry.leases[entry.Lease.ID] {
		t.Fatal("fixture check: revocation lost its tombstone or released allocation before quiescence")
	}
	if _, err := directory.Stat(); err != nil {
		t.Fatal("fixture check: revocation closed its retained containment pin")
	}
	requireCode(t, registry.RevokeContainment(context.Background(), "absent"), api.CodeNotFound)
}
