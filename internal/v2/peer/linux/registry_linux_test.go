package linux

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// This registry is a package fixture for the helper handoff. The native peer
// still reads the child's real kernel facts and compares the actual directory.
type fixtureContainments struct {
	binding       api.ContainmentBinding
	beforeResolve func() error
}

func (r *fixtureContainments) RegisterContainment(_ context.Context, binding api.ContainmentBinding) error {
	if r.binding.Directory != nil {
		return peerError(api.CodeConflict, "fixture containment already registered")
	}
	r.binding = binding
	return nil
}

func (r *fixtureContainments) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	if r.beforeResolve != nil {
		if err := r.beforeResolve(); err != nil {
			return api.ContainmentBinding{}, err
		}
	}
	if r.binding.Directory == nil || r.binding.Revoked {
		return api.ContainmentBinding{}, peerError(api.CodeContainmentUnknown, "fixture containment is absent or revoked")
	}
	return r.binding, nil
}

func TestResolveLockFixture(t *testing.T) {
	f := startNativeFixture(t, "ordinary")
	registry := f.verifier.registry.(*fixtureContainments)
	locked := false
	registry.beforeResolve = func() error {
		if !f.verifier.mu.TryLock() {
			locked = true
			return peerError(api.CodeIntegrity, "verifier lock held across registry resolution")
		}
		f.verifier.mu.Unlock()
		return nil
	}
	err := f.peer.Alive(context.Background())
	if locked || err != nil {
		t.Fatalf("fixture check: registry resolution retained a verifier lock: %v", err)
	}
	f.end(t)
}

func (r *fixtureContainments) RevokeContainment(_ context.Context, id api.ID) error {
	if r.binding.Lease.ContainmentID != id {
		return peerError(api.CodeNotFound, "fixture containment is absent")
	}
	r.binding.Revoked = true
	return nil
}

func fixtureVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New(&fixtureContainments{})
	if err != nil {
		t.Fatalf("fixture setup: native verifier unavailable: %v", err)
	}
	return v
}

func bindFixtureGroup(t *testing.T, v *Verifier, fd int) {
	t.Helper()
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("fixture setup: directory duplicate failed: %v", err)
	}
	directory := os.NewFile(uintptr(duplicate), "fixture-cgroup")
	t.Cleanup(func() { closeFixture(t, directory.Close) })
	observed, err := readProcess(os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatalf("fixture setup: process facts failed: %v", err)
	}
	boot, _, _ := strings.Cut(observed.generation, ":")
	err = v.registry.RegisterContainment(context.Background(), api.ContainmentBinding{
		Config: "fixture", Lease: api.HelperLease{ID: "fixture-lease", UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
			ContainmentID: "fixture-group", EndpointGeneration: 1}, Target: api.LifeRef{LifeID: "fixture-life", Run: 1},
		Backend: "linux-bwrap-landlock", BootID: boot, Generation: 1, Directory: directory})
	if err != nil {
		t.Fatalf("fixture setup: registry handoff failed: %v", err)
	}
}

type fixtureBoundConn struct {
	*net.UnixConn
	binding api.InstalledBinding
}

func (c *fixtureBoundConn) Binding() api.InstalledBinding { return c.binding }

func boundFixtureConn(conn *net.UnixConn) *fixtureBoundConn {
	return &fixtureBoundConn{UnixConn: conn, binding: api.InstalledBinding{
		Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: "fixture", Class: api.EndpointLane, InstallationGeneration: 1, EndpointGeneration: 1,
		ServiceUID: 1234, ServiceGID: 1234, Socket: "/run/fixture/socket", ArtifactSHA256: api.Digest(strings.Repeat("a", 64)),
		ServiceVersion: "fixture-version", Backend: "linux-bwrap-landlock", LaunchID: "fixture-launch",
		Target: &api.LifeRef{LifeID: "fixture-life", Run: 1}}}
}

func TestRegistryBindingFixture(t *testing.T) {
	for _, rule := range []string{"boot", "uid", "gid", "target", "endpoint", "directory", "allocation", "config", "backend"} {
		t.Run(rule, func(t *testing.T) {
			f := startNativeFixture(t, "ordinary")
			registry := f.verifier.registry.(*fixtureContainments)
			switch rule {
			case "boot":
				registry.binding.BootID = "prior-boot"
			case "uid":
				registry.binding.Lease.UID ^= 1
			case "gid":
				registry.binding.Lease.GID ^= 1
			case "target":
				registry.binding.Target.Run++
			case "endpoint":
				registry.binding.Lease.EndpointGeneration++
			case "allocation":
				registry.binding.Generation = 0
			case "config":
				registry.binding.Config = "other"
			case "backend":
				registry.binding.Backend = "darwin-seatbelt"
			case "directory":
				directory := t.TempDir()
				if err := os.Chmod(directory, 0700); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(directory)
				if err != nil {
					t.Fatalf("fixture setup: different directory unavailable: %v", err)
				}
				t.Cleanup(func() { closeFixture(t, file.Close) })
				registry.binding.Directory = file
			}
			requireCode(t, f.peer.Alive(context.Background()), api.CodeContainmentUnknown)
			f.end(t)
		})
	}
}
