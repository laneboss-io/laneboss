//go:build linux

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const privateResolver = "/etc/resolv.conf"

// Anonymous sealed resolver bytes are input data, not a host pathname for
// bwrap's --ro-bind-fd canonicalization. Copy them into a read-only lane file.
func resolverMountArgs(fd int) []string {
	return []string{"--ro-bind-data", strconv.Itoa(fd), privateResolver}
}

func resolverReader(file *os.File) (*os.File, error) {
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&bootstrapSeals != bootstrapSeals {
		return nil, failure(api.CodeIntegrity, "private resolver is not immutable")
	}
	// Reopening the same sealed inode gives each launch an independent offset.
	// F_DUPFD would let the first data projection consume the owner's offset.
	reader, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(file.Fd())))
	if err != nil {
		return nil, failure(api.CodeIntegrity, "cannot open pinned private resolver bytes")
	}
	return reader, nil
}

func newEmptyNetworkNamespace(ctx context.Context) (*os.File, error) {
	type result struct {
		file *os.File
		err  error
	}
	completed := make(chan result)
	// Network namespaces are per-thread. A dedicated locked thread restores
	// its original namespace before reuse. A failed restoration destroys the
	// thread via Goexit instead of returning it to the helper's executor pool.
	go func() {
		runtime.LockOSThread()
		original, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			completed <- result{err: failure(api.CodePrerequisite, "cannot pin helper network namespace")}
			return
		}
		defer original.Close()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			completed <- result{err: failure(api.CodePrerequisite, "cannot create private denied-network namespace")}
			return
		}
		file, openErr := os.Open("/proc/thread-self/ns/net")
		restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET)
		if restoreErr != nil {
			if file != nil {
				file.Close()
			}
			completed <- result{err: failure(api.CodeContainmentUnknown, "helper network thread could not restore its namespace")}
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		if openErr != nil {
			completed <- result{err: failure(api.CodeContainmentUnknown, "cannot pin created network namespace")}
			return
		}
		completed <- result{file: file}
	}()
	// The native operation is bounded and does not wait on a child or user
	// data. Always receive ownership, including after caller cancellation.
	value := <-completed
	if value.err != nil {
		return nil, value.err
	}
	if err := contextError(ctx); err != nil {
		value.file.Close()
		return nil, err
	}
	return value.file, nil
}

func (m *leaseManager) resolveNativeRuntime(ctx context.Context, record leaseRecord, handoff api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	if err := m.requireActive(record, storageReady); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if err := contextError(ctx); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if record.BootID != m.bootID || record.Phase != "active" || record.Spec == nil || record.SpecReceipt == nil ||
		!reflect.DeepEqual(record.Spec.Handoff, handoff) || handoff.Spec.Kind != "agent" || handoff.Spec.Runner == nil {
		return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime lookup lacks its exact registered agent handoff")
	}
	manifest, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		return api.ResolvedRuntime{}, err
	}
	for _, mount := range mounts {
		if err := mount.file.Close(); err != nil {
			return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "runtime pin close failed")
		}
	}
	if record.Network == nil {
		id, err := randomID("network-")
		if err != nil {
			return api.ResolvedRuntime{}, err
		}
		namespace, err := randomID("netns-")
		if err != nil {
			return api.ResolvedRuntime{}, err
		}
		policyBytes, err := json.Marshal(handoff.Spec.Grants.Network)
		if err != nil {
			return api.ResolvedRuntime{}, failure(api.CodeIntegrity, "cannot retain network grant digest")
		}
		endpoints := make([]api.ID, 0, len(handoff.Spec.Grants.Network))
		for _, grant := range handoff.Spec.Grants.Network {
			endpoints = append(endpoints, grant.EndpointID)
		}
		record.Network = &networkJournal{Phase: "creating", SpecID: handoff.Spec.ID, SpecSHA256: handoff.SpecSHA256,
			ClaimID: handoff.Cause.EffectID, ClaimGeneration: 1,
			Lease: api.NetworkLease{ID: id, NamespaceID: namespace, GrantSetID: handoff.Spec.Grants.ID, EndpointIDs: endpoints,
				Generation: handoff.Spec.PolicyGeneration, PolicySHA256: digestBytes(policyBytes), ExpiresAt: handoff.Spec.Grants.ExpiresAt}}
		if err := m.save(record); err != nil {
			return api.ResolvedRuntime{}, err
		}
		var file *os.File
		var owner *namespaceOwner
		if len(handoff.Spec.Grants.Network) == 0 {
			file, err = newEmptyNetworkNamespace(ctx)
		} else {
			resolver := m.networkResolver
			if resolver == nil {
				resolver = m.provisionEgress
			}
			enrolled, resolveErr := resolver(ctx, record, handoff.Spec.Grants.Network)
			if resolveErr != nil {
				return api.ResolvedRuntime{}, resolveErr
			}
			if enrolled.Namespace == nil || enrolled.ClaimID != handoff.Cause.EffectID || enrolled.ClaimGeneration == 0 ||
				!reflect.DeepEqual(enrolled.EndpointIDs, endpoints) || enrolled.PolicySHA256 != digestBytes(policyBytes) {
				var closeErr error
				if enrolled.owner != nil && enrolled.owner.collect != nil {
					closeErr = enrolled.owner.collect()
				}
				if enrolled.Namespace != nil {
					closeErr = errors.Join(closeErr, enrolled.Namespace.Close())
				}
				return api.ResolvedRuntime{}, errors.Join(failure(api.CodeIntegrity, "controlled egress owner changed its live claim or endpoint policy"), closeErr)
			}
			file, owner = enrolled.Namespace, enrolled.owner
		}
		if err != nil {
			return api.ResolvedRuntime{}, err
		}
		var info unix.Stat_t
		if unix.Fstat(int(file.Fd()), &info) != nil {
			var closeErr error
			if owner != nil && owner.collect != nil {
				closeErr = owner.collect()
			}
			return api.ResolvedRuntime{}, errors.Join(failure(api.CodeContainmentUnknown, "private network namespace identity is unavailable"), closeErr, file.Close())
		}
		if m.networks == nil {
			m.networks = map[api.ID]*namespaceOwner{}
		}
		if owner == nil {
			owner = &namespaceOwner{file: file}
		}
		m.networks[record.Lease.ID] = owner
		record.Network.Device, record.Network.Inode, record.Network.Phase = strconv.FormatUint(uint64(info.Dev), 10), strconv.FormatUint(info.Ino, 10), "ready"
		if err := m.save(record); err != nil {
			var closeErr error
			if owner.collect != nil {
				closeErr = owner.collect()
			}
			delete(m.networks, record.Lease.ID)
			return api.ResolvedRuntime{}, errors.Join(err, closeErr, file.Close())
		}
	}
	if _, err := m.ownedNetwork(record); err != nil {
		return api.ResolvedRuntime{}, err
	}
	if err := m.networkHealth(record); err != nil {
		return api.ResolvedRuntime{}, err
	}
	return api.ResolvedRuntime{Manifest: manifest, SpecReceipt: *record.SpecReceipt, Network: record.Network.Lease,
		Home: handoff.Spec.Runner.Home, Workspace: handoff.Spec.Workspace}, nil
}

func (m *leaseManager) ownedNetwork(record leaseRecord) (*os.File, error) {
	owner := m.networks[record.Lease.ID]
	if record.Network == nil || record.Network.Phase != "ready" && record.Network.Phase != "collecting" || owner == nil || owner.file == nil {
		return nil, failure(api.CodeContainmentUnknown, "original network namespace ownership is unavailable; replacement is forbidden")
	}
	var info unix.Stat_t
	if unix.Fstat(int(owner.file.Fd()), &info) != nil || record.Network.Device != strconv.FormatUint(uint64(info.Dev), 10) || record.Network.Inode != strconv.FormatUint(info.Ino, 10) {
		return nil, failure(api.CodeContainmentUnknown, "retained network namespace was replaced")
	}
	return owner.file, nil
}

func (m *leaseManager) networkHealth(record leaseRecord) error {
	owner := m.networks[record.Lease.ID]
	if record.Spec != nil && len(record.Spec.Handoff.Spec.Grants.Network) != 0 && (owner == nil || owner.check == nil || owner.resolv == nil) {
		return failure(api.CodeContainmentUnknown, "networked runtime requires its live egress policy and resolver owner")
	}
	if owner != nil && owner.check != nil {
		if err := owner.check(); err != nil {
			return err
		}
	}
	return nil
}

// Join as the root helper on a dedicated locked thread, before os/exec drops
// the child's UID and groups. An unprivileged bwrap cannot setns into a netns
// owned by the initial user namespace. It instead inherits this exact netns.
func startInNetworkNamespace(cmd *exec.Cmd, namespace *os.File) error {
	return startInNetworkNamespaceLifetime(cmd, namespace, nil, nil)
}

func startInNetworkNamespacePinned(cmd *exec.Cmd, namespace *os.File, lifetime *nativeSpawnLifetime) error {
	if lifetime == nil || lifetime.ended == nil {
		return failure(api.CodeContainmentUnknown, "native launch requires its primary lifetime owner")
	}
	return startInNetworkNamespaceLifetime(cmd, namespace, lifetime, nil)
}

func startInNetworkNamespaceVerified(cmd *exec.Cmd, namespace *os.File, lifetime *nativeSpawnLifetime, runtimePath string) error {
	if lifetime == nil {
		return failure(api.CodeContainmentUnknown, "native launch requires its primary lifetime owner")
	}
	if lifetime.ended == nil {
		return failure(api.CodeContainmentUnknown, "native launch requires its primary lifetime owner")
	}
	return startInNetworkNamespaceLifetime(cmd, namespace, lifetime, func() error {
		if cmd.SysProcAttr == nil || cmd.SysProcAttr.Cloneflags&unix.CLONE_NEWNS != 0 || cmd.SysProcAttr.Unshareflags&unix.CLONE_NEWNS != 0 {
			return failure(api.CodeContainmentUnknown, "gate must inherit the verified helper mount namespace")
		}
		return verifyHelperProcAtSpawn(runtimePath)
	})
}

func startInNetworkNamespaceLifetime(cmd *exec.Cmd, namespace *os.File, lifetime *nativeSpawnLifetime, beforeStart func() error) error {
	completed := make(chan error)
	go func() {
		runtime.LockOSThread()
		lifetime.startedThread()
		unlock := func() {
			lifetime.releasedThread()
			runtime.UnlockOSThread()
		}
		var original *os.File
		if namespace != nil {
			var err error
			original, err = os.Open("/proc/thread-self/ns/net")
			if err != nil {
				unlock()
				completed <- failure(api.CodeContainmentUnknown, "cannot pin native launch thread namespace")
				return
			}
			defer original.Close()
			if err := unix.Setns(int(namespace.Fd()), unix.CLONE_NEWNET); err != nil {
				unlock()
				completed <- failure(api.CodePrerequisite, "cannot join retained private network namespace before UID drop")
				return
			}
		}
		if beforeStart != nil {
			if err := beforeStart(); err != nil {
				if original != nil && unix.Setns(int(original.Fd()), unix.CLONE_NEWNET) != nil {
					completed <- failure(api.CodeContainmentUnknown, "refused launch thread could not restore its network namespace")
					runtime.Goexit()
				}
				unlock()
				completed <- err
				return
			}
		}
		startErr := cmd.Start()
		if startErr != nil {
			// Probe the same locked launch thread before restoring its netns.
			startErr = nativeGateCreationError(startErr, cmd.SysProcAttr)
		}
		var restoreErr error
		if original != nil {
			restoreErr = unix.Setns(int(original.Fd()), unix.CLONE_NEWNET)
		}
		if restoreErr != nil {
			if startErr == nil {
				if killErr := cmd.Process.Kill(); killErr != nil {
					completed <- failure(api.CodeContainmentUnknown, "launch thread restoration and created process stop failed")
					lifetime.holdThread()
					runtime.Goexit()
				}
				waitErr := cmd.Wait()
				lifetime.observedWait(cmd.ProcessState)
				var exited *exec.ExitError
				if waitErr != nil && !errors.As(waitErr, &exited) {
					completed <- failure(api.CodeContainmentUnknown, "launch thread restoration lost the native wait result")
					lifetime.holdThread()
					runtime.Goexit()
				}
			}
			completed <- failure(api.CodeContainmentUnknown, "native launch thread could not restore its network namespace")
			if startErr == nil {
				lifetime.holdThread()
			}
			runtime.Goexit()
		}
		if startErr != nil {
			unlock()
			completed <- startErr
			return
		}
		completed <- nil
		// bwrap's --die-with-parent binds to this creator task, not merely
		// the helper process. Keep the locked task alive until real exit.
		lifetime.holdThread()
		unlock()
	}()
	return <-completed
}

func (m *leaseManager) collectNativeNetwork(ctx context.Context, record *leaseRecord) error {
	if err := m.resources.Quiescent(ctx, *record); err != nil {
		return err
	}
	owner := m.networks[record.Lease.ID]
	if record.Network.Phase == "collecting" && owner != nil && owner.released {
		record.Network.Phase = "collected"
		if err := m.save(*record); err != nil {
			return err
		}
		delete(m.networks, record.Lease.ID)
		return nil
	}
	file, err := m.ownedNetwork(*record)
	if err != nil {
		return err
	}
	record.Network.Phase = "collecting"
	if err := m.save(*record); err != nil {
		return err
	}
	if owner.collect != nil {
		if err := owner.collect(); err != nil {
			return err
		}
	}
	if err := file.Close(); err != nil {
		return failure(api.CodeContainmentUnknown, "private network namespace close is uncertain")
	}
	owner.file, owner.released = nil, true
	record.Network.Phase = "collected"
	if err := m.save(*record); err != nil {
		return err
	}
	delete(m.networks, record.Lease.ID)
	return nil
}

func (m *leaseManager) appendNetworkMount(record leaseRecord, mounts []*nativeMount) ([]*nativeMount, error) {
	if len(record.Spec.Handoff.Spec.Grants.Network) == 0 {
		return mounts, nil
	}
	if _, err := m.ownedNetwork(record); err != nil {
		return mounts, err
	}
	if err := m.networkHealth(record); err != nil {
		return mounts, err
	}
	owner := m.networks[record.Lease.ID]
	if owner.resolv == nil {
		return mounts, failure(api.CodeContainmentUnknown, "network lease has no pinned namespace resolver")
	}
	for _, mount := range mounts {
		if mount.target == "/etc" || mount.target == privateResolver || strings.HasPrefix(mount.target, privateResolver+"/") {
			return mounts, failure(api.CodeIntegrity, "runtime projection collides with the private resolver")
		}
	}
	reader, err := resolverReader(owner.resolv)
	if err != nil {
		return mounts, err
	}
	return append(mounts, &nativeMount{file: reader, target: privateResolver, resolver: true}), nil
}

// The fixed helper uses only administrator-owned tools and exact argv. No
// shell, user-supplied rule source, host-network fallback or global rule flush.
func egressCommand(ctx context.Context, namespace *os.File, tool, input string, args ...string) error {
	_, err := egressOutput(ctx, namespace, tool, input, args...)
	return err
}

func egressOutput(ctx context.Context, namespace *os.File, tool, input string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	path, err := egressTool(tool)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(bounded, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := startInNetworkNamespace(cmd, namespace); err != nil {
		return nil, fmt.Errorf("egress %s start: %w; stderr:\n%s", tool, err, stderr.String())
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("egress %s failed: %w; stderr:\n%s", tool, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

var egressTableName = regexp.MustCompile(`^lb_[A-Za-z0-9_.-]*$`)
var egressLinkTable = regexp.MustCompile(`^lb_[a-f0-9]{12}$`)

// Startup has no surviving descriptor owner. Withdraw links before deleting
// their packet rules, then retire journals; an old launch cannot reopen them.
func (m *leaseManager) recoverNetworks(ctx context.Context) error {
	m.networkMu.Lock()
	defer m.networkMu.Unlock()
	records, err := m.records()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.Network != nil && len(record.Network.Lease.EndpointIDs) != 0 {
			if _, err := egressTool("nft"); err != nil {
				return err
			}
		}
	}
	if err := recoverNetworkTables(ctx); err != nil {
		return err
	}
	for _, record := range records {
		if record.Network != nil && record.Network.Phase != "collected" {
			record.Network.Phase = "collected"
			if err := m.save(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func recoverNetworkTables(ctx context.Context) error {
	// Offline installations need no nftables binary and have no egress state.
	if _, err := os.Stat("/usr/sbin/nft"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	raw, err := egressOutput(ctx, nil, "nft", "", "-j", "list", "tables")
	if err != nil {
		return err
	}
	var listing struct {
		NFTables []struct {
			Table *struct{ Family, Name string } `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil || listing.NFTables == nil {
		return errors.New("cannot decode the helper's network table inventory")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.New("cannot inventory network links during recovery")
	}
	links := map[string]bool{}
	for _, link := range interfaces {
		links[link.Name] = true
	}
	for _, item := range listing.NFTables {
		if item.Table == nil || item.Table.Family != "inet" || !strings.HasPrefix(item.Table.Name, "lb_") {
			continue
		}
		name := item.Table.Name
		if !egressTableName.MatchString(name) {
			return errors.New("owned network table has an unsafe identifier")
		}
		if egressLinkTable.MatchString(name) {
			peer := "lbe" + strings.TrimPrefix(name, "lb_")
			if links[peer] {
				if err := egressCommand(ctx, nil, "ip", "", "link", "set", peer, "down"); err != nil {
					return err
				}
			}
		}
		if err := egressCommand(ctx, nil, "nft", "", "delete", "table", "inet", name); err != nil {
			return err
		}
	}
	return nil
}

func egressTool(tool string) (string, error) {
	if tool != "ip" && tool != "nft" {
		return "", errors.New("unsupported egress tool")
	}
	path, err := filepath.EvalSymlinks("/usr/sbin/" + tool)
	if err != nil {
		return "", failure(api.CodePrerequisite, "controlled egress requires installed iproute2 and nftables")
	}
	if err := protectedPath(path, false); err != nil {
		return "", err
	}
	return path, nil
}

type egressLease struct {
	mu       sync.Mutex
	ns       *os.File
	resolv   *os.File
	peer     string
	link     string
	table    string
	gateway  netip.Addr
	lane     netip.Addr
	pins     []netip.Addr
	pinRound uint32
	endpoint api.NetworkEndpoint
	expires  time.Time
	valid    time.Time
	failed   bool
	rules    bool
	linked   bool
	udp      *net.UDPConn
	tcp      *net.TCPListener
	cancel   context.CancelFunc
	done     chan struct{}
}

func (m *leaseManager) provisionEgress(ctx context.Context, record leaseRecord, grants []api.NetworkGrant) (egressEnrollment, error) {
	m.networkMu.Lock()
	defer m.networkMu.Unlock()
	if len(grants) != 1 || record.Spec == nil {
		return egressEnrollment{}, failure(api.CodeForbidden, "egress requires exactly one enrolled API grant")
	}
	files, err := openEnrollmentFiles(m.binding)
	if err != nil {
		return egressEnrollment{}, err
	}
	defer files.root.Close()
	raw, _, err := files.read("launch-enrollment.json", api.MaxObjectBytes)
	if err != nil {
		return egressEnrollment{}, err
	}
	var enrollment api.LaunchEnrollment
	if err := api.DecodeObject(raw, &enrollment); err != nil {
		return egressEnrollment{}, err
	}
	if err := api.ValidateLaunchEnrollment(enrollment, m.binding.Config, record.Spec.Handoff.Spec.RuntimeManifest); err != nil {
		return egressEnrollment{}, err
	}
	endpoint, err := enrolledNetwork(enrollment, grants[0], time.Now())
	if err != nil {
		return egressEnrollment{}, err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(grants[0].ExpiresAt))
	if err != nil {
		return egressEnrollment{}, err
	}
	lease, err := newEgressLease(ctx, endpoint, expires)
	if err != nil {
		return egressEnrollment{}, err
	}
	policy, err := json.Marshal(grants)
	if err != nil {
		return egressEnrollment{}, errors.Join(err, lease.close())
	}
	owner := &namespaceOwner{file: lease.ns, resolv: lease.resolv, check: lease.check, collect: lease.close}
	return egressEnrollment{Namespace: lease.ns, EndpointIDs: []api.ID{endpoint.ID}, PolicySHA256: digestBytes(policy),
		ClaimID: record.Spec.Handoff.Cause.EffectID, ClaimGeneration: 1, owner: owner}, nil
}

func resolveEgress(ctx context.Context, endpoint api.NetworkEndpoint) ([]netip.Addr, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	answer, err := net.DefaultResolver.LookupNetIP(bounded, "ip", endpoint.Host)
	if err != nil {
		return nil, errors.New("cannot resolve enrolled API hostname")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("cannot inventory host addresses")
	}
	var host []netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return nil, errors.New("cannot parse host address inventory")
		}
		host = append(host, prefix.Addr())
	}
	for _, address := range endpoint.HostAddresses {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, errors.New("invalid enrolled host address")
		}
		host = append(host, ip)
	}
	return egressAddresses(answer, host)
}

func newEgressLease(ctx context.Context, endpoint api.NetworkEndpoint, expires time.Time) (_ *egressLease, resultErr error) {
	lease := &egressLease{endpoint: endpoint, expires: expires}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, lease.close())
			if lease.ns != nil {
				resultErr = errors.Join(resultErr, lease.ns.Close())
			}
		}
	}()
	forward, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil || strings.TrimSpace(string(forward)) != "1" || !expires.After(time.Now()) {
		return nil, failure(api.CodePrerequisite, "controlled egress requires administrator-enabled IPv4 forwarding and a live grant")
	}
	for _, tool := range []string{"ip", "nft"} {
		path, err := egressTool(tool)
		if err != nil {
			return nil, err
		}
		if err := protectedPath(path, false); err != nil {
			return nil, err
		}
	}
	lease.pins, err = resolveEgress(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if err := lease.chooseSubnet(ctx); err != nil {
		return nil, err
	}
	lease.ns, err = newEmptyNetworkNamespace(ctx)
	if err != nil {
		return nil, err
	}
	if err := egressCommand(ctx, nil, "ip", "", "link", "add", lease.peer, "type", "veth", "peer", "name", lease.link); err != nil {
		return nil, err
	}
	lease.linked = true
	// Keep both ends down until the host policy has committed atomically.
	if err := lease.install(ctx); err != nil {
		return nil, err
	}
	if err := egressCommand(ctx, nil, "ip", "", "address", "add", lease.gateway.String()+"/30", "dev", lease.peer); err != nil {
		return nil, err
	}
	// ip opens this inherited namespace FD itself; it is never a host PID or
	// a caller-selected named namespace in a shared /run/netns directory.
	ipPath, err := egressTool("ip")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, ipPath, "link", "set", lease.link, "netns", "/proc/self/fd/3")
	cmd.Env, cmd.ExtraFiles = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, []*os.File{lease.ns}
	if err := cmd.Run(); err != nil {
		return nil, errors.New("cannot move lane veth into its retained namespace")
	}
	for _, args := range [][]string{{"address", "add", lease.lane.String() + "/30", "dev", lease.link},
		{"link", "set", lease.link, "up"}, {"link", "set", "lo", "up"},
		{"route", "add", "default", "via", lease.gateway.String(), "dev", lease.link}} {
		if err := egressCommand(ctx, lease.ns, "ip", "", args...); err != nil {
			return nil, err
		}
	}
	if err := lease.startDNS(); err != nil {
		return nil, err
	}
	lease.resolv, err = egressResolv(lease.gateway)
	if err != nil {
		return nil, err
	}
	if err := egressCommand(ctx, nil, "ip", "", "link", "set", lease.peer, "up"); err != nil {
		return nil, err
	}
	background, cancel := context.WithCancel(context.Background())
	lease.cancel, lease.done = cancel, make(chan struct{})
	go lease.refresh(background)
	return lease, nil
}

func (lease *egressLease) chooseSubnet(ctx context.Context) error {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	var occupied []netip.Prefix
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			return err
		}
		occupied = append(occupied, prefix)
	}
	for attempt := 0; attempt < 16; attempt++ {
		var nonce [6]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		suffix := hex.EncodeToString(nonce[:])
		lease.peer, lease.link, lease.table = "lbe"+suffix, "lbp"+suffix, "lb_"+suffix
		base := [4]byte{100, 64 | nonce[0]&63, nonce[1], nonce[2]&252 | 1}
		lease.gateway = netip.AddrFrom4(base)
		base[3]++
		lease.lane = netip.AddrFrom4(base)
		collision := false
		for _, prefix := range occupied {
			collision = collision || prefix.Contains(lease.gateway) || netip.PrefixFrom(lease.gateway, 30).Contains(prefix.Addr())
		}
		if collision {
			continue
		}
		free, err := freeEgressRoute(ctx, lease.gateway, lease.lane)
		if err != nil {
			return err
		}
		if free {
			return nil
		}
	}
	return errors.New("no unclaimed private egress subnet is available")
}

func freeEgressRoute(ctx context.Context, addresses ...netip.Addr) (bool, error) {
	for _, address := range addresses {
		raw, err := egressOutput(ctx, nil, "ip", "", "-j", "-4", "route", "get", "fibmatch", address.String())
		if err != nil {
			return false, err
		}
		var routes []struct{ Dst string }
		if err := json.Unmarshal(raw, &routes); err != nil || len(routes) != 1 || routes[0].Dst == "" {
			return false, errors.New("cannot inspect candidate egress subnet routes")
		}
		if routes[0].Dst != "default" && routes[0].Dst != "0.0.0.0/0" {
			return false, nil
		}
	}
	return true, nil
}

func (lease *egressLease) policy() string {
	peer, lane, gateway, table := lease.peer, lease.lane.String(), lease.gateway.String(), lease.table
	var early, forward, nat strings.Builder
	for _, set := range egressPinSets {
		fmt.Fprintf(&early, "  iifname %q ip saddr %s ip daddr @%s tcp dport 443 accept\n", peer, lane, set)
		fmt.Fprintf(&forward, "  iifname %q ip saddr %s ip daddr @%s tcp dport 443 tcp flags & syn == syn tcp option maxseg size set rt mtu\n", peer, lane, set)
		fmt.Fprintf(&forward, "  iifname %q ip saddr %s ip daddr @%s tcp dport 443 ct state { new, established } accept\n", peer, lane, set)
		fmt.Fprintf(&forward, "  oifname %q ip daddr %s ip saddr @%s tcp sport 443 tcp flags & syn == syn tcp option maxseg size set rt mtu\n", peer, lane, set)
		fmt.Fprintf(&forward, "  oifname %q ip daddr %s ip saddr @%s tcp sport 443 ct state established accept\n", peer, lane, set)
		fmt.Fprintf(&nat, "  iifname %q ip saddr %s ip daddr @%s tcp dport 443 masquerade\n", peer, lane, set)
	}
	// The early chain checks the original destination; forward checks again
	// after DNAT. IPv6, host INPUT and host OUTPUT have explicit terminal drops.
	return fmt.Sprintf(`table inet %[1]s {
 set api4 { type ipv4_addr; flags timeout; }
 set api4a { type ipv4_addr; flags timeout; }
 set api4b { type ipv4_addr; flags timeout; }
 chain early { type filter hook prerouting priority -310; policy accept;
  iifname "%[2]s" ip saddr %[3]s ip daddr %[4]s meta l4proto { tcp, udp } th dport 53 accept
%[5]s
  iifname "%[2]s" drop
 }
 chain input { type filter hook input priority -10; policy accept;
  iifname "%[2]s" ip saddr %[3]s ip daddr %[4]s meta l4proto { tcp, udp } th dport 53 accept
  iifname "%[2]s" reject with icmpx type admin-prohibited
 }
 chain output { type filter hook output priority -10; policy accept;
  oifname "%[2]s" ip saddr %[4]s ip daddr %[3]s meta l4proto { tcp, udp } th sport 53 ct state established accept
  oifname "%[2]s" drop
 }
 chain forward { type filter hook forward priority -10; policy accept;
  iifname "%[2]s" fib daddr type local drop
%[6]s
  iifname "%[2]s" reject with icmpx type admin-prohibited
  oifname "%[2]s" reject with icmpx type admin-prohibited
 }
 chain nat { type nat hook postrouting priority srcnat; policy accept;
%[7]s
 }
}
`, table, peer, lane, gateway, early.String(), forward.String(), nat.String())
}

// At a 30s refresh cadence, a generation is revisited only after 90s, beyond
// the maximum 70s element lifetime. Thus every addition is fresh, unchanged
// addresses overlap, and departed addresses expire without a flush or delete.
var egressPinSets = []string{"api4", "api4a", "api4b"}

func (lease *egressLease) pinRules(pins []netip.Addr) string {
	remaining := time.Until(lease.expires)
	if remaining > 70*time.Second {
		remaining = 70 * time.Second
	}
	var elements []string
	for _, ip := range pins {
		elements = append(elements, ip.String()+" timeout "+strconv.FormatInt(max(1, remaining.Milliseconds()), 10)+"ms")
	}
	// Retain prior answers until their bounded kernel timeouts. Refresh never
	// flushes membership underneath a stream to a still-valid address.
	text := ""
	if len(elements) != 0 {
		set := egressPinSets[lease.pinRound%uint32(len(egressPinSets))]
		text += "add element inet " + lease.table + " " + set + " { " + strings.Join(elements, ", ") + " }\n"
	}
	return text
}

func (lease *egressLease) install(ctx context.Context) error {
	if err := egressCommand(ctx, nil, "nft", lease.policy()+lease.pinRules(lease.pins), "-f", "-"); err != nil {
		return err
	}
	lease.rules, lease.valid = true, time.Now().Add(65*time.Second)
	lease.pinRound++
	return nil
}

func (lease *egressLease) check() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.failed || !time.Now().Before(lease.expires) || !time.Now().Before(lease.valid) {
		return failure(api.CodeUnavailable, "controlled egress lease expired or its DNS/rules refresh failed")
	}
	return nil
}

func (lease *egressLease) refresh(ctx context.Context) {
	defer close(lease.done)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pins, err := resolveEgress(ctx, lease.endpoint)
		if err := lease.renew(ctx, pins, err); err != nil {
			fmt.Fprintln(os.Stderr, "controlled egress withdrawn after DNS, expiry or rule failure")
			return
		}
	}
}

func (lease *egressLease) renew(ctx context.Context, pins []netip.Addr, resolveErr error) error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	err := resolveErr
	if err == nil && (lease.failed || !time.Now().Before(lease.expires)) {
		err = errors.New("egress grant expired or was withdrawn")
	}
	if err == nil {
		err = egressCommand(ctx, nil, "nft", lease.pinRules(pins), "-f", "-")
	}
	if err != nil {
		lease.failed, lease.pins = true, nil
		// Link withdrawal is immediate. Independently, kernel set timeouts
		// stop existing connections too if the helper dies or loses control.
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return errors.Join(err, egressCommand(stopCtx, nil, "ip", "", "link", "set", lease.peer, "down"))
	}
	lease.pins, lease.valid = pins, time.Now().Add(65*time.Second)
	lease.pinRound++
	return nil
}

func egressResolv(gateway netip.Addr) (*os.File, error) {
	fd, err := unix.MemfdCreate("lane-resolver", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "lane-resolver")
	data := "nameserver " + gateway.String() + "\noptions timeout:2 attempts:1\n"
	_, writeErr := io.WriteString(file, data)
	_, seekErr := file.Seek(0, io.SeekStart)
	modeErr := file.Chmod(0444)
	_, sealErr := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, bootstrapSeals)
	if err := errors.Join(writeErr, seekErr, modeErr, sealErr); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func (lease *egressLease) dnsReply(query []byte) []byte {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.failed || !time.Now().Before(lease.expires) || !time.Now().Before(lease.valid) {
		return egressDNS(query, nil)
	}
	return egressDNS(query, lease.pins)
}

func (lease *egressLease) startDNS() error {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(lease.gateway.AsSlice()), Port: 53})
	if err != nil {
		return errors.New("cannot bind private UDP DNS listener")
	}
	lease.udp = udp
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(lease.gateway.AsSlice()), Port: 53})
	if err != nil {
		return errors.New("cannot bind private TCP DNS listener")
	}
	lease.tcp = tcp
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if !peer.IP.Equal(net.IP(lease.lane.AsSlice())) {
				continue
			}
			if reply := lease.dnsReply(buffer[:n]); reply != nil {
				if _, err := udp.WriteToUDP(reply, peer); err != nil {
					if err := lease.renew(context.Background(), nil, err); err != nil {
						fmt.Fprintln(os.Stderr, "controlled egress withdrawn after DNS listener failure")
					}
					return
				}
			}
		}
	}()
	go func() {
		for {
			connection, err := tcp.AcceptTCP()
			if err != nil {
				return
			}
			// One bounded query at a time: a lane cannot create an unbounded
			// helper goroutine or retain an idle TCP DNS client indefinitely.
			func() {
				defer connection.Close()
				if connection.SetDeadline(time.Now().Add(2*time.Second)) != nil {
					return
				}
				if peer, ok := connection.RemoteAddr().(*net.TCPAddr); !ok || !peer.IP.Equal(net.IP(lease.lane.AsSlice())) {
					return
				}
				var length [2]byte
				if _, err := io.ReadFull(connection, length[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(length[:]))
				if size < 17 || size > 4096 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(connection, query); err != nil {
					return
				}
				reply := lease.dnsReply(query)
				if reply != nil {
					binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
					if _, err := connection.Write(append(length[:], reply...)); err != nil {
						return
					}
				}
			}()
		}
	}()
	return nil
}

func (lease *egressLease) close() error {
	if lease.cancel != nil {
		lease.cancel()
		<-lease.done
		lease.cancel = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if lease.linked {
		if err := egressCommand(ctx, nil, "ip", "", "link", "set", lease.peer, "down"); err != nil {
			return err
		}
		if lease.rules {
			if err := egressCommand(ctx, nil, "nft", "", "delete", "table", "inet", lease.table); err != nil {
				return err
			}
			lease.rules = false
		}
		if err := egressCommand(ctx, nil, "ip", "", "link", "delete", lease.peer); err != nil {
			return err
		}
		lease.linked = false
	}
	var errs []error
	if lease.udp != nil {
		errs = append(errs, lease.udp.Close())
		lease.udp = nil
	}
	if lease.tcp != nil {
		errs = append(errs, lease.tcp.Close())
		lease.tcp = nil
	}
	if lease.resolv != nil {
		errs = append(errs, lease.resolv.Close())
		lease.resolv = nil
	}
	// collectNativeNetwork closes the namespace after this resource teardown;
	// a failed constructor owns it here because it never publishes an owner.
	return errors.Join(errs...)
}
