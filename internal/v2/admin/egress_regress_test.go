//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// A fresh host namespace keeps the test's public-address routes and stale
// table inventory away from the box's real uplink and other helper state.
func egressIsolatedHost(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("egress regression requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] == "egress-isolated-host" {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, self, "-test.run=^"+t.Name()+"$", "-test.v", "--", "egress-isolated-host")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "GOMAXPROCS=2"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	output, err := command.CombinedOutput()
	t.Logf("isolated native regression:\n%s", output)
	if err != nil {
		t.Fatal("isolated regression failed:", err)
	}
	return false
}

// Socket creation occurs on a locked task in the selected namespace; returned
// sockets retain that native namespace after the task restores its original.
func egressSocketNS(namespace *os.File, operation func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		original, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		defer original.Close()
		if err := unix.Setns(int(namespace.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		err = operation()
		if restore := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restore != nil {
			done <- errors.Join(err, restore)
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		done <- err
	}()
	return <-done
}

func egressTestIP(t *testing.T, ctx context.Context, namespace *os.File, args ...string) {
	t.Helper()
	if err := egressCommand(ctx, namespace, "ip", "", args...); err != nil {
		t.Fatal(err)
	}
}

func egressTestPair(t *testing.T, ctx context.Context, namespace *os.File, peer, link, gateway, lane string) {
	t.Helper()
	egressTestIP(t, ctx, nil, "link", "add", peer, "type", "veth", "peer", "name", link)
	path, err := egressTool("ip")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, path, "link", "set", link, "netns", "/proc/self/fd/3")
	command.Env, command.ExtraFiles = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}, []*os.File{namespace}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("move test veth: %v; stderr/output: %s", err, output)
	}
	egressTestIP(t, ctx, nil, "address", "add", gateway+"/30", "dev", peer)
	egressTestIP(t, ctx, namespace, "address", "add", lane+"/30", "dev", link)
	egressTestIP(t, ctx, namespace, "link", "set", link, "up")
	egressTestIP(t, ctx, namespace, "link", "set", "lo", "up")
	egressTestIP(t, ctx, nil, "link", "set", peer, "up")
}

func egressTLSRoundTrip(connection net.Conn) error {
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	var sent, received [32]byte
	if _, err := rand.Read(sent[:]); err != nil {
		return err
	}
	if _, err := connection.Write(sent[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, received[:]); err != nil {
		return err
	}
	if sent != received {
		return errors.New("TLS stream returned different nonce bytes")
	}
	return nil
}

// This component test forwards verified TLS to a native echo peer on three
// public IPv4 addresses in an isolated host. It makes no external API request.
// The same open socket must carry fresh bytes after answers stop including its
// address. Removing old pins is the RED fault; no product code is substituted.
func TestEgressStream(t *testing.T) {
	if !egressIsolatedHost(t) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	clientNS, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clientNS.Close()
	serverNS, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer serverNS.Close()
	pins := []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("93.184.216.35"), netip.MustParseAddr("93.184.216.36")}
	if _, err := egressAddresses(pins, nil); err != nil {
		t.Fatal("test addresses are not public policy candidates:", err)
	}
	lease := &egressLease{ns: clientNS, peer: "lbstream0", link: "lbstream1", table: "lb_stream",
		gateway: egressDocAddr(1), lane: egressDocAddr(2),
		pins: pins[:1], expires: time.Now().Add(time.Minute)}
	// Policy commits before the client veth is brought up, as in production.
	if err := lease.install(ctx); err != nil {
		t.Fatal(err)
	}
	egressTestPair(t, ctx, clientNS, lease.peer, lease.link, lease.gateway.String(), lease.lane.String())
	egressTestIP(t, ctx, clientNS, "route", "add", "default", "via", lease.gateway.String())
	egressTestPair(t, ctx, serverNS, "lbremote0", "lbremote1", egressDocAddr(5).String(), egressDocAddr(6).String())
	for _, pin := range pins {
		egressTestIP(t, ctx, serverNS, "address", "add", pin.String()+"/32", "dev", "lo")
		egressTestIP(t, ctx, nil, "route", "add", pin.String()+"/32", "via", egressDocAddr(6).String())
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.anthropic.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var listener net.Listener
	if err := egressSocketNS(serverNS, func() error {
		var err error
		listener, err = net.Listen("tcp4", "0.0.0.0:443")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				// Both RED withdrawal and normal cleanup end the echo session.
				io.Copy(connection, connection)
			}()
		}
	}()
	dial := func() net.Conn {
		t.Helper()
		var connection net.Conn
		if err := egressSocketNS(clientNS, func() error {
			dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second},
				Config: &tls.Config{RootCAs: roots, ServerName: "api.anthropic.com", MinVersion: tls.VersionTLS12}}
			var err error
			connection, err = dialer.DialContext(ctx, "tcp4", net.JoinHostPort(pins[0].String(), "443"))
			return err
		}); err != nil {
			t.Fatal("verified TLS stream setup:", err)
		}
		if connection.LocalAddr().(*net.TCPAddr).AddrPort().Addr() != lease.lane {
			connection.Close()
			t.Fatal("TLS socket did not originate in the lane namespace")
		}
		return connection
	}
	red := dial()
	if err := egressTLSRoundTrip(red); err != nil {
		t.Fatal("RED stream transport control:", err)
	}
	var flush strings.Builder
	for _, name := range egressPinSets {
		fmt.Fprintf(&flush, "flush set inet %s %s\n", lease.table, name)
	}
	if err := egressCommand(ctx, nil, "nft", flush.String(), "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := lease.renew(ctx, pins[1:2], nil); err != nil {
		t.Fatal(err)
	}
	if err := egressTLSRoundTrip(red); err == nil {
		t.Fatal("RED stream assertion accepted removal of its still-valid pin")
	} else {
		t.Logf("RED stream assertion failed as required after old membership was flushed: %v", err)
	}
	red.Close()
	if err := egressCommand(ctx, nil, "nft", "", "delete", "table", "inet", lease.table); err != nil {
		t.Fatal(err)
	}
	lease.pins, lease.pinRound = pins[:1], 0
	if err := lease.install(ctx); err != nil {
		t.Fatal(err)
	}
	green := dial()
	defer green.Close()
	if err := egressTLSRoundTrip(green); err != nil {
		t.Fatal("initial GREEN TLS stream:", err)
	}
	for round := 1; round < len(egressPinSets); round++ {
		if err := lease.renew(ctx, pins[round:round+1], nil); err != nil {
			t.Fatal(err)
		}
		if err := egressTLSRoundTrip(green); err != nil {
			t.Fatalf("same TLS stream failed after generation %d: %v", round+1, err)
		}
	}
	for round, name := range egressPinSets {
		query := fmt.Sprintf("get element inet %s %s { %s }\n", lease.table, name, pins[round])
		if err := egressCommand(ctx, nil, "nft", query, "-f", "-"); err != nil {
			t.Fatal("one of three overlapping kernel pin generations is absent:", err)
		}
	}
	t.Log("GREEN same verified TLS connection exchanged fresh nonce bytes across three overlapping native pin generations")
}

func egressTableInventory(ctx context.Context) (map[string]bool, error) {
	raw, err := egressOutput(ctx, nil, "nft", "", "-j", "list", "tables")
	if err != nil {
		return nil, err
	}
	var listing struct {
		NFTables []struct {
			Table *struct{ Family, Name string } `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		return nil, err
	}
	tables := map[string]bool{}
	for _, item := range listing.NFTables {
		if item.Table != nil {
			tables[item.Table.Family+"/"+item.Table.Name] = true
		}
	}
	return tables, nil
}

func egressRestartAssertions(ctx context.Context, manager *leaseManager, peer string) error {
	tables, err := egressTableInventory(ctx)
	if err != nil {
		return err
	}
	var problems []error
	for name := range tables {
		if strings.HasPrefix(name, "inet/lb_") {
			problems = append(problems, errors.New("stale table survived"))
		}
	}
	if !tables["inet/egress_control"] || !tables["ip/lb_stale"] {
		problems = append(problems, errors.New("unrelated table was removed"))
	}
	records, err := manager.records()
	if err != nil {
		return err
	}
	if len(records) != 2 {
		problems = append(problems, errors.New("restart lost a retained journal"))
	}
	for _, record := range records {
		if record.Network == nil || record.Network.Phase != "collected" {
			problems = append(problems, errors.New("network journal was not retired"))
		}
	}
	link, err := net.InterfaceByName(peer)
	if err != nil {
		return err
	}
	if link.Flags&net.FlagUp != 0 {
		problems = append(problems, errors.New("stale link remains up"))
	}
	return errors.Join(problems...)
}

// Restart uses a fresh manager and reopened native file store, with no live
// namespace owners. This is the recovery entry called before helper listen;
// it does not claim installation/systemd or authenticated vendor coverage.
func TestEgressRestart(t *testing.T) {
	if !egressIsolatedHost(t) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	manager := newLeaseManager(testBinding(), "boot-a", &fileLeaseStore{root: root}, &observedResources{})
	namespace, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Close()
	var info unix.Stat_t
	if err := unix.Fstat(int(namespace.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	for index, phase := range []string{"ready", "creating"} {
		request := testAllocation()
		if index != 0 {
			request.LifeID, request.Cause.Target.LifeID = "life-b", "life-b"
		}
		lease, err := manager.allocate(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		record, err := manager.find(lease.ID)
		if err != nil {
			t.Fatal(err)
		}
		registration := testSpecRegistration(lease)
		spec := &registration.Handoff.Spec
		spec.Target.LifeID, spec.Grants.LifeID, spec.Injection.Target.LifeID = request.LifeID, request.LifeID, request.LifeID
		registration.Handoff.Cause.Target.LifeID = request.LifeID
		spec.ID = api.ID("spec-" + phase)
		spec.LaunchID = api.ID("launch-" + phase)
		spec.Grants.Network = []api.NetworkGrant{{ID: api.ID("grant-" + phase), EndpointID: "anthropic-api", Mode: "internet", ExpiresAt: spec.Grants.ExpiresAt}}
		original, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := api.CanonicalJSON(original)
		if err != nil {
			t.Fatal(err)
		}
		registration.Original = original
		registration.Handoff.Original.SHA256, registration.Handoff.Original.Bytes = digestBytes(original), int64(len(original))
		registration.Handoff.SpecSHA256 = digestBytes(canonical)
		record.Spec = &registration
		record.SpecReceipt = &api.PreparedSpecReceipt{SpecID: spec.ID, Config: manager.binding.Config, Target: spec.Target,
			LeaseID: lease.ID, SpecSHA256: registration.Handoff.SpecSHA256, RuntimeManifest: spec.RuntimeManifest, OperationID: registration.Handoff.OperationID}
		policy, err := json.Marshal(spec.Grants.Network)
		if err != nil {
			t.Fatal(err)
		}
		record.Network = &networkJournal{Phase: phase, SpecID: spec.ID, SpecSHA256: registration.Handoff.SpecSHA256,
			ClaimID: registration.Handoff.Cause.EffectID, ClaimGeneration: 1,
			Lease: api.NetworkLease{ID: api.ID("network-" + phase), NamespaceID: api.ID("netns-" + phase), GrantSetID: spec.Grants.ID,
				EndpointIDs: []api.ID{"anthropic-api"}, Generation: spec.PolicyGeneration, PolicySHA256: digestBytes(policy), ExpiresAt: spec.Grants.ExpiresAt}}
		if phase == "ready" {
			record.Network.Device, record.Network.Inode = strconv.FormatUint(uint64(info.Dev), 10), strconv.FormatUint(info.Ino, 10)
		}
		if err := manager.save(record); err != nil {
			t.Fatal("retain valid network journal:", err)
		}
	}
	id, err := randomID("lb_")
	if err != nil {
		t.Fatal(err)
	}
	table := string(id[:15])
	peer := "lbe" + strings.TrimPrefix(table, "lb_")
	egressTestIP(t, ctx, nil, "link", "add", peer, "type", "veth", "peer", "name", "lbrestart1")
	egressTestIP(t, ctx, nil, "link", "set", peer, "up")
	rules := fmt.Sprintf("table inet %s {}\ntable inet lb_stale {}\ntable inet egress_control {}\ntable ip lb_stale {}\n", table)
	if err := egressCommand(ctx, nil, "nft", rules, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	reopened, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted := newLeaseManager(manager.binding, manager.bootID, &fileLeaseStore{root: reopened}, &observedResources{})
	// RED deliberately omits the startup sweep before inspecting the native
	// tables, link and reopened journals. GREEN invokes the real startup entry.
	if err := egressRestartAssertions(ctx, restarted, peer); err == nil || !strings.Contains(err.Error(), "stale table survived") ||
		!strings.Contains(err.Error(), "network journal was not retired") || !strings.Contains(err.Error(), "stale link remains up") {
		t.Fatal("RED restart assertion did not detect the unrecovered native state:", err)
	} else {
		t.Logf("RED restart assertions failed as required before startup recovery: %v", err)
	}
	if err := restarted.recoverNetworks(ctx); err != nil {
		t.Fatal("helper startup network recovery:", err)
	}
	if err := egressRestartAssertions(ctx, restarted, peer); err != nil {
		t.Fatal("GREEN helper restart:", err)
	}
	records, err := restarted.records()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		_, err := restarted.ownedNetwork(record)
		requireCode(t, err, api.CodeContainmentUnknown)
	}
	if len(restarted.networks) != 0 {
		t.Fatal("restart recreated an old namespace owner")
	}
	if err := restarted.recoverNetworks(ctx); err != nil {
		t.Fatal("idempotent helper startup recovery:", err)
	}
	if err := egressRestartAssertions(ctx, restarted, peer); err != nil {
		t.Fatal("repeated startup recovery changed retained state:", err)
	}
	t.Log("GREEN helper startup removed both stale inet lb_ tables, disabled the owned link, retired ready/creating journals and refused old namespace reuse")
}
