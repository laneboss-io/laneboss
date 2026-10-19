//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 5 && os.Args[1] == "egress-probe" {
		os.Exit(egressProbe(os.Args[2], os.Args[3], os.Args[4]))
	}
}

func egressDocAddr(host byte) netip.Addr {
	return netip.AddrFrom4([4]byte{198, 51, 100, host})
}

// These are real unprivileged sockets in the retained lane namespace. The
// result separates a refused connect (7) from a failed TLS handshake (8).
func egressProbe(mode, address, dns string) int {
	if mode == "udp" {
		return egressUDPProbe(address)
	}
	if mode == "icmp" {
		return egressICMPProbe(address)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	if dns != "auto" {
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if mode == "dns-tcp" {
				network = "tcp"
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, dns)
		}}
	}
	if strings.HasPrefix(mode, "dns") {
		answer, err := dialer.Resolver.LookupNetIP(ctx, "ip4", address)
		if err != nil || len(answer) == 0 {
			fmt.Fprintf(os.Stderr, "DNS probe failed: %v\n", err)
			return 7
		}
		return 0
	}
	network := "tcp4"
	if mode == "tcp6" {
		network = "tcp6"
	}
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect probe failed: %v\n", err)
		return 7
	}
	defer connection.Close()
	if mode == "tls" {
		client := tls.Client(connection, &tls.Config{ServerName: "api.anthropic.com", MinVersion: tls.VersionTLS12})
		defer client.Close()
		if err := client.HandshakeContext(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "verified TLS probe failed: %v\n", err)
			return 8
		}
	}
	return 0
}

func egressUDPProbe(address string) int {
	connection, err := net.DialTimeout("udp4", address, 3*time.Second)
	if err != nil {
		return 7
	}
	defer connection.Close()
	if connection.SetDeadline(time.Now().Add(3*time.Second)) != nil {
		return 9
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 9
	}
	if _, err := connection.Write(nonce[:]); err != nil {
		return 7
	}
	var reply [64]byte
	n, err := connection.Read(reply[:])
	if err != nil {
		return 7
	}
	if !bytes.Equal(reply[:n], nonce[:]) {
		return 9
	}
	return 0
}

func egressICMPProbe(address string) int {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ICMP datagram socket prerequisite:", err)
		return 9
	}
	defer unix.Close(fd)
	timeout := unix.NsecToTimeval((3 * time.Second).Nanoseconds())
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout) != nil ||
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout) != nil {
		return 9
	}
	packet := make([]byte, 24)
	packet[0], packet[7] = 8, 1
	if _, err := rand.Read(packet[8:]); err != nil {
		return 9
	}
	var sum uint32
	for index := 0; index < len(packet); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	binary.BigEndian.PutUint16(packet[2:4], ^uint16(sum))
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return 9
	}
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{Addr: ip.As4()}); err != nil {
		return 7
	}
	var reply [256]byte
	n, _, err := unix.Recvfrom(fd, reply[:], 0)
	if err != nil {
		return 7
	}
	if n < len(packet) || reply[0] != 0 || !bytes.Equal(reply[8:n], packet[8:]) {
		return 9
	}
	return 0
}

// Test-only responders make UDP/IPv6 RED controls observable even on an
// IPv4-only uplink or an API that provides no UDP service. The original wire
// destinations are unchanged. The same DNAT transport stays during GREEN.
func egressDenyTransport(t *testing.T, ctx context.Context, lease *egressLease) (string, string) {
	t.Helper()
	for _, item := range []struct {
		ns   *os.File
		args []string
	}{{nil, []string{"-6", "addr", "add", "fd42:6c62::1/64", "dev", lease.peer, "nodad"}},
		{lease.ns, []string{"-6", "addr", "add", "fd42:6c62::2/64", "dev", lease.link, "nodad"}},
		{lease.ns, []string{"-6", "route", "add", "default", "via", "fd42:6c62::1", "dev", lease.link}}} {
		if err := egressCommand(ctx, item.ns, "ip", "", item.args...); err != nil {
			t.Fatal("IPv6 RED transport prerequisite:", err)
		}
	}
	ping := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-w", "net.ipv4.ping_group_range=65534 65534")
	ping.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var pingErr bytes.Buffer
	ping.Stderr = &pingErr
	if err := startInNetworkNamespace(ping, lease.ns); err != nil {
		t.Fatal(err)
	}
	if err := ping.Wait(); err != nil {
		t.Fatalf("ICMP RED transport prerequisite: %v; stderr=%q", err, pingErr.String())
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(lease.gateway.AsSlice())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		var buffer [4096]byte
		for {
			n, peer, err := udp.ReadFromUDP(buffer[:])
			if err != nil {
				return
			}
			if _, err := udp.WriteToUDP(buffer[:n], peer); err != nil {
				return
			}
		}
	}()
	listen := func(network, address string) *net.TCPListener {
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				connection.Close()
			}
		}()
		return listener.(*net.TCPListener)
	}
	tcp := listen("tcp4", net.JoinHostPort(lease.gateway.String(), "0"))
	tcp6 := listen("tcp6", "[fd42:6c62::1]:0")
	name := "probe_" + lease.table
	rules := fmt.Sprintf(`table inet %[1]s {
 chain probe_nat { type nat hook prerouting priority dstnat; policy accept;
  iifname "%[2]s" ip daddr %[3]s udp dport 443 dnat ip to %[4]s:%[5]d
  iifname "%[2]s" ip daddr 1.1.1.1 udp dport 53 dnat ip to %[4]s:%[5]d
  iifname "%[2]s" ip daddr 1.1.1.1 tcp dport 53 dnat ip to %[4]s:%[6]d
  iifname "%[2]s" ip6 daddr 2606:4700:4700::1111 tcp dport 443 dnat ip6 to [fd42:6c62::1]:%[7]d
 }
}
`, name, lease.peer, lease.pins[0], lease.gateway, udp.LocalAddr().(*net.UDPAddr).Port,
		tcp.Addr().(*net.TCPAddr).Port, tcp6.Addr().(*net.TCPAddr).Port)
	if err := egressCommand(ctx, nil, "nft", rules, "-f", "-"); err != nil {
		t.Fatal("RED responder transport:", err)
	}
	t.Cleanup(func() {
		if err := egressCommand(context.Background(), nil, "nft", "", "delete", "table", "inet", name); err != nil {
			t.Error(err)
		}
	})
	return tcp.Addr().String(), "[2606:4700:4700::1111]:443"
}

func TestEgressCanary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("egress canary requires disposable Linux root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	nft, err := egressTool("nft")
	if err != nil {
		t.Fatal("nftables unavailable; administrator install line: apt-get install -y nftables;", err)
	}
	version := exec.CommandContext(ctx, nft, "--version")
	version.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	shown, err := version.CombinedOutput()
	if err != nil {
		t.Fatalf("nft --version failed: %v; stderr/output:\n%s", err, shown)
	}
	t.Logf("nft --version: %s", shown)
	for _, module := range []string{"nf_tables", "nft_nat"} {
		command := exec.CommandContext(ctx, "/usr/sbin/modprobe", "-n", module)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		shown, err := command.CombinedOutput()
		t.Logf("module %s available=%t; modprobe -n output:\n%s", module, err == nil, shown)
	}
	// The installed helper cannot change kernel tunables. The administrator
	// enables forwarding in provisioning; this isolated root canary restores it.
	forwardPath := "/proc/sys/net/ipv4/ip_forward"
	previous, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatal("cannot read forwarding prerequisite")
	}
	if strings.TrimSpace(string(previous)) != "1" {
		if err := os.WriteFile(forwardPath, []byte("1\n"), 0644); err != nil {
			t.Fatal("cannot enable disposable forwarding prerequisite")
		}
		t.Cleanup(func() {
			if err := os.WriteFile(forwardPath, previous, 0644); err != nil {
				t.Error("cannot restore forwarding prerequisite")
			}
		})
	}
	directory, err := os.MkdirTemp("/opt", "lb-egress-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	probePath := filepath.Join(directory, "probe")
	if err := os.WriteFile(probePath, self, 0555); err != nil {
		t.Fatal(err)
	}
	endpoint := api.NetworkEndpoint{ID: "anthropic-api", Host: "api.anthropic.com", Protocol: "tcp", Port: 443}
	expires := time.Now().Add(2 * time.Minute)
	grant := api.NetworkGrant{ID: "canary-net", EndpointID: endpoint.ID, Mode: "internet", ExpiresAt: api.Timestamp(expires.UTC().Format(time.RFC3339Nano))}
	if _, err := enrolledNetwork(api.LaunchEnrollment{}, grant, time.Now()); err == nil {
		t.Fatal("unenrolled network grant was admitted")
	}
	selected, err := enrolledNetwork(api.LaunchEnrollment{Network: []api.NetworkEndpoint{endpoint}}, grant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := newEgressLease(ctx, selected, expires)
	if err != nil {
		t.Fatal("provisioned egress lease:", err)
	}
	// Pause only periodic renewal while comparing the exact same namespace
	// without and with rules. Production never publishes this rule-free state.
	lease.cancel()
	<-lease.done
	lease.cancel = nil
	t.Cleanup(func() {
		if err := lease.close(); err != nil {
			t.Error("egress cleanup:", err)
		}
		if err := lease.ns.Close(); err != nil {
			t.Error(err)
		}
	})
	var private, host unix.Stat_t
	if err := unix.Fstat(int(lease.ns.Fd()), &private); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/proc/self/ns/net", &host); err != nil || private.Dev == host.Dev && private.Ino == host.Ino {
		t.Fatal("canary namespace is not private")
	}
	probe := func(namespace *os.File, mode, address string, projected bool) int {
		t.Helper()
		args := []string{"egress-probe", mode, address, net.JoinHostPort(lease.gateway.String(), "53")}
		command := exec.CommandContext(ctx, probePath, args...)
		if projected {
			args[3] = "auto"
			projection := []string{
				"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent",
				"--cap-drop", "ALL", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
				"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
				"--ro-bind", "/etc/ssl/certs", "/etc/ssl/certs"}
			projection = append(projection, resolverMountArgs(3)...)
			projection = append(projection, "--ro-bind", probePath, "/probe", "--proc", "/proc", "--dev", "/dev", "--", "/probe")
			command = exec.CommandContext(ctx, "/usr/bin/bwrap", append(projection, args...)...)
			reader, err := resolverReader(lease.resolv)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			command.ExtraFiles = []*os.File{reader}
		}
		command.Env = []string{"PATH=/usr/bin:/bin", "GODEBUG=netdns=go", "HOME=/home/lane"}
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		lifetime := newNativeSpawnLifetime()
		if err := startInNetworkNamespacePinned(command, namespace, lifetime); err != nil {
			t.Fatalf("cannot start unprivileged namespace probe: %v; stderr:\n%s", err, stderr.String())
		}
		err := command.Wait()
		lifetime.observedWait(command.ProcessState)
		<-lifetime.threadDone
		if err == nil {
			return 0
		}
		var exited *exec.ExitError
		if errors.As(err, &exited) && (exited.ExitCode() == 7 || exited.ExitCode() == 8) {
			if mode == "tls" {
				t.Logf("TLS probe stderr:\n%s", stderr.String())
			}
			return exited.ExitCode()
		}
		t.Fatalf("namespace probe did not return a socket or TLS verdict: %v; stderr:\n%s", err, stderr.String())
		return -1
	}
	// Select the real box interface before making a host listener. Never print
	// private interface addresses, subprocess argv or TLS material.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var hostIP netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() && prefix.Addr() != lease.gateway {
			hostIP = prefix.Addr()
			break
		}
	}
	if !hostIP.IsValid() {
		t.Fatal("box has no host IPv4 control address")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IP(hostIP.AsSlice())})
	if err != nil {
		t.Fatal("cannot start host-address control listener")
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	other, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "example.com")
	if err != nil || len(other) == 0 {
		t.Fatal("cannot resolve public deny control")
	}
	if _, err := egressAddresses(other, nil); err != nil {
		t.Fatal("public deny control is not public")
	}
	for _, ip := range lease.pins {
		if ip == other[0] {
			t.Fatal("public deny control aliases the granted endpoint")
		}
	}
	gatewayPort, public6 := egressDenyTransport(t, ctx, lease)
	cases := []struct{ name, mode, address string }{
		{"public", "tcp", net.JoinHostPort(other[0].String(), "443")},
		{"metadata", "tcp", "169.254.169.254:80"},
		{"host", "tcp", listener.Addr().String()},
		{"port", "tcp", net.JoinHostPort(lease.pins[0].String(), "80")},
		{"ipv6", "tcp6", public6},
		{"pin-udp", "udp", net.JoinHostPort(lease.pins[0].String(), "443")},
		{"dns-udp", "udp", "1.1.1.1:53"},
		{"dns-tcp", "tcp", "1.1.1.1:53"},
		{"gateway", "tcp", gatewayPort},
		{"icmp", "icmp", lease.gateway.String()},
	}
	// RED controls remove the production table and provide only transport NAT.
	// Every required forbidden connect must actually succeed in this phase.
	if err := egressCommand(ctx, nil, "nft", "", "delete", "table", "inet", lease.table); err != nil {
		t.Fatal(err)
	}
	lease.rules = false
	control := fmt.Sprintf("table inet %s {\n chain nat {\n  type nat hook postrouting priority srcnat; policy accept;\n  iifname \"%s\" ip saddr %s masquerade\n }\n}\n", lease.table, lease.peer, lease.lane)
	t.Logf("exact RED ruleset:\n%s", control)
	if err := egressCommand(ctx, nil, "nft", control, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	lease.rules = true
	for _, item := range cases {
		if result := probe(lease.ns, item.mode, item.address, false); result != 0 {
			t.Fatalf("%s has no RED control: connect verdict=%d", item.name, result)
		}
		t.Logf("%s RED=connected with rules absent", item.name)
	}
	if result := probe(lease.ns, "tls", "api.anthropic.com:443", false); result != 0 {
		t.Fatalf("TLS RED transport control failed: verdict=%d", result)
	}
	t.Log("api:443 RED=verified TLS handshake with rules absent")
	if err := egressCommand(ctx, nil, "nft", "", "delete", "table", "inet", lease.table); err != nil {
		t.Fatal(err)
	}
	lease.rules = false
	if err := lease.install(ctx); err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		if result := probe(lease.ns, item.mode, item.address, false); result != 7 {
			t.Fatalf("%s GREEN failed: connect verdict=%d", item.name, result)
		}
		t.Logf("%s GREEN=refused with production rules", item.name)
	}
	if result := probe(lease.ns, "tls", "api.anthropic.com:443", true); result != 0 {
		t.Fatalf("TLS GREEN through the projected private resolver failed: verdict=%d", result)
	}
	t.Log("api:443 GREEN=verified TLS handshake through projected resolver")
	if result := probe(lease.ns, "dns-tcp", "api.anthropic.com", false); result != 0 {
		t.Fatalf("private TCP DNS failed: verdict=%d", result)
	}
	if result := probe(lease.ns, "dns", "example.com", false); result != 7 {
		t.Fatal("private DNS answered a name outside enrollment")
	}
	// Exercise the same renewal transaction, not a second rule implementation.
	pins, err := resolveEgress(ctx, endpoint)
	if err := lease.renew(ctx, pins, err); err != nil {
		t.Fatal("live DNS renewal failed:", err)
	}
	if result := probe(lease.ns, "tls", "api.anthropic.com:443", false); result != 0 {
		t.Fatalf("renewed API pins failed TLS: verdict=%d", result)
	}
	offline, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result := probe(offline, "tcp", net.JoinHostPort(pins[0].String(), "443"), false); result != 7 {
		offline.Close()
		t.Fatal("grantless namespace acquired network")
	}
	if err := offline.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("grantless GREEN=no network in an empty private namespace")
	unsafe := append(append([]netip.Addr{}, pins...), netip.MustParseAddr("169.254.169.254"))
	_, rebindErr := egressAddresses(unsafe, []netip.Addr{hostIP})
	if rebindErr == nil {
		t.Fatal("mixed public/metadata DNS answer was admitted")
	}
	if err := lease.renew(ctx, nil, rebindErr); err == nil || lease.check() == nil {
		t.Fatal("DNS rebinding did not withdraw the lease")
	}
	if result := probe(lease.ns, "tcp", net.JoinHostPort(pins[0].String(), "443"), false); result != 7 {
		t.Fatal("withdrawn rebinding lease retained API connectivity")
	}
	t.Log("rebind GREEN=entire answer rejected and link withdrawn")
	if _, err := net.InterfaceByName(lease.peer); err != nil {
		t.Fatal("lease link disappeared before owned cleanup")
	}
	if err := lease.close(); err != nil {
		t.Fatal("withdrawn lease cleanup:", err)
	}
	if _, err := net.InterfaceByName(lease.peer); err == nil {
		t.Fatal("owned veth survived cleanup")
	}
	// The resolver is immutable and must not become a writable lane file.
	resolver := egressDocAddr(13)
	file, err := egressResolv(resolver)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteAt([]byte("nameserver 127.0.0.1\n"), 0); err == nil {
		t.Fatal("private resolver bytes were writable")
	}
	data, err := io.ReadAll(file)
	if err != nil || !strings.Contains(string(data), "nameserver "+resolver.String()+"\n") {
		t.Fatal("sealed resolver read-back differs")
	}
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'p', 'i', 9, 'a', 'n', 't', 'h', 'r', 'o', 'p', 'i', 'c', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	reply := egressDNS(query, pins)
	if len(reply) < len(query)+16 || int(binary.BigEndian.Uint16(reply[6:8])) != len(pins) {
		t.Fatal("DNS response differs from current firewall pins")
	}
}
