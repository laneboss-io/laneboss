//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

var laneCapFields = []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}

const helperNetBits = uint64(1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_NET_BIND_SERVICE)

type laneCapRead struct {
	PID       int               `json:"pid"`
	ParentPID int               `json:"parent_pid"`
	Namespace string            `json:"namespace"`
	Sets      map[string]uint64 `json:"sets"`
}

type laneNetAttempt struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

type laneCapReport struct {
	Agent    laneCapRead    `json:"agent"`
	Child    laneCapRead    `json:"child"`
	NFTList  laneNetAttempt `json:"nft_list"`
	NFTAdd   laneNetAttempt `json:"nft_add"`
	RouteAdd laneNetAttempt `json:"route_add"`
}

func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case "egress-cap-child":
		read, err := readLaneCaps()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(81)
		}
		if err := json.NewEncoder(os.Stdout).Encode(read); err != nil {
			os.Exit(82)
		}
		os.Exit(0)
	case "egress-cap-agent":
		if err := runCapAgent(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(83)
		}
		os.Exit(0)
	}
}

func readLaneCaps() (laneCapRead, error) {
	read := laneCapRead{PID: os.Getpid(), ParentPID: os.Getppid(), Sets: map[string]uint64{}}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return read, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || !slices.Contains(laneCapFields, name) {
			continue
		}
		if _, duplicate := read.Sets[name]; duplicate {
			return read, errors.New("duplicate kernel capability set")
		}
		bits, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
		if err != nil {
			return read, err
		}
		read.Sets[name] = bits
	}
	if len(read.Sets) != len(laneCapFields) {
		return read, errors.New("kernel capability set is missing")
	}
	read.Namespace, err = os.Readlink("/proc/self/ns/net")
	return read, err
}

func rejectHelperNetCaps(read laneCapRead) error {
	if len(read.Sets) != len(laneCapFields) {
		return errors.New("capability assertion requires all five kernel sets")
	}
	for _, name := range laneCapFields {
		bits, found := read.Sets[name]
		if !found {
			return fmt.Errorf("capability assertion lacks %s", name)
		}
		if bits&helperNetBits != 0 {
			return fmt.Errorf("%s retains helper network bits %#x", name, bits&helperNetBits)
		}
	}
	return nil
}

func capNetAttempt(ctx context.Context, path, input string, args ...string) (laneNetAttempt, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "GOMAXPROCS=1"}
	command.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	result := laneNetAttempt{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return result, nil
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() < 1 {
		return result, errors.Join(errors.New("netlink probe did not execute to a verdict"), err)
	}
	result.Exit = exited.ExitCode()
	return result, nil
}

func runCapAgent() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	agent, err := readLaneCaps()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	child := exec.CommandContext(ctx, self, "egress-cap-child")
	child.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "GOMAXPROCS=1"}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	raw, err := child.Output()
	if err != nil {
		return fmt.Errorf("agent child failed: %w; stderr:\n%s", err, stderr.String())
	}
	report := laneCapReport{Agent: agent}
	if err := json.Unmarshal(raw, &report.Child); err != nil {
		return err
	}
	// The deliberately privileged RED build only reports kernel facts; it
	// performs no netlink mutation. GREEN must execute every command below.
	if rejectHelperNetCaps(agent) == nil && rejectHelperNetCaps(report.Child) == nil {
		report.NFTList, err = capNetAttempt(ctx, "/usr/sbin/nft", "", "list", "ruleset")
		if err != nil {
			return err
		}
		report.NFTAdd, err = capNetAttempt(ctx, "/usr/sbin/nft",
			"add table inet lb_cap_probe\nadd chain inet lb_cap_probe out\nadd rule inet lb_cap_probe out counter\n", "-f", "-")
		if err != nil {
			return err
		}
		report.RouteAdd, err = capNetAttempt(ctx, "/usr/sbin/ip", "", "route", "add", "blackhole", egressDocAddr(9).String()+"/32")
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func TestEgressCapDrop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("capability canary requires disposable Linux root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	forwardPath := "/proc/sys/net/ipv4/ip_forward"
	previous, err := os.ReadFile(forwardPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(previous)) != "1" {
		if err := os.WriteFile(forwardPath, []byte("1\n"), 0644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(forwardPath, previous, 0644); err != nil {
				t.Error(err)
			}
		})
	}
	endpoint := api.NetworkEndpoint{ID: "anthropic-api", Host: "api.anthropic.com", Protocol: "tcp", Port: 443}
	expires := time.Now().Add(2 * time.Minute)
	grant := api.NetworkGrant{ID: "cap-grant", EndpointID: endpoint.ID, Mode: "internet", ExpiresAt: api.Timestamp(expires.UTC().Format(time.RFC3339Nano))}
	selected, err := enrolledNetwork(api.LaunchEnrollment{Network: []api.NetworkEndpoint{endpoint}}, grant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := newEgressLease(ctx, selected, expires)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.close(); err != nil {
			t.Error(err)
		}
		if err := lease.ns.Close(); err != nil {
			t.Error(err)
		}
	})
	owned, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(lease.ns.Fd())))
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil || owned == host {
		t.Fatal("grant namespace is not private")
	}
	directory, err := os.MkdirTemp("/opt", "lb-egress-caps-")
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
	binary := filepath.Join(directory, "agent")
	if err := os.WriteFile(binary, self, 0555); err != nil {
		t.Fatal(err)
	}
	var mounts []*nativeMount
	t.Cleanup(func() {
		for _, mount := range mounts {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	for _, target := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		source, err := filepath.EvalSymlinks(target)
		if err != nil {
			t.Fatal(err)
		}
		mount, err := pinNativeMount(source, target, true, false, true, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, mount)
	}
	probe, err := pinNativeMount(binary, "/runtime/cap-probe", false, false, true, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	mounts = append(mounts, probe)
	reader, err := resolverReader(lease.resolv)
	if err != nil {
		t.Fatal(err)
	}
	mounts = append(mounts, &nativeMount{file: reader, target: privateResolver, resolver: true})
	launch := func(red bool) laneCapReport {
		t.Helper()
		args, files := nativeGateArgs("egress-caps", "prepared-gate", nil, mounts, false)
		boundary := slices.Index(args, "--")
		if boundary < 0 {
			t.Fatal("production gate has no command boundary")
		}
		args = args[:boundary]
		if red {
			// This branch exists only in the root test binary. The new user
			// namespace makes its deliberate grant local to this RED process.
			args = append(args, "--uid", "0", "--gid", "0", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE")
		}
		args = append(args, "--", "/runtime/cap-probe", "egress-cap-agent")
		// ro-bind-data consumes its input. Each launch needs its own offset.
		resolver, err := resolverReader(lease.resolv)
		if err != nil {
			t.Fatal(err)
		}
		defer resolver.Close()
		files[len(files)-1] = resolver
		command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
		command.Env, command.ExtraFiles = []string{}, files
		// Match the gate's UID/group drop while exercising its production
		// bwrap and namespace helpers. Installed cgroup wiring is a separate
		// integration scope; this canary measures capability inheritance.
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
		var output, stderr bytes.Buffer
		command.Stdout, command.Stderr = &output, &stderr
		lifetime := newNativeSpawnLifetime()
		if err := startInNetworkNamespacePinned(command, lease.ns, lifetime); err != nil {
			t.Fatalf("capability agent start failed: %v; stderr:\n%s", err, stderr.String())
		}
		err = command.Wait()
		lifetime.observedWait(command.ProcessState)
		<-lifetime.threadDone
		if err != nil {
			t.Fatalf("capability agent failed: %v; stderr:\n%s", err, stderr.String())
		}
		var report laneCapReport
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatal("capability agent returned invalid observations:", err)
		}
		if report.Agent.PID <= 0 || report.Child.PID == report.Agent.PID || report.Child.ParentPID != report.Agent.PID ||
			report.Agent.Namespace != owned || report.Child.Namespace != owned {
			t.Fatal("agent and child did not run in their granted private namespace")
		}
		return report
	}
	red := launch(true)
	for _, item := range []struct {
		name string
		read laneCapRead
	}{{"agent", red.Agent}, {"child", red.Child}} {
		if item.read.Sets["CapEff"]&helperNetBits != helperNetBits {
			t.Fatal("RED did not actually grant both tested capabilities to", item.name)
		}
		if err := rejectHelperNetCaps(item.read); err == nil {
			t.Fatal("capability assertion missed the privileged RED", item.name)
		} else {
			t.Logf("RED %s assertion failed as required: %s", item.name, err)
		}
	}
	green := launch(false)
	for _, item := range []struct {
		name string
		read laneCapRead
	}{{"agent", green.Agent}, {"child", green.Child}} {
		if err := rejectHelperNetCaps(item.read); err != nil {
			t.Fatal("GREEN", item.name, err)
		}
		for _, field := range laneCapFields {
			t.Logf("GREEN %s %s=%016x; helper bits absent", item.name, field, item.read.Sets[field])
		}
	}
	for _, item := range []struct {
		name string
		read laneNetAttempt
	}{{"nft-list", green.NFTList}, {"nft-add", green.NFTAdd}, {"route-add", green.RouteAdd}} {
		if item.name == "nft-list" && item.read.Exit == 0 && strings.TrimSpace(item.read.Stdout) == "" {
			t.Log("GREEN nft-list returned an empty private ruleset")
			continue
		}
		if item.read.Exit == 0 || !strings.Contains(item.read.Stderr, "Operation not permitted") {
			t.Fatalf("GREEN %s did not prove a kernel refusal: exit=%d; stdout:\n%s; stderr:\n%s", item.name, item.read.Exit, item.read.Stdout, item.read.Stderr)
		}
		// Keep exact bytes on one log line so the box summary retains them.
		t.Logf("GREEN %s refused: exit=%d; exact stderr=%q", item.name, item.read.Exit, item.read.Stderr)
	}
}
