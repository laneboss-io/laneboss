//go:build linux

package linux

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

const canaryFlag = "--lb-linux-canary"

var testHelper = flag.String("linux-helper", "", "installed root-owned test bootstrap executable")

// The root-canary build can install its own bootstrap and run this complete
// suite as a non-root account. Ordinary test invocations keep their checks.
var rootSuite func() int

type canaryInput struct {
	Mode                                       string
	Work, ReadOnly, Nested, Outside, Home, Tmp string
	Address                                    string
	EnvironmentName                            string
}

type canaryOutput struct {
	Operations map[string]int    `json:"operations"`
	Hashes     map[string]string `json:"hashes"`
	Namespaces map[string]string `json:"namespaces"`
	NoNewPrivs int               `json:"no_new_privs"`
	Caps       uint64            `json:"capabilities"`
	UID        int               `json:"uid"`
}

func TestMain(m *testing.M) {
	if handled, err := BootstrapMain(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(125)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == canaryFlag {
		if len(os.Args) != 3 {
			os.Exit(126)
		}
		var input canaryInput
		if err := json.Unmarshal([]byte(os.Args[2]), &input); err != nil {
			os.Exit(126)
		}
		if err := runCanary(input); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(126)
		}
		os.Exit(0)
	}
	flag.Parse()
	if os.Geteuid() == 0 && rootSuite != nil {
		os.Exit(rootSuite())
	}
	os.Exit(m.Run())
}

func mmapWrite(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	mapping, err := unix.Mmap(fd, 0, len(data), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	copy(mapping, data)
	return errors.Join(unix.Msync(mapping, unix.MS_SYNC), unix.Munmap(mapping))
}

func shellWriteCommand(path string, data []byte) *exec.Cmd {
	cmd := exec.Command("/bin/sh", "-c", `/bin/cat > "$1"`, "canary", path)
	cmd.Stdin = bytes.NewReader(data)
	return cmd
}

func runCanary(input canaryInput) error {
	if input.Mode == "mount-admission" {
		return runMountAdmission(input)
	}
	result := canaryOutput{Operations: map[string]int{}, Hashes: map[string]string{}, UID: os.Geteuid()}
	var err error
	result.Namespaces, err = namespaces()
	if err != nil {
		return err
	}
	result.Caps, err = effectiveCaps()
	if err != nil {
		return err
	}
	result.NoNewPrivs, err = unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if input.Mode == "stream" {
		result.Operations["stdout.truncate"] = errnoNumber(unix.Ftruncate(1, 0))
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if input.Mode == "cloexec" {
		fd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
		if err != nil {
			return err
		}
		before, beforeErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		result.Operations["flags.before"] = before
		result.Operations["fcntl.before"] = errnoNumber(beforeErr)
		result.Operations["sweep"] = errnoNumber(markExecDescriptors())
		after, afterErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		result.Operations["flags.after"] = after
		result.Operations["fcntl.after"] = errnoNumber(afterErr)
		var sent, received [8]byte
		if _, err := rand.Read(sent[:7]); err != nil {
			return err
		}
		sent[0] |= 1 // a nonzero event count strictly below the overflow value
		_, writeErr := unix.Write(fd, sent[:])
		_, readErr := unix.Read(fd, received[:])
		result.Operations["event.write"] = errnoNumber(writeErr)
		result.Operations["event.read"] = errnoNumber(readErr)
		result.Operations["event.close"] = errnoNumber(unix.Close(fd))
		sentHash, receivedHash := sha256.Sum256(sent[:]), sha256.Sum256(received[:])
		result.Hashes["sent"] = hex.EncodeToString(sentHash[:])
		result.Hashes["received"] = hex.EncodeToString(receivedHash[:])
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if input.EnvironmentName != "" {
		if value, exists := os.LookupEnv(input.EnvironmentName); exists {
			hash := sha256.Sum256([]byte(value))
			result.Hashes["selected"] = hex.EncodeToString(hash[:])
		}
	}
	seed, err := os.ReadFile(filepath.Join(input.Work, "seed"))
	if err != nil {
		return err
	}
	payload := append(append([]byte{}, seed...), []byte(":written")...)
	result.Operations["work.write"] = errnoNumber(os.WriteFile(filepath.Join(input.Work, "written"), payload, 0600))
	result.Operations["work.mmap"] = errnoNumber(mmapWrite(filepath.Join(input.Work, "written"), payload))
	result.Operations["work.shell"] = exitNumber(shellWriteCommand(filepath.Join(input.Work, "shell"), payload).Run())
	result.Operations["home.write"] = errnoNumber(os.WriteFile(filepath.Join(input.Home, "proof"), payload, 0600))
	result.Operations["tmp.write"] = errnoNumber(os.WriteFile(filepath.Join(input.Tmp, "proof"), payload, 0600))
	for _, item := range []struct{ name, path string }{{"readonly", input.ReadOnly}, {"nested", input.Nested}, {"outside", input.Outside}} {
		data, err := os.ReadFile(item.path)
		result.Operations[item.name+".read"] = errnoNumber(err)
		if err == nil {
			hash := sha256.Sum256(data)
			result.Hashes[item.name] = hex.EncodeToString(hash[:])
		}
		result.Operations[item.name+".write"] = errnoNumber(os.WriteFile(item.path, payload, 0600))
		result.Operations[item.name+".mmap"] = errnoNumber(mmapWrite(item.path, payload))
		result.Operations[item.name+".truncate"] = errnoNumber(os.Truncate(item.path, 0))
	}
	result.Operations["outside.link"] = errnoNumber(os.Link(input.Outside, filepath.Join(input.Work, "outside-link")))
	buffer := make([]byte, 64)
	n, fdErr := unix.Pread(200, buffer, 0)
	result.Operations["inherited.read"] = errnoNumber(fdErr)
	if fdErr == nil {
		hash := sha256.Sum256(buffer[:n])
		result.Hashes["inherited"] = hex.EncodeToString(hash[:])
	}
	if input.Address != "" {
		result.Operations["own.tcp4"] = errnoNumber(ownLoopback("tcp4", "127.0.0.1:0", seed))
		result.Operations["own.tcp6"] = errnoNumber(ownLoopback("tcp6", "[::1]:0", seed))
		connection, err := net.DialTimeout("tcp", input.Address, time.Second)
		result.Operations["host.connect"] = errnoNumber(err)
		if err == nil {
			if err := connection.Close(); err != nil {
				return err
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func exitNumber(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

func saveBytes(t *testing.T, directory, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func saveJSON(t *testing.T, directory, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	saveBytes(t, directory, name, append(data, '\n'))
}

func kernelFixture(t *testing.T) (string, sandboxSpec, []byte) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("run kernel tests as the disposable non-root test account")
	}
	helper := *testHelper
	if helper == "" {
		var err error
		helper, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := safeSystemPath(helper); err != nil {
		t.Fatal("install the test binary into a root-owned path first:", err)
	}
	directory, err := os.MkdirTemp("/var/tmp", "lb-v2-linux-tests-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("retained Linux diagnostic evidence:", directory)
	binary, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	saveBytes(t, directory, "linux.test", binary)
	saveJSON(t, directory, "binary.json", map[string]any{"sha256": hex.EncodeToString(hash[:]), "bytes": len(binary)})
	var seed [33]byte
	if _, err := rand.Read(seed[:32]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"work", "readonly", "nested", "outside", "home", "tmp", "state"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"work/seed", "readonly/record", "nested/record", "outside/record", "state/record"} {
		if err := os.WriteFile(filepath.Join(directory, name), seed[:], 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	spec := sandboxSpec{Helper: helper, HelperSHA256: api.Digest(hex.EncodeToString(hash[:])),
		Worktree: filepath.Join(directory, "work"), StatePaths: []string{filepath.Join(directory, "state")},
		UIDPool: []IDRange{{First: uint32(os.Geteuid()), Last: uint32(os.Geteuid())}},
		GIDPool: []IDRange{{First: uint32(os.Getegid()), Last: uint32(os.Getegid())}}}
	return directory, spec, seed[:]
}

func canaryArgs(t *testing.T, executable string, input canaryInput) []string {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return []string{executable, canaryFlag, string(data)}
}

func TestKernelProbeTruncateAndSeccomp(t *testing.T) {
	directory, spec, _ := kernelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	facts, err := measureHost(ctx)
	saveJSON(t, directory, "host.json", facts)
	if err != nil {
		t.Fatal("required prerequisites (no skips):", err)
	}
	// Actual unrestricted controls, before any rule installation.
	control := filepath.Join(directory, "outside/record")
	fd, err := unix.Open(control, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("truncation control failed:", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unshare(0); err != nil {
		t.Fatal("seccomp unrestricted control failed:", err)
	}
	spec.Argv = []string{helperPath}
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	payload.Mode, payload.Argv, payload.Environment = "probe", nil, nil
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	payload.Nonce = hex.EncodeToString(challenge[:])
	var stdout, stderr bytes.Buffer
	spec.Stdout, spec.Stderr = &stdout, &stderr
	cmd, tail, err := startSandbox(ctx, plan, payload, spec)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	saveBytes(t, directory, "probe.stdout", stdout.Bytes())
	saveBytes(t, directory, "probe.stderr", stderr.Bytes())
	saveJSON(t, directory, "probe.exit.json", map[string]int{"exit": exitNumber(waitErr)})
	if waitErr != nil {
		t.Fatalf("boundary probe failed: %v; stderr tail: %s", waitErr, tail.bytes())
	}
	var observed bootstrapObservation
	if err := json.Unmarshal(stdout.Bytes(), &observed); err != nil {
		t.Fatal("missing actual probe observations:", err)
	}
	if observed.Nonce != payload.Nonce || observed.ABI != facts.LandlockABI ||
		observed.WriteErrno != 0 || observed.TruncateErrno != int(unix.EACCES) ||
		observed.SeccompErrno != int(unix.EPERM) || observed.NoNewPrivs != 1 ||
		observed.Capabilities != 0 || observed.UID != os.Geteuid() {
		t.Fatal("real truncate/seccomp/identity observation mismatch")
	}
	hostNS, err := namespaces()
	if err != nil {
		t.Fatal(err)
	}
	for name, host := range hostNS {
		if observed.Namespaces[name] == "" || observed.Namespaces[name] == host {
			t.Fatalf("namespace %s did not change", name)
		}
	}
}

func TestKernelLayoutAndNestedLandlock(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	host := canaryInput{Work: spec.Worktree, ReadOnly: filepath.Join(directory, "readonly/record"),
		Nested: filepath.Join(directory, "nested/record"), Outside: filepath.Join(directory, "outside/record"),
		Home: filepath.Join(directory, "home"), Tmp: filepath.Join(directory, "tmp")}
	fixtureFD, err := os.Open(filepath.Join(directory, "state/record"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixtureFD.Close()
	// Dup3(flags=0) deliberately introduces a real non-CLOEXEC fixture at
	// descriptor 200. This test is serial. Its unrestricted control must read
	// the planted bytes before EBADF is a meaningful restricted observation.
	if _, err := unix.FcntlInt(200, unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("descriptor 200 was already in use")
	}
	if err := unix.Dup3(int(fixtureFD.Fd()), 200, 0); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(200)
	control := exec.CommandContext(ctx, spec.Helper, canaryArgs(t, spec.Helper, host)[1:]...)
	control.Env = []string{"PATH=/usr/bin:/bin"}
	controlBytes, err := control.Output()
	saveBytes(t, directory, "control.stdout", controlBytes)
	if err != nil {
		t.Fatal("unrestricted syscall control failed:", err)
	}
	var before canaryOutput
	if err := json.Unmarshal(controlBytes, &before); err != nil {
		t.Fatal(err)
	}
	for name, value := range before.Operations {
		if value != 0 {
			t.Fatalf("unrestricted %s failed with %d", name, value)
		}
	}
	expectedHash := sha256.Sum256(seed)
	if before.Hashes["inherited"] != hex.EncodeToString(expectedHash[:]) {
		t.Fatal("inherited descriptor control read wrong bytes")
	}
	for _, path := range []string{host.ReadOnly, host.Nested, host.Outside} {
		if err := os.WriteFile(path, seed, 0644); err != nil {
			t.Fatal(err)
		}
	}
	spec.Grants = []exportSpec{{Source: filepath.Join(directory, "readonly"), Target: "/data/input", Access: ReadOnly}}
	input := canaryInput{Work: "/work/main", ReadOnly: "/data/input/record", Nested: "/data/nested/record",
		Outside: host.Outside, Home: privateHome, Tmp: "/tmp", EnvironmentName: "LB_SELECTED"}
	selected := hex.EncodeToString(seed)
	spec.Environment = []string{"LB_SELECTED=" + selected}
	spec.Argv = canaryArgs(t, helperPath, input)
	// The unrestricted hardlink is an intentional red control. Remove it
	// before materialization so the candidate contains no external hardlink.
	if err := os.Remove(filepath.Join(spec.Worktree, "outside-link")); err != nil {
		t.Fatal(err)
	}
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	// Mount the negative target WRITABLE. Only its Landlock rule is RO, so
	// EACCES cannot be credited to a read-only mount returning EROFS.
	nested, err := pinPath(filepath.Join(directory, "nested"), "/data/nested", false)
	if err != nil {
		t.Fatal(err)
	}
	plan.data = append(plan.data, nested)
	payload.Paths = append(payload.Paths, PathAccess{Path: "/data/nested", Directory: true, Access: ReadOnly})
	// Same pinned writable mount, same seccomp and namespaces, but no
	// Landlock bootstrap. The canary must really change the nested object and
	// read the leaked fixture FD before the candidate may claim either denial.
	controlPayload, err := sealedPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := denyFilter()
	if err != nil {
		t.Fatal(err)
	}
	controlFilter, err := sealedBytes(filterBytes(filter))
	if err != nil {
		t.Fatal(err)
	}
	controlArgs, mounts := buildArgs(plan)
	controlArgs = append(controlArgs[:len(controlArgs)-3], canaryArgs(t, helperPath, input)...)
	namespaceControl := exec.CommandContext(ctx, bwrapPath, controlArgs...)
	namespaceControl.Env = []string{}
	namespaceControl.ExtraFiles = append([]*os.File{controlPayload, controlFilter}, mounts...)
	var controlStderr bytes.Buffer
	namespaceControl.Stderr = &controlStderr
	controlOutput, controlErr := namespaceControl.Output()
	closeErr := errors.Join(controlPayload.Close(), controlFilter.Close())
	saveBytes(t, directory, "namespace-control.stdout", controlOutput)
	saveBytes(t, directory, "namespace-control.stderr", controlStderr.Bytes())
	saveJSON(t, directory, "namespace-control.exit.json", map[string]int{"exit": exitNumber(controlErr)})
	if err := errors.Join(controlErr, closeErr); err != nil {
		t.Fatal("namespace-only control failed:", err)
	}
	var unrestricted canaryOutput
	if err := json.Unmarshal(controlOutput, &unrestricted); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nested.read", "nested.write", "nested.mmap", "nested.truncate", "inherited.read"} {
		value, exists := unrestricted.Operations[name]
		if !exists || value != 0 {
			t.Fatalf("namespace-only %s control failed", name)
		}
	}
	if unrestricted.Hashes["inherited"] != hex.EncodeToString(expectedHash[:]) {
		t.Fatal("namespace control did not read planted FD bytes")
	}
	if err := os.WriteFile(host.Nested, seed, 0644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	spec.Stdout, spec.Stderr = &stdout, &stderr
	cmd, tail, err := startSandbox(ctx, plan, payload, spec)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	saveBytes(t, directory, "sandbox.stdout", stdout.Bytes())
	saveBytes(t, directory, "sandbox.stderr", stderr.Bytes())
	saveJSON(t, directory, "sandbox.exit.json", map[string]int{"exit": exitNumber(waitErr)})
	if waitErr != nil {
		t.Fatalf("sandbox canary failed: %v; stderr tail: %s", waitErr, tail.bytes())
	}
	var got canaryOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"work.write": 0, "work.mmap": 0, "work.shell": 0, "home.write": 0, "tmp.write": 0,
		"readonly.read": 0, "readonly.write": int(unix.EROFS), "readonly.mmap": int(unix.EROFS), "readonly.truncate": int(unix.EROFS),
		"nested.read": 0, "nested.write": int(unix.EACCES), "nested.mmap": int(unix.EACCES), "nested.truncate": int(unix.EACCES),
		"outside.read": int(unix.ENOENT), "outside.write": int(unix.ENOENT), "outside.mmap": int(unix.ENOENT),
		"outside.truncate": int(unix.ENOENT), "outside.link": int(unix.ENOENT), "inherited.read": int(unix.EBADF)}
	if !reflect.DeepEqual(got.Operations, want) {
		t.Fatalf("actual syscall observations differ: %v", got.Operations)
	}
	selectedHash := sha256.Sum256([]byte(selected))
	if got.Hashes["selected"] != hex.EncodeToString(selectedHash[:]) {
		t.Fatal("selected environment bytes changed at exec")
	}
	for _, path := range []string{host.ReadOnly, host.Nested, host.Outside} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, seed) {
			t.Fatal("outside observer found modified bytes")
		}
	}
	payloadBytes := append(append([]byte{}, seed...), []byte(":written")...)
	for _, name := range []string{"written", "shell"} {
		actual, err := os.ReadFile(filepath.Join(spec.Worktree, name))
		if err != nil || !bytes.Equal(actual, payloadBytes) {
			t.Fatal("binary work/shell positive control failed")
		}
	}
}

func ownLoopback(network, address string, payload []byte) error {
	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	if tcp, ok := listener.(*net.TCPListener); ok {
		if err := tcp.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
	}
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			done <- errors.Join(err, connection.Close())
			return
		}
		data := make([]byte, len(payload))
		_, readErr := io.ReadFull(connection, data)
		_, writeErr := connection.Write(data)
		done <- errors.Join(readErr, writeErr, connection.Close())
	}()
	connection, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
	if err != nil {
		return errors.Join(err, listener.Close(), <-done)
	}
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return errors.Join(err, connection.Close(), <-done)
	}
	_, writeErr := connection.Write(payload)
	data := make([]byte, len(payload))
	_, readErr := io.ReadFull(connection, data)
	err = errors.Join(writeErr, readErr, connection.Close(), <-done)
	if err == nil && !bytes.Equal(data, payload) {
		err = errors.New("own loopback changed canary bytes")
	}
	return err
}

func TestKernelPrivateNetwork(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal("host listener unrestricted control failed:", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	input := canaryInput{Work: "/work/main", ReadOnly: "/data/input/record", Nested: "/data/output/record",
		Outside: filepath.Join(directory, "outside/record"), Home: privateHome, Tmp: "/tmp",
		Address: listener.Addr().String()}
	spec.Grants = []exportSpec{
		{Source: filepath.Join(directory, "readonly"), Target: "/data/input", Access: ReadOnly},
		{Source: filepath.Join(directory, "nested"), Target: "/data/output", Access: ReadWrite}}
	spec.Argv = canaryArgs(t, helperPath, input)
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	var stdout bytes.Buffer
	spec.Stdout = &stdout
	cmd, tail, err := startSandbox(ctx, plan, payload, spec)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	saveBytes(t, directory, "network.stdout", stdout.Bytes())
	saveBytes(t, directory, "network.stderr", tail.bytes())
	if waitErr != nil {
		t.Fatal("private network canary failed:", waitErr)
	}
	var got canaryOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	value, exists := got.Operations["host.connect"]
	if !exists || (value != int(unix.ECONNREFUSED) && value != int(unix.ENETUNREACH) &&
		value != int(unix.EHOSTUNREACH) && value != int(unix.EPERM) && value != int(unix.EACCES)) {
		t.Fatal("host-loopback boundary did not produce a network denial")
	}
	for _, name := range []string{"own.tcp4", "own.tcp6"} {
		value, exists := got.Operations[name]
		if !exists || value != 0 {
			t.Fatal("private loopback control failed")
		}
	}
	outside, err := os.ReadFile(filepath.Join(directory, "outside/record"))
	if err != nil || !bytes.Equal(outside, seed) {
		t.Fatal("network fixture outside bytes changed")
	}
	spec.Network = true
	_, _, err = prepareSandbox(spec)
	var refused *PrerequisiteError
	if !errors.As(err, &refused) || refused.Check != "controlled_egress" {
		t.Fatal("network-on without lease did not refuse")
	}
}

func TestBinaryStdinShellControl(t *testing.T) {
	data := make([]byte, 256)
	for index := range data {
		data[index] = byte(index)
	}
	target := filepath.Join(t.TempDir(), "binary")
	bad := exec.Command("/bin/sh", "-c", `printf %s "$1" > "$2"`, "canary", string(data), target)
	if err := bad.Run(); !errors.Is(err, unix.EINVAL) {
		t.Fatal("NUL argv red control did not fail")
	}
	if err := shellWriteCommand(target, data).Run(); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("stdin did not preserve all byte values")
	}
}

func TestKernelMountedSourceSwap(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	input := canaryInput{Work: "/work/main", ReadOnly: "/data/input/record", Nested: "/data/output/record",
		Outside: filepath.Join(directory, "outside/record"), Home: privateHome, Tmp: "/tmp"}
	spec.Argv = canaryArgs(t, helperPath, input)
	spec.Grants = []exportSpec{
		{Source: filepath.Join(directory, "readonly"), Target: "/data/input", Access: ReadOnly},
		{Source: filepath.Join(directory, "nested"), Target: "/data/output", Access: ReadWrite}}
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	moved := filepath.Join(directory, "pinned-work")
	if err := os.Rename(spec.Worktree, moved); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(directory, "state")
	var replacement [33]byte
	if _, err := rand.Read(replacement[:]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "seed"), replacement[:], 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, spec.Worktree); err != nil {
		t.Fatal(err)
	}
	// A pathname-based bind would now execute against the independently
	// planted state seed, and its real write would alter state/written.
	controlSeed, err := os.ReadFile(filepath.Join(spec.Worktree, "seed"))
	if err != nil || !bytes.Equal(controlSeed, replacement[:]) {
		t.Fatal("replacement-name control did not redirect")
	}
	var stdout bytes.Buffer
	spec.Stdout = &stdout
	cmd, tail, err := startSandbox(ctx, plan, payload, spec)
	if err != nil {
		t.Fatal(err)
	}
	waitErr := cmd.Wait()
	saveBytes(t, directory, "swap.stdout", stdout.Bytes())
	saveBytes(t, directory, "swap.stderr", tail.bytes())
	if waitErr != nil {
		t.Fatal("mounted-swap operation failed before observation:", waitErr)
	}
	var observed canaryOutput
	if err := json.Unmarshal(stdout.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if value, exists := observed.Operations["work.write"]; !exists || value != 0 {
		t.Fatal("pinned work write did not actually succeed")
	}
	got, err := os.ReadFile(filepath.Join(moved, "written"))
	want := append(append([]byte{}, seed...), []byte(":written")...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("mounted source followed a replacement name")
	}
	if _, err := os.Lstat(filepath.Join(state, "written")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("replacement state was modified")
	}
	got, err = os.ReadFile(filepath.Join(state, "seed"))
	if err != nil || !bytes.Equal(got, replacement[:]) {
		t.Fatal("replacement state bytes changed")
	}
}

func TestKernelFileStreamRefusal(t *testing.T) {
	directory, spec, seed := kernelFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	statePath := filepath.Join(directory, "state/record")
	state, err := os.OpenFile(statePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	input := canaryInput{Mode: "stream"}
	control := exec.CommandContext(ctx, spec.Helper, canaryArgs(t, spec.Helper, input)[1:]...)
	control.Stdout = state
	control.Env = []string{}
	if err := control.Run(); err != nil {
		t.Fatal("raw file-stream control failed:", err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var observed canaryOutput
	if err := json.Unmarshal(data, &observed); err != nil {
		t.Fatal("raw-stream syscall observation missing:", err)
	}
	if value, exists := observed.Operations["stdout.truncate"]; !exists || value != 0 || bytes.Equal(data, seed) {
		t.Fatal("raw stream did not really truncate/change its file")
	}
	saveBytes(t, directory, "stream-control.json", data)
	if err := os.WriteFile(statePath, seed, 0644); err != nil {
		t.Fatal(err)
	}
	spec.Argv = canaryArgs(t, helperPath, input)
	plan, payload, err := prepareSandbox(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.close()
	spec.Stdout = state
	cmd, _, refused := startSandbox(ctx, plan, payload, spec)
	if cmd != nil {
		waitErr := cmd.Wait()
		saveJSON(t, directory, "stream-mutant-exit.json", map[string]int{"exit": exitNumber(waitErr)})
		t.Fatal("file-backed stream reached the runner")
	}
	if refused == nil || !strings.Contains(refused.Error(), "stdout stream") {
		t.Fatal("raw file stream was not refused by name")
	}
	data, err = os.ReadFile(statePath)
	if err != nil || !bytes.Equal(data, seed) {
		t.Fatal("refused stream changed protected bytes")
	}
}

func TestCloexecLeavesRuntimeFDsLive(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, canaryArgs(t, self, canaryInput{Mode: "cloexec"})[1:]...)
	cmd.Env = []string{}
	output, err := cmd.Output()
	if err != nil {
		t.Fatal("CLOEXEC observation process failed:", err)
	}
	var observed canaryOutput
	if err := json.Unmarshal(output, &observed); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"flags.before": 0, "fcntl.before": 0,
		"sweep": 0, "flags.after": unix.FD_CLOEXEC, "fcntl.after": 0,
		"event.write": 0, "event.read": 0, "event.close": 0}
	if !reflect.DeepEqual(observed.Operations, want) || observed.Hashes["sent"] == "" ||
		observed.Hashes["sent"] != observed.Hashes["received"] {
		t.Fatal("descriptor sweep closed a live FD or lost CLOEXEC")
	}
}
