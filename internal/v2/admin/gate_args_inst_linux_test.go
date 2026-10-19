//go:build linux && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "admin-bwrap-descriptors" {
		payload, err := readBootstrapInput()
		if err != nil || os.Geteuid() == 0 {
			os.Exit(61)
		}
		var release, control unix.Stat_t
		if unix.Fstat(4, &release) != nil || release.Mode&unix.S_IFMT != unix.S_IFIFO ||
			unix.Fstat(5, &control) != nil || control.Mode&unix.S_IFMT != unix.S_IFSOCK {
			os.Exit(62)
		}
		marker := os.NewFile(6, "inherited-marker")
		data := make([]byte, len(payload.Token))
		if n, err := marker.ReadAt(data, 0); err != nil || n != len(data) || string(data) != payload.Token {
			os.Exit(63)
		}
		execErr := executePreparedGate(payload)
		runtime.KeepAlive(marker)
		if execErr != nil {
			os.Exit(64)
		}
		os.Exit(65)
	}
	if len(os.Args) == 5 && os.Args[1] == "admin-bwrap-vendor" {
		device, devErr := strconv.ParseUint(os.Args[3], 10, 64)
		inode, inoErr := strconv.ParseUint(os.Args[4], 10, 64)
		if devErr != nil || inoErr != nil || os.Geteuid() == 0 {
			os.Exit(66)
		}
		var actual unix.Stat_t
		statErr := unix.Fstat(6, &actual)
		if statErr != nil && !errors.Is(statErr, unix.EBADF) || statErr == nil && uint64(actual.Dev) == device && actual.Ino == inode {
			os.Exit(67)
		}
		input, err := os.ReadFile(workerInputPath)
		seals, sealErr := unix.FcntlInt(8, unix.F_GET_SEALS, 0)
		if err != nil || sealErr != nil || seals&bootstrapSeals != bootstrapSeals || string(input) != os.Args[2] {
			os.Exit(69)
		}
		if lanePrivateProc() != nil {
			os.Exit(75)
		}
		connection, err := net.DialTimeout("unix", "/runtime/laneboss-worker.sock", time.Second)
		if err != nil {
			os.Exit(70)
		}
		if n, err := connection.Write([]byte(os.Args[2])); err != nil || n != len(os.Args[2]) {
			os.Exit(71)
		}
		if err := connection.Close(); err != nil {
			os.Exit(72)
		}
		if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
			os.Exit(68)
		}
		os.Exit(0)
	}
}

func TestNativeBwrapDescriptorInheritance(t *testing.T) {
	binary, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal("descriptor canary executable could not be inspected")
	}
	dynamic := false
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	if err := binary.Close(); err != nil || dynamic {
		t.Fatal("descriptor canary requires its retained static CGO_ENABLED=0 build")
	}
	if err := verifyBwrap(); err != nil {
		t.Fatal(err)
	}
	marker, err := os.CreateTemp(privateTestDir(t), "inherited-")
	if err != nil {
		t.Fatal(err)
	}
	defer marker.Close()
	token, err := randomID("bwrap-fds-")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := marker.WriteString(string(token)); err != nil || n != len(token) {
		t.Fatal("descriptor fixture input was not retained")
	}
	var info unix.Stat_t
	if err := unix.Fstat(int(marker.Fd()), &info); err != nil {
		t.Fatal(err)
	}
	payload := gatePayload{Token: string(token), Argv: []string{fixedBootstrapPath, "admin-bwrap-vendor", string(token),
		strconv.FormatUint(uint64(info.Dev), 10), strconv.FormatUint(info.Ino, 10)}, Environment: []string{},
		Paths:     []bootstrapPath{},
		Inherited: []bootstrapDescriptor{{FD: 8, Target: workerInputPath}, {FD: 9, Target: "/runtime/laneboss-worker.sock", Socket: true}}}
	sealed, err := sealedBootstrap(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	if n, err := releaseWrite.WriteString(string(token)); err != nil || n != len(token) {
		t.Fatal(err)
	}
	if err := releaseWrite.Close(); err != nil {
		t.Fatal(err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := os.NewFile(uintptr(pair[0]), "control-owner"), os.NewFile(uintptr(pair[1]), "control-child")
	defer parent.Close()
	defer child.Close()
	stageID, err := randomID("laneboss-fd-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join("/run", string(stageID))
	if err := createLaneStage(stagePath, 65534); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stagePath)
	selfBytes, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	stagedBinary := filepath.Join(stagePath, "canary")
	if err := os.WriteFile(stagedBinary, selfBytes, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stagedBinary, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stagedBinary)
	executable, err := os.Open(stagedBinary)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	immutable, err := sealWorkerInput([]byte(token), api.BlobRef{ID: "descriptor-input", SHA256: digestBytes([]byte(token)), Bytes: int64(len(token)), Class: "materialize_input"})
	if err != nil {
		t.Fatal(err)
	}
	defer immutable.Close()
	socketPath := filepath.Join(privateTestDir(t), "private.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0666); err != nil {
		t.Fatal(err)
	}
	socketFD, err := unix.Open(socketPath, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket := os.NewFile(uintptr(socketFD), "private-socket-pin")
	defer socket.Close()
	connected := make(chan bool, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			connected <- false
			return
		}
		if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			connection.Close()
			connected <- false
			return
		}
		data, readErr := io.ReadAll(io.LimitReader(connection, int64(len(token))+1))
		closeErr := connection.Close()
		connected <- readErr == nil && closeErr == nil && string(data) == string(token)
	}()
	args, files := nativeGateArgs("descriptor-fixture", "prepared-gate", []*os.File{sealed, releaseRead, child, marker},
		[]*nativeMount{{file: executable, target: fixedBootstrapPath, executable: true}, {file: immutable, target: workerInputPath, sealed: true}, {file: socket, target: "/runtime/laneboss-worker.sock", socket: true}}, true)
	// Retain every production option. Only the final internal command selects
	// this real descriptor canary instead of claiming a prepared service gate.
	for index, arg := range args {
		if arg == "--" {
			args = append(args[:index+2], "admin-bwrap-descriptors")
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := unprivilegedBwrapCommand(ctx, args...)
	cmd.ExtraFiles = files
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil || !bytes.Equal(stdout.Bytes(), []byte(token)) {
		if classifyBwrapStderr(stderr.Bytes()) == "mount_source_unavailable" {
			t.Fatal("acceptance: actual bwrap attempted an unresolved descriptor bind source")
		}
		var exited *exec.ExitError
		if errors.As(err, &exited) && exited.ExitCode() == 75 {
			t.Fatal("acceptance: actual bwrap exposed ancestor procfs")
		}
		t.Fatalf("acceptance: actual bwrap lost inherited controls or leaked them through vendor exec (%s; stderr=%s)", nativeReadinessWait(cmd.ProcessState), classifyBwrapStderr(stderr.Bytes()))
	}
	if !<-connected {
		t.Fatal("acceptance: actual bwrap lost its pinned worker socket descriptor")
	}
}
