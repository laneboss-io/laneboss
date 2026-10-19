//go:build linux

package linux

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const payloadLimit = 1024 * 1024

const payloadSeals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL

func sealedBytes(data []byte) (*os.File, error) {
	if len(data) > payloadLimit {
		return nil, errors.New("bootstrap input exceeds one MiB")
	}
	fd, err := unix.MemfdCreate("laneboss-linux", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "sealed-bootstrap-input")
	if _, err := file.Write(data); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, payloadSeals); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}

func sealedPayload(payload launchPayload) (*os.File, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("cannot encode bootstrap payload")
	}
	return sealedBytes(data)
}

func decodePayload(reader io.Reader) (launchPayload, error) {
	var payload launchPayload
	decoder := json.NewDecoder(io.LimitReader(reader, payloadLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		// JSON may contain selected credentials. Do not include the decoder's
		// text, the original JSON or an offending field/value in this error.
		return payload, errors.New("invalid bootstrap payload")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return payload, errors.New("trailing or oversized bootstrap payload")
	}
	return payload, nil
}

func readSealedPayload(fd int) (launchPayload, error) {
	var payload launchPayload
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		return payload, fmt.Errorf("bootstrap input is not a sealed memfd: %w", err)
	}
	if seals&payloadSeals != payloadSeals {
		return payload, errors.New("bootstrap input lacks required seals")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return payload, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 || stat.Size > payloadLimit {
		return payload, errors.New("invalid bootstrap memfd size or type")
	}
	// Read only this descriptor, never a named payload projection. The file
	// wrapper stays alive until exec; close_range marks it CLOEXEC atomically.
	file := os.NewFile(uintptr(fd), "sealed-bootstrap-input")
	payload, err = decodePayload(file)
	runtime.KeepAlive(file)
	if err != nil {
		return payload, errors.Join(err, file.Close())
	}
	// Close explicitly after decoding, before user code exists. CLOEXEC below
	// still covers all other inherited FDs, including runtime epoll/event FDs.
	return payload, file.Close()
}

func errnoNumber(err error) int {
	if err == nil {
		return 0
	}
	var number unix.Errno
	if errors.As(err, &number) {
		return int(number)
	}
	return -1
}

func namespaces() (map[string]string, error) {
	result := map[string]string{}
	for _, name := range []string{"mnt", "user", "pid", "ipc", "uts", "net"} {
		value, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil {
			return nil, err
		}
		result[name] = value
	}
	return result, nil
}

func effectiveCaps() (uint64, error) {
	data, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	return 0, errors.New("missing effective capability observation")
}

type bootstrapObservation struct {
	Nonce         string            `json:"nonce"`
	ABI           int               `json:"abi"`
	RuleABI       int               `json:"rule_abi"`
	UID           int               `json:"uid"`
	Capabilities  uint64            `json:"capabilities"`
	NoNewPrivs    int               `json:"no_new_privs"`
	Namespaces    map[string]string `json:"namespaces"`
	WriteErrno    int               `json:"write_errno"`
	TruncateErrno int               `json:"truncate_errno"`
	SeccompErrno  int               `json:"seccomp_errno"`
}

func markExecDescriptors() error {
	return unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC)
}

// BootstrapMain is the unprivileged fixed bootstrap dispatch. The composition
// root must call it before ordinary command parsing and terminate the process
// whenever handled is true, including on error. Successful run mode replaces
// this permanently locked thread with exec; failure must never fall through.
// This function is not the privileged UID/cgroup helper or a public argv RPC.
func BootstrapMain() (handled bool, err error) {
	if len(os.Args) < 2 || os.Args[1] != helperFlag {
		return false, nil
	}
	if len(os.Args) != 3 || os.Args[2] != "3" {
		return true, errors.New("bootstrap accepts only its sealed descriptor 3")
	}
	if os.Geteuid() == 0 {
		return true, errors.New("bootstrap must run as an unprivileged lane UID")
	}
	payload, err := readSealedPayload(3)
	if err != nil {
		return true, err
	}
	if payload.Mode == "options" {
		if payload.Nonce == "" || len(payload.Argv) != 0 || len(payload.Environment) != 0 || len(payload.Paths) != 0 {
			return true, errors.New("invalid binary option probe payload")
		}
		caps, err := effectiveCaps()
		if err != nil {
			return true, err
		}
		if caps != 0 {
			return true, errors.New("option probe retained effective capabilities")
		}
		return true, observeBwrapOptions(payload.Nonce)
	}
	if payload.Mode != "run" && payload.Mode != "probe" {
		return true, errors.New("unknown bootstrap mode")
	}
	if payload.Mode == "run" {
		if len(payload.Argv) == 0 || !canonical(payload.Argv[0]) || payload.Argv[0] == "/" ||
			!canonical(payload.CWD) || payload.CWD == "/" {
			return true, errors.New("bootstrap lacks an absolute executable")
		}
		for _, argument := range payload.Argv {
			if strings.ContainsRune(argument, 0) {
				return true, errors.New("NUL in bootstrap argv")
			}
		}
	} else if payload.Nonce == "" || len(payload.Argv) != 0 || len(payload.Environment) != 0 {
		return true, errors.New("invalid probe payload")
	}
	abi, err := landlockABI()
	if err != nil {
		return true, err
	}
	rules, err := BuildRuleset(abi, payload.Paths)
	if err != nil {
		return true, err
	}
	caps, err := effectiveCaps()
	if err != nil {
		return true, err
	}
	if caps != 0 {
		return true, errors.New("bootstrap retained effective capabilities")
	}
	if payload.Mode == "probe" {
		if err := os.WriteFile("/tmp/ll-truncate", []byte("before"), 0600); err != nil {
			return true, err
		}
		for index := range rules.Rules {
			if rules.Rules[index].Path == "/tmp" {
				// Independently observe TRUNCATE, not merely the WRITE_FILE bit
				// or a mask recomputed by the same pure helper.
				rules.Rules[index].AllowedAccess &^= truncate
			}
		}
	}
	runtime.LockOSThread()
	if err := applyLandlock(rules); err != nil {
		return true, err
	}
	if payload.Mode == "probe" {
		openErrno := func(flags int) (int, error) {
			fd, err := unix.Open("/tmp/ll-truncate", flags|unix.O_CLOEXEC, 0)
			if err != nil {
				return errnoNumber(err), nil
			}
			return 0, unix.Close(fd)
		}
		writeErrno, err := openErrno(unix.O_WRONLY)
		if err != nil {
			return true, err
		}
		truncateErrno, err := openErrno(unix.O_WRONLY | unix.O_TRUNC)
		if err != nil {
			return true, err
		}
		ns, err := namespaces()
		if err != nil {
			return true, err
		}
		nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
		if err != nil {
			return true, err
		}
		return true, json.NewEncoder(os.Stdout).Encode(bootstrapObservation{
			Nonce: payload.Nonce, ABI: abi, RuleABI: rules.RuleABI, UID: os.Geteuid(),
			Capabilities: caps, NoNewPrivs: nnp, Namespaces: ns, WriteErrno: writeErrno,
			TruncateErrno: truncateErrno, SeccompErrno: errnoNumber(unix.Unshare(0)),
		})
	}
	// Mark for close-on-exec instead of closing Go's live epoll/event FDs.
	// The kernel closes every inherited descriptor atomically at execve.
	if err := markExecDescriptors(); err != nil {
		return true, fmt.Errorf("mark inherited descriptors CLOEXEC: %w", err)
	}
	if err := unix.Chdir(payload.CWD); err != nil {
		return true, err
	}
	return true, unix.Exec(payload.Argv[0], payload.Argv, payload.Environment)
}
