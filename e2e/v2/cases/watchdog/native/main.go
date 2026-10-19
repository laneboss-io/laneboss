//go:build linux

// Command native is the declared credential-free watchdog runtime fixture.
// It is native ELF on Linux so the fixed broker usage job can execute the
// same pinned bytes with `usage --max-age 0`. It authenticates no vendor.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"regexp"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type config struct {
	Schema        string `json:"schema"`
	VendorStoodIn bool   `json:"vendor_stood_in"`
	Socket        string `json:"provider_socket"`
	ProviderUID   uint32 `json:"provider_uid"`
	HistoryDir    string `json:"history_dir"`
	Canary        struct {
		File string `json:"file"`
		PID  int    `json:"signal_pid"`
	} `json:"canary"`
}

type options struct {
	Fixture, Config, Client, Binding, Challenge, Life, Mode, Driver string
	Session, Home, History, VendorSession, Model, Effort            string
	Run                                                             uint
	WaitMS                                                          int64
	Version                                                         bool
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func random() (string, error) {
	var value [16]byte
	_, err := rand.Read(value[:])
	return hex.EncodeToString(value[:]), err
}

func encode(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err) // All callers encode fixed JSON data types.
	}
	return append(data, '\n')
}

func emit(value any) error {
	_, err := os.Stdout.Write(encode(value))
	return err
}

func readConfig(path string) (config, error) {
	var value config
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return value, err
	}
	file := os.NewFile(uintptr(fd), "fixture-input")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return value, errors.New("fixture requires its immutable runtime enrollment")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	mapped, _, mappedErr := wire.NamespaceServiceIDs()
	if !ok || identity.Nlink != 1 || identity.Uid != 0 && identity.Uid != uint32(os.Getuid()) &&
		(path != "/runtime/wd-run" || mappedErr != nil || identity.Uid != mapped) {
		return value, errors.New("fixture runtime enrollment has another owner or inode shape")
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return value, err
	}
	data, err = api.CanonicalJSON(data)
	if err != nil {
		return value, errors.New("fixture runtime enrollment is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != "laneboss.wd-runner.v1" || !value.VendorStoodIn || !filepath.IsAbs(value.Socket) ||
		!filepath.IsLocal(value.HistoryDir) || value.HistoryDir == "." {
		return value, errors.New("fixture runtime enrollment differs")
	}
	return value, nil
}

// Read every fragment with kernel credentials, closing any unexpected rights.
// A socket path or a claimed profile is never peer authentication.
func receive(connection *net.UnixConn, peer *syscall.Ucred, length int) ([]byte, error) {
	result := make([]byte, length)
	for offset := 0; offset < length; {
		ancillary := make([]byte, syscall.CmsgSpace(12)+syscall.CmsgSpace(256))
		n, count, flags, _, err := connection.ReadMsgUnix(result[offset:], ancillary)
		if err != nil {
			return nil, err
		}
		messages, err := syscall.ParseSocketControlMessage(ancillary[:count])
		if err != nil || n == 0 || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 {
			return nil, errors.New("fixture response fragment is incomplete")
		}
		valid := 0
		for _, message := range messages {
			if message.Header.Level == syscall.SOL_SOCKET && message.Header.Type == syscall.SCM_RIGHTS {
				fds, parseErr := syscall.ParseUnixRights(&message)
				for _, fd := range fds {
					if closeErr := syscall.Close(fd); closeErr != nil {
						return nil, closeErr
					}
				}
				return nil, errors.Join(errors.New("fixture response transferred descriptors"), parseErr)
			}
			credentials, err := syscall.ParseUnixCredentials(&message)
			if err != nil || *credentials != *peer {
				return nil, errors.New("fixture response writer differs")
			}
			valid++
		}
		if valid != 1 {
			return nil, errors.New("fixture response has no exact kernel writer")
		}
		offset += n
	}
	return result, nil
}

func query(c config, op, profile, cell string) (json.RawMessage, error) {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.Socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *syscall.Ucred
	var nativeErr error
	if err := raw.Control(func(fd uintptr) {
		peer, nativeErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if nativeErr == nil {
			nativeErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
		}
	}); err != nil {
		return nil, err
	}
	if nativeErr != nil || peer == nil || peer.Uid != c.ProviderUID || peer.Pid < 0 ||
		(peer.Pid == 0 && c.Socket != "/runtime/wd-provider.sock") {
		return nil, errors.New("fixture provider kernel peer differs")
	}
	id, err := random()
	if err != nil {
		return nil, err
	}
	request := encode(map[string]any{"schema": "laneboss.wd-provider.v1", "op": op, "profile_id": profile, "cell": cell, "request_id": id})
	frame := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(frame, uint32(len(request)))
	copy(frame[4:], request)
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return nil, err
	}
	header, err := receive(connection, peer, 4)
	if err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > 1<<20 {
		return nil, errors.New("fixture provider reply exceeds its bound")
	}
	data, err := receive(connection, peer, int(size))
	if err != nil {
		return nil, err
	}
	var response struct {
		Schema     string          `json:"schema"`
		RequestID  string          `json:"request_id"`
		Generation uint64          `json:"generation"`
		Result     json.RawMessage `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || response.Schema != "laneboss.wd-provider-reply.v1" || response.RequestID != id || response.Generation == 0 {
		return nil, errors.New("fixture provider correlation differs")
	}
	return response.Result, nil
}

func usage(c config) error {
	data, err := query(c, "usage", "", "")
	if err != nil {
		return err
	}
	var value struct {
		Raw    string `json:"raw"`
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	}
	if json.Unmarshal(data, &value) != nil {
		return errors.New("outside fixture usage reply is malformed")
	}
	raw, err := base64.StdEncoding.DecodeString(value.Raw)
	if err != nil || len(raw) != value.Bytes || digest(raw) != value.SHA256 {
		return errors.New("outside fixture usage bytes changed")
	}
	_, err = os.Stdout.Write(raw)
	return err
}

type history struct {
	Nonce, Cell, Session, Home, History, Vendor, TaskSHA256 string
}

type fixture struct {
	options
	c            config
	root         string
	serial       int
	probeReports []map[string]any
}

func retain(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func (f *fixture) call(method string, params any, refusal bool) (map[string]any, error) {
	f.serial++
	stem := filepath.Join(f.root, fmt.Sprintf("%d-%d", f.Run, f.serial))
	if err := retain(stem+".input", encode(params)); err != nil {
		return nil, err
	}
	id, err := random()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append(strings.Split(method, "."), "--config", f.Config, "--binding", f.Binding, "--request", stem+".input", "--request-id", id, "--idempotency-key", id)
	command := exec.CommandContext(ctx, f.Client, args...)
	command.Stdin = bytes.NewReader(nil)
	command.WaitDelay = time.Second
	inherited, err := client.InheritLaneCommand(command, f.Config)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Start()
	closeErr := inherited.Close()
	if err == nil {
		err = command.Wait()
	}
	exit := -1
	if command.ProcessState != nil {
		exit = command.ProcessState.ExitCode()
	}
	if keepErr := errors.Join(retain(stem+".stdout", stdout.Bytes()), retain(stem+".stderr", stderr.Bytes()), retain(stem+".exit", encode(map[string]int{"exit_code": exit}))); keepErr != nil {
		return nil, keepErr
	}
	if closeErr != nil || ctx.Err() != nil {
		return nil, errors.Join(closeErr, ctx.Err())
	}
	var value map[string]any
	if exit != 0 {
		if refusal && json.Unmarshal(stderr.Bytes(), &value) == nil {
			return value, nil
		}
		return nil, fmt.Errorf("installed CLI %s exited %d; retain exact private stderr", method, exit)
	}
	if err != nil || json.Unmarshal(stdout.Bytes(), &value) != nil || value["error"] != nil {
		return nil, errors.New("fixture CLI returned a malformed result")
	}
	if value["protocol"] == "laneboss.rpc.v2" {
		value, _ = value["result"].(map[string]any)
	}
	if value == nil {
		return nil, errors.New("fixture CLI returned no object")
	}
	return value, nil
}

func (f *fixture) remembered(prompt []byte) (history, error) {
	var h history
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`).MatchString(f.History) {
		return h, errors.New("fixture history selector differs")
	}
	path := filepath.Join(f.root, f.History+".json")
	if f.Run == 1 {
		tokens := regexp.MustCompile(`(?m)^History nonce: ([a-f0-9]{32})$`).FindAllSubmatch(prompt, -1)
		cells := regexp.MustCompile(`(?m)^Cell: (limit|no-room|tamper|stop-race|resume-race|restart)$`).FindAllSubmatch(prompt, -1)
		if len(tokens) != 1 || len(cells) != 1 {
			return h, errors.New("fixture seed lacks one unpredictable task token")
		}
		h = history{Nonce: string(tokens[0][1]), Cell: string(cells[0][1]), Session: f.Session, Home: f.Home, History: f.History, Vendor: f.VendorSession, TaskSHA256: digest(prompt)}
		return h, retain(path, encode(h))
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return h, err
	}
	file := os.NewFile(uintptr(fd), "retained-history")
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 65536 {
		return h, errors.New("fixture retained history shape differs")
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || identity.Nlink != 1 || identity.Uid != uint32(os.Getuid()) {
		return h, errors.New("fixture retained history has another owner or inode shape")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || json.Unmarshal(data, &h) != nil || h.Session != f.Session || h.Home != f.Home || h.History != f.History || h.Vendor != f.VendorSession {
		return h, errors.New("fixture continuation replaced retained history identity")
	}
	return h, nil
}

func (f *fixture) profile() (string, error) {
	lane, err := f.call("lane.status", map[string]any{"life_id": f.Life, "run": f.Run}, false)
	if err != nil {
		return "", err
	}
	grants, err := f.call("grants.get", map[string]any{"grant_set_id": lane["grant_set_id"]}, false)
	if err != nil {
		return "", err
	}
	profiles, _ := grants["profiles"].([]any)
	selected := ""
	for _, raw := range profiles {
		profile, _ := raw.(map[string]any)
		if profile["id"] == lane["profile_grant_id"] && profile["driver"] == f.Driver {
			id, ok := profile["profile_id"].(string)
			if !ok || selected != "" {
				return "", errors.New("fixture selected profile is ambiguous")
			}
			selected = id
		}
	}
	if selected == "" {
		return "", errors.New("fixture has no actual delegated profile")
	}
	return selected, nil
}

func (f *fixture) run(prompt []byte) (int, error) {
	if token := regexp.MustCompile(`(?m)^WD-PROBE ([A-Za-z0-9+/=]+)$`).FindSubmatch(prompt); len(token) == 2 {
		return f.independentProbe(token[1])
	}
	h, err := f.remembered(prompt)
	if err != nil {
		return 1, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	if err := emit(map[string]any{"type": "system", "subtype": "init", "session_id": f.VendorSession, "cwd": cwd}); err != nil {
		return 1, err
	}
	if err := f.emitCheckInput(); err != nil {
		return 1, err
	}
	if f.Run == 1 {
		return 0, emit(map[string]any{"type": "result", "is_error": false, "session_id": f.VendorSession, "result": "Retained history " + h.TaskSHA256})
	}
	profile, err := f.profile()
	if err != nil {
		return 1, err
	}
	deadline, attacked := time.Now().Add(time.Duration(f.WaitMS)*time.Millisecond), false
	for time.Now().Before(deadline) {
		data, err := query(f.c, "poll", profile, h.Cell)
		if err != nil {
			return 1, err
		}
		var measured struct {
			Action   string `json:"action"`
			Used     int64  `json:"used"`
			Capacity int64  `json:"capacity"`
		}
		if json.Unmarshal(data, &measured) != nil || measured.Capacity < 1 || measured.Used < 0 {
			return 1, errors.New("fixture quota counters differ")
		}
		switch measured.Action {
		case "limit":
			if measured.Used < measured.Capacity {
				return 1, errors.New("fixture limit has no observed exhaustion")
			}
			return 1, emit(map[string]any{"type": "result", "subtype": "error_during_execution", "is_error": true, "session_id": f.VendorSession, "result": "Usage limit reached"})
		case "complete":
			return 0, emit(map[string]any{"type": "result", "subtype": "success", "is_error": false, "session_id": f.VendorSession, "result": h.Nonce})
		case "attacks":
			if !attacked {
				if err := f.attacks(); err != nil {
					return 1, err
				}
				attacked = true
			}
		case "wait":
		default:
			return 1, errors.New("fixture provider action differs")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 1, errors.New("fixture turn exceeded its actual wall budget")
}

func execute(args []string) (int, error) {
	var o options
	set := flag.NewFlagSet("watchdog-fixture", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&o.Fixture, "fixture", "/runtime/wd-run", "pinned fixture descriptor")
	set.BoolVar(&o.Version, "version", false, "version")
	for name, value := range map[string]*string{"config": &o.Config, "client": &o.Client, "binding": &o.Binding, "challenge": &o.Challenge, "life": &o.Life, "mode": &o.Mode, "driver": &o.Driver, "session": &o.Session, "home": &o.Home, "history": &o.History, "vendor-session": &o.VendorSession, "model": &o.Model, "effort": &o.Effort} {
		set.StringVar(value, name, "", "reserved launch input")
	}
	set.UintVar(&o.Run, "run", 0, "actual run")
	set.Int64Var(&o.WaitMS, "wait-ms", 0, "remaining wall budget")
	usageMode := len(args) > 0 && args[0] == "usage"
	if usageMode {
		args = args[1:]
		set.Int("max-age", 0, "fresh external measurement")
	}
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 1, errors.New("fixture launch flags differ")
	}
	if o.Version {
		return 0, emit(map[string]any{"program": "laneboss-serve-fixture", "version": "1.0.0", "vendor_stood_in": true})
	}
	c, err := readConfig(o.Fixture)
	if err != nil {
		return 1, err
	}
	if usageMode {
		return 0, usage(c)
	}
	if o.Run == 0 || o.WaitMS < 1 || o.WaitMS > 1800000 || o.Session == "" || o.VendorSession == "" || o.Home == "" || o.Driver != "claudock-cli" && o.Driver != "codex" {
		return 1, errors.New("fixture launch lacks its reserved identity or finite budget")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, err
	}
	root := filepath.Join(home, c.HistoryDir)
	if err := os.MkdirAll(root, 0700); err != nil {
		return 1, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return 1, errors.New("fixture history is not its private home")
	}
	f := fixture{options: o, c: c, root: root}
	if o.Client != "" {
		identity, err := f.call("identity.self", map[string]any{}, false)
		if err != nil {
			return 1, err
		}
		actor, _ := identity["actor"].(map[string]any)
		if actor["kind"] != "lane" {
			return 1, errors.New("fixture has no actual lane identity")
		}
		if actor["level"] == float64(5) {
			original := os.Args
			defer func() { os.Args = original }()
			os.Args = append([]string{}, original...)
			for n := 1; n+1 < len(os.Args); n++ {
				if os.Args[n] == "--wait-ms" && o.WaitMS > 300000 {
					os.Args[n+1] = "300000"
				}
			}
			legacyMain()
			return 0, nil
		}
		if actor["level"] == float64(6) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(o.WaitMS)*time.Millisecond)
			defer cancel()
			return 0, relayRun(ctx, relayOptions{Config: o.Config, Client: o.Client, Binding: o.Binding, Life: o.Life, Session: o.Session, Home: o.Home, History: o.History, Vendor: o.VendorSession,
				Driver: o.Driver, Mode: o.Mode, Model: o.Model, Effort: o.Effort, Challenge: o.Challenge, Run: o.Run, Wait: o.WaitMS})
		}
		if actor["level"] != float64(3) {
			return 1, errors.New("fixture lane level is unsupported")
		}
	}
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return 1, errors.New("fixture prompt exceeds its bound")
	}
	return f.run(prompt)
}

func main() {
	code, err := execute(os.Args[1:])
	if err != nil {
		// Diagnostic errors stay on stderr and cannot become provider limits.
		_, writeErr := os.Stderr.Write(encode(map[string]any{"type": "error", "error": map[string]any{"code": "fixture_failure", "message": err.Error()}}))
		if writeErr != nil || code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}
