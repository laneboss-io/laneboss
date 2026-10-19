// Command policy_agent is an explicitly enrolled, credential-free vendor
// fixture. It invokes the installed CLI inside an authentic confinement.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

const queueRoot = ".policy-q"
const startupRoot = "/home/lane/policy-start"

type options struct {
	Config, Client, Binding, Challenge, Life string
	Mode, Driver, Session, Home, History     string
	VendorSession, Model, Effort             string
	Run                                      uint
	WaitMS                                   int64
}

type job struct {
	Kind    string          `json:"kind"`
	Request json.RawMessage `json:"request,omitempty"`
	Key     string          `json:"idempotency_key,omitempty"`
}

type reply struct {
	Exit       int             `json:"exit"`
	TimedOut   bool            `json:"timed_out"`
	Stdout     []byte          `json:"stdout_bytes"`
	Stderr     []byte          `json:"stderr_bytes"`
	Request    json.RawMessage `json:"request"`
	Raw        []byte          `json:"request_bytes"`
	SHA256     string          `json:"request_sha256"`
	Binary     string          `json:"binary_sha256"`
	Config     string          `json:"config"`
	Contract   string          `json:"contract_revision"`
	Key        string          `json:"idempotency_key"`
	Command    []string        `json:"command"`
	CommandRaw *[]byte         `json:"command_file_bytes,omitempty"`
	CommandSum string          `json:"command_file_sha256,omitempty"`
}

var commands = map[string][]string{
	"identity": {"identity", "self"}, "status": {"lane", "status"},
	"list": {"org", "blacklist", "list"}, "hook": {"org", "hook"},
	"propose": {"org", "change", "propose"}, "apply": {"org", "change", "apply"},
	"events": {"event", "tail"}, "blob": {"blob", "read"},
	"brief": {"brief", "start"}, "start": {"lane", "start"},
	"grants": {"grants", "get"}, "begin": {"blob", "begin"},
	"chunk": {"blob", "chunk"}, "commit": {"blob", "commit"},
}

var mutations = map[string]bool{
	"hook": true, "propose": true, "apply": true, "start": true,
	"begin": true, "chunk": true, "commit": true,
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func retain(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	return errors.Join(err, f.Sync(), f.Close())
}

func encode(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := retain(tmp, append(raw, '\n')); err != nil {
		return err
	}
	// Exclusive publication cannot replace an existing reply or retained key.
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return os.Remove(tmp)
}

func privateRead(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	deadline := time.Now().Add(200 * time.Millisecond)
	for ok && owner.Nlink == 2 && time.Now().Before(deadline) {
		// The exclusive publisher is unlinking its temporary name. A lasting
		// alias remains invalid; no CLI runs until publication is complete.
		time.Sleep(time.Millisecond)
		info, err = f.Stat()
		if err != nil {
			return nil, err
		}
		owner, ok = info.Sys().(*syscall.Stat_t)
	}
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || owner.Nlink != 1 ||
		owner.Uid != uint32(os.Geteuid()) || info.Size() <= 0 || info.Size() > 2<<20 {
		return nil, errors.New("worker input must be private and owned by its actual lane UID")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, errors.New("worker input changed length")
	}
	return raw, nil
}

func hookArgs(o options, input json.RawMessage, path string) ([]string, []byte, error) {
	var request api.PolicyEvaluateRequest
	if err := api.DecodeObject(input, &request); err != nil {
		return nil, nil, err
	}
	c := request.Command
	if c.Argv == nil || len(c.Argv) != 0 || c.DeclaredPaths == nil || len(c.DeclaredPaths) != 0 ||
		digest(c.Command) != string(c.RawSHA256) || request.Target.LifeID != api.ID(o.Life) ||
		uint(request.Target.Run) != o.Run || request.LogicalTurnID == "" {
		return nil, nil, errors.New("hook cannot discard data or change the authentic target")
	}
	if err := retain(path, c.Command); err != nil {
		return nil, nil, err
	}
	argv := []string{o.Client, "org", "hook", "--config", o.Config,
		"--command-file", path, "--life-id", string(request.Target.LifeID),
		"--run", fmt.Sprint(request.Target.Run), "--turn-id", string(request.LogicalTurnID),
		"--tool", c.Tool, "--cwd", c.CWD}
	return argv, c.Command, nil
}

func jobArgs(o options, j job, stem string) ([]string, []byte, error) {
	argv := append([]string{o.Client}, commands[j.Kind]...)
	argv = append(argv, "--config", o.Config, "--binding", o.Binding, "--request", stem+".request.json")
	var hook []byte
	if j.Kind == "hook" {
		var err error
		argv, hook, err = hookArgs(o, j.Request, stem+".command")
		if err != nil {
			return nil, nil, err
		}
	}
	if j.Key != "" {
		argv = append(argv, "--idempotency-key="+j.Key)
	}
	return argv, hook, nil
}

func execute(ctx context.Context, o options, j job, stem, binary string) error {
	_, ok := commands[j.Kind]
	if !ok || len(j.Request) == 0 || !json.Valid(j.Request) {
		return errors.New("unknown worker command or absent exact request")
	}
	if mutations[j.Kind] != (j.Key != "") || j.Key != "" &&
		!regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`).MatchString(j.Key) {
		return errors.New("worker mutation lacks its retained key")
	}
	raw := append(append([]byte{}, j.Request...), '\n')
	if err := retain(stem+".request.json", raw); err != nil {
		return err
	}
	argv, hook, err := jobArgs(o, j, stem)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, argv[0], argv[1:]...)
	command.Stdin = bytes.NewReader(nil)
	inherited, err := client.InheritLaneCommand(command, o.Config)
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	startErr := command.Start()
	closeErr := inherited.Close()
	if startErr != nil {
		return errors.Join(startErr, closeErr)
	}
	waitErr := command.Wait()
	result := reply{Exit: command.ProcessState.ExitCode(), TimedOut: bounded.Err() != nil,
		Stdout: append([]byte{}, stdout.Bytes()...), Stderr: append([]byte{}, stderr.Bytes()...),
		Request: j.Request, Raw: raw, SHA256: digest(raw), Binary: binary,
		Config: o.Config, Contract: "v2.0-draft.4", Key: j.Key, Command: argv}
	if hook != nil {
		readback, err := os.ReadFile(stem + ".command")
		if err != nil || !bytes.Equal(readback, hook) {
			return errors.New("hook command bytes changed during execution")
		}
		result.CommandRaw, result.CommandSum = &hook, digest(hook)
	}
	if err := encode(stem+".reply.json", result); err != nil {
		return err
	}
	if result.TimedOut || closeErr != nil || result.Exit != 0 && (j.Kind != "hook" || result.Exit != 2) {
		return errors.Join(waitErr, closeErr, errors.New("installed CLI refused; exact reply retained"))
	}
	return nil
}

func clearQueue(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := filepath.Join(path, entry.Name())
		if entry.Type().IsRegular() {
			if err := os.Remove(name); err != nil {
				return err
			}
		} else if entry.Name() == "control" && entry.IsDir() {
			if err := clearQueue(name); err != nil {
				return err
			}
		} else {
			return errors.New("refuse collection of an unexpected queue entry")
		}
	}
	return os.Remove(path)
}

func sessionFrame(o options, scope api.Scope) (map[string]any, error) {
	if scope.Config != o.Config || scope.Actor.Kind != "lane" || scope.Actor.LifeID != api.ID(o.Life) ||
		scope.LaunchID == "" || o.Session == "" || o.Home == "" || o.History == "" || o.VendorSession == "" ||
		o.Run == 0 || scope.Actor.Level < 3 || scope.Actor.Level > 6 || scope.Actor.Role == "" {
		return nil, errors.New("startup CLI identity differs from the reserved worker session")
	}
	return map[string]any{"type": "serve.session", "vendor_stood_in": true,
		"driver": o.Driver, "session_id": o.Session, "home_id": o.Home, "history_id": o.History,
		"vendor_session_id": o.VendorSession, "identity": scope}, nil
}

func serve(ctx context.Context, o options) error {
	// Stop may arrive before the CLI authenticates this actor. Startup bytes
	// must never become uncommitted project work, even on an early failure.
	if err := os.Mkdir(startupRoot, 0700); err != nil {
		return err
	}
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return errors.New("worker requires its actual launch prompt")
	}
	if err := retain(filepath.Join(startupRoot, "prompt.input"), prompt); err != nil {
		return err
	}
	binaryBytes, err := os.ReadFile(o.Client)
	if err != nil {
		return err
	}
	versionCommand := exec.CommandContext(ctx, o.Client, "--version")
	versionCommand.Stdin = bytes.NewReader(nil)
	version, err := versionCommand.Output()
	if err != nil {
		return err
	}
	var metadata struct {
		Contract string `json:"contract_revision"`
	}
	if json.Unmarshal(version, &metadata) != nil || metadata.Contract != "v2.0-draft.4" {
		return errors.New("installed CLI contract differs")
	}
	// Baseline serve lanes and policy role lanes authenticate by the same
	// installed CLI before any queue label or requested role is considered.
	if err := execute(ctx, o, job{Kind: "identity", Request: json.RawMessage(`{}`)},
		filepath.Join(startupRoot, "startup"), digest(binaryBytes)); err != nil {
		return err
	}
	identityRaw, err := privateRead(filepath.Join(startupRoot, "startup.reply.json"))
	if err != nil {
		return err
	}
	var identityReply reply
	var identity api.Scope
	if json.Unmarshal(identityRaw, &identityReply) != nil || json.Unmarshal(identityReply.Stdout, &identity) != nil {
		return errors.New("installed startup identity is not a typed scope")
	}
	frame, err := sessionFrame(o, identity)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(frame); err != nil {
		return err
	}
	if identity.Actor.Level == 5 && identity.Actor.Role == "supervisor" {
		// Keep the required pre-item L5 lifecycle walk intact and its Git
		// workspace clean. Its service-issued stop is observed independently.
		<-ctx.Done()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	}
	if err := os.Mkdir(queueRoot, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(queueRoot, "control"), 0700); err != nil {
		return err
	}
	indices := map[string]int{"control": 0, "": 0}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	stopped := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if stopped {
			raw, err := privateRead(filepath.Join(queueRoot, "release.json"))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			var release struct {
				Nonce string `json:"nonce"`
			}
			if err != nil || api.DecodeObject(raw, &release) != nil || len(release.Nonce) < 16 {
				return errors.New("outside collector release input missing")
			}
			return clearQueue(queueRoot)
		}
		for _, channel := range []string{"control", ""} {
			stem := filepath.Join(queueRoot, channel, fmt.Sprintf("%04d", indices[channel]))
			raw, err := privateRead(stem + ".job.json")
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			var input job
			if err := api.DecodeObject(raw, &input); err != nil {
				return err
			}
			if input.Kind == "stop" {
				if channel != "" || input.Key != "" || len(input.Request) != 0 {
					return errors.New("invalid collector stop job")
				}
				if err := encode(stem+".reply.json", map[string]bool{"stopped": true}); err != nil {
					return err
				}
				stopped = true
				break
			}
			if err := execute(ctx, o, input, stem, digest(binaryBytes)); err != nil {
				return err
			}
			indices[channel]++
		}
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"program": "laneboss-serve-fixture", "version": "1.0.0", "vendor_stood_in": true,
			"fixture": "policy-role-worker"})
	}
	var o options
	flags := flag.NewFlagSet("policy-role-worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for name, target := range map[string]*string{
		"config": &o.Config, "client": &o.Client, "binding": &o.Binding,
		"challenge": &o.Challenge, "life": &o.Life, "mode": &o.Mode, "driver": &o.Driver,
		"session": &o.Session, "home": &o.Home, "history": &o.History,
		"vendor-session": &o.VendorSession, "model": &o.Model, "effort": &o.Effort,
	} {
		flags.StringVar(target, name, "", "installed fixture selector")
	}
	flags.UintVar(&o.Run, "run", 0, "actual reserved run")
	flags.Int64Var(&o.WaitMS, "wait-ms", 0, "installed wall budget")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || runtime.GOOS != "linux" || os.Geteuid() == 0 ||
		o.Client != "/run/laneboss/client" || o.Binding != "/run/laneboss/binding.json" ||
		o.Mode != "lifecycle" || o.Run == 0 || o.WaitMS <= 0 || o.WaitMS > 300000 ||
		o.Driver != "codex" && o.Driver != "claudock-cli" {
		return errors.New("invalid installed policy worker invocation")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	bounded, stop := context.WithTimeout(ctx, time.Duration(o.WaitMS)*time.Millisecond)
	defer stop()
	return serve(bounded, o)
}

func main() {
	if err := run(); err != nil {
		// Detailed CLI replies remain in the private retained queue.
		fmt.Fprintln(os.Stderr, "policy worker stopped; inspect its retained exact CLI replies")
		os.Exit(1)
	}
}
