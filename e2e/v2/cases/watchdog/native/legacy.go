//go:build linux

// Command serve-fixture stands in only for a vendor executable. Every product
// observation is obtained by invoking the installed CLI inside the real lane.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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

	"laneboss.io/laneboss/internal/v2/client"
)

const legacyProgram = "laneboss-serve-fixture"
const legacyVersion = "1.0.0"

type legacyOptions struct {
	Config, Client, Binding, Challenge, Life, Mode, Driver string
	Session, Home, History, VendorSession, Model, Effort   string
	Run                                                    uint
	WaitMS                                                 int64
}

type legacyCallRecord struct {
	Name     string   `json:"name"`
	Argv     []string `json:"argv"`
	Request  string   `json:"request"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	Started  bool     `json:"started"`
	TimedOut bool     `json:"timed_out"`
	ExitCode int      `json:"exit_code"`
}

type legacyTranscript struct {
	Schema        string             `json:"schema"`
	Program       string             `json:"program"`
	Version       string             `json:"version"`
	VendorStoodIn bool               `json:"vendor_stood_in"`
	Config        string             `json:"config"`
	Challenge     string             `json:"challenge"`
	Life          string             `json:"life"`
	Run           uint               `json:"run"`
	UID           int                `json:"uid"`
	Calls         []legacyCallRecord `json:"calls"`
	StoppedAt     string             `json:"stopped_at,omitempty"`
}

type legacyFixture struct {
	legacyOptions
	log legacyTranscript
}

func legacyWrite(name string, data []byte) error {
	file, err := os.OpenFile(filepath.Join("serve-state", name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Sync(), file.Close())
}

func legacyEncode(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	return append(data, '\n'), err
}

func (f *legacyFixture) call(ctx context.Context, name string, words []string, request any, mutation bool, expected int) (map[string]any, error) {
	requestName, requestID := name, name
	if name == "retry" {
		requestName = "append"
	}
	if name == "unready" {
		requestName = "identity"
	}
	if name == "retry" || name == "changed" {
		requestID = "append"
	}
	file := requestName + ".request.json"
	if requestName == name {
		data, err := legacyEncode(request)
		if err != nil {
			return nil, err
		}
		if err := legacyWrite(file, data); err != nil {
			return nil, err
		}
	}
	argv := append([]string{f.Client}, words...)
	argv = append(argv, "--config", f.Config, "--binding", f.Binding, "--request", "serve-state/"+file,
		"--request-id", f.Challenge+"-"+requestID)
	if mutation {
		argv = append(argv, "--idempotency-key", f.Challenge+"-"+requestID)
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, argv[0], argv[1:]...)
	inherited, err := client.InheritLaneCommand(command, f.Config)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	row := legacyCallRecord{Name: name, Argv: argv, Request: file, Stdout: name + ".stdout", Stderr: name + ".stderr", ExitCode: -1}
	err = command.Start()
	closeErr := inherited.Close()
	if err == nil {
		row.Started = true
		err = command.Wait()
		row.ExitCode = command.ProcessState.ExitCode()
	}
	err = errors.Join(err, closeErr)
	row.TimedOut = bounded.Err() != nil
	f.log.Calls = append(f.log.Calls, row)
	if saveErr := errors.Join(legacyWrite(row.Stdout, stdout.Bytes()), legacyWrite(row.Stderr, stderr.Bytes())); saveErr != nil {
		return nil, saveErr
	}
	if !row.Started || row.TimedOut || row.ExitCode != expected {
		return nil, fmt.Errorf("installed CLI step %s failed; inspect retained output", name)
	}
	data := stdout.Bytes()
	if expected != 0 {
		data = stderr.Bytes()
		if stdout.Len() != 0 {
			return nil, errors.New("refused CLI returned result bytes")
		}
	} else if err != nil || stderr.Len() != 0 {
		return nil, errors.New("successful CLI retained an error")
	}
	var value map[string]any
	if json.Unmarshal(data, &value) != nil || value == nil {
		return nil, errors.New("installed CLI response is not an object")
	}
	return value, nil
}

func (f *legacyFixture) state(ctx context.Context) error {
	content := []byte("SERVE-STATE " + f.Challenge + "\n")
	if err := legacyWrite("content.input", content); err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	upload, err := f.call(ctx, "blob-begin", []string{"blob", "begin"}, map[string]any{"class": "record", "bytes": len(content), "sha256": digest}, true, 0)
	if err != nil {
		return err
	}
	object, ok := upload["object_id"].(string)
	if !ok || object == "" {
		return errors.New("upload has no real object selector")
	}
	if _, err := f.call(ctx, "blob-chunk", []string{"blob", "chunk"}, map[string]any{
		"object_id": object, "offset": 0, "data": base64.StdEncoding.EncodeToString(content), "sha256": digest}, true, 0); err != nil {
		return err
	}
	ref, err := f.call(ctx, "blob-commit", []string{"blob", "commit"}, map[string]any{"object_id": object, "sha256": digest}, true, 0)
	if err != nil {
		return err
	}
	appendRequest := map[string]any{"collection": "observations", "content": ref, "related_ids": []string{}}
	record, err := f.call(ctx, "append", []string{"records", "append"}, appendRequest, true, 0)
	if err != nil {
		return err
	}
	identifier, ok := record["id"].(string)
	if !ok || identifier == "" {
		return errors.New("append has no real record selector")
	}
	if _, err := f.call(ctx, "get", []string{"records", "get"}, map[string]any{"record_id": identifier}, false, 0); err != nil {
		return err
	}
	if _, err := f.call(ctx, "read", []string{"blob", "read"}, map[string]any{"object_id": object, "offset": 0, "limit": len(content)}, false, 0); err != nil {
		return err
	}
	if _, err := f.call(ctx, "retry", []string{"records", "append"}, appendRequest, true, 0); err != nil {
		return err
	}
	changed := map[string]any{"collection": "reports", "content": ref, "related_ids": []string{}}
	conflict, err := f.call(ctx, "changed", []string{"records", "append"}, changed, true, 2)
	if err != nil {
		return err
	}
	if conflict["code"] != "idempotency_conflict" {
		return errors.New("changed request did not return the exact conflict")
	}
	// The historical evidence label is retained, but an unfinished method is
	// a failure. No not_implemented response can complete this probe.
	_, err = f.call(ctx, "unready", []string{"judge", "list"}, map[string]any{}, false, 0)
	return err
}

func (f *legacyFixture) run(ctx context.Context) (resultErr error) {
	if err := os.Mkdir("serve-state", 0700); err != nil {
		return err
	}
	scratchRemoved := false
	defer func() {
		if scratchRemoved {
			return
		}
		if resultErr != nil {
			f.log.StoppedAt = resultErr.Error()
		}
		data, err := legacyEncode(f.log)
		if err == nil {
			err = legacyWrite("transcript.json", data)
		}
		resultErr = errors.Join(resultErr, err)
	}()
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return errors.New("fixture requires the actual bounded launch prompt")
	}
	if err := legacyWrite("prompt.input", prompt); err != nil {
		return err
	}
	identity, err := f.call(ctx, "identity", []string{"identity", "self"}, map[string]any{}, false, 0)
	if err != nil {
		return err
	}
	actor, ok := identity["actor"].(map[string]any)
	if !ok || identity["config"] != f.Config || identity["launch_id"] == "" || identity["launch_id"] == nil ||
		actor["kind"] != "lane" || actor["life_id"] != f.Life {
		return errors.New("installed CLI authenticated another lane")
	}
	if f.Mode == "state" {
		return f.state(ctx)
	}
	// A lifecycle lane leaves its worktree clean like a finished agent (box 105): nothing reads this scratch in
	// lifecycle mode, and dirty work is retained by design, so it would keep clean from ever completing.
	if err := os.RemoveAll("serve-state"); err != nil {
		return err
	}
	scratchRemoved = true
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "serve.session", "vendor_stood_in": true,
		"driver": f.Driver, "session_id": f.Session, "home_id": f.Home, "history_id": f.History,
		"vendor_session_id": f.VendorSession, "identity": identity}); err != nil {
		return err
	}
	wait := time.NewTimer(time.Duration(f.WaitMS) * time.Millisecond)
	defer wait.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-wait.C:
		return errors.New("fixture stop deadline expired")
	}
}

func legacyMain() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"program": legacyProgram, "version": legacyVersion, "vendor_stood_in": true}) != nil {
			os.Exit(1)
		}
		return
	}
	var input legacyOptions
	flags := flag.NewFlagSet(legacyProgram, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for name, target := range map[string]*string{"config": &input.Config, "client": &input.Client, "binding": &input.Binding,
		"challenge": &input.Challenge, "life": &input.Life, "mode": &input.Mode, "driver": &input.Driver,
		"session": &input.Session, "home": &input.Home, "history": &input.History, "vendor-session": &input.VendorSession,
		"model": &input.Model, "effort": &input.Effort} {
		flags.StringVar(target, name, "", "reserved fixture input")
	}
	flags.UintVar(&input.Run, "run", 0, "actual reserved run")
	flags.Int64Var(&input.WaitMS, "wait-ms", 0, "bounded stop wait")
	identifier := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	valid := flags.Parse(os.Args[1:]) == nil && flags.NArg() == 0 && runtime.GOOS == "linux" && os.Geteuid() != 0 &&
		input.Client == "/run/laneboss/client" && input.Binding == "/run/laneboss/binding.json" &&
		regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(input.Challenge) && input.Run > 0 &&
		(input.Mode == "state" || input.Mode == "lifecycle") && (input.Driver == "claudock-cli" || input.Driver == "codex") &&
		input.WaitMS > 0 && input.WaitMS <= 300000 && input.Model != "" && input.Effort != ""
	for _, value := range []string{input.Config, input.Life, input.Session, input.Home, input.History, input.VendorSession} {
		valid = valid && identifier.MatchString(value)
	}
	if !valid {
		fmt.Fprintln(os.Stderr, "invalid isolated fixture invocation")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	f := legacyFixture{legacyOptions: input, log: legacyTranscript{Schema: "laneboss.serve-observed.v1", Program: legacyProgram, Version: legacyVersion,
		VendorStoodIn: true, Config: input.Config, Challenge: input.Challenge, Life: input.Life, Run: input.Run, UID: os.Geteuid(), Calls: []legacyCallRecord{}}}
	if err := f.run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "fixture stopped; inspect retained installed CLI evidence")
		os.Exit(1)
	}
}
