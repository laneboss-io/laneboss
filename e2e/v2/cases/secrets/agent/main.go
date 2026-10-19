// The secrets fixture implements the enrolled serve-fixture vendor protocol.
// Every input comes from the installed lane CLI; it never contacts a vendor.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

const program = "laneboss-serve-fixture"

type options struct {
	Config, Client, Binding, Challenge, Life, Mode, Driver string
	Session, Home, History, VendorSession, Model, Effort   string
	Run                                                    uint
	WaitMS                                                 int64
}

type task struct {
	Schema        string   `json:"schema"`
	Mode          string   `json:"mode"`
	EnvName       string   `json:"env_name"`
	EnvSHA        string   `json:"env_sha256"`
	FilePath      string   `json:"file_path"`
	FileSHA       string   `json:"file_sha256"`
	HiddenEnv     []string `json:"hidden_env_names"`
	HiddenFiles   []string `json:"hidden_file_paths"`
	ReservedName  string   `json:"reserved_env_name"`
	ReservedSHA   string   `json:"reserved_sha256"`
	OtherProfile  string   `json:"other_profile"`
	OtherHistory  string   `json:"other_history"`
	HistoryObject api.ID   `json:"other_history_id"`
	Registry      string   `json:"registry"`
	Keyring       string   `json:"keyring"`
	Nonce         string   `json:"nonce"`
}

type nativeFacts struct {
	Schema, Config, LifeID, StartTime, MountNS, PIDNS, ExecutableSHA, TaskSHA, PromptSHA, MountInfoSHA string
	PID, UID, GID                                                                                      int
	Run                                                                                                uint
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func encode(value any) ([]byte, error) { return json.Marshal(value) }

type rpc struct {
	options
	directory string
	sequence  int
}

type turnRPC interface {
	call(context.Context, string, any, any) error
	blob(context.Context, api.BlobRef) ([]byte, error)
	history(context.Context, []byte) (api.BlobRef, error)
	historyDenied(context.Context, api.ID) bool
}

func (r *rpc) call(ctx context.Context, method string, body any, out any) error {
	r.sequence++
	raw, err := encode(body)
	if err != nil {
		return err
	}
	path := filepath.Join(r.directory, strconv.Itoa(r.sequence)+".json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	argv := append([]string{}, strings.Split(method, ".")...)
	argv = append(argv, "--config", r.Config, "--binding", r.Binding, "--request", path)
	if api.Methods[api.Method(method)].Mutation {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		argv = append(argv, "--idempotency-key", hex.EncodeToString(nonce))
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, r.Client, argv...)
	inherited, err := client.InheritLaneCommand(command, r.Config)
	if err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	err = errors.Join(err, inherited.Close())
	if err != nil || stderr.Len() != 0 || bounded.Err() != nil || json.Unmarshal(stdout.Bytes(), out) != nil {
		return errors.New("actual installed lane RPC refused")
	}
	return nil
}

func (r *rpc) blob(ctx context.Context, ref api.BlobRef) ([]byte, error) {
	if ref.Bytes < 1 || ref.Bytes > 1<<20 {
		return nil, errors.New("actual task is outside its bound")
	}
	var raw []byte
	for int64(len(raw)) < ref.Bytes {
		var chunk struct {
			ObjectID api.ID     `json:"object_id"`
			Offset   int64      `json:"offset"`
			Data     []byte     `json:"data"`
			SHA256   api.Digest `json:"sha256"`
		}
		if err := r.call(ctx, "blob.read", api.BlobReadRequest{ObjectID: ref.ID, Offset: int64(len(raw)), Limit: 262144}, &chunk); err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(raw)) || len(chunk.Data) == 0 || digest(chunk.Data) != string(chunk.SHA256) || int64(len(raw)+len(chunk.Data)) > ref.Bytes {
			return nil, errors.New("actual task chunk changed")
		}
		raw = append(raw, chunk.Data...)
	}
	if digest(raw) != string(ref.SHA256) {
		return nil, errors.New("actual task digest changed")
	}
	return raw, nil
}

func facts(in options, raw, prompt []byte) (nativeFacts, error) {
	result := nativeFacts{Schema: "laneboss.secret-native.v1", Config: in.Config, LifeID: in.Life, Run: in.Run,
		PID: os.Getpid(), UID: os.Getuid(), GID: os.Getgid(), TaskSHA: digest(raw), PromptSHA: digest(prompt)}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return result, err
	}
	fields := strings.Fields(string(stat)[strings.LastIndex(string(stat), ")")+2:])
	if len(fields) < 20 {
		return result, errors.New("actual process generation is absent")
	}
	result.StartTime = fields[19]
	if result.MountNS, err = os.Readlink("/proc/self/ns/mnt"); err != nil {
		return result, err
	}
	if result.PIDNS, err = os.Readlink("/proc/self/ns/pid"); err != nil {
		return result, err
	}
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return result, err
	}
	result.ExecutableSHA = digest(executable)
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return result, err
	}
	result.MountInfoSHA = digest(mounts)
	return result, nil
}

func (r *rpc) history(ctx context.Context, content []byte) (api.BlobRef, error) {
	var upload api.BlobUpload
	sha := api.Digest(digest(content))
	if err := r.call(ctx, "blob.begin", api.BlobBeginRequest{Class: "record", Bytes: int64(len(content)), SHA256: sha}, &upload); err != nil {
		return api.BlobRef{}, err
	}
	var chunk map[string]any
	if err := r.call(ctx, "blob.chunk", api.BlobChunk{ObjectID: upload.ObjectID, Offset: 0, Data: content, SHA256: sha}, &chunk); err != nil {
		return api.BlobRef{}, err
	}
	var ref api.BlobRef
	if err := r.call(ctx, "blob.commit", api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: sha}, &ref); err != nil {
		return ref, err
	}
	if ref.ID != upload.ObjectID || ref.Bytes != int64(len(content)) || ref.SHA256 != sha {
		return api.BlobRef{}, errors.New("actual stand-in history commit changed")
	}
	return ref, nil
}

func (r *rpc) historyDenied(ctx context.Context, id api.ID) bool {
	if id == "" {
		return false
	}
	raw, err := json.Marshal(api.BlobReadRequest{ObjectID: id, Offset: 0, Limit: 1})
	if err != nil {
		return false
	}
	path := filepath.Join(r.directory, "foreign-history.json")
	if os.WriteFile(path, raw, 0600) != nil {
		return false
	}
	command := exec.CommandContext(ctx, r.Client, "blob", "read", "--config", r.Config, "--binding", r.Binding, "--request", path)
	inherited, err := client.InheritLaneCommand(command, r.Config)
	if err != nil {
		return false
	}
	var out, stderr bytes.Buffer
	command.Stdout, command.Stderr = &out, &stderr
	err = command.Run()
	closeErr := inherited.Close()
	var refusal api.Error
	return err != nil && closeErr == nil && command.ProcessState != nil && command.ProcessState.ExitCode() == 2 && out.Len() == 0 &&
		json.Unmarshal(stderr.Bytes(), &refusal) == nil && (refusal.Code == api.CodeForbidden || refusal.Code == api.CodeNotFound)
}

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func selectedEnv(name, want string) bool {
	if !envName.MatchString(name) {
		return false
	}
	value, found := os.LookupEnv(name)
	return found && digest([]byte(value)) == want
}

func absent(path string) bool {
	if !filepath.IsAbs(path) || path == "/" {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission)
	}
	file.Close()
	return false
}

func injection(plan task) map[string]bool {
	verdict := map[string]bool{"env": selectedEnv(plan.EnvName, plan.EnvSHA), "file": false,
		"reserved": selectedEnv(plan.ReservedName, plan.ReservedSHA), "undelegated": false}
	filePath := plan.FilePath
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(os.Getenv("HOME"), filePath)
	}
	material, err := os.ReadFile(filePath)
	if err == nil && len(material) <= 65536 && digest(material) == plan.FileSHA {
		file, writeErr := os.OpenFile(filePath, os.O_WRONLY|os.O_APPEND, 0)
		if file != nil {
			file.Close()
		}
		verdict["file"] = errors.Is(writeErr, syscall.EACCES) || errors.Is(writeErr, syscall.EPERM) || errors.Is(writeErr, syscall.EROFS)
	}
	clear(material)
	hidden := len(plan.HiddenEnv) > 0 && len(plan.HiddenFiles) > 0
	for _, name := range plan.HiddenEnv {
		_, present := os.LookupEnv(name)
		hidden = hidden && envName.MatchString(name) && !present
	}
	for _, path := range plan.HiddenFiles {
		hidden = absent(path) && hidden
	}
	verdict["undelegated"] = hidden
	return verdict
}

func ownProfile(in options, selected api.ProfileGrant, executableSHA string) bool {
	var raw []byte
	if in.Driver == string(api.DriverClaudock) {
		raw = []byte(os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"))
	} else {
		root := os.Getenv("CODEX_HOME")
		if root == "" {
			return false
		}
		file, err := os.ReadFile(filepath.Join(root, "auth.json"))
		if err != nil {
			return false
		}
		defer clear(file)
		var login struct {
			Mode   string `json:"auth_mode"`
			Tokens struct {
				Access string `json:"access_token"`
			} `json:"tokens"`
		}
		if json.Unmarshal(file, &login) != nil || login.Mode != "chatgpt" {
			return false
		}
		raw, err = base64.StdEncoding.DecodeString(login.Tokens.Access)
		if err != nil {
			return false
		}
	}
	defer clear(raw)
	var auth struct {
		Program, Config, Challenge string
		Vendor                     bool           `json:"vendor_stood_in"`
		ProfileID                  api.ID         `json:"profile_id"`
		Driver                     api.Driver     `json:"driver"`
		Runtime                    api.Executable `json:"runtime"`
	}
	return json.Unmarshal(raw, &auth) == nil && auth.Program == "laneboss-e2e-authenticator" && auth.Vendor &&
		auth.Config == in.Config && auth.Challenge == in.Challenge && auth.ProfileID == selected.ProfileID &&
		auth.Driver == selected.Driver && selected.Driver == api.Driver(in.Driver) && string(auth.Runtime.SHA256) == executableSHA
}

func run(ctx context.Context, in options) error {
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return errors.New("actual bounded prompt is missing")
	}
	directory, err := os.MkdirTemp("", "secret-turn-")
	if err != nil {
		return err
	}
	r := rpc{options: in, directory: directory}
	return runTurn(ctx, in, &r, prompt, os.Stdout, os.Stderr)
}

func runTurn(ctx context.Context, in options, r turnRPC, prompt []byte, stdout, stderr io.Writer) error {
	var peer struct {
		Config   string    `json:"config"`
		Actor    api.Actor `json:"actor"`
		LaunchID api.ID    `json:"launch_id"`
	}
	if err := r.call(ctx, "identity.self", api.Empty{}, &peer); err != nil || peer.Config != in.Config || peer.Actor.Kind != "lane" || peer.Actor.LifeID != api.ID(in.Life) || peer.LaunchID == "" {
		return errors.New("actual lane identity differs")
	}
	var lane api.Lane
	if err := r.call(ctx, "lane.status", api.LifeRef{LifeID: api.ID(in.Life), Run: api.RunNumber(in.Run)}, &lane); err != nil {
		return err
	}
	raw, err := r.blob(ctx, lane.Task)
	if err != nil {
		return err
	}
	var plan task
	if json.Unmarshal(raw, &plan) != nil || plan.Schema != "laneboss.secret-task.v1" {
		return errors.New("enrolled secrets fixture requires its actual task")
	}
	observed, err := facts(in, raw, prompt)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stderr).Encode(observed); err != nil {
		return err
	}
	var grants api.GrantSet
	if err := r.call(ctx, "grants.get", api.GrantGetRequest{GrantSetID: lane.GrantSetID}, &grants); err != nil {
		return err
	}
	var selected api.ProfileGrant
	for _, grant := range grants.Profiles {
		if grant.ID == lane.ProfileGrantID {
			selected = grant
		}
	}
	credentialOK := selected.ID != "" && ownProfile(in, selected, observed.ExecutableSHA)
	switch plan.Mode {
	case "baseline":
		nonce := make([]byte, 64)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		history := filepath.Join(os.Getenv("HOME"), "secret-history.private")
		if err := os.WriteFile(history, nonce, 0600); err != nil {
			clear(nonce)
			return err
		}
		ref, err := r.history(ctx, nonce)
		if err != nil {
			clear(nonce)
			return err
		}
		err = json.NewEncoder(stdout).Encode(map[string]any{"schema": plan.Schema, "mode": plan.Mode,
			"reserved_sha256": digest([]byte(os.Getenv(plan.ReservedName))), "history_sha256": digest(nonce),
			"history_ref": ref, "profile_id": selected.ProfileID, "own_profile_turn": credentialOK, "vendor_stood_in": true})
		clear(nonce)
		if err != nil || !credentialOK {
			return errors.New("stand-in baseline credential comparison failed")
		}
	case "injection":
		verdicts := injection(plan)
		for _, name := range []string{"env", "file", "undelegated", "reserved"} {
			if err := json.NewEncoder(stdout).Encode(map[string]any{"name": name, "ok": verdicts[name]}); err != nil {
				return err
			}
		}
		for _, ok := range verdicts {
			if !ok {
				return errors.New("actual injection comparison failed")
			}
		}
	case "credential":
		result := map[string]any{"schema": "laneboss.secret-credential.v1", "vendor_stood_in": true,
			"profile_id": selected.ProfileID, "profile_grant_id": selected.ID, "own_profile_turn": credentialOK,
			"other_profile_absent": absent(plan.OtherProfile), "other_history_absent": r.historyDenied(ctx, plan.HistoryObject),
			"registry_absent": absent(plan.Registry), "keyring_fallback_absent": absent(plan.Keyring), "nonce": plan.Nonce}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			return err
		}
		for _, name := range []string{"own_profile_turn", "other_profile_absent", "other_history_absent", "registry_absent", "keyring_fallback_absent"} {
			if result[name] != true {
				return errors.New("actual stand-in credential comparison failed")
			}
		}
	default:
		return errors.New("unknown secrets task mode")
	}
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(time.Duration(in.WaitMS) * time.Millisecond):
		return errors.New("actual stop deadline expired")
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"program": program, "version": "1.0.0", "vendor_stood_in": true, "case": "secrets"})
		return
	}
	var in options
	flags := flag.NewFlagSet(program, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	for name, target := range map[string]*string{"config": &in.Config, "client": &in.Client, "binding": &in.Binding,
		"challenge": &in.Challenge, "life": &in.Life, "mode": &in.Mode, "driver": &in.Driver,
		"session": &in.Session, "home": &in.Home, "history": &in.History, "vendor-session": &in.VendorSession,
		"model": &in.Model, "effort": &in.Effort} {
		flags.StringVar(target, name, "", "enrolled fixture input")
	}
	flags.UintVar(&in.Run, "run", 0, "actual run")
	flags.Int64Var(&in.WaitMS, "wait-ms", 0, "actual budget")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || os.Getuid() == 0 || in.Client != "/run/laneboss/client" ||
		in.Binding != "/run/laneboss/binding.json" || in.Run == 0 || in.WaitMS < 1 || in.WaitMS > 300000 {
		fmt.Fprintln(os.Stderr, "invalid enrolled secrets fixture invocation")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := run(ctx, in); err != nil {
		fmt.Fprintln(os.Stderr, "secrets fixture stopped; retain native evidence")
		os.Exit(1)
	}
}
