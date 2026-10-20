// Command grants_actor is an explicitly enrolled vendor stand-in. It invokes
// only the installed CLI, inside its original confinement and sealed transport.
package main

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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/scripts/v2-serve/relaymsg"
)

type options struct {
	Config, Client, Binding, Life          string
	Session, Home, History, Vendor         string
	Driver, Mode, Model, Effort, Challenge string
	Run                                    uint
	Wait                                   int64
}

type envelope struct {
	Schema    string          `json:"schema"`
	Nonce     string          `json:"nonce"`
	Command   string          `json:"command"`
	Request   json.RawMessage `json:"request"`
	RequestID string          `json:"request_id"`
	Key       string          `json:"idempotency_key"`
}

type reply struct {
	Type   string      `json:"type"`
	Nonce  string      `json:"nonce"`
	Target api.LifeRef `json:"target"`
	Exit   int         `json:"exit_code"`
	Stdout []byte      `json:"stdout"`
	Stderr []byte      `json:"stderr"`
}

func nonce() (string, error) {
	var raw [16]byte
	_, err := rand.Read(raw[:])
	return hex.EncodeToString(raw[:]), err
}

func hash(raw []byte) api.Digest {
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func invoke(ctx context.Context, opt options, input envelope) (reply, error) {
	result := reply{Type: "grants.reply", Nonce: input.Nonce,
		Target: api.LifeRef{LifeID: api.ID(opt.Life), Run: api.RunNumber(opt.Run)}}
	dir, err := os.MkdirTemp("/tmp", "lb-grants-rpc-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "request.json")
	if err := os.WriteFile(path, input.Request, 0600); err != nil {
		return result, err
	}
	argv := append(strings.Fields(input.Command), "--config", opt.Config,
		"--binding", opt.Binding, "--request", path,
		"--request-id", input.RequestID, "--idempotency-key", input.Key)
	bounded, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, opt.Client, argv...)
	cmd.Stdin = bytes.NewReader(nil)
	inherited, err := client.InheritLaneCommand(cmd, opt.Config)
	if err != nil {
		return result, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Start()
	closed := inherited.Close()
	if err != nil {
		return result, errors.Join(err, closed)
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if closed != nil || bounded.Err() != nil || (err != nil && !errors.As(err, &exit)) {
		return result, errors.Join(err, closed, bounded.Err())
	}
	result.Exit = cmd.ProcessState.ExitCode()
	result.Stdout, result.Stderr = stdout.Bytes(), stderr.Bytes()
	if len(result.Stdout)+len(result.Stderr) > api.MaxFrameBytes {
		return result, errors.New("installed CLI output exceeds relay bound")
	}
	return result, nil
}

func internal(ctx context.Context, opt options, command string, request any, out any) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	id, err := nonce()
	if err != nil {
		return err
	}
	started := time.Now()
	result, err := invoke(ctx, opt, envelope{Command: command, Request: raw, RequestID: id, Key: id})
	ended := time.Now()
	if err != nil {
		return fmt.Errorf("installed CLI %s: %w", command, err)
	}
	if result.Exit != 0 {
		// A native error is emitted whole, so the outside observer can retain
		// its exact owner, code and bytes even when mailbox setup fails.
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		if _, err := os.Stderr.Write(result.Stderr); err != nil {
			return err
		}
		if err := json.NewEncoder(os.Stderr).Encode(struct {
			Event     string `json:"event"`
			Command   string `json:"command"`
			RequestID string `json:"request_id"`
			Started   int64  `json:"started_unix_ms"`
			Ended     int64  `json:"ended_unix_ms"`
			Exit      int    `json:"exit_code"`
		}{"actor_cli_refused", command, id, started.UnixMilli(), ended.UnixMilli(), result.Exit}); err != nil {
			return err
		}
		return fmt.Errorf("installed CLI %s exited %d", command, result.Exit)
	}
	return json.Unmarshal(result.Stdout, out)
}

func blob(ctx context.Context, opt options, ref api.BlobRef) ([]byte, error) {
	if ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, errors.New("mail envelope has an invalid size")
	}
	var raw []byte
	for int64(len(raw)) < ref.Bytes {
		var chunk api.BlobChunk
		if err := internal(ctx, opt, "blob read", api.BlobReadRequest{
			ObjectID: ref.ID, Offset: int64(len(raw)), Limit: 262144}, &chunk); err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(raw)) || len(chunk.Data) == 0 || hash(chunk.Data) != chunk.SHA256 {
			return nil, errors.New("mail envelope chunk differs")
		}
		raw = append(raw, chunk.Data...)
	}
	if int64(len(raw)) != ref.Bytes || hash(raw) != ref.SHA256 {
		return nil, errors.New("mail envelope differs from its committed bytes")
	}
	return raw, nil
}

func allowed(command string) bool {
	switch command {
	case "identity self", "grants get", "grants validate", "grants test-child", "grants revoke",
		"lane start", "lane status", "lane check", "lane resume", "operation get",
		"blob begin", "blob chunk", "blob commit", "blob read", "event tail", "fixture exit":
		return true
	}
	return false
}

func emit(ctx context.Context, opt options, encoder *json.Encoder, message any) error {
	_, err := relaymsg.Publish(ctx, func(ctx context.Context, command string, input, output any) error {
		return internal(ctx, opt, command, input, output)
	}, message)
	if err != nil {
		return err
	}
	// Native stdout remains the independently captured transcript. Live
	// coordination cannot wait for its release-stage spool acknowledgement.
	return encoder.Encode(message)
}

func run(ctx context.Context, opt options) error {
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return errors.New("actual bounded launch prompt is required")
	}
	var identity api.Scope
	if err := internal(ctx, opt, "identity self", map[string]any{}, &identity); err != nil {
		return err
	}
	if identity.Config != opt.Config || identity.Actor.Kind != "lane" || string(identity.Actor.LifeID) != opt.Life ||
		identity.LaunchID == "" || (identity.Actor.Level != 3 && identity.Actor.Level != 5) {
		return errors.New("relay authenticated a different actor")
	}
	meta, err := os.ReadFile(opt.Binding)
	if err != nil {
		return err
	}
	target := api.LifeRef{LifeID: api.ID(opt.Life), Run: api.RunNumber(opt.Run)}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"type": "serve.session", "vendor_stood_in": true,
		"driver": opt.Driver, "session_id": opt.Session, "home_id": opt.Home,
		"history_id": opt.History, "vendor_session_id": opt.Vendor, "identity": identity}); err != nil {
		return err
	}
	if err := emit(ctx, opt, encoder, map[string]any{"type": "grants.ready", "target": target,
		"identity": identity, "binding": json.RawMessage(meta), "binding_bytes": meta, "metadata_only": true}); err != nil {
		return err
	}
	seen := map[api.ID]bool{}
	// Mail arrival has a one-second fixture latency. Each read still invokes
	// the installed CLI and all of its current authorization checks.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		var page api.MailPage
		cursor := ""
		for {
			if err := internal(ctx, opt, "mail list", api.ListRequest{LifeID: target.LifeID, Cursor: cursor, Limit: 200}, &page); err != nil {
				return err
			}
			for _, mail := range page.Messages {
				if seen[mail.ID] || mail.Sender.Kind != "human" || mail.RecipientLifeID != target.LifeID {
					continue
				}
				seen[mail.ID] = true
				raw, err := blob(ctx, opt, mail.Content)
				if err != nil {
					return err
				}
				var input envelope
				if err := api.DecodeObject(raw, &input); err != nil {
					return err
				}
				if input.Schema != "laneboss.item-rpc.v1" || len(input.Nonce) != 32 || !allowed(input.Command) {
					return errors.New("unrecognized private fixture instruction")
				}
				if input.Command == "fixture exit" {
					return emit(ctx, opt, encoder, reply{Type: "grants.exiting", Nonce: input.Nonce, Target: target})
				}
				result, err := invoke(ctx, opt, input)
				if err != nil {
					return err
				}
				if err := emit(ctx, opt, encoder, result); err != nil {
					return err
				}
			}
			if page.Cursor == "" {
				break
			}
			if page.Cursor == cursor {
				return errors.New("mail cursor did not advance")
			}
			cursor = page.Cursor
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"program": "laneboss-serve-fixture",
			"version": "1.0.0", "vendor_stood_in": true, "fixture_kind": "grants-relay"}) != nil {
			os.Exit(1)
		}
		return
	}
	var opt options
	for key, target := range map[string]*string{"config": &opt.Config, "client": &opt.Client,
		"binding": &opt.Binding, "life": &opt.Life, "driver": &opt.Driver, "mode": &opt.Mode,
		"session": &opt.Session, "home": &opt.Home, "history": &opt.History,
		"vendor-session": &opt.Vendor, "model": &opt.Model, "effort": &opt.Effort, "challenge": &opt.Challenge} {
		flag.StringVar(target, key, "", "actual reserved fixture input")
	}
	flag.UintVar(&opt.Run, "run", 0, "reserved run")
	flag.Int64Var(&opt.Wait, "wait-ms", 0, "bounded actor lifetime")
	flag.Parse()
	if flag.NArg() != 0 || os.Geteuid() == 0 || opt.Config == "" || opt.Life == "" || opt.Run == 0 ||
		opt.Client != "/run/laneboss/client" || opt.Binding != "/run/laneboss/binding.json" ||
		opt.Wait < 1 || opt.Wait > 300000 {
		fmt.Fprintln(os.Stderr, "invalid grants fixture invocation")
		os.Exit(1)
	}
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, time.Duration(opt.Wait)*time.Millisecond)
	defer cancel()
	if err := run(ctx, opt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
