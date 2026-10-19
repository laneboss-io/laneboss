//go:build linux

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
)

type relayOptions struct {
	Config, Client, Binding, Life          string
	Session, Home, History, Vendor         string
	Driver, Mode, Model, Effort, Challenge string
	Run                                    uint
	Wait                                   int64
}

type relayEnvelope struct {
	Schema    string          `json:"schema"`
	Nonce     string          `json:"nonce"`
	Command   string          `json:"command"`
	Request   json.RawMessage `json:"request"`
	RequestID string          `json:"request_id"`
	Key       string          `json:"idempotency_key"`
}

type relayReply struct {
	Type   string      `json:"type"`
	Nonce  string      `json:"nonce"`
	Target api.LifeRef `json:"target"`
	Exit   int         `json:"exit_code"`
	Stdout []byte      `json:"stdout"`
	Stderr []byte      `json:"stderr"`
}

func relayNonce() (string, error) {
	var raw [16]byte
	_, err := rand.Read(raw[:])
	return hex.EncodeToString(raw[:]), err
}

func relayHash(raw []byte) api.Digest {
	sum := sha256.Sum256(raw)
	return api.Digest(hex.EncodeToString(sum[:]))
}

func relayInvoke(ctx context.Context, opt relayOptions, input relayEnvelope) (relayReply, error) {
	result := relayReply{Type: "watchdog.reply", Nonce: input.Nonce,
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

func relayInternal(ctx context.Context, opt relayOptions, command string, request any, out any) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	id, err := relayNonce()
	if err != nil {
		return err
	}
	result, err := relayInvoke(ctx, opt, relayEnvelope{Command: command, Request: raw, RequestID: id, Key: id})
	if err != nil {
		return err
	}
	if result.Exit != 0 {
		// A native error is emitted whole, so the outside observer can retain
		// its exact owner, code and bytes even when mailbox setup fails.
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
		return errors.New("installed relay setup refused")
	}
	return json.Unmarshal(result.Stdout, out)
}

func relayBlob(ctx context.Context, opt relayOptions, ref api.BlobRef) ([]byte, error) {
	if ref.Bytes < 1 || ref.Bytes > api.MaxFrameBytes {
		return nil, errors.New("mail envelope has an invalid size")
	}
	var raw []byte
	for int64(len(raw)) < ref.Bytes {
		var chunk api.BlobChunk
		if err := relayInternal(ctx, opt, "blob read", api.BlobReadRequest{
			ObjectID: ref.ID, Offset: int64(len(raw)), Limit: 262144}, &chunk); err != nil {
			return nil, err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != int64(len(raw)) || len(chunk.Data) == 0 || relayHash(chunk.Data) != chunk.SHA256 {
			return nil, errors.New("mail envelope chunk differs")
		}
		raw = append(raw, chunk.Data...)
	}
	if int64(len(raw)) != ref.Bytes || relayHash(raw) != ref.SHA256 {
		return nil, errors.New("mail envelope differs from its committed bytes")
	}
	return raw, nil
}

func relayAllowed(command string) bool {
	switch command {
	case "identity self", "grants get", "grants validate", "grants test-child", "grants revoke",
		"lane start", "lane status", "lane list", "lane check", "lane resume", "lane turn", "lane stop", "lane review", "lane mark", "lane archive", "lane clean", "mail send", "operation get",
		"blob begin", "blob chunk", "blob commit", "blob read", "event tail", "fixture exit":
		return true
	}
	return false
}

func relayRun(ctx context.Context, opt relayOptions) error {
	prompt, err := io.ReadAll(io.LimitReader(os.Stdin, 16<<20+1))
	if err != nil || len(prompt) == 0 || len(prompt) > 16<<20 {
		return errors.New("actual bounded launch prompt is required")
	}
	var identity api.Scope
	if err := relayInternal(ctx, opt, "identity self", map[string]any{}, &identity); err != nil {
		return err
	}
	if identity.Config != opt.Config || identity.Actor.Kind != "lane" || string(identity.Actor.LifeID) != opt.Life ||
		identity.LaunchID == "" || (identity.Actor.Level != 6) {
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
	if err := encoder.Encode(map[string]any{"type": "watchdog.ready", "target": target,
		"identity": identity, "binding": json.RawMessage(meta), "binding_bytes": meta, "metadata_only": true}); err != nil {
		return err
	}
	seen := map[api.ID]bool{}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		var page api.MailPage
		cursor := ""
		for {
			if err := relayInternal(ctx, opt, "mail list", api.ListRequest{LifeID: target.LifeID, Cursor: cursor, Limit: 200}, &page); err != nil {
				return err
			}
			for _, mail := range page.Messages {
				if seen[mail.ID] || mail.Sender.Kind != "human" || mail.RecipientLifeID != target.LifeID {
					continue
				}
				seen[mail.ID] = true
				raw, err := relayBlob(ctx, opt, mail.Content)
				if err != nil {
					return err
				}
				var input relayEnvelope
				if err := api.DecodeObject(raw, &input); err != nil {
					return err
				}
				if input.Schema != "laneboss.item-rpc.v1" || len(input.Nonce) != 32 || !relayAllowed(input.Command) {
					return errors.New("unrecognized private fixture instruction")
				}
				if input.Command == "fixture exit" {
					return encoder.Encode(relayReply{Type: "watchdog.exiting", Nonce: input.Nonce, Target: target})
				}
				result, err := relayInvoke(ctx, opt, input)
				if err != nil {
					return err
				}
				if err := encoder.Encode(result); err != nil {
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

func relayMain() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if json.NewEncoder(os.Stdout).Encode(map[string]any{"program": "laneboss-serve-fixture",
			"version": "1.0.0", "vendor_stood_in": true, "fixture_kind": "grants-relay"}) != nil {
			os.Exit(1)
		}
		return
	}
	var opt relayOptions
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
	if err := relayRun(ctx, opt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
