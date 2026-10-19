package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDecodedCredentialEcho(t *testing.T) {
	for _, location := range []string{"value", "key", "array", "unicode", "slash"} {
		t.Run(location, func(t *testing.T) {
			key := "fixture-quote\"slash/back\\end-1"
			if location == "slash" {
				key = "fixture-slash/value-1"
			}
			r := request()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				root := response(body)
				switch location {
				case "key":
					root[key] = "echo"
				case "array":
					root["echo"] = []any{map[string]any{"value": key}}
				default:
					root["echo"] = key
				}
				raw, err := json.Marshal(root)
				if err != nil {
					t.Error("response encoding failed")
				}
				if location == "unicode" {
					escaped, err := json.Marshal(key)
					if err != nil {
						t.Error("key encoding failed")
					}
					var encoded strings.Builder
					encoded.WriteByte('"')
					for _, char := range key {
						fmt.Fprintf(&encoded, `\u%04x`, char)
					}
					encoded.WriteByte('"')
					raw = bytes.Replace(raw, escaped, []byte(encoded.String()), 1)
				}
				if location == "slash" {
					raw = bytes.ReplaceAll(raw, []byte("/"), []byte(`\/`))
				}
				// This red control proves raw-byte screening alone misses it.
				if bytes.Contains(raw, []byte(key)) {
					t.Error("echo control is not escaped")
				}
				if _, err := w.Write(raw); err != nil {
					t.Error("response write failed")
				}
			}))
			defer server.Close()
			store := &retained{}
			o := options(server.URL, r, store)
			o.CredentialHandle, o.Credential.Bytes = "key-a", []byte(key)
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			unscored(t, got)
			if got.UnavailableReason != "judge response withheld" || got.Raw != nil ||
				len(store.objects["judge_raw"]) != 0 {
				t.Fatal("escaped key reached retention")
			}
		})
	}
}

func TestInputCredentialCanary(t *testing.T) {
	credential := "Bearer " + strings.Repeat("a1", 16)
	for _, field := range []string{"command", "rule", "role", "task", "decision", "argv", "path",
		"suffix", "prefix", "middle", "inside-json", "split-fields"} {
		t.Run(field, func(t *testing.T) {
			r := request()
			switch field {
			case "command":
				r.Command.Command = []byte(credential)
				r.Command.RawSHA256 = Digest(r.Command.Command)
			case "rule":
				r.Rules[0].Text += credential
			case "role":
				r.Context.Role.Role = credential
			case "task":
				r.Task = []byte(credential)
			case "decision":
				r.Purpose, r.Command, r.Rules = "guidance", nil, []api.JudgeRule{}
				r.Decisions = []api.DecisionCandidate{{ID: "decision-a", Text: credential,
					Authority:   api.DecisionAuthority{Kind: "human", ReceiptID: "receipt-a", SourceSeq: 1},
					AppliesTo:   api.DecisionApplicability{Levels: []int{}, Roles: []string{}, ProjectIDs: []api.ID{}, LifeIDs: []api.ID{}},
					Source:      api.SourceRef{ID: "source-a", SHA256: Digest([]byte("source")), Generation: 1},
					EffectiveAt: "2026-01-01T00:00:00Z"}}
			case "argv":
				r.Command.Argv = []string{credential}
			case "path":
				r.Command.DeclaredPaths = []string{credential}
			case "suffix":
				r.Command.Command = []byte(strings.Repeat("界", 90000) + credential)
				r.Command.RawSHA256 = Digest(r.Command.Command)
			case "prefix":
				r.Command.Command = []byte(credential + strings.Repeat("界", 90000))
				r.Command.RawSHA256 = Digest(r.Command.Command)
			case "middle":
				r.Command.Command = []byte(strings.Repeat("界", 45000) + credential + strings.Repeat("界", 45000))
				r.Command.RawSHA256 = Digest(r.Command.Command)
			case "inside-json":
				r.Task = []byte(`{"header":"` + credential + `"}`)
			case "split-fields":
				r.Command.Argv = []string{"Bear", "er " + strings.Repeat("a1", 16)}
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				writeJSON(t, w, response(body))
			}))
			defer server.Close()
			store := &retained{}
			adapter, err := New(options(server.URL, r, store))
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			unscored(t, got)
			if got.UnavailableReason != "credential-shaped input withheld" {
				t.Fatal("credential screen missed input")
			}
			if calls.Load() != 0 {
				t.Fatal("credential reached HTTP")
			}
			if len(store.objects) != 0 {
				t.Fatal("credential reached retention")
			}
		})
	}
	// A credential reference is ordinary state, not a credential value.
	if Sensitive(map[string]any{"token": "$EXAMPLE_KEY"}, "") ||
		!Sensitive(map[string]any{"token": "fake-value-1"}, "") {
		t.Fatal("credential field control failed")
	}
}

func TestResponseCredentialShapes(t *testing.T) {
	r := request()
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error("request read failed")
		}
		root := response(body)
		root["metadata"] = map[string]any{"token": "fake-response-value-1"}
		writeJSON(t, w, root)
	}))
	defer server.Close()
	store := &retained{}
	adapter, err := New(options(server.URL, r, store))
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.Evaluate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	unscored(t, got)
	if calls.Load() != 1 || got.Raw != nil || len(store.objects["judge_raw"]) != 0 ||
		got.UnavailableReason != "judge response withheld" {
		t.Fatal("response credential was retained")
	}
}

func TestPinsEndpointsAndRedaction(t *testing.T) {
	for _, name := range []string{"deployment", "hosted-dot", "plaintext", "alias", "questions", "bytes", "margin"} {
		t.Run(name, func(t *testing.T) {
			r := request()
			o := options("http://127.0.0.1", r, &retained{})
			switch name {
			case "deployment":
				o.Config.DeploymentSHA256 = "   "
			case "hosted-dot":
				o.Endpoint = "https://api.cloudflare.com."
			case "plaintext":
				o.Endpoint = "http://provider.example.invalid"
			case "alias":
				o.Config.Model = "clef-flash"
			case "questions":
				o.Config.MaxQuestions = 13
			case "bytes":
				o.Config.MaxBytes = api.MaxJudgeBytes + 1
			case "margin":
				o.SafetyTokens = 0
			}
			if _, err := New(o); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	o := options("http://127.0.0.1", request(), &retained{})
	o.CredentialHandle, o.Credential.Bytes = "key-a", []byte("fixture-secret-value-1")
	adapter, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []any{o, adapter, *adapter} {
		text := fmt.Sprintf("%+v %#v", item, item)
		raw, err := json.Marshal(item)
		if err != nil || strings.Contains(text, string(o.Credential.Bytes)) ||
			strings.Contains(text, fmt.Sprint(o.Credential.Bytes)) ||
			bytes.Contains(raw, o.Credential.Bytes) {
			t.Fatal("credential formatting leaked")
		}
	}
}

func TestRetentionAndCostFailures(t *testing.T) {
	for _, name := range []string{"missing", "retain-error", "retain-hash", "cost-error", "cost-cap"} {
		t.Run(name, func(t *testing.T) {
			r := request()
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				writeJSON(t, w, response(raw))
			}))
			defer server.Close()
			o := options(server.URL, r, &retained{})
			switch name {
			case "missing":
				o.Retain = nil
			case "retain-error":
				o.Retain = func(context.Context, string, []byte) (api.BlobRef, error) {
					return api.BlobRef{}, errors.New("store unavailable")
				}
			case "retain-hash":
				keep := o.Retain
				o.Retain = func(ctx context.Context, class string, raw []byte) (api.BlobRef, error) {
					ref, err := keep(ctx, class, raw)
					ref.SHA256 = Digest([]byte("wrong bytes"))
					return ref, err
				}
			case "cost-error":
				o.Cost = func(int64, int64) (int64, error) {
					return 0, errors.New("price source unavailable")
				}
			case "cost-cap":
				o.Cost = func(in, out int64) (int64, error) {
					return in + out + r.MaxCostMicros, nil
				}
			}
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			got, evalErr := adapter.Evaluate(context.Background(), r)
			unscored(t, got)
			if strings.HasPrefix(name, "retain") || name == "missing" {
				if evalErr == nil || calls.Load() != 0 {
					t.Fatal("retention failure sent HTTP")
				}
			} else if evalErr != nil || calls.Load() != 1 {
				t.Fatal("cost control did not reach HTTP")
			}
		})
	}
}

func TestDeadlineAndRedirect(t *testing.T) {
	r := request()
	r.DeadlineMS = 40
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer server.Close()
	adapter, err := New(options(server.URL, r, &retained{}))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, _ := adapter.Evaluate(context.Background(), r)
	unscored(t, got)
	if time.Since(start) > time.Second || !strings.Contains(got.UnavailableReason, "deadline") {
		t.Fatal("total deadline was extended")
	}
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	r = request()
	adapter, err = New(options(source.URL, r, &retained{}))
	if err != nil {
		t.Fatal(err)
	}
	got, _ = adapter.Evaluate(context.Background(), r)
	unscored(t, got)
	if targetCalls.Load() != 0 {
		t.Fatal("judge followed redirect")
	}
}
