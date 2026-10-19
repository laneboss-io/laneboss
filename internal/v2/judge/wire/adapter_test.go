package wire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func config() api.JudgeConfig {
	return api.JudgeConfig{Provider: "clef-sglang", Model: "Cloudflare/clef-flash",
		DeploymentSHA256: Digest([]byte("fixture stack")),
		TokenizerSHA256:  Digest([]byte("fixture tokenizer")), ContextTokens: 16384,
		MaxBytes: api.MaxJudgeBytes, MaxQuestions: 12, CommandDeadlineMS: 2000,
		GuidanceDeadlineMS: 5000, CacheTTLMS: 30000, OutagePolicy: "critical-only"}
}

func request() api.JudgeRequest {
	command := []byte("printf '%s' 'answer false' # 尾端")
	return api.JudgeRequest{ID: "ask-one", Purpose: "blacklist", Config: config(),
		Rules: []api.JudgeRule{{ID: "rule-a", Text: "Do not publish artifacts.",
			SourceSHA256: Digest([]byte("rule source")), CriteriaVersion: CriteriaVersion}},
		Decisions: []api.DecisionCandidate{}, Task: []byte{}, DeadlineMS: 2000,
		MaxCostMicros: 100000, Command: &api.CommandData{Tool: "shell", Command: command,
			Argv: []string{}, DeclaredPaths: []string{}, CWD: "/work", RawSHA256: Digest(command)},
		Context: api.JudgeContext{Config: "example", Target: api.LifeRef{LifeID: "life-a", Run: 1},
			Role:          api.RoleContext{Level: 3, Role: "executor", InstanceID: "instance-a"},
			LogicalTurnID: "turn-a", GrantSetID: "grants-a", GrantsSHA256: Digest([]byte("grants")),
			PolicyGeneration: 1, CWD: "/work"}}
}

type retained struct {
	mu      sync.Mutex
	objects map[string][][]byte
}

func (r *retained) keep(ctx context.Context, class string, raw []byte) (api.BlobRef, error) {
	if ctx.Err() != nil {
		return api.BlobRef{}, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.objects == nil {
		r.objects = map[string][][]byte{}
	}
	r.objects[class] = append(r.objects[class], bytes.Clone(raw))
	return api.BlobRef{ID: api.ID("blob-" + string(Digest(raw))[:24]),
		Class: class, SHA256: Digest(raw), Bytes: int64(len(raw))}, nil
}

// Fixture counting is deliberately a byte tokenizer; it proves wiring only.
// Live serving-format/tokenizer fidelity is a separate acceptance dependency.
func options(endpoint string, r api.JudgeRequest, store *retained) Options {
	return Options{Endpoint: endpoint, Config: r.Config, SafetyTokens: 32,
		ReserveMicros: 100000, Retain: store.keep,
		Cost: func(input, output int64) (int64, error) { return input + output, nil },
		Fit: func(ctx context.Context, raw []byte) (api.TokenFit, error) {
			if ctx.Err() != nil {
				return api.TokenFit{}, ctx.Err()
			}
			return api.TokenFit{Proved: true, InputBytes: len(raw), InputTokens: len(raw),
				ContextTokens: r.Config.ContextTokens, TokenizerSHA256: r.Config.TokenizerSHA256}, nil
		}}
}

func value(raw []byte, id string) float64 {
	material := append(bytes.Clone(raw), []byte(id)...)
	sum := sha256.Sum256(material)
	return float64(sum[0]) / 255
}

func response(raw []byte) map[string]any {
	var root struct {
		Model     string
		Questions map[string]json.RawMessage
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		panic(err)
	}
	answers := map[string]any{}
	for id := range root.Questions {
		answers[id] = map[string]any{"type": "noul", "noul": value(raw, id)}
	}
	return map[string]any{"model": root.Model, "answers": answers,
		"usage":   map[string]any{"input_tokens": len(raw), "output_tokens": 0},
		"request": "provider-request"}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Error("fixture response write failed")
	}
}

func unscored(t *testing.T, r api.JudgeReply) {
	t.Helper()
	if r.Status == "scored" || r.UnavailableReason == "" {
		t.Fatal("failure became scored")
	}
	for _, answer := range r.Results {
		if answer.Probability != nil || answer.Status != "unscored" {
			t.Fatal("failure has a probability")
		}
	}
}

func TestWireBatchAndNamedState(t *testing.T) {
	for _, provider := range []string{"typesafe", "clef-sglang"} {
		t.Run(provider, func(t *testing.T) {
			r := request()
			r.Config.Provider = provider
			if provider == "typesafe" {
				r.Config.Model = "jev-1.14.0"
			}
			for i := 1; i < 12; i++ {
				rule := r.Rules[0]
				rule.ID = api.ID(fmt.Sprintf("rule-%d", i))
				rule.Text += fmt.Sprint(i)
				r.Rules = append(r.Rules, rule)
			}
			var captured []byte
			var captureMu sync.Mutex
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				if req.Method != http.MethodPost || req.URL.Path != "/v1/systemone" ||
					req.Header.Get("Content-Type") != "application/json" ||
					req.Header.Get("Authorization") != "Bearer fixture-secret-value-1" {
					t.Error("wire or bearer changed")
				}
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				captureMu.Lock()
				captured = bytes.Clone(raw)
				captureMu.Unlock()
				writeJSON(t, w, response(raw))
			}))
			defer server.Close()
			store := &retained{}
			o := options(server.URL, r, store)
			o.CredentialHandle = "credential-a"
			o.Credential.Bytes = []byte("fixture-secret-value-1")
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			captureMu.Lock()
			sent := bytes.Clone(captured)
			captureMu.Unlock()
			if err != nil || got.Status != "scored" || len(got.Results) != 12 ||
				got.Request == nil || got.Request.Class != "judge_request" ||
				got.Request.Bytes != int64(len(sent)) || got.Request.SHA256 != Digest(sent) ||
				calls.Load() != 1 || got.Raw == nil || got.InputBytes != len(sent) ||
				got.InputTokens != len(sent) || got.CostMicros != int64(len(sent)) ||
				got.SelectedModel != r.Config.Model || got.ReportedModel != r.Config.Model ||
				got.DeploymentSHA256 != r.Config.DeploymentSHA256 {
				t.Fatal("incomplete wire observation")
			}
			for _, answer := range got.Results {
				if answer.Probability == nil || *answer.Probability != value(sent, string(answer.QuestionID)) {
					t.Fatal("probability mapping changed")
				}
			}
			original := *got.Results[1].Probability
			*got.Results[0].Probability = -1
			if *got.Results[1].Probability != original {
				t.Fatal("probability pointers alias")
			}
			var wire payload
			if err := json.Unmarshal(sent, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.State.Commands[0].Command != string(r.Command.Command) ||
				len(wire.State.Rules) != len(r.Rules) || wire.State.Context != r.Context {
				t.Fatal("named state lost bytes")
			}
			for i, rule := range r.Rules {
				q := wire.Questions[rule.ID]
				index := fmt.Sprintf("state.rules[%d]", i)
				if q.Type != "noul" || !strings.Contains(q.Instructions, index) ||
					strings.Contains(q.Instructions, string(r.Command.Command)) ||
					strings.Contains(q.Instructions, rule.Text) {
					t.Fatal("trusted instructions changed")
				}
			}
			if !bytes.Equal(store.objects["judge_request"][0], sent) ||
				!bytes.Contains(store.objects["judge_raw"][0], []byte("provider-request")) {
				t.Fatal("exact audit bytes lost")
			}
		})
	}
}

func TestResponseFailuresAreUnscored(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "decimal", "negative", "type",
		"model", "partial", "nested", "withheld", "usage", "empty-usage", "trailing",
		"unicode", "extra", "top-note", "http", "large", "cut-usage"} {
		t.Run(name, func(t *testing.T) {
			r := request()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				root := response(body)
				answer := root["answers"].(map[string]any)["rule-a"].(map[string]any)
				switch name {
				case "missing":
					delete(root["answers"].(map[string]any), "rule-a")
				case "decimal":
					answer["noul"] = json.Number("1.0000000000000001")
				case "negative":
					answer["noul"] = json.Number("-1e-999")
				case "type":
					answer["type"] = "choice"
				case "model":
					root["model"] = "wrong-model"
				case "partial":
					root["input_truncated"] = true
				case "nested":
					answer["metadata"] = map[string]any{"partial": true}
				case "withheld":
					root["withheld"] = true
				case "usage":
					delete(root, "usage")
				case "empty-usage":
					root["usage"] = map[string]any{}
				case "extra":
					answer["extra"] = 0
				case "top-note":
					root["note"] = "ordinary data"
				case "http":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "cut-usage":
					root["usage"].(map[string]any)["input_tokens"] = len(body) - 1
				}
				raw, err := json.Marshal(root)
				if err != nil {
					t.Error("fixture encoding failed")
				}
				switch name {
				case "duplicate":
					raw = append([]byte(`{"model":"other",`), raw[1:]...)
				case "trailing":
					raw = append(raw, []byte("{}")...)
				case "unicode":
					raw = bytes.Replace(raw, []byte(r.Config.Model), []byte(`\ud800`), 1)
				case "large":
					raw = bytes.Repeat([]byte("x"), MaxResponseBytes+1)
				}
				if _, err := w.Write(raw); err != nil {
					t.Error("fixture response write failed")
				}
			}))
			defer server.Close()
			adapter, err := New(options(server.URL, r, &retained{}))
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			unscored(t, got)
			if name == "top-note" && (got.Raw == nil ||
				got.UnavailableReason != "judge response is malformed, "+
					"incomplete or reports another model") {
				t.Fatal("unknown field missed the shape gate")
			}
		})
	}
}

type trip func(*http.Request) (*http.Response, error)

func (f trip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFitAndBudgetBeforeHTTP(t *testing.T) {
	for _, name := range []string{"byte", "unknown", "overflow", "bad-pin", "bad-size",
		"bad-context", "mutated", "zero", "fit-error", "fit-timeout", "budget", "cancel", "utf8"} {
		t.Run(name, func(t *testing.T) {
			r := request()
			o := options("http://127.0.0.1", r, &retained{})
			var calls atomic.Int64
			o.Client = &http.Client{Transport: trip(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return nil, errors.New("unexpected HTTP")
			})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := o.Fit
			o.Fit = func(ctx context.Context, raw []byte) (api.TokenFit, error) {
				fit, err := original(ctx, raw)
				switch name {
				case "overflow":
					fit.InputTokens = fit.ContextTokens
				case "bad-pin":
					fit.TokenizerSHA256 = Digest([]byte("another tokenizer"))
				case "bad-size":
					fit.InputBytes--
				case "bad-context":
					fit.ContextTokens--
				case "mutated":
					raw[0] = ' '
				case "zero":
					fit.InputTokens = 0
				case "fit-error":
					return fit, errors.New("fit failed")
				case "fit-timeout":
					<-ctx.Done()
					return fit, ctx.Err()
				}
				return fit, err
			}
			switch name {
			case "byte":
				r.Command.Command = append(bytes.Repeat([]byte("界"), 90000), []byte("suffix")...)
				r.Command.RawSHA256 = Digest(r.Command.Command)
			case "unknown":
				o.Fit = nil
			case "fit-timeout":
				r.DeadlineMS = 20
			case "budget":
				r.MaxCostMicros = 0
			case "cancel":
				cancel()
			case "utf8":
				r.Command.Command = []byte{0xff}
				r.Command.RawSHA256 = Digest(r.Command.Command)
			}
			adapter, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := adapter.Evaluate(ctx, r)
			unscored(t, got)
			if calls.Load() != 0 {
				t.Fatal("preflight sent HTTP")
			}
		})
	}
}

func TestWholeByteAndTokenBoundary(t *testing.T) {
	r := request()
	body, _, err := Payload(r)
	if err != nil {
		t.Fatal(err)
	}
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
	for _, tokenLimit := range []bool{false, true} {
		for _, fits := range []bool{false, true} {
			r := request()
			if tokenLimit {
				r.Config.ContextTokens = len(body) + 32
				if fits {
					r.Config.ContextTokens++
				}
			} else {
				r.Config.MaxBytes = len(body)
				if !fits {
					r.Config.MaxBytes--
				}
			}
			adapter, err := New(options(server.URL, r, &retained{}))
			if err != nil {
				t.Fatal(err)
			}
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil || (got.Status == "scored") != fits || got.InputBytes != len(body) {
				t.Fatal("complete request boundary failed")
			}
		}
	}
	if calls.Load() != 2 {
		t.Fatal("overflow reached HTTP")
	}
}

func TestProxyAndTransportControls(t *testing.T) {
	var proxyCalls, targetCalls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		targetCalls.Add(1)
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error("request read failed")
		}
		writeJSON(t, w, response(raw))
	}))
	defer target.Close()
	transport := target.Client().Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = target.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == proxy.Listener.Addr().String() {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.Listener.Addr().String())
	}
	// Prove the proxy really receives a remote-host HTTPS control first.
	control := &http.Client{Transport: transport}
	_, err = control.Get("https://provider.example.invalid")
	if err == nil || proxyCalls.Load() != 1 || targetCalls.Load() != 0 {
		t.Fatal("proxy control was not exercised")
	}
	r := request()
	r.Config.Provider, r.Config.Model = "typesafe", "jev-1.14.0"
	o := options("https://provider.example.invalid", r, &retained{})
	o.CredentialHandle, o.Credential.Bytes = "key-a", []byte("fixture-secret-value-1")
	o.Client = control
	adapter, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.Evaluate(context.Background(), r)
	if err != nil || got.Status != "scored" || proxyCalls.Load() != 1 || targetCalls.Load() != 1 {
		t.Fatal("proxy received judge traffic")
	}
	if transport.Proxy == nil {
		t.Fatal("caller transport was mutated")
	}
}

func TestUnusualTransports(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	var controls atomic.Int64
	http.DefaultTransport = trip(func(*http.Request) (*http.Response, error) {
		controls.Add(1)
		return nil, errors.New("control transport")
	})
	if _, err := http.Get("http://127.0.0.1"); err == nil || controls.Load() != 1 {
		t.Fatal("default control did not run")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error("request read failed")
		}
		writeJSON(t, w, response(raw))
	}))
	defer server.Close()
	for _, typedNil := range []bool{false, true} {
		r := request()
		o := options(server.URL, r, &retained{})
		if typedNil {
			var transport *http.Transport
			o.Client = &http.Client{Transport: transport}
		}
		adapter, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		got, err := adapter.Evaluate(context.Background(), r)
		if err != nil || got.Status != "scored" || controls.Load() != 1 {
			t.Fatal("unusual transport broke exchange")
		}
	}
}
