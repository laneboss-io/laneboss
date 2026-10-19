package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/judge/clef"
	"laneboss.io/laneboss/internal/v2/judge/typesafe"
	"laneboss.io/laneboss/internal/v2/judge/wire"
)

func TestProviderFactoriesAndSecrets(t *testing.T) {
	for _, provider := range []string{"clef-sglang", "typesafe", "clef-default"} {
		t.Run(provider, func(t *testing.T) {
			r := testRequest()
			r.Config.Provider = provider
			if provider == "clef-default" {
				r.Config.Provider = "clef-sglang"
			}
			if provider == "typesafe" {
				r.Config.Model = "jev-1.14.0"
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				raw, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error("request read failed")
				}
				if req.Header.Get("Authorization") != "Bearer fixture-secret-value-1" {
					t.Error("bearer was lost")
				}
				p := float64(len(raw)) / float64(len(raw)+1)
				reply := map[string]any{"model": r.Config.Model,
					"usage":   map[string]any{"input_tokens": len(raw), "output_tokens": 0},
					"answers": map[string]any{"rule-a": map[string]any{"type": "noul", "noul": p}}}
				if err := json.NewEncoder(w).Encode(reply); err != nil {
					t.Error("response write failed")
				}
			}))
			defer server.Close()
			fit := func(ctx context.Context, raw []byte) (api.TokenFit, error) {
				return api.TokenFit{Proved: true, InputBytes: len(raw), InputTokens: len(raw),
					ContextTokens: r.Config.ContextTokens, TokenizerSHA256: r.Config.TokenizerSHA256}, ctx.Err()
			}
			keep := func(ctx context.Context, class string, raw []byte) (api.BlobRef, error) {
				return api.BlobRef{ID: "object-a", Class: class, SHA256: wire.Digest(raw), Bytes: int64(len(raw))}, ctx.Err()
			}
			cost := func(in, out int64) (int64, error) { return in + out, nil }
			key := api.SecretMaterial{Bytes: []byte("fixture-secret-value-1")}
			var judge api.Judge
			var deps any
			var err error
			if provider == "typesafe" {
				o := typesafe.Dependencies{Endpoint: server.URL, Config: r.Config,
					CredentialHandle: "key-a", Credential: key, Fit: fit,
					SafetyTokens: 32, Retain: keep, Cost: cost, ReserveMicros: 100000}
				judge, err = typesafe.New(o)
				deps = o
			} else {
				selected := r.Config
				if provider == "clef-default" {
					selected.Provider, selected.Model = "", ""
				}
				o := clef.Dependencies{Endpoint: server.URL, Config: selected,
					CredentialHandle: "key-a", Credential: key, Fit: fit,
					SafetyTokens: 32, Retain: keep, Cost: cost, ReserveMicros: 100000}
				judge, err = clef.New(o)
				deps = o
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := judge.Evaluate(context.Background(), r)
			if err != nil || got.Status != "scored" || calls.Load() != 1 || got.Results[0].Probability == nil {
				t.Fatal("provider factory did not exchange")
			}
			for _, value := range []any{deps, judge} {
				raw, err := json.Marshal(value)
				if err != nil || strings.Contains(string(raw), string(key.Bytes)) ||
					strings.Contains(fmt.Sprintf("%+v", value), fmt.Sprint(key.Bytes)) ||
					strings.Contains(fmt.Sprintf("%+v %#v", value, value), string(key.Bytes)) {
					t.Fatal("provider formatting leaked key")
				}
			}
		})
	}
}
