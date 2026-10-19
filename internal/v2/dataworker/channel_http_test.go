package dataworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

type channelClock struct{}

func (channelClock) Now() time.Time { return time.Now() }

func httpJob() (api.ChannelJob, []byte) {
	data := []byte(`{"content":"an actual channel message","artifacts":[]}`)
	ref := func(id, class string, raw []byte) api.BlobRef {
		return api.BlobRef{ID: api.ID(id), Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	runtime := ref("runtime", "manifest", []byte("runtime bytes"))
	return api.ChannelJob{ChannelID: "channel", ChannelGeneration: 1, DestinationID: "sink", MailID: "mail", ProviderIdempotencyKey: "provider-key",
		Payload: ref("payload", "channel_payload", data), Content: ref("content", "report", []byte("an actual channel message")), Artifacts: []api.BlobRef{},
		Runtime: &api.ChannelRuntime{Executable: api.Executable{ID: "fixed-worker", Version: "1", SHA256: manifest.Hash([]byte("worker"))}, Manifest: runtime, Reconcile: "provider_key"},
		Lease: api.WorkerLease{ID: "lease", Kind: "channel", Target: api.LifeRef{LifeID: "sender", Run: 1}, OperationID: "operation", EffectID: "effect", GrantSetID: "grants",
			Generation: 1, ExpiresAt: api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)), RuntimeManifest: runtime, Input: ref("input", "channel_input", []byte("input"))}}, data
}

func TestChannelHTTP(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(fmt.Sprint(lost), func(t *testing.T) {
			job, payload := httpJob()
			var mu sync.Mutex
			posts, reads := 0, 0
			var stored []byte
			receipt := ""
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/warm" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if r.Header.Get("Authorization") != "Bearer component-token" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodPost {
					posts++
					if r.Header.Get("Idempotency-Key") != string(job.ProviderIdempotencyKey) {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					stored, receipt = body, fmt.Sprintf("receipt-%d", posts)
					if lost && posts == 1 {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						if err := connection.Close(); err != nil {
							t.Error(err)
						}
						return
					}
				} else if r.Method == http.MethodGet {
					reads++
					if r.URL.Query().Get("key") != string(job.ProviderIdempotencyKey) || receipt == "" {
						w.WriteHeader(http.StatusNotFound)
						return
					}
				} else {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"receipt_id": receipt, "payload_sha256": manifest.Hash(stored)}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			kept := map[api.ID][]byte{}
			keep := func(ctx context.Context, data []byte) (api.BlobRef, error) {
				id := api.ID(fmt.Sprintf("response-%d", len(kept)))
				kept[id] = append([]byte(nil), data...)
				return api.BlobRef{ID: id, Class: "channel_receipt", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}, ctx.Err()
			}
			provider := ChannelHTTP{Endpoint: "endpoint", URL: server.URL, Token: "component-token", Client: server.Client()}
			if lost {
				warm, err := provider.Client.Get(server.URL + "/warm")
				if err != nil {
					t.Fatal(err)
				}
				if err := warm.Body.Close(); err != nil || warm.StatusCode != http.StatusNoContent {
					t.Fatal("provider connection was not warmed", err)
				}
			}
			result, err := ExchangeChannel(context.Background(), provider, job, payload, false, keep, channelClock{})
			if err != nil {
				t.Fatal("native provider exchange unavailable", err)
			}
			if lost && result.Outcome != "uncertain" {
				t.Fatal("lost acknowledgement was reported as confirmed")
			}
			result, err = ExchangeChannel(context.Background(), provider, job, payload, true, keep, channelClock{})
			if err != nil || result.Outcome != "confirmed" || api.ValidateChannelSendEvidence(job, result) != nil {
				t.Fatal("provider read-back did not recover exact accepted bytes", err)
			}
			mu.Lock()
			if posts != 1 || reads == 0 || !bytes.Equal(stored, payload) {
				t.Error("read-back resent or changed the provider payload", posts, reads)
			}
			mu.Unlock()
			if result.Response == nil || !bytes.Equal(kept[result.ReadBack.Response.ID], kept[result.Response.ID]) {
				t.Fatal("provider responses were not actually retained")
			}
		})
	}
}

func TestChannelReceiptMode(t *testing.T) {
	job, payload := httpJob()
	job.Runtime.Reconcile = "receipt_id"
	posts, reads := 0, 0
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			posts++
			body, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, payload) {
				t.Error("provider received different bytes", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		} else {
			reads++
			if r.URL.Query().Get("receipt_id") != "ack-1" || r.URL.Query().Has("key") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		if err := json.NewEncoder(w).Encode(channelAck{Receipt: "ack-1", Digest: manifest.Hash(payload)}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	keep := func(_ context.Context, raw []byte) (api.BlobRef, error) {
		return api.BlobRef{ID: "receipt", Class: "channel_receipt", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}, nil
	}
	result, err := ExchangeChannel(context.Background(), ChannelHTTP{URL: server.URL, Client: server.Client()}, job, payload, false, keep, channelClock{})
	if err != nil || result.Outcome != "confirmed" || api.ValidateChannelSendEvidence(job, result) != nil {
		t.Fatal("receipt capability did not read the acknowledged receipt", result.Error, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 || reads != 1 {
		t.Fatal("receipt exchange did not perform one send and read", posts, reads)
	}
}

func TestChannelDigest(t *testing.T) {
	job, payload := httpJob()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(channelAck{Receipt: "bad-ack", Digest: manifest.Hash([]byte("different payload"))}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	kept := false
	keep := func(_ context.Context, raw []byte) (api.BlobRef, error) {
		kept = true
		return api.BlobRef{ID: "receipt", Class: "channel_receipt", Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}, nil
	}
	result, err := ExchangeChannel(context.Background(), ChannelHTTP{URL: server.URL, Client: server.Client()}, job, payload, false, keep, channelClock{})
	if err != nil || result.Outcome != "uncertain" || result.Error == nil || result.Error.Code != api.CodeIntegrity || result.Error.Retryable || kept {
		t.Fatal("provider integrity failure lost its owning classification", result.Error, err)
	}
}
