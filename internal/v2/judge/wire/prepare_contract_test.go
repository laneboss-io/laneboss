package wire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPositiveReservationRequired(t *testing.T) {
	for _, provider := range []string{"clef-sglang", "typesafe"} {
		t.Run(provider, func(t *testing.T) {
			r := request()
			r.Config.Provider = provider
			if provider == "typesafe" {
				r.Config.Model = "jev-1.14.0"
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error(err)
					return
				}
				writeJSON(t, w, response(body))
			}))
			defer server.Close()
			for _, reserve := range []int64{0, -1, 100000} {
				store := &retained{}
				o := options(server.URL, r, store)
				o.ReserveMicros = reserve
				if provider == "typesafe" {
					o.CredentialHandle, o.Credential.Bytes = "key-a", []byte("fixture-secret-value-1")
				}
				adapter, err := New(o)
				if reserve <= 0 {
					var typed *api.Error
					if adapter != nil || !errors.As(err, &typed) || typed.Code != api.CodeInvalid ||
						typed.Message != "invalid judge cost reservation" || calls.Load() != 0 || len(store.objects) != 0 {
						t.Fatal("nonpositive reservation accepted")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				got, err := adapter.Evaluate(context.Background(), r)
				if err != nil || got.Status != "scored" || calls.Load() != 1 || got.CostMicros < 1 ||
					got.CostMicros > reserve || got.Raw == nil {
					t.Fatal("positive reservation control did not score")
				}
			}
		})
	}
}

// Preview is currently one fully retained batch. This boundary documents the
// contract gap rather than dropping the thirteenth rule or inventing receipts.
func TestSingleBatchPreviewBound(t *testing.T) {
	for _, size := range []int{12, 13} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			r := request()
			r.Purpose = "preview"
			for i := 1; i < size; i++ {
				rule := r.Rules[0]
				rule.ID = api.ID(fmt.Sprintf("rule-%d", i))
				r.Rules = append(r.Rules, rule)
			}
			var calls atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Error(err)
					return
				}
				writeJSON(t, w, response(body))
			}))
			defer server.Close()
			store := &retained{}
			adapter, err := New(options(server.URL, r, store))
			if err != nil {
				t.Fatal(err)
			}
			fit, fitErr := adapter.Fit(context.Background(), r)
			got, err := adapter.Evaluate(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if size == 12 {
				if fitErr != nil || !fit.Proved || got.Status != "scored" || len(got.Results) != size || calls.Load() != 1 {
					t.Fatal("single batch preview lost rules")
				}
				return
			}
			var typed *api.Error
			if !errors.As(fitErr, &typed) || typed.Code != api.CodeUnscored || fit.Proved ||
				got.Status != "unavailable" || got.UnavailableReason != "complete question set exceeds batch bound" ||
				len(got.Results) != 0 || got.Request != nil || got.Raw != nil || len(got.BatchIDs) != 0 ||
				calls.Load() != 0 || len(store.objects) != 0 || ScoredReply(got, r) == nil {
				t.Fatal("preview overflow became partial success")
			}
		})
	}
}
