//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The EOF-driven stand-in exits before Stop. Only one twin publishes its
// observation; the other actually fails that write. A containment refusal
// must not choose the credential disposition in either order.
func TestStopContainmentExit(t *testing.T) {
	for _, committed := range []bool{true, false} {
		name := "uncommitted"
		if committed {
			name = "committed"
		}
		t.Run(name, func(t *testing.T) {
			m, reg, _, store, owner, broker, _ := stopCredentialFixture(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var audit bytes.Buffer
			ctx = context.WithValue(ctx, helperTimingKey{}, &helperRequestTrace{timing: &audit})
			request := stopExitRequest(reg)
			naturalCanaryExit(t, ctx, owner)
			if committed {
				if _, err := m.observeGate(ctx, request.Target); err != nil {
					t.Fatal(err)
				}
			} else {
				refuseExitCommit(t, ctx, m, request.Target)
			}
			_, err := m.stopGate(ctx, request)
			if !errors.Is(err, broker.failure) {
				t.Fatal("stop did not reach the actual broker refusal", err)
			}
			raw, err := EncodeWire(containmentQuery{LeaseID: request.Target.LeaseID, Opened: true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = m.dispatch(ctx, "containment_live", raw)
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown && typed.Code != api.CodeUnauthenticated {
				t.Fatal("ended stand-in regained live authentication", err)
			}
			records, err := store.Records()
			if err != nil || len(records) != 1 || records[0].Credentials.Stop == nil {
				t.Fatal("stop lost the durable credential decision", err)
			}
			r := records[0]
			if committed {
				if !committedExit(r) || r.Revoked || broker.request.Reason != "release" || r.Credentials.Stop.Note != stopAfterExit {
					t.Fatal("live containment refusal quarantined a committed natural exit")
				}
			} else if !r.Revoked || broker.request.Reason != api.CredentialStopReason || r.Credentials.Stop.Note != "" || typed.Code != api.CodeContainmentUnknown {
				t.Fatal("unknown containment without a committed exit lost rotation")
			}
			if bytes.Contains(audit.Bytes(), []byte(stopAfterExit)) != committed {
				t.Fatal("stop audit disagrees with the durable exit order")
			}
		})
	}
}
