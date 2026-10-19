//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCredExecBound(t *testing.T) {
	m, registration, gate, store, _, _, _ := stopCredentialFixture(t, false)
	gate.control, _ = nativePair(t)
	records, err := store.Records()
	if err != nil || len(records) != 1 {
		t.Fatal("exec packet fixture journal unavailable")
	}
	record := records[0]
	// Projection metadata is comparison input in this component. Its opaque
	// helper version is unbounded by the receipt validator and makes the real
	// encoded packet exceed 64 KiB without changing the prepared spec/claim.
	p := *record.Credentials.Record
	p.Authority.Helper.Version = strings.Repeat("ordinary-version-", 5000)
	record.Credentials.Record = &p
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	_, err = m.openGate(context.Background(), registration)
	var typed *api.Error
	records, readErr := store.Records()
	if !errors.As(err, &typed) || typed.Code != api.CodeBudget || readErr != nil || len(records) != 1 || records[0].Gate.State != "prepared" || records[0].Gate.Permit != nil || records[0].Gate.Open != nil {
		t.Fatal("acceptance: oversized exec metadata consumed the permit")
	}
	if gate.released {
		t.Fatal("acceptance: oversized exec metadata released the real canary")
	}
	// A bounded no-environment packet still uses a real empty JSON array.
	p.Authority.Helper.Version = "ordinary-version"
	record.Credentials.Record = &p
	delivery, err := m.prepareCredentialExec(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := delivery.close(); err != nil {
			t.Error(err)
		}
	}()
	var packet credentialExecPacket
	if len(delivery.data) < 4 || json.Unmarshal(delivery.data[4:], &packet) != nil || decodeStrict(delivery.data[4:], &packet) != nil || packet.Objects == nil || len(packet.Objects) != 0 {
		t.Fatal("acceptance: credential exec packet lost its empty object array")
	}
}
