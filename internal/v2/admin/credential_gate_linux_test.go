//go:build linux

package admin

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestCredentialProjectionUnavailable(t *testing.T) {
	manager := &leaseManager{binding: testBinding()}
	record := leaseRecord{Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{
		Injection: api.Injection{SlotIDs: []api.ID{"retained-profile-slot"}},
	}}}}
	gate, err := manager.startConfinedGate(context.Background(), record)
	expected := failure(api.CodeUnavailable, "native credential projection receiver is not bound")
	var typed *api.Error
	if gate != nil || !errors.As(err, &typed) || typed.Code != expected.Code || typed.Owner != expected.Owner ||
		typed.Message != expected.Message || typed.Instead != expected.Instead {
		t.Fatal("acceptance: credential projection absence did not stop native preparation")
	}
}
