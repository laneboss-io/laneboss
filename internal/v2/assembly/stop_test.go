package assembly

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestRequestedStopOutcome(t *testing.T) {
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	expired, release := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer release()
	hostCancel := &api.Error{Code: api.CodeCancelled, Owner: "lb-v2-service", Message: "request cancelled"}
	cleanup := errors.New("owned resource close failed")
	for _, check := range []struct {
		name    string
		ctx     context.Context
		err     error
		success bool
	}{
		{"normal", context.Background(), nil, true},
		{"requested", stopped, hostCancel, true},
		{"wrapped", stopped, fmt.Errorf("host: %w", hostCancel), true},
		{"joined_cancel", stopped, errors.Join(hostCancel, context.Canceled), true},
		{"active", context.Background(), hostCancel, false},
		{"deadline", expired, hostCancel, false},
		{"cleanup", stopped, errors.Join(hostCancel, cleanup), false},
		{"foreign", stopped, &api.Error{Code: api.CodeCancelled, Owner: "lb-v2-identity"}, false},
		{"runtime", stopped, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-service"}, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			result := serveOutcome(check.ctx, check.err)
			if (result == nil) != check.success {
				t.Fatal("installed stop outcome changed an actual failure or refused a requested stop")
			}
			if !check.success && result != check.err {
				t.Fatal("installed stop rewrote its failure")
			}
		})
	}
}
