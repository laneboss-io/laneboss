package ticket

import (
	"context"
	"testing"
	"time"
)

func TestConsumerAndRetention(t *testing.T) {
	s, _ := newTestStore(t)
	instant := time.Now()
	s.now = func() time.Time { return instant }
	scope := Scope{Config: "example", Level: 5, Role: "top"}
	raw := issueTestTicket(t, s, scope, DefaultTTL)
	peer := Consumer{PID: 42, Start: "kernel-generation", UID: 1001}
	if err := s.Consume(WithConsumer(context.Background(), peer), scope, raw); err != nil {
		t.Fatal("the actual conditional consume did not record its peer")
	}
	read, err := s.LastConsumer(context.Background())
	if err != nil || read == nil || *read != peer {
		t.Fatal("the persisted consuming peer differs from the trusted context")
	}
	requireReason(t, s.Consume(context.Background(), scope, raw), Used)
	instant = instant.Add(48 * time.Hour)
	control := issueTestTicket(t, s, scope, DefaultTTL)
	read, err = s.LastConsumer(context.Background())
	if err != nil || read != nil {
		t.Fatal("authorized issue did not prune the old consumer")
	}
	requireReason(t, s.Consume(context.Background(), scope, raw), Unknown)
	if err := s.Consume(context.Background(), scope, control); err != nil {
		t.Fatal("retention cleanup burned the newly issued control")
	}
}
