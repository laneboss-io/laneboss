package ticket

import (
	"context"
	"database/sql"
	"errors"
)

type consumerKey struct{}

// Consumer is set only by the service from its accepted kernel peer. No ticket
// or raw request body is retained in this record.
type Consumer struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
	UID   uint32 `json:"uid"`
}

func WithConsumer(ctx context.Context, peer Consumer) context.Context {
	return context.WithValue(ctx, consumerKey{}, peer)
}

func (s *Store) LastConsumer(ctx context.Context) (*Consumer, error) {
	var peer Consumer
	err := s.db.QueryRowContext(ctx, `SELECT pid, start, uid FROM identity_ticket_consumers ORDER BY consumed_at DESC LIMIT 1`).Scan(&peer.PID, &peer.Start, &peer.UID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, refusal(Unavailable)
	}
	return &peer, nil
}
