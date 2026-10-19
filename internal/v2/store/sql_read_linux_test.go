//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// A closed real sql.Conn produces a database/sql error independent of the
// caller's context. The boundary wrapper passes through the actual SQL call.
func TestSQLReadCauses(t *testing.T) {
	s, _ := testStore(t)
	id := testID(t)
	readers := map[string]func(context.Context, queryer) error{
		"projection": func(ctx context.Context, q queryer) error {
			var value api.Lane
			return storedProjection(ctx, q, "lane", id, &value)
		},
		"object": func(ctx context.Context, q queryer) error {
			_, _, err := objectRow(ctx, q, id)
			return err
		},
		"effect": func(ctx context.Context, q queryer) error {
			_, err := effectRow(ctx, q, id)
			return err
		},
		"allocation": func(ctx context.Context, q queryer) error {
			_, err := s.dataAllocation(ctx, q, api.LaunchPlanRecord{}, id)
			return err
		},
		"parent": func(ctx context.Context, q queryer) error {
			// The selector is deliberately absent from SQL; supply its complete
			// shape so the test exercises the row read and its actual error.
			scope := api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: id}}
			plan := api.LaunchPlanRecord{Reservation: api.LaunchReservation{ID: id}}
			claim := api.LaunchClaim{ReservationID: id, EffectID: id, ClaimID: id, ClaimantID: id, Generation: 1}
			_, err := s.dataParent(ctx, q, scope, plan, claim)
			return err
		},
		"budget": func(ctx context.Context, q queryer) error {
			_, err := allocationBudget(ctx, q, api.LaunchPlanRecord{}, id)
			return err
		},
	}
	for name, read := range readers {
		t.Run(name, func(t *testing.T) {
			// An absent row is still an authority/not-found refusal, rather
			// than a database or context error.
			var absent *api.Error
			want := api.CodeNotFound
			if name == "allocation" {
				want = api.CodeForbidden
			}
			missingErr := read(context.Background(), s.db)
			if name == "budget" {
				if !errors.Is(missingErr, sql.ErrNoRows) {
					t.Fatal("SQL absence changed its existing refusal", missingErr)
				}
			} else if !errors.As(missingErr, &absent) || absent.Code != want {
				t.Fatal("SQL absence changed its existing refusal", missingErr)
			}
			connection, err := s.db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := connection.Close(); err != nil {
				t.Fatal(err)
			}
			if err := read(context.Background(), connection); !errors.Is(err, sql.ErrConnDone) {
				t.Fatal("SQL read failure was relabeled as authority", err)
			}
			for _, mode := range []string{"cancelled", "deadline"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					cause := error(context.Canceled)
					before := cancel
					if mode == "deadline" {
						cancel()
						ctx, cancel = context.WithDeadline(context.Background(), time.Unix(0, 0))
						cause, before = context.DeadlineExceeded, nil
					}
					defer cancel()
					q := &receiptBoundary{queryer: connection, before: before}
					err := read(ctx, q)
					if q.queries != 1 || !errors.Is(err, cause) {
						t.Fatal("failed SQL read lost its context cause", err, q.queries)
					}
				})
			}
		})
	}
}

func TestSQLSuccessAfterCancel(t *testing.T) {
	s, scope, ref, content := linearObjectFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = context.WithValue(ctx, objectVerificationKey{}, func(api.ID, int64) { cancel() })
	metadata, actual, err := objectRow(ctx, s.db, ref.ID)
	if ctx.Err() == nil || err != nil || metadata.Ref != ref || testDigest(actual) != testDigest(content) {
		t.Fatal("successful SQL read was replaced by context expiry", err)
	}
	if !objectVisible(scope, metadata.ACL) {
		t.Fatal("successful object control lost visibility")
	}
}
