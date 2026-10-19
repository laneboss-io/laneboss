//go:build linux

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The boundary wrapper supplies the actual query and context to database/sql.
// It never fabricates a row, request bytes or database error.
type receiptBoundary struct {
	queryer
	before  func()
	queries int
}

func (q *receiptBoundary) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	q.queries++
	if q.before != nil {
		q.before()
	}
	return q.queryer.QueryRowContext(ctx, query, args...)
}

func TestLaunchReceiptRead(t *testing.T) {
	for _, mode := range []string{"exact", "deadline", "cancelled", "changed", "missing", "read_error"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := testStore(t)
			input := testTransaction(t)
			raw, err := json.MarshalIndent(input.Scope.Request, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			input.RawRequest = bytes.Clone(raw)
			commit, err := s.Transact(context.Background(), input)
			if err != nil {
				t.Fatal("receipt byte fixture did not commit", err)
			}
			if err := checkLaunchReceipt(context.Background(), s.db, commit.Operation.ID, raw); err != nil {
				t.Fatal("original receipt byte control failed", err)
			}
			ctx := context.Background()
			q := &receiptBoundary{queryer: s.db}
			operation, expected := commit.Operation.ID, bytes.Clone(raw)
			var cause error
			switch mode {
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(0, 0))
				defer cancel()
				cause = context.DeadlineExceeded
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				q.before = cancel // Expire at this SQL boundary, not an earlier plan read.
				cause = context.Canceled
			case "changed":
				expected, err = json.Marshal(input.Scope.Request)
				if err != nil || bytes.Equal(expected, raw) {
					t.Fatal("receipt representation control did not change bytes", err)
				}
			case "missing":
				operation = testID(t)
			case "read_error":
				// A closed real connection forces database/sql to refuse this
				// read without closing or corrupting the fixture's store.
				connection, err := s.db.Conn(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := connection.Close(); err != nil {
					t.Fatal(err)
				}
				q.queryer = connection
			}
			err = checkLaunchReceipt(ctx, q, operation, expected)
			if q.queries != 1 {
				t.Fatal("receipt control did not reach its SQL boundary", q.queries)
			}
			if cause != nil {
				if !errors.Is(err, cause) {
					t.Fatal("receipt read lost its context failure", err)
				}
			} else if mode == "changed" || mode == "missing" {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeIntegrity || typed.Message != "launch request is not the exact original receipt bytes" {
					t.Fatal("receipt read lost its exact byte integrity gate", err)
				}
			} else if mode == "read_error" {
				if !errors.Is(err, sql.ErrConnDone) {
					t.Fatal("receipt query failure became a byte mismatch", err)
				}
			} else if err != nil {
				t.Fatal("exact retained receipt bytes were refused", err)
			}
			var retained []byte
			if err := s.db.QueryRowContext(context.Background(), "SELECT request FROM receipts WHERE json_extract(operation,'$.id')=?", string(commit.Operation.ID)).Scan(&retained); err != nil || !bytes.Equal(retained, raw) {
				t.Fatal("receipt failure changed the retained original bytes", err)
			}
		})
	}
}
