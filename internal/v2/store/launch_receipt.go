package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// A failed read supplies no bytes to compare. Preserve cancellation/deadline
// failures so the caller can report their actual cause. A missing receipt or
// successfully read different bytes still fail the exact-byte integrity gate.
func checkLaunchReceipt(ctx context.Context, db queryer, operation api.ID, original []byte) error {
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT request FROM receipts WHERE json_extract(operation,'$.id')=?", string(operation)).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fault(api.CodeIntegrity, "launch request is not the exact original receipt bytes")
		}
		// SQLite can surface an interrupted query through a driver error. The
		// failed query's expired context remains the authoritative cause.
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return err
	}
	if !bytes.Equal(raw, original) {
		return fault(api.CodeIntegrity, "launch request is not the exact original receipt bytes")
	}
	return nil
}
