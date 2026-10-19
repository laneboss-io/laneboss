package store

import (
	"context"
	"database/sql"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// A deletion's protected object ID is never reused. New references cannot
// resurrect it between object collection and the final lane CAS, or afterward.
func rejectCollectedReferences(ctx context.Context, db queryer, raw []byte) error {
	for _, ref := range blobEdges(raw) {
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='collection_delete' AND id=?", string(ref.ID)).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fault(api.CodeConflict, "new reference selects an already collected immutable object")
		}
	}
	return nil
}

func collectionProjection(kind string) bool {
	return kind == "collection" || strings.HasPrefix(kind, "collection_")
}

func rejectCollectedKey(ctx context.Context, tx *sql.Tx, id api.ID) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='collection_delete' AND id=?", string(id)).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fault(api.CodeConflict, "collected immutable object identity cannot be reused")
	}
	return nil
}
