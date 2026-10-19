//go:build linux

package store

import (
	"context"
	"database/sql"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchUnknownSchema(t *testing.T) {
	for _, kind := range []string{"weakened-trigger", "unknown-table"} {
		t.Run(kind, func(t *testing.T) {
			s, deps := testStore(t)
			if kind == "weakened-trigger" {
				if _, err := s.db.Exec("DROP TRIGGER objects_no_delete; CREATE TRIGGER objects_no_delete BEFORE DELETE ON objects WHEN 0 BEGIN SELECT RAISE(ABORT, 'immutable objects'); END;"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := s.db.Exec("CREATE TABLE unknown_extension(value TEXT)"); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			opened, err := New(deps)
			if opened != nil {
				t.Cleanup(func() {
					if err := opened.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			if err == nil {
				t.Fatal("unknown or weakened schema was accepted as a legacy upgrade")
			}
			expectCode(t, err, api.CodeIntegrity)
			// A refused open must preserve the unexpected schema for investigation.
			db, err := sql.Open("sqlite", deps.Directory+"/state.sqlite")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var count int
			name := "unknown_extension"
			if kind == "weakened-trigger" {
				name = "objects_no_delete"
			}
			if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM sqlite_master WHERE name=?", name).Scan(&count); err != nil || count != 1 {
				t.Fatal("schema refusal silently repaired the unknown input", err)
			}
		})
	}
}
