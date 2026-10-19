package orgtree

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/rolepolicy"
)

// Runner data belongs to a named configuration. Check only the explicitly
// selected configuration; never enumerate other configurations or their state.
func configuredRoleUses(org, name string) (map[string]bool, error) {
	configuration, err := config.Load(name)
	if err != nil {
		return nil, err
	}
	folder, err := rolepolicy.ConfigRoot(configuration.Home, configuration.Data)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(folder)
	if err != nil || resolved != org {
		return nil, errors.New("the named configuration does not select this org")
	}
	used := map[string]bool{}
	info, err := os.Lstat(configuration.Store)
	if os.IsNotExist(err) {
		return used, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("lane usage store must be an ordinary readable file")
	}
	location := url.URL{Scheme: "file", Path: configuration.Store, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, errors.New("lane usage store cannot be opened read-only")
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx, "SELECT payload FROM events WHERE kind IN ('lane.started','lane.adopted') ORDER BY seq LIMIT 50001")
	if err != nil {
		return nil, errors.New("lane usage records could not be checked")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 50000 {
			return nil, errors.New("lane usage check exceeded its record limit")
		}
		var text string
		if err := rows.Scan(&text); err != nil {
			return nil, errors.New("lane usage record cannot be read")
		}
		value, err := decodeJSON(text)
		if err != nil {
			return nil, errors.New("lane usage record is invalid JSON")
		}
		payload, ok := value.(map[string]any)
		if !ok || rolepolicy.ValidateEvent(payload) != nil {
			return nil, errors.New("lane usage record has an invalid role context")
		}
		context, _ := payload["role_context"].(map[string]any)
		role, _ := payload["role"].(string)
		level, ok := integer(context["level"])
		if context["org_dir"] == org && ok && role != "" {
			used[fmt.Sprintf("L%d/%s", level, role)] = true
		}
	}
	if rows.Err() != nil {
		return nil, errors.New("lane usage records could not be fully checked")
	}
	return used, nil
}
