package cli

import (
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/jobcatalog"
)

func TestJobCatalogChoicesUsable(t *testing.T) {
	// Use the actual startup registration, not a miniature syntax stand-in.
	catalog, err := jobcatalog.Build([]byte("name = \"catalog-check\"\nlevels = [3]\n"), map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := catalog["laneboss_jobs"].([]map[string]any)
	if !ok || len(rows) == 0 {
		t.Fatal("the registered CLI produced no job rows")
	}
	for _, row := range rows {
		purpose, ok := row["purpose"].(string)
		if !ok || strings.TrimSpace(purpose) == "" {
			t.Fatalf("registered job %v has no CLI purpose and would disable all job judging", row["path"])
		}
	}
	criteria, err := jobcatalog.Criteria(catalog)
	if err != nil {
		t.Fatal("the actual registered CLI cannot reach job judging", err)
	}
	if len(criteria) != len(rows)+1 {
		t.Fatal("a registered job was dropped from the Choice options")
	}
	for _, command := range []string{"decisions init", "decisions load", "dashboard", "service", "none"} {
		if criteria[command] == "" {
			t.Fatalf("registered Choice lost %s", command)
		}
	}
}
