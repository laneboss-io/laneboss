package orgdiscord

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"time"
)

// ReadLookups reads the history hook's existing injection receipts in full.
// Query/prompt text is never returned. The org file reader pins all paths.
func ReadLookups(org string) ([]map[string]any, error) {
	return ReadLookupsContext(context.Background(), org)
}

func ReadLookupsContext(ctx context.Context, org string) ([]map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := openOrg(org)
	if err != nil {
		return nil, err
	}
	defer f.close()
	path := filepath.Join(".laneboss", "shared", "state", "history", "injections.jsonl")
	if _, err = f.root.Lstat(path); os.IsNotExist(err) {
		return []map[string]any{}, nil
	} else if err != nil {
		return nil, err
	}
	data, err := f.readContext(ctx, path, "the history injection log")
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		value, err := parseJSON(line, "the history injection receipt")
		record, ok := value.(map[string]any)
		if err != nil || !ok {
			return nil, refused("the history injection log holds an invalid receipt")
		}
		instance, instanceOK := record["instance"].(string)
		stamp, stampOK := record["at"].(string)
		ids, idsOK := record["ids"].([]any)
		if _, err = time.Parse(time.RFC3339Nano, stamp); err != nil || !stampOK || !instanceOK || instance == "" || !idsOK {
			return nil, refused("the history injection receipt has invalid metadata")
		}
		for _, id := range ids {
			if text, ok := id.(string); !ok || text == "" {
				return nil, refused("the history injection receipt has an invalid decision id")
			}
		}
		rows = append(rows, map[string]any{"instance": instance, "time": stamp, "decision_ids": ids})
	}
	return rows, nil
}
