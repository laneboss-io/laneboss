package config

import (
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// ReadBoard reads only the explicitly configured Markdown board, using the
// configuration command's contained, bounded regular-file reader. It never
// accepts a client-supplied file path. Output is screened by the display caller.
func (c *Configuration) ReadBoard(now time.Time) ([]map[string]any, error) {
	path := stringOf(tableOf(c.Data["dashboard"])["board"])
	result := []map[string]any{}
	if path == "" {
		return result, nil
	}
	if filepath.Ext(path) != ".md" {
		return nil, invalid("dashboard.board must name a Markdown file")
	}
	reader, err := newReader(c.Name, c.ConfigDir, "configuration")
	if err != nil {
		return nil, err
	}
	defer reader.close()
	data, err := reader.read(path)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, invalid("dashboard.board must be UTF-8")
	}
	columns := map[string]int{}
	seen := map[string]bool{}
	fenced := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
			fenced = !fenced
			continue
		}
		if fenced || !strings.Contains(line, "|") {
			columns = map[string]int{}
			continue
		}
		cells := boardCells(line)
		candidate := map[string]int{}
		for i, cell := range cells {
			candidate[strings.ToLower(cell)] = i
		}
		if len(candidate) == 4 {
			_, id := candidate["id"]
			_, status := candidate["status"]
			_, due := candidate["due"]
			_, title := candidate["title"]
			if id && status && due && title {
				columns = candidate
				continue
			}
		}
		if len(columns) == 0 || strings.Trim(line, "|:- \t") == "" {
			continue
		}
		if len(cells) != 4 {
			return nil, invalid("dashboard.board has a row with the wrong number of columns")
		}
		id, status := cells[columns["id"]], cells[columns["status"]]
		due, title := cells[columns["due"]], cells[columns["title"]]
		if id == "" || title == "" || status == "" || seen[id] {
			return nil, invalid("dashboard.board rows need unique IDs, a status and a title")
		}
		seen[id] = true
		late := false
		if due != "" && due != "-" {
			at, e := time.Parse("2006-01-02", due)
			if e == nil {
				late = now.UTC().Format("2006-01-02") > at.Format("2006-01-02")
			} else {
				at, e = time.Parse(time.RFC3339, due)
				if e != nil {
					return nil, invalid("dashboard.board due dates must be YYYY-MM-DD or RFC3339")
				}
				late = now.After(at)
			}
		}
		switch strings.ToLower(status) {
		case "done", "completed", "complete", "closed", "cancelled", "canceled":
			late = false
		}
		result = append(result, map[string]any{"id": id, "status": status, "due": due, "title": title, "late": late})
	}
	return result, nil
}

func boardCells(line string) []string {
	line = strings.TrimSuffix(strings.TrimPrefix(line, "|"), "|")
	cells := []string{}
	var cell strings.Builder
	escaped := false
	for _, r := range line {
		if escaped {
			cell.WriteRune(r)
			escaped = false
		} else if r == '\\' {
			escaped = true
		} else if r == '|' {
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
		} else {
			cell.WriteRune(r)
		}
	}
	if escaped {
		cell.WriteRune('\\')
	}
	return append(cells, strings.TrimSpace(cell.String()))
}
