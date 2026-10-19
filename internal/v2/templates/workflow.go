package templates

import (
	"math"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"laneboss.io/laneboss/internal/v2/api"
)

type seedEntry struct {
	ID       string `toml:"id"`
	Text     string `toml:"text"`
	Instead  string `toml:"instead"`
	Band     string `toml:"band"`
	Critical bool   `toml:"critical"`
}

var workflowRoutes = map[string]string{
	"raw-codex-exec":              "session",
	"raw-claude-p":                "session",
	"raw-claude-print":            "session",
	"raw-claudock-run":            "session",
	"raw-tmux-new-session":        "laneboss lane start",
	"raw-tmux-new":                "laneboss lane start",
	"raw-tmux-kill-session":       "laneboss lane stop",
	"raw-tmux-send-keys":          "laneboss lane attach",
	"raw-tmux-attach":             "laneboss lane attach",
	"raw-tmux-attach-session":     "laneboss lane attach",
	"raw-aws-run-instances":       "laneboss box",
	"raw-gcloud-instances-create": "laneboss box",
}

// SeedRules validates the explicit initial workflow source. It is not a matcher
// and is never called to insert rules into an existing org during a render.
// Thresholds come from policy; the template module does not choose or lower them.
func SeedRules(source Source, thresholds api.Thresholds) ([]api.Rule, error) {
	if err := checkSource(source, WorkflowPath, source.Ref.Generation); err != nil {
		return nil, err
	}
	values := []float64{thresholds.Match, thresholds.UncertainLow, thresholds.UncertainHigh}
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return nil, invalid("seed thresholds must be finite probabilities")
		}
	}
	if thresholds.UncertainLow > thresholds.UncertainHigh || !safeID.MatchString(string(thresholds.CalibrationID)) {
		return nil, invalid("seed thresholds require ordered uncertainty bounds and calibration provenance")
	}
	entries, err := parseSeed(source.Bytes)
	if err != nil {
		return nil, err
	}
	result := make([]api.Rule, 0, len(entries))
	for _, entry := range entries {
		result = append(result, api.Rule{
			ID: api.ID(entry.ID), Text: entry.Text, Instead: entry.Instead,
			Band: entry.Band, Critical: false,
			Scope:  api.RuleScope{Levels: []int{}, Roles: []string{}},
			Source: source.Ref, Thresholds: thresholds,
		})
	}
	return result, nil
}

// parseSeed checks the initial pack without selecting policy thresholds or
// modifying an org. Bootstrap and full org validation both use this gate.
func parseSeed(data []byte) ([]seedEntry, error) {
	if len(data) == 0 || len(data) > MaxSourceBytes || !utf8.Valid(data) || strings.ContainsRune(string(data), 0) {
		return nil, invalid("initial workflow source must be bounded UTF-8 text")
	}
	var document struct {
		Blacklist []seedEntry `toml:"blacklist"`
	}
	metadata, err := toml.Decode(string(data), &document)
	if err != nil || len(metadata.Undecoded()) != 0 || len(document.Blacklist) != len(workflowRoutes) {
		return nil, invalid("initial workflow source must contain exactly the twelve plain-language entries")
	}
	seen := map[string]bool{}
	result := make([]seedEntry, 0, len(document.Blacklist))
	for _, entry := range document.Blacklist {
		route, known := workflowRoutes[entry.ID]
		if !known || seen[entry.ID] || strings.TrimSpace(entry.Text) == "" || entry.Band != "refuse" || entry.Critical {
			return nil, invalid("initial workflow entry has an invalid identity, band or critical flag")
		}
		if route == "session" {
			route = "laneboss lane start / laneboss lane resume / laneboss lane turn"
		}
		if entry.Instead != route {
			return nil, invalid("initial workflow entry lost its authentic Instead route")
		}
		if strings.HasPrefix(entry.ID, "raw-tmux-") &&
			(!strings.Contains(strings.ToLower(entry.Text), "agent session") ||
				!strings.Contains(strings.ToLower(entry.Text), "private build or test")) {
			return nil, invalid("tmux workflow entries must distinguish agent sessions from private build or test sessions")
		}
		seen[entry.ID] = true
		result = append(result, entry)
	}
	return result, nil
}
