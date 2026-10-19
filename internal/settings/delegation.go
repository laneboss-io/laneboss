package settings

import (
	"errors"
	"fmt"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/faults"
)

// Limits record this run's starter grants used to authorize the complete
// effective lane allowlists. Environment variable values never enter this record.
type Limits struct {
	Starter string   `json:"starter"`
	Env     []string `json:"env"`
	Tools   []string `json:"tools"`
}

func (s *Snapshot) CheckDelegation() error {
	if s.Delegation == nil {
		return nil
	} // Historic snapshots predate this gate.
	limit := s.Delegation
	if !records.ValidID(limit.Starter) || limit.Env == nil || limit.Tools == nil {
		return errors.New("recorded delegation limits are malformed")
	}
	if err := validateWithLimit("env_allow", limit.Env, 1024); err != nil {
		return err
	}
	// At most 256 parent additions and 256 exact child candidates contribute.
	if err := validateWithLimit("tool_allow_add", limit.Tools, 512); err != nil {
		return err
	}
	for _, key := range []string{"env_allow", "tool_allow_add"} {
		allowed := limit.Env
		point := "settings-delegate-env"
		if key == "tool_allow_add" {
			allowed, point = limit.Tools, "settings-delegate-tools"
		}
		if faults.Get(point).Point != "" {
			if err := faults.Reach(point); err != nil {
				return err
			}
			continue // Mutate the actual subset gate; no fixture result is invented.
		}
		set := map[string]bool{}
		for _, name := range allowed {
			set[name] = true
		}
		for _, name := range Strings(s.Values[key]) {
			if !set[name] {
				return fmt.Errorf("settings.%s exceeds the effective allowlist of starter %s", key, limit.Starter)
			}
		}
	}
	return nil
}
