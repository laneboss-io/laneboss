package orghook

import (
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/settings"
)

// Tool additions use the authenticated run's immutable snapshot. Instance-only
// sessions use the same resolver, with the instance's role and org sources.
type hookCaller struct {
	principal caller.Principal
	record    *caller.LaneRecord
}

func resolveHookCaller() (*hookCaller, error) {
	if name := os.Getenv("LANEBOSS_CONFIG"); name != "" {
		c, err := config.Load(name)
		if err != nil {
			return nil, invalid(configInvalid(err))
		}
		principal, record, err := caller.ResolveWithLane(c)
		if err != nil {
			return nil, invalid("layered tools cannot resolve their caller")
		}
		return &hookCaller{principal: principal, record: record}, nil
	}
	return &hookCaller{}, nil
}

func layeredTools(inst *instance, resolved *hookCaller) (*settings.Snapshot, error) {
	if strings.HasPrefix(resolved.principal.ID, "lane:") {
		record := resolved.record
		if record == nil || !record.Open {
			return nil, invalid("layered tools require an authenticated open lane")
		}
		if record.Payload["settings"] == nil {
			if faults.Get("settings-history-live").Point == "" {
				return settings.Empty(), nil
			}
			if err := faults.Reach("settings-history-live"); err != nil {
				return nil, err
			}
			role, _ := inst.data["role"].(string)
			return settings.Resolve(filepath.Dir(inst.home), inst.level, role, inst.name, map[string]any{}, config.ScreenSettings)
		}
		s, err := settings.Decode(record.Payload["settings"])
		if err != nil {
			return nil, invalid("layered tools cannot read the run settings")
		}
		return s, nil
	}
	role, _ := inst.data["role"].(string)
	return settings.Resolve(filepath.Dir(inst.home), inst.level, role, inst.name, map[string]any{}, config.ScreenSettings)
}
