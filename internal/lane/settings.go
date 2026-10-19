package lane

import (
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/delegation"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

func (c *configuration) startSettings(a arguments) (arguments, *settings.Snapshot, error) {
	root, err := rolepolicy.ConfigRoot(c.home, c.data)
	if err != nil {
		return a, nil, refuse("%s", err)
	}
	if instance := a.get("instance"); instance != "" {
		level, role, err := settings.Instance(root, instance, screenRoleSource)
		if err != nil {
			return a, nil, refuse("%s", err)
		}
		if a.get("level") != "" && a.get("level") != strconv.Itoa(level) || a.get("role") != "" && a.get("role") != role {
			return a, nil, refuse("--instance must agree with --level and --role")
		}
		a.values["level"], a.values["role"] = strconv.Itoa(level), role
	}
	if err := rolepolicy.CheckStartName(c.home, c.data, a.get("level"), a.get("role"), screenRoleSource); err != nil {
		return a, nil, refuse("%s", err)
	}
	overrides, err := settings.Parse(a.sets, screenRoleSource)
	if err != nil {
		return a, nil, refuse("%s", err)
	}
	for _, key := range []string{"runner", "model", "effort", "account", "budget_minutes"} {
		option := key
		if key == "budget_minutes" {
			option = "budget"
		}
		if a.get(option) == "" {
			continue
		}
		// Account requests use checkAccount after runner selection. That gate
		// names the configured alternatives without repeating an unknown value.
		if key != "account" {
			if err := settings.ScreenChoice(a.get(option), screenRoleSource); err != nil {
				return a, nil, err
			}
		}
		if _, exists := overrides[key]; exists {
			return a, nil, refuse("a launch option and --set cannot define the same key")
		}
		// Keep the CLI's full-model diagnostic ahead of typed settings
		// validation, after credential screening has withheld unsafe values.
		if key == "model" && (!match(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, a.get(option)) || !strings.ContainsAny(a.get(option), "0123456789")) {
			return a, nil, refuse("--model must be a full model name that includes its version, not a family alias")
		}
		var value any = a.get(option)
		if key == "budget_minutes" {
			value, err = parseBudget(a.get(option))
			if err != nil {
				return a, nil, err
			}
		}
		if err := settings.Validate(key, value); err != nil {
			return a, nil, refuse("%s", err)
		}
		if key != "account" {
			overrides[key] = value
		}
	}
	level := 3
	if a.get("level") != "" {
		level, _ = strconv.Atoi(a.get("level"))
	}
	snapshot, err := settings.Resolve(root, level, a.get("role"), a.get("instance"), overrides, screenRoleSource)
	if err != nil {
		return a, nil, refuse("%s", err)
	}
	if account := a.get("account"); account != "" {
		if err := snapshot.RequestAccount(account); err != nil {
			return a, nil, refuse("%s", err)
		}
	}
	for _, key := range []string{"runner", "model", "effort", "account"} {
		if value, ok := snapshot.Values[key].(string); ok {
			a.values[key] = value
		}
	}
	return a, snapshot, nil
}

func (s *session) againSettings(previous object, a arguments) (*settings.Snapshot, error) {
	c := s.c
	root, err := rolepolicy.ConfigRoot(c.home, c.data)
	if err != nil {
		return nil, refuse("%s", err)
	}
	changes := object{}
	if a.get("account") != "" {
		// The recorded runner's account gate validates this request before any
		// resumed run is written; it is not an org role source.
		changes["account"] = a.get("account")
	}
	if a.get("budget") != "" {
		changes["budget_minutes"], err = parseBudget(a.get("budget"))
		if err != nil {
			return nil, err
		}
	}
	snapshot, err := settings.Again(root, previous, changes, screenRoleSource)
	if err != nil {
		return nil, refuse("%s", err)
	}
	starter := str(previous["starter"])
	if starter == "" {
		principal, err := c.caller()
		if err != nil {
			return nil, err
		}
		starter = principal.ID
	}
	if err := delegation.Bind(c.callerConfig(), starter, snapshot); err != nil {
		if unresolved, ok := err.(*delegation.Unresolved); ok {
			lane := a.get("lane")
			name := "settings-refusal-" + newID() + ".log"
			data, payload := unresolved.Record(integer(previous["run"]), s.lanePath(lane, name))
			root, err := s.laneRoot(lane, false)
			if err != nil {
				return nil, err
			}
			err = rootWrite(root, name, data, false, 0600)
			root.Close()
			if err != nil {
				return nil, err
			}
			if _, err := s.append(envelope(lane, "lane.refusal", payload, "laneboss"), 10); err != nil {
				return nil, err
			}
		}
		return nil, refuse("%s", err)
	}
	return snapshot, nil
}

func launchEnvironment(payload object, name, lane string, run int) ([]string, error) {
	return settings.Environment(os.Environ(), payload["settings"], map[string]string{"LANEBOSS_CONFIG": name, "LANEBOSS_LANE": lane, "LANEBOSS_RUN": strconv.Itoa(run), "LANEBOSS_PRINCIPAL": "supervisor"})
}
