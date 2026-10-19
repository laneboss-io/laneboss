// Package delegation binds explicit child grants to the recorded starter.
package delegation

import (
	"errors"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/orghook"
	"laneboss.io/laneboss/internal/rolepolicy"
	"laneboss.io/laneboss/internal/settings"
)

// Bind accepts an already authenticated starter, or its immutable recorded ID
// on resume and turn. A missing starter supplies no authority; only independent
// current owner grants can then authorize the child's names.
func Bind(c *config.Configuration, starter string, child *settings.Snapshot) error {
	if err := caller.RequireIdentity(caller.Principal{ID: starter}); err != nil {
		// The unidentified-start mutant removes the identity requirement as a
		// whole, so this secondary boundary must not mask its real admission.
		// Release builds have no active fault point; identified starters always
		// pass through the full delegation checks below.
		if faults.Get("caller-unidentified-start").Point != "" {
			return faults.Reach("caller-unidentified-start")
		}
		return err
	}
	if child.Delegation != nil && faults.Get("settings-frozen-delegation").Point != "" {
		return child.CheckDelegation()
	}
	if !records.ValidID(starter) {
		return errors.New("delegation requires a recorded starter")
	}
	// Recorded limits describe the previous run; they never authorize this one.
	child.Delegation = nil
	root, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil {
		return &Unresolved{Starter: starter, cause: err}
	}
	unresolved := func(cause error) error {
		// Only current owner sources can replace missing delegated authority.
		// Replay their precedence without the lane's retained --set selections.
		owner := settings.Empty()
		for _, key := range []string{"env_allow", "tool_allow_add", "tool_deny_add"} {
			for _, layer := range child.Entries[key].Layers {
				if layer.Scope == "org" || layer.Scope == "role" || layer.Scope == "instance" {
					owner.Add(key, layer)
				}
			}
		}
		current, err := limits(root, starter, child.Instance, owner, child)
		if err == nil {
			child.Delegation = current
			err = child.CheckDelegation()
			if err == nil {
				return nil
			}
		}
		child.Delegation = nil
		return &Unresolved{Starter: starter, cause: cause}
	}
	var parent *settings.Snapshot
	instance := ""
	if strings.HasPrefix(starter, "lane:") {
		lanes, err := caller.Lanes(c)
		if err != nil {
			return unresolved(err)
		}
		record, exists := lanes[strings.TrimPrefix(starter, "lane:")]
		if !exists || record.Principal.ID != starter {
			return unresolved(errors.New("delegation starter has no matching lane record"))
		}
		if record.Payload["settings"] != nil {
			parent, err = settings.Decode(record.Payload["settings"])
			if err != nil {
				return unresolved(err)
			}
			instance = parent.Instance
		} else {
			parent = settings.Empty()
		}
	} else if strings.HasPrefix(starter, "instance:") {
		instance = strings.TrimPrefix(starter, "instance:")
		level, role, err := settings.Instance(root, instance, config.ScreenSettings)
		if err != nil {
			return unresolved(err)
		}
		parent, err = settings.Resolve(root, level, role, instance, map[string]any{}, config.ScreenSettings)
		if err != nil {
			return unresolved(err)
		}
	} else {
		// Configured supervisors and humans have no automatic org-instance
		// assignment. Their declared grants are the org's settings.
		parent, err = settings.Resolve(root, 0, "", "", map[string]any{}, config.ScreenSettings)
		if err != nil {
			return unresolved(err)
		}
	}
	current, err := limits(root, starter, instance, parent, child)
	if err != nil {
		return unresolved(err)
	}
	child.Delegation = current
	return child.CheckDelegation()
}

func limits(root, starter, instance string, parent, child *settings.Snapshot) (*settings.Limits, error) {
	envNames := map[string]bool{}
	for _, name := range append(append([]string{}, settings.BaseEnv...), settings.Strings(parent.Values["env_allow"])...) {
		envNames[name] = true
	}
	env := make([]string, 0, len(envNames))
	for name := range envNames {
		env = append(env, name)
	}
	sort.Strings(env)
	// Keep all declared parent additions in the recorded ceiling, not only the
	// child's first selection, so later re-resolution can choose another owned
	// name without extending the starter's authority.
	requested := map[string]bool{}
	for _, name := range append(settings.Strings(parent.Values["tool_allow_add"]), settings.Strings(child.Values["tool_allow_add"])...) {
		requested[name] = true
	}
	candidates := make([]string, 0, len(requested))
	for name := range requested {
		candidates = append(candidates, name)
	}
	sort.Strings(candidates)
	tools, err := orghook.DelegableTools(root, instance, settings.Strings(parent.Values["tool_allow_add"]), settings.Strings(parent.Values["tool_deny_add"]), candidates)
	if err != nil {
		return nil, err
	}
	return &settings.Limits{Starter: starter, Env: env, Tools: tools}, nil
}
