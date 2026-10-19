package lane

import (
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/peers"
	"laneboss.io/laneboss/internal/rolepolicy"
)

func (c *configuration) callerConfig() *config.Configuration {
	return caller.Configuration(c.name, c.home, c.states, c.directory, c.state, c.data)
}

// starter resolves who starts a lane and the report line the lane records. The lane's level is the org role policy's
// (--level, L3 when absent): --role names an org role template at that level, so it is never read as a supervisor or
// instance name. The caller's authenticated identity, not the environment, says whether the caller is the human: a
// declared --principal human is refused for any other authenticated caller, before the role policy runs.
func (c *configuration) starter(a arguments) (caller.Principal, caller.Line, error) {
	level, err := rolepolicy.ParseLevel(a.get("level"))
	if err != nil {
		return caller.Principal{}, caller.Line{}, refuse("%s", err.Error())
	}
	principal, line, err := caller.LaunchLevel(c.callerConfig(), level)
	if err != nil {
		return caller.Principal{}, caller.Line{}, refuse("%s", err)
	}
	if err = rolepolicy.Authenticated(a.get("principal"), principal.ID); err != nil {
		// This role gate's 0.7.0 CLI contract prefixes every diagnostic line.
		// Keep setup/service recovery lines under their separate plain format.
		return caller.Principal{}, caller.Line{}, &problem{code: 2, prefix: "refused", message: err.Error(), prefixRecovery: true}
	}
	return principal, line, nil
}

func (c *configuration) caller() (caller.Principal, error) {
	p, err := caller.Resolve(c.callerConfig())
	if err != nil {
		return caller.Principal{}, refuse("%s", err)
	}
	return p, nil
}

// Collection requires a lower recorded level and starter ancestry for the same
// lane lives, bounded to four hops within this configuration. Each parent's
// start/adoption must precede its child, including the caller's final hop;
// reusing a name cannot transfer the old life's descendants to the new life.
func (c *configuration) archivePermission(from caller.Principal, lane string) error {
	if !strings.HasPrefix(from.ID, "lane:") || from.ID == "lane:"+lane {
		return nil
	}
	all, err := caller.Lanes(c.callerConfig())
	if err != nil {
		return refuse("%s", err)
	}
	target, ok := all[lane]
	if !ok {
		return refuse("the target lane has no recorded start or adoption")
	}
	to := target.Principal
	if from.Level >= 4 && from.Level <= 6 && to.Level >= 3 && to.Level < from.Level {
		if faults.Get("archive-level-only").Point != "" {
			if err = faults.Reach("archive-level-only"); err != nil {
				return err
			}
			return nil
		}
		current := target
		for hops := 0; hops < 4 && strings.HasPrefix(current.Principal.Starter, "lane:"); hops++ {
			parent, ok := all[strings.TrimPrefix(current.Principal.Starter, "lane:")]
			if !ok {
				break
			}
			if parent.Seq >= current.Seq {
				if faults.Get("archive-ancestry-any-life").Point == "" {
					break
				}
				if err = faults.Reach("archive-ancestry-any-life"); err != nil {
					return err
				}
			}
			if parent.Principal.ID == from.ID {
				if faults.Get("archive-refuse-child").Point != "" {
					if err = faults.Reach("archive-refuse-child"); err != nil {
						return err
					}
					return refuse("a lane may archive only itself")
				}
				return nil
			}
			current = parent
		}
	}
	return refuse("a lane may collect itself or, as a recorded L4-L6 supervisor, lower-level descendants started directly or through the same recorded lane lives")
}

func (c *configuration) messagePermission(from caller.Principal, lane string) error {
	all, err := caller.Lanes(c.callerConfig())
	if err != nil {
		return refuse("%s", err)
	}
	to, ok := all[lane]
	if !ok {
		return refuse("the target lane has no recorded report line")
	}
	if peers.Allowed(from, to.Principal) {
		return nil
	}
	principals := []caller.Principal{}
	for _, r := range all {
		principals = append(principals, r.Principal)
	}
	return refuse("%s", peers.Refusal(from, to.Principal, principals))
}
