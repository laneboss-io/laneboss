package laneturns

import "laneboss.io/laneboss/internal/rolepolicy"

func screenRoleSource(data []byte) error {
	return credentialError("org role source", data)
}

// turnConfiguration retains the org of the launcher's previous run when a
// configuration rewrite omits its org. The copy belongs only to this turn:
// other lanes and the loop's next configuration read keep their own binding.
// An explicitly configured org still reaches Previous's org comparison, and
// current role sources, drivers and settings are read again from that org.
func (c *configuration) turnConfiguration(previous object) (*configuration, error) {
	root, err := rolepolicy.ConfigRoot(c.home, c.data)
	if err != nil {
		return nil, err
	}
	if root != "" {
		return c, nil
	}
	if err := rolepolicy.ValidateEvent(previous); err != nil {
		return nil, err
	}
	context := obj(previous["role_context"])
	if context == nil {
		// Previous retains the refusal for lanes without a recorded org role.
		return c, nil
	}
	bound := *c
	bound.data = copyObject(c.data)
	bound.data["org_dir"] = context["org_dir"]
	bound.recordedTurnOrg = true
	return &bound, nil
}
