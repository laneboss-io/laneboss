package report

import (
	"fmt"
	"os"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/peers"
)

// Resolve uses the recorded caller identity, never a CLI-supplied actor.
func Resolve(name string) (caller.Principal, error) {
	c, err := config.Load(name)
	if err != nil {
		return caller.Principal{}, err
	}
	p, err := caller.Resolve(c)
	if err != nil {
		return caller.Principal{}, err
	}
	if faults.Get("caller-trust-env").Point != "" && strings.HasPrefix(p.ID, "lane:") && os.Getenv("LANEBOSS_LANE") == "" {
		if err := faults.Reach("caller-trust-env"); err != nil {
			return caller.Principal{}, err
		}
		// Instrumentation deliberately loses the recorded identity when the
		// label is unset; R4's allowed-peer control must reject this mutation.
		return caller.Principal{}, nil
	}
	return p, nil
}

func nodes(c *config.Configuration) (map[string]caller.Principal, error) {
	lanes, err := caller.Lanes(c)
	if err != nil {
		return nil, err
	}
	result := map[string]caller.Principal{"human": {ID: "human"}}
	for _, lane := range lanes {
		result[lane.Principal.ID] = lane.Principal
	}
	return result, nil
}

func principalNode(p caller.Principal, recorded map[string]caller.Principal) caller.Principal {
	if node, ok := recorded[p.ID]; ok {
		return node
	}
	return p
}

func refusal(from, to caller.Principal, recorded map[string]caller.Principal, action string) error {
	lanes := make([]caller.Principal, 0, len(recorded))
	for _, node := range recorded {
		lanes = append(lanes, node)
	}
	message := peers.Refusal(from, to, lanes)
	if action != "message" {
		message = strings.Replace(message, " may not message ", " may not "+action+" ", 1)
	}
	return fmt.Errorf("%s", message)
}

// CheckMessage is shared by all mail producers, including authenticated
// dashboard calls and report's lane terminal channel. The returned flag must
// be recorded as legacy_relationship on the delivery, including human mail.
func CheckMessage(name string, from caller.Principal, lane string) (bool, error) {
	if err := caller.RequireIdentity(from); err != nil {
		return false, err
	}
	c, err := config.Load(name)
	if err != nil {
		return false, err
	}
	recorded, err := nodes(c)
	if err != nil {
		return false, err
	}
	to, ok := recorded["lane:"+lane]
	if !ok {
		binding, err := eventstore.Bind(c.Name)
		if err != nil {
			return false, err
		}
		lanes, events, err := eventstore.ReadDisplay(binding)
		if err != nil {
			return false, err
		}
		projected := false
		for _, row := range lanes {
			projected = projected || row["lane"] == lane
		}
		if projected {
			for _, event := range events {
				if event["lane"] == lane && eventstore.ExternallyAppended(event) {
					// A target observation supplies only its name. Never add
					// it to recorded nodes or trust its claimed report line.
					to, ok = caller.Principal{ID: "lane:" + lane}, true
					break
				}
			}
		}
		if !ok {
			return false, fmt.Errorf("lane %s is not known", lane)
		}
	}
	source := principalNode(from, recorded)
	if to.Starter == "" {
		// Resolve role/instance levels from this configuration, never from a
		// sender label or a principal supplied by a mail adapter.
		local, err := caller.Lookup(c, source.ID)
		if err != nil {
			return false, err
		}
		source = local
	}
	allowed, legacy := peers.MessageDecision(source, to)
	if legacy && faults.Get("legacy-relationship-disabled").Point != "" {
		if err := faults.Reach("legacy-relationship-disabled"); err != nil {
			return false, err
		}
		allowed, legacy = peers.Allowed(source, to), false
	}
	if faults.Get("peers-allow-all").Point != "" {
		if err := faults.Reach("peers-allow-all"); err != nil {
			return false, err
		}
		allowed = true
	}
	if source.ID == "human" && faults.Get("peers-no-human-exception").Point != "" {
		if err := faults.Reach("peers-no-human-exception"); err != nil {
			return false, err
		}
		allowed = false
	}
	if !allowed {
		return false, refusal(source, to, recorded, "message")
	}
	return legacy, nil
}

// CheckAttach permits the recorded starter and a terminal human only.
func CheckAttach(name string, from caller.Principal, lane string) error {
	c, err := config.Load(name)
	if err != nil {
		return err
	}
	recorded, err := nodes(c)
	if err != nil {
		return err
	}
	to, ok := recorded["lane:"+lane]
	if !ok {
		return fmt.Errorf("lane %s is not known to configuration %s", lane, c.Name)
	}
	if from.ID == "human" || from.ID != "" && to.Starter == from.ID {
		return nil
	}
	return refusal(principalNode(from, recorded), to, recorded, "attach to")
}
