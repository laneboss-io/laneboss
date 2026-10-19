package ledger

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/decisions"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/orgdiscord"
	"laneboss.io/laneboss/internal/orgtree"
)

type associationContext struct {
	kind, id                            string
	aliases, projects                   map[string]bool
	scopes, feedback, messages, lookups []object
}

func (c *associationContext) references(e object) bool {
	p := obj(e["payload"])
	for _, key := range []string{"instance", "supervisor", "employee", "parent_instance", "from", "to", "sender"} {
		if c.aliases[text(p[key])] {
			return true
		}
	}
	actor := text(e["actor"])
	return actor != "laneboss" && actor != "supervisor" && c.aliases[strings.TrimPrefix(actor, "instance:")]
}
func rootFor(c *config.Configuration) string {
	root := text(obj(c.Data["dashboard"])["org"])
	if root == "" && c.Organisation != "" {
		candidate := filepath.Join(c.Home, "orgs", c.Organisation)
		if _, err := os.Stat(filepath.Join(candidate, ".laneboss", "org.toml")); err == nil {
			root = candidate
		}
	}
	if filepath.Base(root) == ".laneboss" {
		root = filepath.Dir(root)
	}
	return root
}
func readContext(ctx context.Context, c *config.Configuration, s Selection) (*associationContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	x := &associationContext{kind: "org", id: c.Name, aliases: map[string]bool{}, projects: map[string]bool{}, scopes: []object{}, feedback: []object{}, messages: []object{}}
	if s.Lane != "" {
		x.kind, x.id = "lane", s.Lane
		x.aliases[s.Lane] = true
	}
	if s.Instance != "" {
		x.kind, x.id = "instance", s.Instance
		x.aliases[s.Instance] = true
	}
	root := rootFor(c)
	if root != "" {
		org, err := orgtree.ReadOverview(root)
		if err != nil {
			return nil, err
		}
		for _, entry := range list(org["instances"]) {
			row := obj(entry)
			name := text(row["name"])
			level, _ := numeric(row["level"])
			alias := strings.TrimPrefix(name, fmt.Sprintf("L%d-", int(level)))
			if s.Instance != "" && (name == s.Instance || alias == s.Instance) {
				x.id = name
				x.aliases[name], x.aliases[alias], x.aliases[strings.ToLower(name)] = true, true, true
			}
		}
		messages, err := orgdiscord.ReadMessagesContext(ctx, root)
		if err != nil {
			return nil, err
		}
		x.messages = messages
		lookups, err := orgdiscord.ReadLookupsContext(ctx, root)
		if err != nil {
			return nil, err
		}
		x.lookups = lookups
	}
	if s.Instance != "" {
		for name, value := range obj(c.Data["supervisors"]) {
			if x.aliases[name] {
				for _, project := range list(obj(value)["projects"]) {
					x.projects[text(project)] = true
				}
			}
		}
	}
	paths := []string{filepath.Join(c.StateDir, "decisions.sqlite")}
	if root != "" {
		paths = append(paths, filepath.Join(root, ".laneboss", "shared", "services", "decisions.sqlite"))
	}
	for _, path := range paths {
		view, err := decisions.ReadDisplay(path, "")
		if err != nil {
			return nil, err
		}
		if obj(view["integrity"])["ok"] == false {
			return nil, errors.New("the decision store failed integrity verification")
		}
		x.scopes = append(x.scopes, view["lane_scopes"].([]map[string]any)...)
		x.feedback = append(x.feedback, view["feedback"].([]map[string]any)...)
	}
	return x, nil
}

// Only the title of the hash-checked kept original brief is returned. The
// rendered prompt, rules, message bodies and arbitrary path fields are not served.
func readTitle(c *eventstore.Configuration, lane string, rendered object) (any, any, error) {
	if rendered == nil {
		return nil, nil, nil
	}
	d, err := c.OpenDirectory(false)
	if err != nil {
		return nil, nil, err
	}
	if d == nil {
		return nil, nil, errors.New("the kept brief is unavailable")
	}
	defer d.Close()
	if err = eventstore.CheckRendered(rendered, d); err != nil {
		return nil, nil, err
	}
	inputs := list(obj(rendered["payload"])["inputs"])
	hash := text(obj(inputs[0])["sha256"])
	data, err := d.ReadLane(lane, "inputs", hash, 8*1024*1024)
	if err != nil {
		return nil, nil, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != hash {
		return nil, nil, errors.New("the kept brief changed while its title was read")
	}
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			heading := strings.TrimLeft(trim, "#")
			if strings.HasPrefix(heading, " ") || strings.HasPrefix(heading, "\t") {
				return capText(fmt.Sprint(eventstore.ScreenValue(strings.TrimSpace(heading)))), hash, nil
			}
		}
	}
	return nil, hash, nil
}
