package dashboard

import (
	"context"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/authorship"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/orgdiscord"
)

func messageView(ctx context.Context, c *config.Configuration, binding *eventstore.Configuration, events []eventstore.Object) (object, error) {
	human, agent := []object{}, []object{}
	for i := len(events) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := events[i]
		p, kind := obj(e["payload"]), str(e["kind"])
		byHuman := authorship.Reserved(str(e["actor"]))
		group := ""
		if strings.HasPrefix(kind, "owner.message") || strings.HasPrefix(kind, "channel.message") || strings.HasPrefix(kind, "org.message") || strings.HasPrefix(kind, "orgdiscord.message") || kind == "message.received" || kind == "message.sent" || p["audience"] == "human-agent" {
			group = "human"
		} else if strings.HasPrefix(kind, "agent.message") || strings.HasPrefix(kind, "supervisor.message") || kind == "lane.inbox" || kind == "lane.outbox" || kind == "lane.mailed" || kind == "lane.resumed" || kind == "lane.delivered" || kind == "brief.rendered" && e["lane"] != nil || p["audience"] == "agent-agent" {
			group = "agent"
		}
		if kind == "report.sent" {
			group = "agent"
			if p["to"] == "human" || p["from"] == "human" {
				group = "human"
			}
		}
		if kind == "lane.mailed" && byHuman {
			group = "human"
		}
		if group == "" || group == "human" && len(human) >= 100 || group == "agent" && len(agent) >= 100 {
			continue
		}
		from, to, role := p["from"], p["to"], p["sender_role"]
		if from == nil {
			from = p["sender"]
		}
		if from == nil {
			from = obj(p["author"])["display_name"]
		}
		if from == nil {
			from = e["actor"]
		}
		if to == nil {
			to = p["instance"]
		}
		if to == nil {
			to = e["lane"]
		}
		text := str(p["text"])
		if kind == "lane.mailed" {
			var err error
			text, err = eventstore.ReadMail(binding, e)
			if err != nil {
				return nil, err
			}
			role = e["actor"]
			if byHuman {
				group, from, role = "human", e["actor"], "human"
			}
		}
		// Brief/resume delivery events are visible as metadata. Their rendered
		// prompt files are never opened by the messages reader.
		direction := str(p["direction"])
		if byHuman {
			direction = "inbound"
		}
		if kind == "report.sent" && p["to"] == "human" {
			direction = "outbound"
		}
		if direction == "" {
			if strings.HasSuffix(kind, ".received") || strings.HasSuffix(kind, ".inbound") || kind == "lane.inbox" {
				direction = "inbound"
			} else if strings.HasSuffix(kind, ".sent") || strings.HasSuffix(kind, ".outbound") || kind == "lane.outbox" {
				direction = "outbound"
			}
		}
		if role == nil && group == "human" {
			if direction == "inbound" {
				role = e["actor"]
			} else if direction == "outbound" {
				role = "agent"
			}
		}
		// Sender/recipient metadata is text, never an arbitrary payload object.
		from, to, role = textField(from), textField(to), textField(role)
		row := object{"id": e["id"], "seq": e["seq"], "time": e["recorded_at"], "direction": direction, "sender_role": role, "from": from, "to": to, "text": text, "kind": kind}
		if p["legacy_relationship"] == true {
			row["legacy_relationship"] = true
		}
		if group == "human" {
			human = append(human, row)
		} else {
			agent = append(agent, row)
		}
	}
	if root := orgRoot(c); root != "" {
		stored, err := orgdiscord.ReadMessagesContext(ctx, root)
		if err != nil {
			return nil, err
		}
		human = append(human, stored...)
	}
	for _, rows := range []*[]object{&human, &agent} {
		sort.SliceStable(*rows, func(i, j int) bool {
			a, _ := time.Parse(time.RFC3339Nano, str((*rows)[i]["time"]))
			b, _ := time.Parse(time.RFC3339Nano, str((*rows)[j]["time"]))
			return a.After(b)
		})
		if len(*rows) > 100 {
			*rows = (*rows)[:100]
		}
		for _, row := range *rows {
			text := str(screen(row["text"]))
			runes := []rune(text)
			row["truncated"] = len(runes) > 500
			if len(runes) > 500 {
				text = string(runes[:499]) + "…"
			}
			row["text"] = text
		}
	}
	return object{"human_agent": human, "agent_agent": agent}, nil
}

func textField(value any) any {
	if text, ok := value.(string); ok {
		return text
	}
	return nil
}
