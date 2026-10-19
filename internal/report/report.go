// Package report delivers a credential-screened report through every installed
// channel and keeps each outcome in the event store.
package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/protocol"
)

const usage = "usage: laneboss report --config NAME --file FILE|- [--ask]\n       laneboss report watch --config NAME --as TARGET"

type arguments struct {
	config, file, as string
	watch, help, ask bool
}

func parse(args []string) (arguments, error) {
	var a arguments
	if len(args) > 0 && args[0] == "watch" {
		a.watch = true
		args = args[1:]
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == "-h" || word == "--help" {
			a.help = true
			continue
		}
		key, value, set := strings.Cut(word, "=")
		if key == "--ask" {
			if set || seen[key] {
				return a, fmt.Errorf("%s", cliargs.Reject(key))
			}
			seen[key], a.ask = true, true
			continue
		}
		if key != "--config" && key != "--file" && key != "--as" {
			return a, fmt.Errorf("%s", cliargs.Reject(""))
		}
		if seen[key] {
			return a, fmt.Errorf("%s", cliargs.Reject(key))
		}
		seen[key] = true
		if !set {
			i++
			if i >= len(args) {
				return a, fmt.Errorf("%s", cliargs.Expected(key))
			}
			value = args[i]
		}
		if value == "" || strings.HasPrefix(value, "--") {
			return a, fmt.Errorf("%s", cliargs.Expected(key))
		}
		switch key {
		case "--config":
			a.config = value
		case "--file":
			a.file = value
		case "--as":
			a.as = value
		}
	}
	if a.help {
		return a, nil
	}
	if a.watch {
		if a.as == "" || a.file != "" || a.ask {
			return a, fmt.Errorf("watch requires --as TARGET and takes no --file or --ask")
		}
	} else if a.file == "" || a.as != "" {
		return a, fmt.Errorf("report requires --file FILE|- and takes no --as")
	}
	return a, nil
}

// LaneSender connects report to the checked lane mail queue without an import
// cycle. The CLI supplies laneturns.SendReport.
type LaneSender func(string, caller.Principal, string, []byte) error

type Delivery struct {
	ReportID           string `json:"report_id"`
	Channel            string `json:"channel"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	To                 string `json:"to,omitempty"`
	LegacyRelationship bool   `json:"legacy_relationship,omitempty"`
}

type channel struct {
	name      string
	installed bool
	send      func() error
}

func deliver(id string, channels []channel, record func(Delivery) error, stdout, stderr io.Writer, route ...Delivery) int {
	delivered, failed := 0, 0
	for _, ch := range channels {
		result := Delivery{ReportID: id, Channel: ch.name, Status: "skipped", Reason: "not installed"}
		if len(route) > 0 {
			result.To, result.LegacyRelationship = route[0].To, route[0].LegacyRelationship
		}
		if ch.installed {
			result.Status, result.Reason = "delivered", ""
			if err := ch.send(); err != nil {
				result.Status = "failed"
				result.Reason = err.Error()
				failed++
			} else {
				delivered++
			}
		}
		if err := record(result); err != nil {
			failed++
			fmt.Fprintln(stderr, "report: cannot record report.delivered for "+ch.name+": "+err.Error())
		}
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			failed++
			fmt.Fprintln(stderr, "report: cannot write channel outcome")
		}
		if result.Status == "failed" && faults.Get("report-stop-at-failure").Point != "" {
			if err := faults.Reach("report-stop-at-failure"); err != nil {
				fmt.Fprintln(stderr, "report: cannot record mutation reach")
				return 3
			}
			break
		}
	}
	if delivered == 0 {
		return 3
	}
	if failed > 0 {
		return 4
	}
	return 0
}

func levelValue(level int) any {
	if level == 0 {
		return nil
	}
	return level
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("cannot create report identity")
	}
	return "report-" + hex.EncodeToString(bytes[:]), nil
}

func validateText(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("the report must be valid UTF-8 text")
	}
	if utf8.RuneCount(data) > 4000 {
		return fmt.Errorf("the report is larger than 4000 characters")
	}
	if strings.TrimSpace(string(data)) == "" {
		return fmt.Errorf("the report is empty")
	}
	_, err := eventstore.Validate(eventstore.Object{"kind": "report.sent", "actor": "laneboss", "protocol_version": protocol.Version, "payload": eventstore.Object{"text": string(data)}})
	return err
}

func appendRecord(c *eventstore.Configuration, actor, kind string, payload any) error {
	d, err := c.OpenDirectory(true)
	if err != nil {
		return err
	}
	defer d.Close()
	s, err := eventstore.Open(d, true)
	if err != nil {
		return err
	}
	defer s.Close()
	if actor == "" {
		actor = "laneboss"
	}
	_, err = s.Append(eventstore.Object{"kind": kind, "actor": actor, "protocol_version": protocol.Version, "payload": payload})
	return err
}

func target(c *config.Configuration, from caller.Principal, recorded map[string]caller.Principal) caller.Principal {
	if source, ok := recorded[from.ID]; ok && strings.HasPrefix(from.ID, "lane:") && source.Level != 0 && source.Starter != "" {
		if parent, ok := recorded[source.Starter]; ok {
			return parent
		}
		if parent, err := caller.Lookup(c, source.Starter); err == nil {
			return parent
		}
		// Keep the recorded recipient even if its role record is no longer
		// available; its current level is then unrecorded.
		return caller.Principal{ID: source.Starter}
	}
	return caller.Principal{ID: "human"}
}

// targets preserves the configuration-wide report route of a historical lane
// whose start has no starter. No relationship is adopted by sending a report.
func targets(c *config.Configuration, from caller.Principal, recorded map[string]caller.Principal) ([]caller.Principal, bool, error) {
	source, known := recorded[from.ID]
	if !known || !strings.HasPrefix(source.ID, "lane:") || source.Starter != "" {
		return []caller.Principal{target(c, from, recorded)}, false, nil
	}
	names := []string{}
	for name := range table(c.Data["supervisors"]) {
		names = append(names, name)
	}
	sort.Strings(names)
	result := []caller.Principal{}
	for _, name := range names {
		p, _, err := caller.Role(c, name)
		if err != nil {
			return nil, false, err
		}
		result = append(result, p)
	}
	if len(result) == 0 {
		result = append(result, caller.Principal{ID: "human"})
	}
	return result, true, nil
}

func sendReport(c *config.Configuration, store *eventstore.Configuration, from, to caller.Principal, level int, legacy bool, data []byte, sendLane LaneSender, stdout, stderr io.Writer) int {
	id, err := newID()
	if err != nil {
		fmt.Fprintln(stderr, "report: "+err.Error())
		return 3
	}
	payload := eventstore.Object{"report_id": id, "from": from.ID, "from_level": levelValue(level), "to": to.ID, "to_level": levelValue(to.Level), "text": string(data)}
	if legacy {
		payload["legacy_relationship"] = true
	}
	channels := installedChannels(c, store, from, to, payload, data, sendLane)
	route := Delivery{}
	if legacy {
		route.To, route.LegacyRelationship = to.ID, true
	}
	return deliver(id, channels, func(result Delivery) error {
		outcome := eventstore.Object{"report_id": result.ReportID, "channel": result.Channel, "status": result.Status, "reason": result.Reason}
		if legacy {
			outcome["to"], outcome["legacy_relationship"] = to.ID, true
		}
		return appendRecord(store, from.ID, "report.delivered", outcome)
	}, stdout, stderr, route)
}

// Run handles report and report watch. Channel failures return 4 for partial
// delivery or 3 when none succeeded; input and identity refusals return 2.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, sendLane LaneSender) int {
	a, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, usage+"\nrefused: "+err.Error())
		return 2
	}
	if a.help {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	c, err := config.Load(a.config)
	if err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	from, err := caller.Resolve(c)
	if err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	if err := caller.RequireIdentity(from); err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	store, err := eventstore.Bind(c.Name)
	if err != nil {
		fmt.Fprintln(stderr, "report: "+err.Error())
		return 3
	}
	if a.watch {
		return watch(c, store, from, a.as, stdout, stderr)
	}
	var data []byte
	if a.file == "-" {
		if stdin == nil {
			fmt.Fprintln(stderr, "refused: standard input is closed")
			return 2
		}
		data, err = io.ReadAll(io.LimitReader(stdin, 16001))
	} else {
		data, err = store.ReadExternal(a.file, 16000)
	}
	if err != nil {
		fmt.Fprintln(stderr, "refused: the report file cannot be read")
		return 2
	}
	if err = validateText(data); err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	if a.ask {
		answered, check := decidedQuestion(c, from, data)
		if answered != nil {
			if err := json.NewEncoder(stdout).Encode(answered); err != nil {
				fmt.Fprintln(stderr, "report: cannot write recorded answer")
				return 3
			}
			return 0
		}
		// Delivery retains its channel-by-channel contract. A separate result
		// tells the caller whether this question could be checked before sending.
		if err := json.NewEncoder(stdout).Encode(check); err != nil {
			fmt.Fprintln(stderr, "report: cannot write question check")
			return 3
		}
	}
	recorded, err := nodes(c)
	if err != nil {
		fmt.Fprintln(stderr, "report: "+err.Error())
		return 3
	}
	to := target(c, from, recorded)
	if to.ID == "human" && faults.Get("report-drop-without-supervisor").Point != "" {
		if err := faults.Reach("report-drop-without-supervisor"); err != nil {
			fmt.Fprintln(stderr, "report: cannot record mutation reach")
			return 3
		}
		return 0
	}
	recipients, legacy, err := targets(c, from, recorded)
	if err != nil {
		fmt.Fprintln(stderr, "report: "+err.Error())
		return 3
	}
	delivered, failed := false, false
	for _, recipient := range recipients {
		code := sendReport(c, store, from, recipient, principalNode(from, recorded).Level, legacy, data, sendLane, stdout, stderr)
		delivered = delivered || code == 0 || code == 4
		failed = failed || code != 0
	}
	if !delivered {
		return 3
	}
	if failed {
		return 4
	}
	return 0
}

func table(v any) map[string]any { m, _ := v.(map[string]any); return m }
func text(v any) string          { s, _ := v.(string); return s }
