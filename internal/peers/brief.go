package peers

import (
	"fmt"
	"sort"
	"strings"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/orghook"
)

// ReportLine is shared by the start, adoption, resume and turn composers.
func ReportLine(c *config.Configuration, lane string, line caller.Line) (string, error) {
	all, err := caller.Lanes(c)
	if err != nil {
		return "", err
	}
	p := caller.Principal{ID: "lane:" + lane, Level: line.Level, Starter: line.Starter}
	names := []string{}
	for name, r := range all {
		if name != lane && r.Principal.Level == p.Level && p.Level > 0 && p.Starter != "" && r.Principal.Starter == p.Starter && Allowed(p, r.Principal) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	level, source := "unrecorded", "unrecorded"
	if line.Level > 0 {
		level = fmt.Sprintf("L%d", line.Level)
		source = line.LevelSource
	}
	parent := line.Starter
	if parent == "" {
		parent = "unrecorded; reports go to human"
	}
	channels, err := Channels(c, line.Starter)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "## Report line\n\n- Level: %s (source: %s)\n- Supervisor: %s\n- Report: `laneboss report --config %s --file FILE` (or `--file -`).\n", level, source, parent, c.Name)
	for _, channel := range []string{"dashboard", "discord", "file", "terminal"} {
		status := "not installed"
		if channels[channel] {
			status = "installed"
		}
		fmt.Fprintf(&b, "- %s: %s\n", channel, status)
	}
	peers := "none recorded"
	if len(names) > 0 {
		peers = strings.Join(names, ", ")
	}
	fmt.Fprintf(&b, "- Allowed peers at render time: %s.\n\nLanes talk only to lanes of the same recorded level under the same recorded supervisor. Reports and messages may go up or down the recorded report line. A null level or supervisor has no peers; reports go to the human.\n\nThe human may message you at any time, from the dashboard.\n\n", peers)
	fmt.Fprintf(&b, "Use `laneboss lane send --config %s --lane PEER --file FILE` for a permitted peer, or `-` for standard input. The org hook understands these checked communication commands and their configuration state effects; identity and recipient authorization remain the CLI's checks.\n\n", c.Name)
	if orghook.LanebossFlag([]string{"lane", "send"}, "--ask") {
		fmt.Fprintf(&b, "For a peer question, use `laneboss lane send --config %s --lane PEER --ask --file FILE`.\n\n", c.Name)
	} else {
		b.WriteString("For a question, keep its text in a file and use the report or permitted peer-message route above. This CLI's lane-send grammar does not yet declare --ask.\n\n")
	}
	return b.String(), nil
}
