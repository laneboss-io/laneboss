// Package caller resolves launchers from recorded processes, never from labels alone.
package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/instancename"
)

// Principal uses dashboard node IDs. Level zero and Starter empty mean unrecorded.
// Starter is read from the lane event; callers must never infer it from Level.
type Principal struct {
	ID      string
	Level   int
	Starter string
}

// Line is the ancestry recorded for a lane's current life.
type Line struct {
	Level       int
	LevelSource string
	Starter     string
}

func (l Line) Fields() map[string]any {
	var level, source, starter any
	if l.Level != 0 {
		level, source = l.Level, l.LevelSource
	}
	if l.Starter != "" {
		starter = l.Starter
	}
	return map[string]any{"level": level, "level_source": source, "starter": starter}
}

func LineFrom(p map[string]any) Line {
	n, _ := records.Integer(p["level"])
	source, _ := p["level_source"].(string)
	starter, _ := p["starter"].(string)
	return Line{n, source, starter}
}

type LaneRecord struct {
	Principal Principal
	Payload   map[string]any
	Open      bool
	Line      Line
	Seq       int64 // the sequence of the start or adoption that began this recorded life
}

// Lanes reads the first launcher start of each run. A resume retains the
// original report line of its life, so later events cannot make a current lane
// legacy. A reuse starts a new life. It does not change the event projection.
func Lanes(c *config.Configuration) (map[string]LaneRecord, error) {
	if c == nil {
		return nil, fmt.Errorf("caller resolution needs a configuration")
	}
	ec := &eventstore.Configuration{Name: c.Name, Home: c.Home, StateHome: c.StateHome, Directory: c.ConfigDir, StatePath: c.StateDir}
	dir, err := ec.OpenDirectory(false)
	if err != nil {
		return nil, fmt.Errorf("the caller's recorded state cannot be read")
	}
	result := map[string]LaneRecord{}
	if dir == nil {
		return result, nil
	}
	defer dir.Close()
	store, err := eventstore.Open(dir, false)
	if err != nil {
		return nil, fmt.Errorf("the caller's event store cannot be read")
	}
	if store == nil {
		return result, nil
	}
	defer store.Close()
	events, err := store.Events(0)
	if err != nil {
		return nil, fmt.Errorf("the caller's lane records cannot be read")
	}
	return lanesFromEvents(events)
}

func lanesFromEvents(events []eventstore.Object) (map[string]LaneRecord, error) {
	result := map[string]LaneRecord{}
	seen := map[string]map[int]bool{}
	for _, e := range events {
		// Projection inputs are observations. They cannot open or close a
		// recorded life, establish ancestry, or activate legacy fallback.
		if eventstore.ExternallyAppended(e) {
			continue
		}
		name, _ := e["lane"].(string)
		kind, _ := e["kind"].(string)
		p, _ := e["payload"].(map[string]any)
		if name == "" {
			continue
		}
		if kind == "lane.started" || kind == "lane.adopted" {
			run, _ := records.Integer(p["run"])
			if kind == "lane.adopted" {
				run = 1
			}
			if seen[name] == nil {
				seen[name] = map[int]bool{}
			}
			if seen[name][run] {
				continue
			}
			seen[name][run] = true
			if err := records.Validate(p); err != nil {
				return nil, eventstore.Integrity("the caller's lane report line is invalid: %s", err)
			}
			seq, ok := e["seq"].(int64)
			if !ok || seq <= 0 {
				return nil, fmt.Errorf("the caller's lane start sequence is invalid")
			}
			line := LineFrom(p)
			if previous, ok := result[name]; ok && p["how"] == "resume" {
				// Once a life has a starter, no later resume can erase or
				// replace it. A historical non-null starter closes fallback.
				if previous.Line.Starter != "" || line.Starter == "" {
					line = previous.Line
				}
				// A resume continues the same life: it keeps the life's start
				// sequence, so ancestry checks still see a parent that started
				// before its child even when the parent was resumed later.
				seq = previous.Seq
			}
			result[name] = LaneRecord{Principal: Principal{"lane:" + name, line.Level, line.Starter}, Payload: p, Open: kind == "lane.started", Line: line, Seq: seq}
		} else if kind == "lane.ended" || kind == "lane.lost" || kind == "lane.gone" {
			r, ok := result[name]
			if ok && sameInteger(p["run"], r.Payload["run"]) {
				r.Open = false
				result[name] = r
			}
		}
	}
	return result, nil
}

func sameInteger(a, b any) bool {
	x, ok := records.Integer(a)
	y, other := records.Integer(b)
	return ok && other && x == y
}

// Lane returns a target principal from recorded ancestry, not configuration guesses.
func Lane(c *config.Configuration, name string) (Principal, error) {
	all, err := Lanes(c)
	if err != nil {
		return Principal{}, err
	}
	r, ok := all[name]
	if !ok {
		return Principal{}, fmt.Errorf("the target lane has no recorded start or adoption")
	}
	return r.Principal, nil
}

// Lookup reads a stored message sender or report target by its canonical node ID.
func Lookup(c *config.Configuration, id string) (Principal, error) {
	if !records.ValidID(id) {
		return Principal{}, fmt.Errorf("the principal has no recorded identity")
	}
	if id == "human" {
		return Principal{ID: id}, nil
	}
	if strings.HasPrefix(id, "lane:") {
		return Lane(c, strings.TrimPrefix(id, "lane:"))
	}
	_, name, _ := strings.Cut(id, ":")
	p, _, err := Role(c, name)
	if err != nil {
		return Principal{}, err
	}
	if p.ID != id {
		return Principal{}, fmt.Errorf("the principal disagrees with its role record")
	}
	return p, nil
}

func readJSON(root *os.Root, path string, target any) error {
	f, err := root.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return fmt.Errorf("a caller record is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("a caller record is malformed")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("a caller record has trailing data")
	}
	return nil
}

// Resolve implements lane -> recorded session -> terminal ticket -> human -> unknown.
// LANEBOSS_LANE is only an agreement check: removing it cannot remove a lane identity.
func Resolve(c *config.Configuration) (Principal, error) {
	principal, _, err := ResolveWithLane(c)
	return principal, err
}

// ResolveWithLane returns the authenticated lane's current start record from the
// same event snapshot used to resolve its process identity. Labels alone never
// select a record, and non-lane callers have no lane record.
func ResolveWithLane(c *config.Configuration) (Principal, *LaneRecord, error) {
	all, err := Lanes(c)
	if err != nil {
		return Principal{}, nil, err
	}
	principal, err := resolveRecorded(c, all)
	if err != nil {
		return Principal{}, nil, err
	}
	if !strings.HasPrefix(principal.ID, "lane:") {
		return principal, nil, nil
	}
	record, ok := all[strings.TrimPrefix(principal.ID, "lane:")]
	if !ok || !record.Open || record.Principal != principal {
		return Principal{}, nil, fmt.Errorf("the caller's lane has no matching open start record")
	}
	return principal, &record, nil
}

func resolveRecorded(c *config.Configuration, all map[string]LaneRecord) (Principal, error) {
	table, err := processTable()
	if err != nil {
		return Principal{}, err
	}
	mine, ok := table[os.Getpid()]
	if !ok {
		return Principal{}, fmt.Errorf("the caller's process identity cannot be read")
	}
	tty, err := ttyName()
	if err != nil {
		return Principal{}, err
	}
	var root *os.Root
	if len(all) > 0 {
		root, err = os.OpenRoot(c.StateDir)
		if err != nil {
			return Principal{}, fmt.Errorf("the caller's run records cannot be read")
		}
		defer root.Close()
	}
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	matched := Principal{}
	for _, name := range names {
		r := all[name]
		if !r.Open {
			continue
		}
		launch, _ := r.Payload["launch"].(string)
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(launch) {
			return Principal{}, eventstore.Integrity("an open run has no recorded launch identity")
		}
		var run struct {
			Config        string    `json:"config"`
			Lane          string    `json:"lane"`
			Launch        string    `json:"launch"`
			Supervisor    process   `json:"supervisor"`
			Runner        *process  `json:"runner"`
			RunnerSession *process  `json:"runner_session"`
			Processes     []process `json:"processes"`
		}
		err := readJSON(root, "lanes/"+name+"/runs/"+launch+".json", &run)
		if err != nil && !os.IsNotExist(err) {
			return Principal{}, fmt.Errorf("an open lane's process record cannot be read")
		}
		found := false
		if err == nil {
			if run.Config != c.Name || run.Lane != name || run.Launch != launch {
				return Principal{}, fmt.Errorf("an open lane's process record disagrees with its event")
			}
			ids := []process{run.Supervisor}
			if run.Runner != nil {
				ids = append(ids, *run.Runner)
			}
			// A sampled orphan is not a current ancestor of the runner. On
			// Darwin it can supply identity only in that runner's live session;
			// otherwise a remembered setsid child would evade the session gate.
			if runtime.GOOS != "darwin" {
				ids = append(ids, run.Processes...)
			}
			for _, id := range ids {
				if p, ok := table[id.PID]; ok && id.Start != "" && numericStart(p.Start) != numericStart(id.Start) {
					return Principal{}, fmt.Errorf("a recorded process identity uses another process-table format; use the recorded setting")
				}
				if ancestor(id, mine, table) || tty != "" && laneProcess(id, mine, table) {
					found = true
					break
				}
			}
			if !found {
				found, err = laneSessionMatches(run.Runner, run.RunnerSession, mine.SID)
				if err != nil {
					return Principal{}, err
				}
			}
		}
		if !found && tty != "" {
			pane, err := lanePane(r.Payload, tty)
			if err != nil {
				return Principal{}, err
			}
			found = pane
		}
		if found {
			if matched.ID != "" && matched.ID != r.Principal.ID {
				return Principal{}, fmt.Errorf("the caller matches more than one lane")
			}
			matched = r.Principal
		}
	}
	label, set := os.LookupEnv("LANEBOSS_LANE")
	if set && (matched.ID == "" || matched.ID != "lane:"+label) {
		return Principal{}, fmt.Errorf("LANEBOSS_LANE disagrees with the caller's recorded lane identity")
	}
	if matched.ID != "" {
		return matched, nil
	}
	_, configured, selectionError := config.IdentityService(c)
	if selectionError != nil {
		return Principal{}, selectionError
	}
	if configured {
		p, err := resolveService(c)
		if err != nil {
			return Principal{}, err
		}
		for _, key := range []string{"LANEBOSS_ROLE", "LANEBOSS_INSTANCE"} {
			if label := os.Getenv(key); p.ID != "human" && label != "" && p.ID != "supervisor:"+label && p.ID != "instance:"+label {
				return Principal{}, fmt.Errorf("the role label disagrees with the service identity%s", sessionInstead)
			}
		}
		return p, nil
	}
	if p, err := resolveSession(c); err != nil || p.ID != "" {
		return p, err
	}
	for _, signal := range []struct{ Variable, Kind string }{{"LANEBOSS_ROLE", "supervisor"}, {"LANEBOSS_INSTANCE", "instance"}} {
		name := os.Getenv(signal.Variable)
		if name == "" {
			continue
		}
		if !roleName.MatchString(name) && !instancename.Valid(name) {
			return Principal{}, fmt.Errorf("the caller's role or instance name is invalid")
		}
		p, _, err := Role(c, name)
		if err != nil {
			return Principal{}, err
		}
		if signal.Kind == "instance" && !strings.HasPrefix(p.ID, "instance:") {
			continue
		}
		roles, err := os.OpenRoot(c.StateDir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Principal{}, fmt.Errorf("the caller's role ticket cannot be read")
		}
		var ticket roleTicket
		err = readJSON(roles, "roles/"+name+".json", &ticket)
		roles.Close()
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return Principal{}, fmt.Errorf("the caller's role ticket is unreadable")
		}
		if recorded, ok := table[ticket.Process.PID]; ok && ticket.Process.Start != "" && numericStart(recorded.Start) != numericStart(ticket.Process.Start) {
			return Principal{}, fmt.Errorf("a role ticket uses another process-table format; use the recorded setting")
		}
		if ticket.Config == c.Name && ticket.Principal == p.ID && ticketMatches(ticket, mine, table) {
			return p, nil
		}
	}
	if tty != "" {
		return Principal{ID: "human"}, nil
	}
	return Principal{}, nil
}

func ticketMatches(ticket roleTicket, mine process, table map[int]process) bool {
	return ancestor(ticket.Process, mine, table) && mine.SID > 0 && table[ticket.Process.PID].SID == mine.SID
}

func lanePane(p map[string]any, tty string) (bool, error) {
	session, _ := p["session"].(map[string]any)
	socket, _ := session["socket"].(string)
	name, _ := session["name"].(string)
	if socket == "" || name == "" {
		return false, fmt.Errorf("the lane has no recorded terminal socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tmux", "-S", socket, "list-panes", "-t", "="+name, "-F", "#{pane_tty}")
	var errors bytes.Buffer
	cmd.Stderr = &errors
	data, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return false, fmt.Errorf("the lane terminal did not answer")
		}
		// A missing pane/socket is normal after a supervising process exits.
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, fmt.Errorf("the lane terminal cannot be checked")
	}
	for _, pane := range strings.Fields(string(data)) {
		if pane == tty {
			return true, nil
		}
	}
	return false, nil
}

// LifecycleActor records unknown callers and detected steps as the launcher.
func LifecycleActor(id string) string {
	if faults.Get("actor-fixed-laneboss").Point != "" {
		if err := faults.Reach("actor-fixed-laneboss"); err != nil {
			panic(err)
		}
		return "laneboss"
	}
	if records.ValidID(id) {
		return id
	}
	return "laneboss"
}

// Launch resolves the starter once, and selects the lane's own recorded level.
func Launch(c *config.Configuration, role string) (Principal, Line, error) {
	p, err := Resolve(c)
	if err != nil {
		return Principal{}, Line{}, err
	}
	line := Line{Level: 3, LevelSource: "protocol", Starter: p.ID}
	if role != "" {
		target, source, err := Role(c, role)
		if err != nil {
			return Principal{}, Line{}, err
		}
		line.Level, line.LevelSource = target.Level, source
	}
	return belowStarter(p, line)
}

// LaunchLevel is Launch for a lane whose level the org's role policy chose: lane start and lane adopt take it from
// --level (L3 when absent), because --role names an org role template there, not a supervisor or instance entry. L3 is
// the protocol's own lane level; any other level is recorded with the source "org". A caller that nothing identifies
// (no recorded lane, session or ticket, and not the human at a terminal) is refused here at every level, before the
// level rule and the role gate; registering a supervisor session does not come through this function.
func LaunchLevel(c *config.Configuration, level int) (Principal, Line, error) {
	p, err := Resolve(c)
	if err != nil {
		return Principal{}, Line{}, err
	}
	if err = requireStarter(p); err != nil {
		return Principal{}, Line{}, err
	}
	line := Line{Level: level, LevelSource: "protocol", Starter: p.ID}
	if level != 3 {
		line.LevelSource = "org"
	}
	return belowStarter(p, line)
}

// belowStarter keeps a lane's level below its starter's recorded level.
func belowStarter(p Principal, line Line) (Principal, Line, error) {
	level := p.Level
	if level == 0 && strings.HasPrefix(p.ID, "lane:") {
		level = 3
	}
	if faults.Get("starter-level-minus-one").Point != "" && p.Level > 3 {
		if err := faults.Reach("starter-level-minus-one"); err != nil {
			return Principal{}, Line{}, err
		}
		line.Level = p.Level - 1
	}
	if level > 0 && line.Level >= level {
		return Principal{}, Line{}, fmt.Errorf("the lane's level must be below its starter's recorded level")
	}
	return p, line, nil
}

// Configuration adapts already validated command-group configurations.
func Configuration(name, home, states, directory, state string, data map[string]any) *config.Configuration {
	return &config.Configuration{Name: name, Home: home, StateHome: states, ConfigDir: directory, StateDir: state, Store: filepath.Join(state, "events.sqlite"), Data: data}
}
