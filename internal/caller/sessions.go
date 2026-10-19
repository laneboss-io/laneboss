package caller

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/faults"
)

const sessionInstead = "\nInstead: run laneboss start --role ROLE from the persistent session that will issue these commands."

// startInstead is the recovery route of a lane start or adoption by a caller that nothing identifies. It names both
// ways to be identified: a headless session presents a human-issued ticket, and
// the human runs the command from a terminal.
const startInstead = "\nInstead: register with laneboss start --role ROLE from the persistent session that will issue these commands, or run this command from a terminal as the human."

// RequireIdentity is for operations that need a proven caller. Read-only state
// can still use Resolve without this check.
func RequireIdentity(p Principal) error {
	if p.ID == "" {
		return fmt.Errorf("the caller has no recorded identity%s", sessionInstead)
	}
	return nil
}

// requireStarter is RequireIdentity for a lane start or adoption, at every level: a caller with no recorded lane,
// session or ticket, and not the human at a terminal, starts or adopts nothing. Registration (laneboss start --role)
// does not come through here; it instead requires a human-issued ticket. The mutant deliberately admits the
// unidentified caller, as every start did before this check, so that a row can show that the refusal is what stops it.
func requireStarter(p Principal) error {
	if p.ID != "" {
		return nil
	}
	if faults.Get("caller-unidentified-start").Point != "" {
		return faults.Reach("caller-unidentified-start")
	}
	return fmt.Errorf("the caller has no recorded identity%s", startInstead)
}

// A headless session is its persistent parent process, not its OS session ID.
// Each parent has its own record, so simultaneous sessions of one role coexist.
type sessionRecord struct {
	Config    string `json:"config"`
	Principal string `json:"principal"`
	PID       int    `json:"pid"`
	Start     string `json:"start"`
}

func sessionPath(pid int) string {
	return "sessions/" + strconv.Itoa(pid) + ".json"
}

// RecordSession retains an already resolved headless starter at lane start and
// adoption. Unknown callers gain no identity; lanes use their live run records,
// and terminal callers continue to use terminal tickets.
func RecordSession(c *config.Configuration, p Principal) error {
	_, configured, err := config.IdentityService(c)
	if err != nil {
		return err
	}
	if configured {
		return nil
	}
	if !strings.HasPrefix(p.ID, "supervisor:") && !strings.HasPrefix(p.ID, "instance:") {
		return nil
	}
	tty, err := ttyName()
	if err != nil || tty != "" {
		return err
	}
	parent, err := nativeProcess(os.Getppid())
	if err != nil || parent.PID <= 1 || parent.Start == "" || strings.HasPrefix(parent.State, "Z") {
		return fmt.Errorf("the supervisor session's process identity cannot be recorded%s", sessionInstead)
	}
	record := sessionRecord{c.Name, p.ID, parent.PID, parent.Start}
	if err := writePrivate(c, sessionPath(parent.PID), record); err != nil {
		return fmt.Errorf("the supervisor session's process identity could not be recorded%s", sessionInstead)
	}
	return nil
}

func readSession(root *os.Root, pid int) (sessionRecord, error) {
	var record sessionRecord
	if err := readJSON(root, sessionPath(pid), &record); err != nil {
		return record, err
	}
	if record.PID != pid || pid <= 1 || record.Start == "" {
		return record, fmt.Errorf("invalid session identity")
	}
	return record, nil
}

// resolveSession walks real parents and compares the OS start time at the
// recorded PID. Neither a shared SID nor an environment label proves ancestry.
func resolveSession(c *config.Configuration) (Principal, error) {
	root, err := os.OpenRoot(c.StateDir)
	if os.IsNotExist(err) {
		return Principal{}, nil
	}
	if err != nil {
		return Principal{}, fmt.Errorf("the caller's session records cannot be read%s", sessionInstead)
	}
	defer root.Close()
	if _, err := root.Stat("sessions"); os.IsNotExist(err) {
		return Principal{}, nil
	} else if err != nil {
		return Principal{}, fmt.Errorf("the caller's session records cannot be read%s", sessionInstead)
	}
	selected := 0
	if name := os.Getenv("LANEBOSS_SESSION"); name != "" {
		selected, err = strconv.Atoi(name)
		if err != nil || selected <= 1 || strconv.Itoa(selected) != name {
			return Principal{}, fmt.Errorf("the caller's session record name is invalid%s", sessionInstead)
		}
		// The mutant deliberately accepts a live env-named record belonging
		// to an unrelated process. The normal path below always walks parents.
		if faults.Get("caller-session-env").Point != "" {
			if err := faults.Reach("caller-session-env"); err != nil {
				return Principal{}, err
			}
			record, err := readSession(root, selected)
			if err == nil {
				return sessionPrincipal(c, record)
			}
			if !os.IsNotExist(err) {
				return Principal{}, fmt.Errorf("the caller's session record is unreadable%s", sessionInstead)
			}
		}
	}
	seen := map[int]bool{}
	for pid := os.Getpid(); pid > 1 && !seen[pid]; {
		seen[pid] = true
		p, err := nativeProcess(pid)
		if err != nil {
			return Principal{}, fmt.Errorf("the caller's process ancestry cannot be read%s", sessionInstead)
		}
		if p.PID == 0 || strings.HasPrefix(p.State, "Z") {
			break
		}
		record, err := readSession(root, pid)
		if err == nil {
			principal, err := sessionPrincipal(c, record)
			if err != nil {
				return Principal{}, err
			}
			if principal.ID != "" {
				if selected != 0 && selected != pid {
					return Principal{}, fmt.Errorf("LANEBOSS_SESSION disagrees with the caller's recorded session identity%s", sessionInstead)
				}
				for _, key := range []string{"LANEBOSS_ROLE", "LANEBOSS_INSTANCE"} {
					if name := os.Getenv(key); name != "" && principal.ID != "supervisor:"+name && principal.ID != "instance:"+name {
						return Principal{}, fmt.Errorf("the role label disagrees with the caller's recorded session identity%s", sessionInstead)
					}
				}
				return principal, nil
			}
		} else if !os.IsNotExist(err) {
			return Principal{}, fmt.Errorf("the caller's session record is unreadable%s", sessionInstead)
		}
		pid = p.Parent
	}
	return Principal{}, nil
}

func sessionPrincipal(c *config.Configuration, record sessionRecord) (Principal, error) {
	if record.Config != c.Name {
		return Principal{}, fmt.Errorf("the caller's session record disagrees with its configuration%s", sessionInstead)
	}
	// Re-read after opening the record: a cached PID alone is never enough.
	current, err := nativeProcess(record.PID)
	if err != nil {
		return Principal{}, fmt.Errorf("the recorded session process cannot be read%s", sessionInstead)
	}
	if current.PID == 0 || strings.HasPrefix(current.State, "Z") {
		return Principal{}, nil
	}
	checkStart := true
	if faults.Get("caller-session-no-start").Point != "" {
		if err := faults.Reach("caller-session-no-start"); err != nil {
			return Principal{}, err
		}
		checkStart = false
	}
	if checkStart && current.Start != record.Start {
		return Principal{}, fmt.Errorf("the caller's session process start time disagrees with its record%s", sessionInstead)
	}
	if !strings.HasPrefix(record.Principal, "supervisor:") && !strings.HasPrefix(record.Principal, "instance:") {
		return Principal{}, fmt.Errorf("the recorded session principal is invalid%s", sessionInstead)
	}
	p, err := Lookup(c, record.Principal)
	if err != nil {
		return Principal{}, fmt.Errorf("the recorded session role cannot be resolved%s", sessionInstead)
	}
	return p, nil
}
