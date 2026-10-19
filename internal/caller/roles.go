package caller

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"laneboss.io/laneboss/internal/caller/records"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/instancename"
	"laneboss.io/laneboss/internal/rolepolicy"
)

var roleName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var launchName = regexp.MustCompile(`^[0-9a-f]{32}$`)
var laneName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type roleTicket struct {
	Config    string  `json:"config"`
	Principal string  `json:"principal"`
	Process   process `json:"process"`
}

// OrgRoot is the org the loaded configuration names, and no other. A lane picks
// its own working directory and environment, so neither selects the org that
// supplies an instance's level (which report records as the recipient's level).
func OrgRoot(c *config.Configuration) string {
	if c == nil {
		return ""
	}
	root, err := rolepolicy.ConfigRoot(c.Home, c.Data)
	if err != nil || !filepath.IsAbs(root) {
		return ""
	}
	return root
}

func readTOML(root *os.Root, path string) (map[string]any, error) {
	f, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("the role record is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if _, err = toml.Decode(string(data), &result); err != nil {
		return nil, fmt.Errorf("the role record is not readable TOML")
	}
	return result, nil
}

// Role chooses configured supervisor levels before instance.toml levels.
func Role(c *config.Configuration, name string) (Principal, string, error) {
	if c == nil || !roleName.MatchString(name) && !instancename.Valid(name) {
		return Principal{}, "", fmt.Errorf("the role name is invalid")
	}
	supervisors, _ := c.Data["supervisors"].(map[string]any)
	if value, exists := supervisors[name]; exists {
		entry, _ := value.(map[string]any)
		level, ok := records.Integer(entry["level"])
		if !ok {
			// Command groups that use their own TOML reader still accept the
			// documented old role spelling, as config.Load does.
			switch entry["role"] {
			case "mini":
				level, ok = 4, true
			case "top":
				level, ok = 5, true
			}
		}
		if !ok || level < 4 || level > 6 {
			return Principal{}, "", fmt.Errorf("the selected supervisor has no valid recorded level")
		}
		return Principal{ID: "supervisor:" + name, Level: level}, "supervisors", nil
	}
	org := OrgRoot(c)
	if org == "" {
		return Principal{}, "", fmt.Errorf("the selected role is not a configured supervisor or a readable instance")
	}
	root, err := os.OpenRoot(org)
	if err != nil {
		return Principal{}, "", fmt.Errorf("the selected instance cannot be read")
	}
	defer root.Close()
	entry, err := readTOML(root, ".laneboss/instances/"+name+"/instance.toml")
	if err != nil {
		return Principal{}, "", fmt.Errorf("the selected instance cannot be read")
	}
	if actual, exists := entry["name"]; exists && actual != name {
		return Principal{}, "", fmt.Errorf("the selected instance's name disagrees with its directory")
	}
	level, ok := records.Integer(entry["level"])
	if !ok || level < 3 || level > 6 {
		return Principal{}, "", fmt.Errorf("the selected instance has no valid recorded level")
	}
	return Principal{ID: "instance:" + name, Level: level}, "instance", nil
}

// registerLegacyRole preserves the 0.7.0 bootstrap only without a service.
// It is deliberately private and cannot authorize the configured-service path.
func registerLegacyRole(c *config.Configuration, name string) (Principal, error) {
	_, configured, err := config.IdentityService(c)
	if err != nil {
		return Principal{}, err
	}
	if configured {
		return Principal{}, fmt.Errorf("supervisor registration requires a human-issued ticket%s", sessionInstead)
	}
	target, _, err := Role(c, name)
	if err != nil {
		return Principal{}, err
	}
	current, err := Resolve(c)
	if err != nil {
		return Principal{}, err
	}
	if strings.HasPrefix(current.ID, "lane:") || current.Level > 0 && target.Level > current.Level {
		return Principal{}, fmt.Errorf("a role ticket cannot raise the session's recorded level%s", sessionInstead)
	}
	tty, err := ttyName()
	if err != nil {
		return Principal{}, err
	}
	if tty == "" {
		return target, RecordSession(c, target)
	}
	table, err := processTable()
	if err != nil {
		return Principal{}, err
	}
	mine, ok := table[os.Getpid()]
	parent, present := table[os.Getppid()]
	if !ok || !present || parent.SID != mine.SID || strings.HasPrefix(parent.State, "Z") {
		return Principal{}, fmt.Errorf("the supervisor session's process identity cannot be recorded%s", sessionInstead)
	}
	if err := writePrivate(c, "roles/"+name+".json", roleTicket{c.Name, target.ID, parent}); err != nil {
		return Principal{}, fmt.Errorf("the supervisor role ticket could not be recorded")
	}
	return target, nil
}

func writePrivate(c *config.Configuration, path string, value any) error {
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(c.StateDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err = root.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	temp := filepath.Join(filepath.Dir(path), ".caller-"+hex.EncodeToString(random[:]))
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	_, err = f.Write(append(data, '\n'))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = root.Rename(temp, path); err != nil {
		return err
	}
	dir, err := root.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

type stopRequest struct {
	Config string `json:"config"`
	Lane   string `json:"lane"`
	Launch string `json:"launch"`
	Actor  string `json:"actor"`
}

// RecordStop persists the caller before any signal is sent to the worker.
func RecordStop(c *config.Configuration, lane, launch string, p Principal) error {
	if !laneName.MatchString(lane) || !launchName.MatchString(launch) {
		return fmt.Errorf("the stop request has no valid launch identity")
	}
	request := stopRequest{c.Name, lane, launch, LifecycleActor(p.ID)}
	if err := writePrivate(c, "lanes/"+lane+"/stop-"+launch+".json", request); err != nil {
		return fmt.Errorf("the stop caller could not be recorded; nothing was signalled")
	}
	return nil
}

// StopActor reads a bound stop request; a raw signal is a detected launcher step.
func StopActor(c *config.Configuration, lane, launch string) (string, error) {
	if !laneName.MatchString(lane) || !launchName.MatchString(launch) {
		return "", fmt.Errorf("the stopped run has no valid launch identity")
	}
	root, err := os.OpenRoot(c.StateDir)
	if err != nil {
		return "", fmt.Errorf("the stop request cannot be read")
	}
	defer root.Close()
	var request stopRequest
	err = readJSON(root, "lanes/"+lane+"/stop-"+launch+".json", &request)
	if os.IsNotExist(err) {
		return "laneboss", nil
	}
	if err != nil || request.Config != c.Name || request.Lane != lane || request.Launch != launch || request.Actor != "laneboss" && !records.ValidID(request.Actor) {
		return "", fmt.Errorf("the stop request disagrees with its run")
	}
	return LifecycleActor(request.Actor), nil
}
