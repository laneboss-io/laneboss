// Package doctor performs one real check per JSON line and returns failure when
// any check fails, without running a configured runner, judge or adapter.
package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/doctorbase"
)

func writable(c *doctorbase.Configuration, z *doctorbase.Zones) (bool, string) {
	s, err := doctorbase.OpenState(c, z, true)
	if err != nil {
		return false, doctorbase.Detail(err)
	}
	defer s.Close()
	id, err := doctorbase.RandomID()
	if err != nil {
		return false, doctorbase.Detail(err)
	}
	name := ".doctor-probe-" + id
	f, err := s.Root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return false, fmt.Sprintf("%s is not writable: %s", c.StateDir, doctorbase.OSReason(err))
	}
	if err := f.Close(); err != nil {
		s.Root.Remove(name)
		return false, doctorbase.Detail(err)
	}
	if err := s.Root.Remove(name); err != nil {
		return false, doctorbase.Detail(err)
	}
	return true, c.StateDir + " is writable"
}
func roundTrip(c *doctorbase.Configuration, z *doctorbase.Zones) (bool, string) {
	s, err := doctorbase.OpenState(c, z, false)
	if err != nil {
		return false, "scratch store failed: " + doctorbase.Detail(err)
	}
	if s == nil {
		return false, "scratch store failed: the state directory disappeared"
	}
	defer s.Close()
	if err := doctorbase.ScratchRoundTrip(s); err != nil {
		return false, "scratch store failed: " + doctorbase.Detail(err)
	}
	return true, "created, appended to, read back, verified and removed a scratch store"
}
func findCommand(program string) string {
	if filepath.IsAbs(program) {
		info, err := os.Stat(program)
		if err != nil || !info.Mode().IsRegular() || syscall.Access(program, 1) != nil {
			return ""
		}
		return program
	}
	found, err := exec.LookPath(program)
	if err != nil && !errors.Is(err, exec.ErrDot) {
		return ""
	}
	return found
}
func organisationTools(c *doctorbase.Configuration) (bool, string) {
	if c.Organisation == "" {
		key := c.CommandIntoOrganisation()
		if key == "" {
			return true, "no organisation is named"
		}
		return false, fmt.Sprintf("this configuration names no organisation, but %s points into an organisation's directory: add organisation = \"NAME\" to config.toml, with the name of that organisation", key)
	}
	tools := filepath.Join(c.Home, "orgs", c.Organisation, "tools")
	info, err := os.Stat(tools)
	if err == nil && info.IsDir() {
		return true, fmt.Sprintf("%s is the tools directory of organisation %s", tools, c.Organisation)
	}
	if _, err := os.Lstat(tools); err == nil {
		return false, tools + " is not a directory"
	}
	return false, tools + " does not exist"
}
func turnLimitWarning(c *doctorbase.Configuration) string {
	names := []string{}
	runners := doctorbase.Object(c.Data["runners"])
	for _, name := range doctorbase.Keys(runners) {
		r := doctorbase.Object(runners[name])
		if r["prompt"] == "stdin" && doctorbase.Uses(r["command"], "session") && doctorbase.Uses(r["resume"], "session") && len(doctorbase.Array(r["limit_patterns"])) == 0 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	subject := "runners " + strings.Join(names, ", ") + " can take turns and have"
	if len(names) == 1 {
		subject = "runner " + names[0] + " can take turns and has"
	}
	return "warning: " + subject + " no limit_patterns, so a turn that ends at a usage limit with exit code 0 is counted as delivered; give each of them limit_patterns"
}
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			fmt.Fprintln(stdout, "usage: laneboss doctor [-h] [--config NAME]\nCheck the bound configuration, state, store and configured programs.")
			return 0
		}
	}
	name, err := doctorbase.Bind(args)
	if err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	encoder := json.NewEncoder(stdout)
	status := 0
	var outputErr error
	record := func(check string, ok bool, detail string) {
		if !ok {
			status = 1
		}
		if outputErr == nil {
			outputErr = encoder.Encode(map[string]any{"check": check, "ok": ok, "detail": detail})
		}
	}
	c, err := doctorbase.Load(name)
	if err != nil {
		record("config", false, doctorbase.Detail(err))
		for _, check := range []string{"state.isolated", "store.recorded", "state.writable", "store.round_trip"} {
			record(check, false, "not checked: the configuration is invalid")
		}
	} else {
		record("config", true, "configuration "+name+" is valid")
		zones := doctorbase.NewZones(c)
		isolated, detail := doctorbase.Isolated(c, zones)
		record("state.isolated", isolated, detail)
		if !isolated {
			for _, check := range []string{"store.recorded", "state.writable", "store.round_trip"} {
				record(check, false, "not checked: the state directory is not isolated")
			}
		} else {
			ok, detail := doctorbase.VerifyRecorded(c, zones)
			record("store.recorded", ok, detail)
			ok, detail = writable(c, zones)
			record("state.writable", ok, detail)
			if ok {
				ok, detail = roundTrip(c, zones)
				record("store.round_trip", ok, detail)
			} else {
				record("store.round_trip", false, "not checked: the state directory is not writable")
			}
		}
	}
	for _, tool := range []string{"git", "tmux"} {
		found := findCommand(tool)
		detail := tool + " is not on PATH"
		if found != "" {
			detail = "found at " + found
		}
		record("tool."+tool, found != "", detail)
	}
	if c != nil {
		runners := doctorbase.Object(c.Data["runners"])
		for _, name := range doctorbase.Keys(runners) {
			runner := doctorbase.Object(runners[name])
			programs := []string{doctorbase.String(doctorbase.Array(runner["command"])[0])}
			if resume := doctorbase.Array(runner["resume"]); len(resume) > 0 {
				programs = append(programs, doctorbase.String(resume[0]))
			}
			missing := []string{}
			found := map[string]any{}
			for _, p := range programs {
				path := findCommand(p)
				if path == "" {
					missing = append(missing, p+" is not found on PATH")
				} else {
					found[p] = path
				}
			}
			details := missing
			if len(missing) == 0 {
				for _, p := range doctorbase.Keys(found) {
					details = append(details, p+" found at "+doctorbase.String(found[p]))
				}
			}
			record("runner."+name, len(missing) == 0, strings.Join(details, "; "))
		}
		if warning := turnLimitWarning(c); warning != "" {
			record("turns.limit_patterns", true, warning)
		}
		for _, group := range []string{"judges", "resources"} {
			entries := doctorbase.Object(c.Data[group])
			label := "judge."
			if group == "resources" {
				label = "resource."
			}
			for _, name := range doctorbase.Keys(entries) {
				program := doctorbase.String(doctorbase.Array(doctorbase.Object(entries[name])["command"])[0])
				found := findCommand(program)
				detail := program + " is not found on PATH"
				if found != "" {
					detail = program + " found at " + found
				}
				record(label+name, found != "", detail)
			}
		}
		ok, detail := organisationTools(c)
		record("organisation.tools", ok, detail)
	}
	if outputErr != nil {
		return doctorbase.ExitError(stderr, outputErr)
	}
	return status
}
