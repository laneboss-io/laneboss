package laneturns

import (
	"bytes"
	"context"
	"fmt"
	"laneboss.io/laneboss/internal/testenv"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func parseBudget(value string) (any, error) {
	if value == "" {
		return nil, nil
	}
	if !regexp.MustCompile(`^[0-9]{1,5}(?:\.[0-9]{1,3})?$`).MatchString(value) {
		return nil, refused("--budget: must be a number of minutes, for example 30 or 0.5")
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || n <= 0 || n > 10080 {
		return nil, refused("--budget: must be above 0 and at most 10080 minutes")
	}
	if !strings.Contains(value, ".") {
		return int(n), nil
	}
	return n, nil
}
func parseIdle(value string) (any, error) {
	if value == "" {
		return nil, nil
	}
	if !regexp.MustCompile(`^[0-9]{1,6}$`).MatchString(value) {
		return nil, refused("--idle: must be a whole number of seconds from 1 to 604800")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > 604800 {
		return nil, refused("--idle: must be a whole number of seconds from 1 to 604800")
	}
	return n, nil
}
func checkAccount(name string, r object, account string, project object, option string) error {
	if !senderPattern.MatchString(account) {
		return refused("%s must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}", option)
	}
	if !contains(r["accounts"], account) {
		return refused("%s: runner %s does not list that account; its accounts: %s", option, name, strings.Join(texts(r["accounts"]), ", "))
	}
	if contains(project["excluded_accounts"], account) {
		return refused("%s: project %s excludes account %s", option, str(project["name"]), account)
	}
	return nil
}
func gitKind(directory string) (string, string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", "", refused("git is not on PATH, so the working directory cannot be checked")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", directory, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir", "--git-common-dir")
	cmd.Env = []string{}
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !strings.HasPrefix(key, "GIT_") && key != "LANGUAGE" && key != "LC_ALL" && key != "LANG" {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "LC_ALL=C", "LANG=C")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 3 {
			return "", "", refused("Git's answer about the working directory is not in the expected form")
		}
		for _, line := range lines {
			if !filepath.IsAbs(line) {
				return "", "", refused("Git's answer about the working directory is not an absolute path")
			}
		}
		if realPath(lines[1]) == realPath(lines[2]) {
			return "main", realPath(lines[0]), nil
		}
		return "linked", realPath(lines[1]), nil
	}
	if strings.Contains(errOut.String(), "not a git repository") {
		for p := directory; ; p = filepath.Dir(p) {
			if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
				return "", "", refused("Git did not recognize a repository above the working directory")
			}
			if filepath.Dir(p) == p {
				break
			}
		}
		return "none", "", nil
	}
	return "", "", refused("Git cannot be asked whether the working directory lies inside a repository")
}

type directoryClaim struct{ holder, name, registry string }

func claimRegistry() (string, error) {
	path := testenv.ClaimsDirectory()
	if path != "" {
		if !filepath.IsAbs(path) {
			return "", refused("LANEBOSS_TEST_CLAIMS_DIR must be an absolute path")
		}
		return filepath.Clean(path), nil
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil || !filepath.IsAbs(account.HomeDir) {
		return "", refused("the account's claims registry cannot be found in the user database")
	}
	return filepath.Join(account.HomeDir, ".local", "state", "laneboss", ".lane-claims"), nil
}
func locateClaim(directory string, starting bool, recorded any) (*directoryClaim, error) {
	registry, err := claimRegistry()
	if err != nil {
		return nil, err
	}
	if recorded != nil && str(recorded) != registry {
		return nil, refused("the lane's claim was recorded in another claims registry; LANEBOSS_TEST_CLAIMS_DIR differs")
	}
	if err = os.MkdirAll(registry, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(registry)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || int(stat.Uid) != os.Getuid() {
		return nil, refused("the claims registry must be a directory of this user's alone (mode 0700, not a link)")
	}
	dirInfo, err := os.Stat(directory)
	if err != nil {
		return nil, err
	}
	identity, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, refused("the working directory's identity cannot be read")
	}
	claim := &directoryClaim{registry, fmt.Sprintf("%d-%d.json", identity.Dev, identity.Ino), registry}
	if !starting && recorded != nil {
		v, e := claim.read()
		if e != nil {
			return nil, e
		}
		if v != nil {
			return claim, nil
		}
	}
	kind, place, err := gitKind(directory)
	if err != nil {
		return nil, err
	}
	if kind == "main" && starting {
		return nil, refused("--worktree is inside the main working copy of the repository; a lane works in its own worktree")
	}
	if kind == "linked" {
		return &directoryClaim{place, "laneboss-claim", ""}, nil
	}
	return claim, nil
}
func (c *directoryClaim) read() (object, error) {
	root, err := os.OpenRoot(c.holder)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := readAt(root, c.name, "the claim", 65536)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return object{}, nil
	}
	v, err := decodeJSON(data)
	if err != nil {
		return object{}, nil
	}
	return v, nil
}
func sameClaim(v, mine object) bool {
	return v != nil && v["config"] == mine["config"] && v["state"] == mine["state"] && v["lane"] == mine["lane"]
}
func describeClaim(v object) string {
	if namePattern.MatchString(str(v["config"])) && lanePattern.MatchString(str(v["lane"])) {
		return "lane " + str(v["lane"]) + " of configuration " + str(v["config"])
	}
	return "another lane"
}
func (c *directoryClaim) take(mine object) (bool, error) {
	root, err := os.OpenRoot(c.holder)
	if err != nil {
		return false, err
	}
	defer root.Close()
	data, err := canonical(mine)
	if err != nil {
		return false, err
	}
	data = append(data, '\n')
	err = writeAtomic(root, c.name, data, 0600, false)
	if err == nil {
		return true, nil
	}
	if !os.IsExist(err) {
		return false, err
	}
	v, err := c.read()
	if err != nil {
		return false, err
	}
	if !sameClaim(v, mine) {
		return false, refused("the working directory is claimed by %s; one lane works in a directory at a time", describeClaim(v))
	}
	return false, writeAtomic(root, c.name, data, 0600, true)
}
func (c *directoryClaim) check(mine object) error {
	v, err := c.read()
	if err != nil {
		return err
	}
	if v == nil {
		return refused("the working directory no longer carries lane %s's claim", str(mine["lane"]))
	}
	if !sameClaim(v, mine) {
		return refused("the working directory is claimed by %s", describeClaim(v))
	}
	return nil
}
func (c *directoryClaim) release(mine object) error {
	v, err := c.read()
	if err != nil {
		return err
	}
	if !sameClaim(v, mine) {
		return nil
	}
	root, err := os.OpenRoot(c.holder)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(c.name)
}
func claimOwner(s *laneSession, lane, dir string, launch any) object {
	return object{"config": s.c.name, "state": s.state.path, "lane": lane, "path": dir, "launch": launch}
}

func adopt(c *configuration, a arguments) (object, error) {
	lane := a.get("lane")
	projectName := a.get("project")
	project := c.projects[projectName]
	if projectName != "" && project == nil {
		return nil, refused("--project: configuration %s has no project file projects/%s.toml", c.name, safeName(projectName))
	}
	if prefix := str(project["lane_prefix"]); prefix != "" && !strings.HasPrefix(lane, prefix) {
		return nil, refused("project %s's lane names start with %s", projectName, prefix)
	}
	s, err := openSession(c, true)
	if err != nil {
		return nil, err
	}
	defer s.close()
	lock, err := s.state.lock("lanes.lock", "lanes lock", c.setting("lanes", "lock_wait_seconds", 60))
	if err != nil {
		return nil, err
	}
	defer lock.close()
	if err = s.refresh(); err != nil {
		return nil, err
	}
	row, err := s.store.row(lane)
	if err != nil {
		return nil, err
	}
	if row != nil {
		return nil, refused("lane %s is already known (run %d, state %s); adoption is only for a lane that has no event yet", lane, integer(row["run"]), str(row["state"]))
	}
	if err = refuseLive(s, lane); err != nil {
		return nil, err
	}
	sessionID := a.get("session")
	if !uuidPattern.MatchString(sessionID) {
		return nil, refused("--session must be a lower-case UUID")
	}
	for _, kind := range []string{"lane.started", "lane.adopted"} {
		events, err := s.store.events("", kind)
		if err != nil {
			return nil, err
		}
		for _, e := range events {
			if str(e["lane"]) != lane && obj(e["payload"])["session_id"] == sessionID {
				return nil, refused("session %s already belongs to lane %s of configuration %s", sessionID, str(e["lane"]), c.name)
			}
		}
	}
	name := a.get("runner")
	r, err := c.runner(name)
	if err != nil {
		return nil, err
	}
	if project["workers"] != nil && !contains(project["workers"], name) {
		return nil, refused("runner %s is not one of project %s's workers", name, projectName)
	}
	model := a.get("model")
	if !modelPattern.MatchString(model) || !hasDigit.MatchString(model) {
		return nil, refused("--model must be a full model name that includes its version, not a family alias")
	}
	effort, account := a.optional("effort"), a.optional("account")
	if effort != nil && !namePattern.MatchString(str(effort)) {
		return nil, refused("--effort must match [a-z0-9][a-z0-9-]{0,31}")
	}
	if account != nil {
		if err = checkAccount(name, r, str(account), project, "--account"); err != nil {
			return nil, err
		}
	}
	if problems := turnProblems(name, r); len(problems) > 0 {
		return nil, refused("runner %s cannot take turns, because %s", name, strings.Join(problems, "; "))
	}
	for field, value := range (object{"effort": effort, "project": nilIfEmpty(projectName)}) {
		if value == nil && uses(r["resume"], field) {
			return nil, refused("runner %s's resume template uses {%s}, which no turn of this lane could fill: give --%s", name, field, field)
		}
	}
	templates := []string{}
	for _, entry := range array(r["records"]) {
		for _, path := range texts(obj(entry)["paths"]) {
			if uses([]string{"records", path}, "session") {
				templates = append(templates, path)
			}
		}
	}
	if len(templates) == 0 {
		return nil, refused("runner %s's records name no {session}: no records entry uses {session}, so nothing could show that the session exists or that nothing writes to it", name)
	}
	idle, err := parseIdle(a.get("idle"))
	if err != nil {
		return nil, err
	}
	if idle == nil {
		idle = obj(c.data["turns"])["idle_seconds"]
	}
	directory := realPath(a.get("worktree"))
	if a.get("worktree") == "" {
		return nil, refused("--worktree is required")
	}
	if err = c.checkExternal(a.get("worktree"), "--worktree", true); err != nil {
		return nil, err
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, refused("--worktree: is not an existing directory")
	}
	claim, err := locateClaim(directory, true, nil)
	if err != nil {
		return nil, err
	}
	others, err := s.store.rows()
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if str(other["lane"]) == lane {
			continue
		}
		if !flag(other["cleaned"]) && str(other["worktree"]) != "" && sameDir(str(other["worktree"]), directory) {
			return nil, refused("lane %s already works in this directory; one lane per working directory", str(other["lane"]))
		}
		if sessionName(str(other["lane"])) == sessionName(lane) {
			return nil, refused("the lane's tmux session would have the same name as another lane's (tmux turns . into _)")
		}
	}
	socket := socketPath(c.name, s.state.path)
	if _, err = exec.LookPath("tmux"); err != nil {
		return nil, refused("tmux is not on PATH; lanes run in tmux sessions")
	}
	alive, err := tmuxAlive(socket, sessionName(lane))
	if err != nil {
		return nil, err
	}
	if alive {
		return nil, refused("a tmux session %s is still open at %s", sessionName(lane), socket)
	}
	values := object{"account": account, "effort": effort, "lane": lane, "log": s.state.lanePath(lane, "output.log"), "model": model, "project": nilIfEmpty(projectName), "session": sessionID, "worktree": directory}
	var newest time.Time
	for _, template := range templates {
		pattern, why := expandRecordTemplate(template, values)
		if why != "" {
			continue
		}
		if strings.HasPrefix(pattern, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			pattern = filepath.Join(home, pattern[2:])
		}
		matches, err := recordMatches(pattern, 10000)
		if err != nil {
			return nil, refused("the session's record paths cannot be listed")
		}
		for _, path := range matches {
			if err = checkPathCredential(path, "the session record"); err != nil {
				return nil, err
			}
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	if newest.IsZero() {
		return nil, refused("session %s has no session record: the runner's records entries that use {session} found none", sessionID)
	}
	quiet := c.quiet(r)
	if time.Since(newest) < time.Duration(quiet)*time.Second {
		return nil, refused("session %s's newest record was written within the runner's quiet seconds (%d s), so it is still being written; adopt it when nothing writes to it", sessionID, quiet)
	}
	budget, err := parseBudget(a.get("budget"))
	if err != nil {
		return nil, err
	}
	if budget == nil {
		budget = obj(c.data["lanes"])["budget_minutes"]
	}
	if budget == nil {
		return nil, refused("no time budget: give --budget MINUTES or set [lanes] budget_minutes")
	}
	data, err := c.readExternal(a.get("brief"), "--brief", maxBrief)
	if err != nil {
		return nil, err
	}
	output, err := composeBrief(c, lane, projectName, data, "--brief")
	if err != nil {
		return nil, err
	}
	chosen := object{"runner": "supervisor", "model": "supervisor", "effort": nil, "account": nil}
	if effort != nil {
		chosen["effort"] = "supervisor"
	}
	if account != nil {
		chosen["account"] = "supervisor"
	}
	payload := object{"runner": name, "model": model, "effort": effort, "account": account, "chosen_by": chosen, "difficulty": nil, "project": nilIfEmpty(projectName), "worktree": directory, "branch": nil, "base": nil, "repository": nil, "budget_minutes": budget, "quiet_seconds": quiet, "brief": object{"path": s.state.lanePath(lane, "rendered", digest(output)+".md"), "sha256": digest(output)}, "log": s.state.lanePath(lane, "output.log"), "session": object{"socket": socket, "name": sessionName(lane)}, "touches": []any{}, "claims": nilIfEmpty(claim.registry), "session_id": sessionID, "idle_seconds": idle}
	if err = checkValueCredentials(payload, "payload", 0); err != nil {
		return nil, err
	}
	if err = checkPayload("lane.adopted", payload); err != nil {
		return nil, err
	}
	if err = checkBinding(s.state, lane, "lane.adopted", payload); err != nil {
		return nil, err
	}
	mine := claimOwner(s, lane, directory, nil)
	made, err := claim.take(mine)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success && made {
			claim.release(mine)
		}
	}()
	rendered, err := renderBrief(s, lane, projectName, a.get("brief"), data, output)
	if err != nil {
		return nil, err
	}
	if !equalJSON(rendered, payload["brief"]) {
		return nil, integrity("the rendered brief is not where it was expected")
	}
	event, err := s.append("lane.adopted", lane, "laneboss", payload)
	if err != nil {
		return nil, err
	}
	success = true
	result := copyObject(payload)
	result["lane"] = lane
	result["event"] = eventRef(event)
	return result, nil
}
func recordMatches(pattern string, limit int) ([]string, error) {
	if !filepath.IsAbs(pattern) {
		return nil, refused("a session record path is not absolute")
	}
	bases := []string{"/"}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(pattern), "/"), "/") {
		following := []string{}
		if part == "**" {
			visited := map[string]bool{}
			stack := append([]string{}, bases...)
			for len(stack) > 0 {
				path := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				info, err := os.Stat(path)
				if os.IsNotExist(err) || err == syscall.ENOTDIR {
					continue
				}
				if err != nil {
					return nil, err
				}
				if !info.IsDir() {
					continue
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return nil, refused("a record directory's identity cannot be read")
				}
				key := fmt.Sprintf("%d/%d", stat.Dev, stat.Ino)
				if visited[key] {
					continue
				}
				visited[key] = true
				following = append(following, path)
				if len(following) > limit {
					return nil, refused("the session records template names more than %d candidates", limit)
				}
				entries, err := os.ReadDir(path)
				if err != nil {
					return nil, err
				}
				for i := len(entries) - 1; i >= 0; i-- {
					entry := entries[i]
					if strings.HasPrefix(entry.Name(), ".") {
						continue
					}
					child := filepath.Join(path, entry.Name())
					info, err := os.Stat(child)
					if os.IsNotExist(err) {
						continue
					}
					if err != nil {
						return nil, err
					}
					if info.IsDir() {
						stack = append(stack, child)
					}
				}
			}
		} else if strings.ContainsAny(part, "*?[") {
			for _, base := range bases {
				entries, err := os.ReadDir(base)
				if os.IsNotExist(err) || errorsIsNotDirectory(err) {
					continue
				}
				if err != nil {
					return nil, err
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(part, ".") {
						continue
					}
					match, err := filepath.Match(part, entry.Name())
					if err != nil {
						return nil, err
					}
					if match {
						following = append(following, filepath.Join(base, entry.Name()))
						if len(following) > limit {
							return nil, refused("the session records template names more than %d candidates", limit)
						}
					}
				}
			}
		} else {
			for _, base := range bases {
				following = append(following, filepath.Join(base, part))
			}
		}
		bases = following
	}
	found := []string{}
	for _, path := range bases {
		if _, err := os.Lstat(path); err == nil {
			found = append(found, path)
		} else if !os.IsNotExist(err) && !errorsIsNotDirectory(err) {
			return nil, err
		}
	}
	return found, nil
}
func errorsIsNotDirectory(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*os.PathError); ok {
		return e.Err == syscall.ENOTDIR
	}
	return err == syscall.ENOTDIR
}
