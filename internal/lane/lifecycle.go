package lane

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (s *session) runner(name string) (object, error) {
	r := obj(obj(s.c.data["runners"])[name])
	if r == nil {
		return nil, refuse("runner is not defined in configuration %s", s.c.name)
	}
	return r, nil
}
func checkAccount(runner object, account string, project object, what string) error {
	if !match(`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, account) {
		return refuse("%s must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}", what)
	}
	if !contains(stringsOf(runner["accounts"]), account) {
		return refuse("%s: the runner does not list that account; its accounts: %s", what, strings.Join(stringsOf(runner["accounts"]), ", "))
	}
	if contains(stringsOf(project["excluded_accounts"]), account) {
		return refuse("%s: the project excludes account %s", what, account)
	}
	return nil
}
func (s *session) choose(a arguments, project object) (string, object, string, any, any, object, error) {
	runnerName := a.get("runner")
	if runnerName != "" {
		if _, err := s.runner(runnerName); err != nil {
			return "", nil, "", nil, nil, nil, err
		}
	}
	if a.get("model") != "" && (!match(`[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}`, a.get("model")) || !strings.ContainsAny(a.get("model"), "0123456789")) {
		return "", nil, "", nil, nil, nil, refuse("--model must be a full model name that includes its version, not a family alias")
	}
	if a.get("effort") != "" && !match(`[a-z0-9][a-z0-9-]{0,31}`, a.get("effort")) {
		return "", nil, "", nil, nil, nil, refuse("--effort must match [a-z0-9][a-z0-9-]{0,31}")
	}
	difficulty := a.get("difficulty")
	if difficulty != "" && !contains(strings.Fields("mechanical standard hard review"), difficulty) {
		return "", nil, "", nil, nil, nil, refuse("--difficulty is not a documented difficulty")
	}
	usable := func(name string) bool {
		runner := obj(obj(s.c.data["runners"])[name])
		if runner == nil {
			return false
		}
		if project["workers"] != nil && !contains(stringsOf(project["workers"]), name) {
			return false
		}
		if a.get("account") != "" {
			return contains(stringsOf(runner["accounts"]), a.get("account")) && !contains(stringsOf(project["excluded_accounts"]), a.get("account"))
		}
		if len(list(runner["accounts"])) == 0 {
			return true
		}
		for _, acc := range stringsOf(runner["accounts"]) {
			if !contains(stringsOf(project["excluded_accounts"]), acc) {
				return true
			}
		}
		return false
	}
	var route object
	for _, v := range list(obj(s.c.data["routing"])[difficulty]) {
		r := obj(v)
		if (runnerName == "" || str(r["runner"]) == runnerName) && usable(str(r["runner"])) {
			route = r
			break
		}
	}
	if runnerName == "" {
		runnerName = str(route["runner"])
	}
	if runnerName == "" {
		return "", nil, "", nil, nil, nil, refuse("no runner: give --runner, or --difficulty with a usable entry in [routing]")
	}
	runner, err := s.runner(runnerName)
	if err != nil {
		return "", nil, "", nil, nil, nil, err
	}
	if project["workers"] != nil && !contains(stringsOf(project["workers"]), runnerName) {
		return "", nil, "", nil, nil, nil, refuse("runner %s is not one of the project's workers", runnerName)
	}
	model := a.get("model")
	if model == "" {
		model = str(route["model"])
	}
	if model == "" {
		return "", nil, "", nil, nil, nil, refuse("no model: a full model name is required, from --model or a [routing] entry; nothing is guessed")
	}
	effort := nullable(a.get("effort"))
	if effort == nil {
		effort = route["effort"]
	}
	account := nullable(a.get("account"))
	if account != nil {
		if err = checkAccount(runner, str(account), project, "--account"); err != nil {
			return "", nil, "", nil, nil, nil, err
		}
	} else {
		for _, acc := range stringsOf(runner["accounts"]) {
			if !contains(stringsOf(project["excluded_accounts"]), acc) {
				account = acc
				break
			}
		}
		if len(list(runner["accounts"])) > 0 && account == nil {
			return "", nil, "", nil, nil, nil, refuse("project excludes every account of the runner")
		}
	}
	chosen := object{"runner": "routing", "model": "routing", "effort": nil, "account": nil}
	if a.get("runner") != "" {
		chosen["runner"] = "supervisor"
	}
	if a.get("model") != "" {
		chosen["model"] = "supervisor"
	}
	if effort != nil {
		chosen["effort"] = "routing"
		if a.get("effort") != "" {
			chosen["effort"] = "supervisor"
		}
	}
	if account != nil {
		chosen["account"] = "default"
		if a.get("account") != "" {
			chosen["account"] = "supervisor"
		}
	}
	return runnerName, runner, model, effort, account, chosen, nil
}

type workingPlace struct {
	path, repository, branch, base string
	claim                          *claim
}

func (s *session) workingPlace(a arguments, project object) (*workingPlace, error) {
	lane := a.get("lane")
	if a.get("worktree") != "" {
		if a.get("base") != "" {
			return nil, refuse("--worktree and --base exclude each other")
		}
		path := realPath(a.get("worktree"))
		if rule, _ := credential(path); rule != "" {
			return nil, refuse("--worktree: the path looks like a credential")
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return nil, refuse("--worktree is not an existing directory")
		}
		if err = s.c.checkPath(path, "--worktree", true); err != nil {
			return nil, err
		}
		claim, err := locateClaim(path, true, nil)
		if err != nil {
			return nil, err
		}
		return &workingPlace{path: path, claim: claim}, nil
	}
	repository := str(project["repository"])
	if !filepath.IsAbs(repository) {
		return nil, refuse("a lane needs a working directory: --project naming a project with a local repository, or --worktree PATH")
	}
	code, out, _, err := gitRun(repository, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	if code != 0 || out == "" {
		return nil, refuse("the project's repository is not a Git work tree")
	}
	root := realPath(out)
	path := filepath.Join(filepath.Dir(root), filepath.Base(root)+"-"+lane)
	if _, err = os.Lstat(path); err == nil {
		return nil, refuse("the lane's worktree %s already exists", path)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err = s.c.checkPath(filepath.Dir(path), "the lane's worktree", true); err != nil {
		return nil, err
	}
	if err = gitRequired(root, "check-ref-format", "--branch", lane); err != nil {
		return nil, err
	}
	code, _, _, err = gitRun(root, "rev-parse", "--verify", "--quiet", "refs/heads/"+lane)
	if err != nil {
		return nil, err
	}
	if code == 0 {
		return nil, refuse("the project's repository already has a branch %s; a lane's branch is new", lane)
	}
	base := a.get("base")
	if base == "" {
		base = "HEAD"
	}
	if strings.HasPrefix(base, "-") || strings.IndexFunc(base, func(r rune) bool { return r <= 32 }) >= 0 {
		return nil, refuse("--base must name a commit, branch or tag")
	}
	code, commit, _, err := gitRun(root, "rev-parse", "--verify", "--quiet", base+"^{commit}")
	if err != nil {
		return nil, err
	}
	if code != 0 || !match(`[0-9a-f]{40}|[0-9a-f]{64}`, commit) {
		return nil, refuse("--base: the given reference does not name a commit in the project's repository")
	}
	return &workingPlace{path: path, repository: root, branch: lane, base: commit}, nil
}
func sameDirectory(a, b string) bool {
	if realPath(a) == realPath(b) {
		return true
	}
	ia, ea := os.Stat(a)
	ib, eb := os.Stat(b)
	return ea == nil && eb == nil && os.SameFile(ia, ib)
}
func (s *session) start(a arguments, stderr io.Writer) (any, error) {
	lane, projectName := a.get("lane"), a.get("project")
	var project object
	if projectName != "" {
		project = obj(s.c.projects[projectName])
		if project == nil {
			return nil, refuse("--project: configuration %s has no project file for that name", s.c.name)
		}
		if prefix := str(project["lane_prefix"]); prefix != "" && !strings.HasPrefix(lane, prefix) {
			return nil, refuse("project %s's lane names start with %s", projectName, prefix)
		}
	}
	var idle any
	if value, supplied := a.values["idle"]; supplied {
		if !match(`[0-9]{1,6}`, value) {
			return nil, refuse("--idle: must be a whole number of seconds from 1 to 604800")
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 604800 {
			return nil, refuse("--idle: must be a whole number of seconds from 1 to 604800")
		}
		idle = n
		if !a.has("turns") {
			return nil, refuse("--idle goes with --turns: only a turn-based lane has an idle interval")
		}
	}
	runnerName, runner, model, effort, account, chosen, err := s.choose(a, project)
	if err != nil {
		return nil, err
	}
	if a.has("turns") {
		problems := []string{}
		if !uses(runner["command"], "session") {
			problems = append(problems, fmt.Sprintf("its command (runners.%s.command) does not use {session}", runnerName))
		}
		if runner["resume"] == nil {
			problems = append(problems, fmt.Sprintf("it has no resume template (runners.%s.resume)", runnerName))
		} else if !uses(runner["resume"], "session") {
			problems = append(problems, fmt.Sprintf("its resume template (runners.%s.resume) does not use {session}", runnerName))
		}
		if str(runner["prompt"]) != "stdin" {
			problems = append(problems, fmt.Sprintf("it does not take its prompt on standard input (runners.%s.prompt needs prompt = \"stdin\")", runnerName))
		}
		if len(problems) > 0 {
			return nil, refuse("--turns: runner %s cannot take turns, because %s", runnerName, strings.Join(problems, "; "))
		}
		if idle == nil {
			idle = obj(s.c.data["turns"])["idle_seconds"]
		}
	}
	budget, err := parseBudget(a.get("budget"))
	if err != nil {
		return nil, err
	}
	if budget == nil {
		budget = obj(s.c.data["lanes"])["budget_minutes"]
	}
	if budget == nil {
		return nil, refuse("no time budget: give --budget MINUTES or set [lanes] budget_minutes")
	}
	if _, err = exec.LookPath("tmux"); err != nil {
		return nil, refuse("tmux is not on PATH; lanes run in tmux sessions")
	}
	data, err := s.c.external(a.get("brief"), "--brief", 4*1024*1024)
	if err != nil {
		return nil, err
	}
	source := realPath(a.get("brief"))
	composed, err := s.c.compose(lane, projectName, source, data, a.touches)
	if err != nil {
		return nil, err
	}
	unlock, err := s.lanesLock()
	if err != nil {
		return nil, err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	if err = s.refresh(); err != nil {
		return nil, err
	}
	if err = s.diskGate(stderr); err != nil {
		return nil, err
	}
	row, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	if row != nil {
		if err = s.drain(lane); err != nil {
			return nil, err
		}
		row, err = s.row(lane)
		if err != nil {
			return nil, err
		}
		if flag(row["running"]) {
			return nil, refuse("lane %s is running run %d", lane, integer(row["run"]))
		}
		if integer(row["run"]) > 0 {
			if !a.has("reuse") {
				return nil, refuse("lane %s is already known; a lane name is never reused silently: once merged or abandoned, pass --reuse", lane)
			}
			if !contains([]string{"merged", "abandoned"}, str(row["state"])) {
				return nil, refuse("--reuse: only a merged or abandoned lane is started again")
			}
			mail := obj(row["mail"])
			if len(list(mail["waiting"]))+len(list(mail["returned"])) > 0 {
				return nil, refuse("--reuse: lane has messages that wait or have returned; a new life is never sent mail for the old one")
			}
			previous, _, err := s.latest(lane)
			if err != nil {
				return nil, err
			}
			if _, err = sameRegistry(previous["claims"]); err != nil {
				return nil, err
			}
		}
	}
	if err = s.refuseLive(lane); err != nil {
		return nil, err
	}
	place, err := s.workingPlace(a, project)
	if err != nil {
		return nil, err
	}
	rows, err := s.rows()
	if err != nil {
		return nil, err
	}
	name, socket := sessionName(lane), socketPath(s.c)
	for _, other := range rows {
		if str(other["lane"]) == lane {
			continue
		}
		if str(other["worktree"]) != "" && !flag(other["cleaned"]) && sameDirectory(str(other["worktree"]), place.path) {
			return nil, refuse("lane %s already works in %s; one lane per working directory", str(other["lane"]), place.path)
		}
		if sessionName(str(other["lane"])) == name {
			return nil, refuse("tmux turns . into _: the lane's session would have the same name as another lane's")
		}
	}
	alive, err := tmuxAlive(socket, name)
	if err != nil {
		return nil, err
	}
	if alive {
		return nil, refuse("a tmux session %s is still open at %s", name, socket)
	}
	run := integer(row["run"]) + 1
	launch := newID()
	var sessionID any
	if uses(runner["command"], "session") {
		sessionID = uuid()
	}
	brief := object{"path": s.lanePath(lane, "rendered", digest(composed.output)+".md"), "sha256": digest(composed.output)}
	values := object{"account": account, "brief": brief["path"], "effort": effort, "lane": lane, "log": s.lanePath(lane, "output.log"), "model": model, "project": nullable(projectName), "session": sessionID, "worktree": place.path}
	argv, err := fill(runner["command"], values)
	if err != nil {
		return nil, err
	}
	how := "start"
	if run > 1 {
		how = "reuse"
	}
	var registry any
	if place.claim != nil && place.claim.name != "laneboss-claim" {
		registry = place.claim.holder
	}
	started := object{"run": run, "how": how, "launch": launch, "runner": runnerName, "model": model, "effort": effort, "account": account, "chosen_by": chosen, "difficulty": nullable(a.get("difficulty")), "project": nullable(projectName), "worktree": place.path, "branch": nullable(place.branch), "base": nullable(place.base), "repository": nullable(place.repository), "budget_minutes": budget, "quiet_seconds": valueOr(runner, "quiet_seconds", valueOr(obj(s.c.data["lanes"]), "quiet_seconds", 900)), "brief": brief, "log": values["log"], "session": object{"socket": socket, "name": name}, "touches": unique(a.touches), "claims": registry}
	if sessionID != nil {
		started["session_id"] = sessionID
	}
	if a.has("turns") {
		started["mail"] = []any{}
		started["idle_seconds"] = idle
	}
	if err = s.validatePlanned(row, lane, "lane.started", started); err != nil {
		return nil, err
	}
	mine := s.claimOwner(lane, launch, place.path)
	madeClaim, madeBranch, madeWorktree := false, false, false
	begun := false
	defer func() {
		if !begun {
			if madeClaim {
				if _, rollbackError := releaseClaim(place.claim, mine); rollbackError != nil {
					fmt.Fprintln(stderr, "note: the start's claim could not be released; its worktree and branch were left alone")
					return
				}
			}
			if madeWorktree {
				code, _, _, rollbackError := gitRun(place.repository, "worktree", "remove", place.path)
				if rollbackError != nil || code != 0 {
					fmt.Fprintln(stderr, "note: Git refused to undo the start's worktree; its branch was left alone")
					return
				}
			}
			if madeBranch {
				code, _, _, rollbackError := gitRun(place.repository, "branch", "-d", place.branch)
				if rollbackError != nil || code != 0 {
					fmt.Fprintln(stderr, "note: Git kept the start's branch because it could not be deleted without force")
				}
			}
		}
	}()
	if place.claim != nil {
		madeClaim, err = takeClaim(place.claim, mine)
		if err != nil {
			return nil, err
		}
	}
	if place.repository != "" {
		if err = gitRequired(place.repository, "branch", place.branch, place.base); err != nil {
			return nil, err
		}
		madeBranch = true
		if err = gitRequired(place.repository, "worktree", "add", place.path, place.branch); err != nil {
			return nil, err
		}
		madeWorktree = true
		place.claim, err = locateClaim(place.path, true, nil)
		if err != nil {
			return nil, err
		}
		madeClaim, err = takeClaim(place.claim, mine)
		if err != nil {
			return nil, err
		}
	}
	if _, err = s.render(lane, composed); err != nil {
		return nil, err
	}
	spec := s.makeSpec(lane, argv, started, nil, runner, composed.output)
	record, err := s.begin(lane, spec)
	if err != nil {
		return nil, err
	}
	unlock()
	locked = false
	event, err := s.waitStarted(lane, spec, record)
	if err != nil {
		latest, _ := s.last(lane, "lane.started")
		if latest != nil && str(obj(latest["payload"])["launch"]) == launch {
			begun = true
		}
		return nil, err
	}
	begun = true
	result := clone(obj(event["payload"]))
	result["lane"] = lane
	result["event"] = eventPointer(event)
	return result, nil
}
func (s *session) validatePlanned(row object, lane, kind string, p object) error {
	if err := validatePayload(kind, lane, p); err != nil {
		return err
	}
	if err := checkSecrets(p); err != nil {
		return err
	}
	if err := s.validateBinding(kind, lane, p); err != nil {
		return err
	}
	return checkTransition(row, envelope(lane, kind, p, "laneboss"))
}
func (s *session) makeSpec(lane string, argv []string, started, resumed, runner object, rendered []byte) object {
	var prompt any
	if str(runner["prompt"]) == "stdin" {
		prompt = base64.StdEncoding.EncodeToString(rendered)
	}
	return object{"config": s.c.name, "lane": lane, "run": started["run"], "launch": started["launch"], "argv": argv, "cwd": started["worktree"], "started": started, "resumed": resumed, "prompt": prompt, "budget_seconds": number(started["budget_minutes"]) * 60, "quiet_seconds": started["quiet_seconds"], "grace_seconds": valueOr(obj(s.c.data["lanes"]), "stop_grace_seconds", 10), "limit_patterns": stringsOf(runner["limit_patterns"]), "dropped_patterns": stringsOf(runner["dropped_patterns"]), "launcher_version": launcherVersion}
}
func (s *session) begin(lane string, spec object) (object, error) {
	r, err := s.laneRoot(lane, true)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	name := ".launch-" + str(spec["launch"]) + ".fifo"
	fifo := s.lanePath(lane, name)
	if err = makeFIFO(r, name); err != nil {
		return nil, refuse("cannot create the launch FIFO")
	}
	defer r.Remove(name)
	socket := str(obj(obj(spec["started"])["session"])["socket"])
	session := str(obj(obj(spec["started"])["session"])["name"])
	if err = os.Mkdir(filepath.Dir(socket), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err = checkSocket(socket); err != nil {
		return nil, err
	}
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	code, _, errors, err := tmuxRun(socket, "new-session", "-d", "-s", session, "-c", str(spec["cwd"]), "-x", "200", "-y", "50", binary, "__supervise", fifo)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, refuse("tmux could not create session %s: %s", session, safeMessage(errors))
	}
	code, out, _, err := tmuxRun(socket, "list-panes", "-t", "="+session, "-F", "#{pane_pid}")
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(out)
	if code != 0 || len(fields) == 0 {
		return nil, refuse("the supervising process ended at once; its messages are in %s", s.lanePath(lane, "watch.log"))
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, refuse("tmux returned no supervising process identity")
	}
	identity, err := processIdentity(pid)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, refuse("the supervising process ended at once")
	}
	record := object{"config": s.c.name, "lane": lane, "run": spec["run"], "launch": spec["launch"], "supervisor": identity, "runner": nil, "processes": []any{}, "finished": false}
	if err = s.writeRecord(lane, record); err != nil {
		signalChecked(identity, syscall.SIGHUP)
		return nil, err
	}
	environment := object{}
	for _, entry := range os.Environ() {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			environment[k] = v
		}
	}
	data := canonical(object{"environment": environment, "spec": spec})
	deadline := time.Now().Add(30 * time.Second)
	var file *os.File
	for {
		file, err = childOpen(r, name, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			break
		}
		if err2 := s.checkStateIdentity(); err2 != nil {
			return nil, err2
		}
		alive, e := identityAlive(identity, nil)
		if e != nil {
			return nil, e
		}
		if !alive || !time.Now().Before(deadline) {
			signalChecked(identity, syscall.SIGHUP)
			return nil, refuse("the supervising process ended before it read its input; its messages are in %s", s.lanePath(lane, "watch.log"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer file.Close()
	fd := int(file.Fd())
	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	for len(data) > 0 {
		n, e := syscall.Write(fd, data)
		if e == nil {
			data = data[n:]
			continue
		}
		if e != syscall.EAGAIN && e != syscall.EINTR {
			return nil, refuse("the supervising process stopped reading its input")
		}
		if !time.Now().Before(deadline) {
			signalChecked(identity, syscall.SIGHUP)
			return nil, refuse("the supervising process did not read its input within 30 seconds")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return record, nil
}
func (s *session) waitStarted(lane string, spec, record object) (object, error) {
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := s.refresh(); err != nil {
			return nil, err
		}
		e, err := s.last(lane, "lane.started")
		if err != nil {
			return nil, err
		}
		if e != nil && obj(e["payload"])["launch"] == spec["launch"] {
			return e, nil
		}
		alive, err := recordAlive(record, nil)
		if err != nil {
			return nil, err
		}
		if !alive {
			return nil, refuse("the supervising process ended before the run started; its messages are in %s", s.lanePath(lane, "watch.log"))
		}
		if !time.Now().Before(deadline) {
			signalChecked(obj(record["supervisor"]), syscall.SIGHUP)
			return nil, refuse("the run did not start within 30 seconds; its supervising process was stopped")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
func (s *session) resume(a arguments) (any, error) {
	lane := a.get("lane")
	budget, err := parseBudget(a.get("budget"))
	if err != nil {
		return nil, err
	}
	if _, err = s.known(lane); err != nil {
		return nil, err
	}
	unlock, err := s.lanesLock()
	if err != nil {
		return nil, err
	}
	locked := true
	defer func() {
		if locked {
			unlock()
		}
	}()
	if err = s.refresh(); err != nil {
		return nil, err
	}
	if err = s.drain(lane); err != nil {
		return nil, err
	}
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	if integer(row["run"]) == 0 {
		return nil, refuse("lane %s has not run yet; start it with lane start", lane)
	}
	if flag(row["running"]) {
		return nil, refuse("lane %s is running run %d; resuming a running lane is refused", lane, integer(row["run"]))
	}
	if flag(row["cleaned"]) {
		return nil, refuse("lane %s was cleaned; start it again with lane start --reuse", lane)
	}
	previous, _, err := s.latest(lane)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		return nil, integrity("the lane has no latest run")
	}
	if _, based := previous["mail"]; based || flag(obj(row["mail"])["turn_based"]) {
		return nil, refuse("lane %s is turn-based, so lane resume is refused: send a message with lane send and start the turn with lane turn", lane)
	}
	if err = s.refuseLive(lane); err != nil {
		return nil, err
	}
	runner, err := s.runner(str(previous["runner"]))
	if err != nil {
		return nil, err
	}
	template := runner["resume"]
	if template == nil {
		return nil, refuse("runner %s has no resume template", str(previous["runner"]))
	}
	if uses(template, "session") && previous["session_id"] == nil {
		return nil, refuse("lane %s has no recorded session identity: its original start template does not use {session}; runners.%s.resume cannot resume it by identity", lane, str(previous["runner"]))
	}
	if !uses(template, "session") && previous["session_id"] != nil {
		return nil, refuse("lane %s has a recorded session identity, but runners.%s.resume does not use {session}", lane, str(previous["runner"]))
	}
	projectName := str(previous["project"])
	project := obj(s.c.projects[projectName])
	account := previous["account"]
	accountBy := any(nil)
	if account != nil {
		accountBy = "previous"
	}
	if a.get("account") != "" {
		if err = checkAccount(runner, a.get("account"), project, "--account"); err != nil {
			return nil, err
		}
		account = a.get("account")
		accountBy = "supervisor"
	}
	if runner["room"] != nil {
		account, accountBy, err = s.chooseRoom(runner, project, account, a.get("account"))
		if err != nil {
			return nil, err
		}
	} else if account != nil {
		if err = checkAccount(runner, str(account), project, "the previous run's account (give --account to use another)"); err != nil {
			return nil, err
		}
	}
	if budget == nil {
		budget = previous["budget_minutes"]
	}
	directory := str(previous["worktree"])
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, refuse("lane %s's working directory no longer exists", lane)
	}
	if err = s.c.checkPath(directory, "the lane's working directory", true); err != nil {
		return nil, err
	}
	claim, err := locateClaim(directory, false, previous["claims"])
	if err != nil {
		return nil, err
	}
	mine := s.claimOwner(lane, "", directory)
	if err = checkClaim(claim, mine); err != nil {
		return nil, err
	}
	if err = s.verifyRendered(lane, previous["brief"]); err != nil {
		return nil, err
	}
	if _, err = exec.LookPath("tmux"); err != nil {
		return nil, refuse("tmux is not on PATH")
	}
	takes := str(runner["prompt"]) == "stdin" || uses(template, "message")
	if a.get("message") != "" && !takes {
		return nil, refuse("runner's resume template has no {message}, so a follow-up message would not reach the runner")
	}
	var message object
	var composed *composedBrief
	if takes {
		source := a.get("message")
		var data []byte
		if source != "" {
			data, err = s.c.external(source, "--message", 4*1024*1024)
			if err != nil {
				return nil, err
			}
			source = realPath(source)
		} else {
			data = continueBytes
			source = "embedded:continue.md"
		}
		composed, err = s.c.compose(lane, projectName, source, data, []string{})
		if err != nil {
			return nil, err
		}
		message = object{"path": s.lanePath(lane, "rendered", digest(composed.output)+".md"), "sha256": digest(composed.output)}
	}
	socket, name := socketPath(s.c), sessionName(lane)
	alive, err := tmuxAlive(socket, name)
	if err != nil {
		return nil, err
	}
	if alive {
		return nil, refuse("a tmux session %s is still open", name)
	}
	values := object{"account": account, "brief": obj(previous["brief"])["path"], "effort": previous["effort"], "lane": lane, "log": previous["log"], "model": previous["model"], "project": previous["project"], "session": previous["session_id"], "worktree": directory, "message": message["path"]}
	argv, err := fill(template, values)
	if err != nil {
		return nil, err
	}
	started := clone(previous)
	started["run"] = integer(row["run"]) + 1
	started["how"] = "resume"
	started["launch"] = newID()
	started["account"] = account
	started["budget_minutes"] = budget
	started["quiet_seconds"] = valueOr(runner, "quiet_seconds", valueOr(obj(s.c.data["lanes"]), "quiet_seconds", 900))
	started["session"] = object{"socket": socket, "name": name}
	effortBy := any(nil)
	if previous["effort"] != nil {
		effortBy = "previous"
	}
	started["chosen_by"] = object{"runner": "previous", "model": "previous", "effort": effortBy, "account": accountBy}
	resumed := object{"run": started["run"], "after": row["reason"], "message": message}
	if err = s.validatePlanned(row, lane, "lane.resumed", resumed); err != nil {
		return nil, err
	}
	if err = s.validatePlanned(row, lane, "lane.started", started); err != nil {
		return nil, err
	}
	rendered := []byte{}
	if composed != nil {
		if _, err = s.render(lane, composed); err != nil {
			return nil, err
		}
		rendered = composed.output
	}
	mine["launch"] = started["launch"]
	if _, err = takeClaim(claim, mine); err != nil {
		return nil, err
	}
	spec := s.makeSpec(lane, argv, started, resumed, runner, rendered)
	record, err := s.begin(lane, spec)
	if err != nil {
		return nil, err
	}
	unlock()
	locked = false
	event, err := s.waitStarted(lane, spec, record)
	if err != nil {
		return nil, err
	}
	marker, err := s.last(lane, "lane.resumed")
	if err != nil {
		return nil, err
	}
	result := clone(obj(event["payload"]))
	result["lane"] = lane
	result["event"] = eventPointer(event)
	result["resumed"] = eventPointer(marker)
	return result, nil
}

func (s *session) stop(a arguments) (any, error) {
	lane := a.get("lane")
	row, err := s.known(lane)
	if err != nil {
		return nil, err
	}
	event, err := s.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	if event == nil {
		return nil, refuse("lane %s has not run", lane)
	}
	p := obj(event["payload"])
	run := integer(p["run"])
	if a.get("run") != "" {
		n, e := strconv.Atoi(a.get("run"))
		if e != nil || n < 1 {
			return nil, refuse("--run must be a positive integer")
		}
		if n != run {
			return nil, refuse("lane %s's latest run is run %d; run %d is not going on, so nothing was stopped", lane, run, n)
		}
	}
	if err = checkSocket(str(obj(p["session"])["socket"])); err != nil {
		return nil, err
	}
	record, err := s.readRecord(lane, str(p["launch"]))
	if err != nil {
		return nil, err
	}
	grace := number(valueOr(obj(s.c.data["lanes"]), "stop_grace_seconds", 10))
	result := object{"lane": lane, "run": run, "launch": p["launch"], "reason": nil, "exit_code": nil, "signal": nil, "event": nil, "pending": false, "removed": 0, "survivors": 0, "stopped_by": nil}
	alive, err := recordAlive(record, nil)
	if err != nil {
		return nil, err
	}
	if alive {
		sent, e := signalChecked(obj(record["supervisor"]), syscall.SIGTERM)
		if e != nil {
			return nil, e
		}
		if !sent {
			// It may have exited after the first observation. Only a still-live
			// supervisor makes a failed signal a refusal; otherwise reread the
			// record below to include workers saved before its exit.
			alive, err = recordAlive(record, nil)
			if err != nil {
				return nil, err
			}
			if alive {
				return nil, refuse("lane %s's supervising process could not be signalled; nothing was stopped", lane)
			}
		}
		if sent {
			deadline := time.Now().Add(time.Duration((grace + 30) * float64(time.Second)))
			for {
				if err = s.refresh(); err != nil {
					return nil, err
				}
				ended, err := s.last(lane, "lane.ended")
				if err != nil {
					return nil, err
				}
				waiting := false
				if ended == nil || integer(obj(ended["payload"])["run"]) != run {
					ended = nil
					pending, err := s.waiting(lane)
					if err != nil {
						return nil, err
					}
					for _, e := range pending {
						if str(e["kind"]) == "lane.ended" && integer(obj(e["payload"])["run"]) == run {
							ended = e
							waiting = true
							break
						}
					}
				}
				alive, err = recordAlive(record, nil)
				if err != nil {
					return nil, err
				}
				if ended != nil {
					if alive && time.Now().Before(deadline) {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					end := obj(ended["payload"])
					for _, k := range []string{"reason", "exit_code", "signal", "survivors"} {
						result[k] = end[k]
					}
					result["pending"] = waiting
					if !waiting {
						result["event"] = eventPointer(ended)
					}
					result["stopped_by"] = "supervisor"
					return result, nil
				}
				if !alive {
					break
				}
				if !time.Now().Before(deadline) {
					return nil, refuse("lane %s's supervising process did not report the end of run %d in time", lane, run)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	record, err = s.readRecord(lane, str(p["launch"]))
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, refuse("lane %s run %d: its run record cannot be read, so its processes cannot be found; nothing was removed", lane, run)
	}
	left, err := recordSurvivors(record, nil)
	if err != nil {
		return nil, err
	}
	if len(left) == 0 {
		if flag(row["running"]) {
			return nil, refuse("lane %s's supervising process is gone and no process survives; lane check records the run", lane)
		}
		return nil, refuse("lane %s is not running", lane)
	}
	removed, surviving, err := stopIdentities(left, grace, nil)
	if err != nil {
		return nil, err
	}
	if len(surviving) > 0 {
		pids := []string{}
		for _, id := range surviving {
			pids = append(pids, "pid "+strconv.Itoa(integer(id["pid"])))
		}
		return nil, refuse("lane %s run %d: %d of %d process(es) removed; %d survive (%s): they could not be signalled or did not end; lane stop tries again", lane, run, len(removed), len(left), len(surviving), strings.Join(pids, ", "))
	}
	result["removed"] = len(removed)
	result["stopped_by"] = "lane-stop"
	return result, nil
}

func makeFIFO(r *os.Root, name string) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return fifoAt(f, r.Name(), name)
}
func debugRun(run int, w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "%s run %d: %s\n", utcNow(), run, fmt.Sprintf(format, args...))
}
