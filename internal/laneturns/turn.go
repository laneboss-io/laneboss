package laneturns

import (
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/hookconfig"
	"laneboss.io/laneboss/internal/runnermodel"
)

func turn(c *configuration, a arguments, environment object, passStarted map[string]int) (object, error) {
	// One snapshot feeds both offline gates and the eventual turn worker.
	if environment == nil {
		environment = captureEnvironment()
	}
	environment = copyObject(environment)
	lane := a.get("lane")
	budget, err := parseBudget(a.get("budget"))
	if err != nil {
		return nil, err
	}
	s, err := openSession(c, false)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if s.state == nil {
		return nil, refused("lane %s is not known to configuration %s", lane, c.name)
	}
	lock, err := s.state.lock("lanes.lock", "lanes lock", c.setting("lanes", "lock_wait_seconds", 60))
	if err != nil {
		return nil, err
	}
	defer func() {
		if lock != nil {
			lock.close()
		}
	}()
	if err = s.refresh(); err != nil {
		return nil, err
	}
	if _, err = s.known(lane); err != nil {
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
		return nil, refused("lane %s has not run yet; start it with lane start --turns", lane)
	}
	if flag(row["running"]) {
		return nil, refused("lane %s is running run %d; a turn while a run goes on is refused", lane, integer(row["run"]))
	}
	if flag(row["cleaned"]) {
		return nil, refused("lane %s was cleaned; start it again with lane start --reuse --turns", lane)
	}
	previous, err := s.latest(lane)
	if err != nil {
		return nil, err
	}
	if row["state"] == "merged" {
		return nil, refused("lane %s is merged, and a merged lane is never turn-based: it takes no turn", lane)
	}
	if row["state"] == "abandoned" {
		return nil, refused("lane %s is abandoned, so no turn starts for it; its mail is kept", lane)
	}
	if str(row["reason"]) == "hook-config" {
		data, err := s.state.read("lanes/"+lane+"/hook-config.json", 65536)
		if err != nil || hookconfig.Repaired(data, integer(row["run"])) != nil {
			return nil, refused("%s", hookconfig.Repair)
		}
	}
	mail := obj(row["mail"])
	if !flag(mail["turn_based"]) {
		return nil, refused("lane %s is not turn-based: only a lane started with lane start --turns, or an adopted lane, takes turns", lane)
	}
	if previous == nil {
		return nil, integrity("a turn-based lane has no previous run or adoption")
	}
	name := str(previous["runner"])
	r, err := c.runner(name)
	if err != nil {
		return nil, err
	}
	if problems := turnProblems(name, r); len(problems) > 0 {
		return nil, refused("lane %s's runner %s cannot take turns, because %s", lane, name, strings.Join(problems, "; "))
	}
	if err = refuseLive(s, lane); err != nil {
		return nil, err
	}
	var data []byte
	var taken []any
	kind, source := "mail", s.state.lanePath(lane, "mail")
	if queued(mail) > 0 {
		data, taken, err = takeMail(s, lane, mail)
		if err != nil {
			return nil, err
		}
	} else if a.flags["idle"] {
		kind = "idle"
		taken = []any{}
		if c.idlePath == "" {
			return nil, refused("lane turn --idle: the configuration has no [turns] idle_message, so there is no idle message to send")
		}
		data = c.idle
		source = c.idlePath
	} else {
		return object{"lane": lane, "started": false, "reason": "no mail", "waiting": 0}, nil
	}
	if previous["session_id"] == nil {
		return nil, refused("lane %s has no recorded session identity, so it cannot be resumed by runner %s whose resume template uses {session}", lane, name)
	}
	projectName := str(previous["project"])
	project := c.projects[projectName]
	if projectName != "" && project == nil {
		return nil, refused("lane %s's project file is missing from the configuration; no turn starts without its standing rules", lane)
	}
	account := a.optional("account")
	if account != nil {
		if err = checkAccount(name, r, str(account), project, "--account"); err != nil {
			return nil, err
		}
	}
	var accountBy any
	if r["room"] == nil {
		if account != nil {
			accountBy = "supervisor"
		} else {
			account = previous["account"]
			if account != nil {
				accountBy = "previous"
				if err = checkAccount(name, r, str(account), project, "the previous run's account (give --account to use another)"); err != nil {
					return nil, err
				}
			}
		}
	} else {
		account, accountBy, err = chooseAccount(c, r, account, previous["account"], project, passStarted)
		if err != nil {
			return nil, refused("lane %s: no turn starts, because %s", lane, err.Error())
		}
	}
	if budget == nil {
		budget = previous["budget_minutes"]
	}
	directory := str(previous["worktree"])
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return nil, refused("lane %s's working directory no longer exists", lane)
	}
	if err = c.checkExternal(directory, "the lane's working directory", true); err != nil {
		return nil, err
	}
	claim, err := locateClaim(directory, false, previous["claims"])
	if err != nil {
		return nil, err
	}
	mine := claimOwner(s, lane, directory, nil)
	if err = claim.check(mine); err != nil {
		return nil, err
	}
	if err = verifyRendered(s, lane, obj(previous["brief"])); err != nil {
		return nil, err
	}
	if _, err = exec.LookPath("tmux"); err != nil {
		return nil, refused("tmux is not on PATH; lanes run in tmux sessions")
	}
	output, err := composeBrief(c, lane, projectName, data, "the message of the turn")
	if err != nil {
		return nil, err
	}
	message := object{"path": s.state.lanePath(lane, "rendered", digest(output)+".md"), "sha256": digest(output)}
	socket := socketPath(c.name, s.state.path)
	alive, err := tmuxAlive(socket, sessionName(lane))
	if err != nil {
		return nil, err
	}
	if alive {
		return nil, refused("a tmux session %s is still open at %s", sessionName(lane), socket)
	}
	run := integer(row["run"]) + 1
	values := object{"account": account, "brief": obj(previous["brief"])["path"], "effort": previous["effort"], "lane": lane, "log": previous["log"], "model": previous["model"], "project": previous["project"], "session": previous["session_id"], "worktree": directory, "message": message["path"]}
	values["model"] = runnermodel.API(r, str(previous["model"]))
	argv, err := fillTemplate(r["resume"], values)
	if err != nil {
		return nil, err
	}
	gate := hookconfig.CodexGate{}
	argv, err = gate.Prepare(argv, directory, environmentList(environment))
	if err != nil {
		return nil, refused("%s", err.Error())
	}
	launch, err := randomID()
	if err != nil {
		return nil, err
	}
	started := copyObject(previous)
	started["run"] = run
	started["how"] = "resume"
	started["launch"] = launch
	started["account"] = account
	started["budget_minutes"] = budget
	started["quiet_seconds"] = c.quiet(r)
	started["session"] = object{"socket": socket, "name": sessionName(lane)}
	chosen := object{"runner": "previous", "model": "previous", "effort": nil, "account": accountBy}
	if previous["effort"] != nil {
		chosen["effort"] = "previous"
	}
	started["chosen_by"] = chosen
	started["mail"] = taken
	started["idle_seconds"] = mail["idle_seconds"]
	resumed := object{"run": run, "after": row["reason"], "message": message}
	for eventKind, p := range map[string]object{"lane.resumed": resumed, "lane.started": started} {
		if err = checkValueCredentials(p, "payload", 0); err != nil {
			return nil, err
		}
		if err = checkPayload(eventKind, p); err != nil {
			return nil, err
		}
		if err = checkBinding(s.state, lane, eventKind, p); err != nil {
			return nil, err
		}
		e := object{"kind": eventKind, "lane": lane, "payload": p}
		if err = checkTransition(row, e); err != nil {
			return nil, err
		}
	}
	actual, err := renderBrief(s, lane, projectName, source, data, output)
	if err != nil {
		return nil, err
	}
	if !equalJSON(actual, message) {
		return nil, integrity("the rendered message is not where it was expected")
	}
	mine["launch"] = launch
	if _, err = claim.take(mine); err != nil {
		return nil, err
	}
	spec := object{"config": c.name, "lane": lane, "run": run, "launch": launch, "argv": argv, "cwd": directory, "started": started, "resumed": resumed, "prompt": base64.StdEncoding.EncodeToString(output), "budget_seconds": number(budget) * 60, "quiet_seconds": c.quiet(r), "grace_seconds": c.setting("lanes", "stop_grace_seconds", 10), "limit_patterns": array(r["limit_patterns"]), "dropped_patterns": array(r["dropped_patterns"]), "launcher_version": launcherVersion}
	process, err := beginWorker(s, lane, spec, environment)
	if err != nil {
		return nil, err
	}
	lock.close()
	lock = nil
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err = s.refresh(); err != nil {
			return nil, err
		}
		event, err := s.store.last(lane, "lane.started")
		if err != nil {
			return nil, err
		}
		if event != nil && obj(event["payload"])["launch"] == launch {
			marker, err := s.store.last(lane, "lane.resumed")
			if err != nil {
				return nil, err
			}
			result := copyObject(obj(event["payload"]))
			result["lane"] = lane
			result["event"] = eventRef(event)
			result["resumed"] = eventRef(marker)
			result["started"] = true
			result["turn"] = object{"kind": kind, "mail": taken}
			return result, nil
		}
		alive, err := processAlive(process)
		if err != nil {
			return nil, err
		}
		if !alive {
			return nil, refused("the supervising process ended before the run started; its messages are in %s", s.state.lanePath(lane, "watch.log"))
		}
		if time.Now().After(deadline) {
			if _, err = signalChecked(process, hangupSignal()); err != nil {
				return nil, err
			}
			return nil, refused("the run did not start within 30 seconds; its supervising process was stopped")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
