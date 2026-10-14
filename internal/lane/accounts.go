package lane

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

func (s *session) chooseRoom(runner, project object, previous any, named string) (any, any, error) {
	candidates := []string{}
	if named != "" {
		candidates = append(candidates, named)
	} else {
		if previous != nil && contains(stringsOf(runner["accounts"]), str(previous)) && !contains(stringsOf(project["excluded_accounts"]), str(previous)) {
			candidates = append(candidates, str(previous))
		}
		for _, a := range stringsOf(runner["accounts"]) {
			if a != str(previous) && !contains(stringsOf(project["excluded_accounts"]), a) {
				candidates = append(candidates, a)
			}
		}
	}
	reasons := []string{}
	for _, account := range candidates {
		room, reason := s.roomAnswer(runner, account)
		if room {
			by := "room"
			if account == named {
				by = "supervisor"
			} else if account == str(previous) {
				by = "previous"
			}
			return account, by, nil
		}
		if named != "" {
			return nil, nil, refuse("no turn starts, because %s", reason)
		}
		reasons = append(reasons, account+": "+reason)
	}
	reason := "no account is left to ask"
	if len(reasons) > 0 {
		reason = "no account has room (" + strings.Join(reasons, "; ") + ")"
	}
	return nil, nil, refuse("no turn starts, because %s", reason)
}
func (s *session) roomAnswer(runner object, account string) (bool, string) {
	failure := fmt.Sprintf("the room command of account %s did not answer in the documented form", account)
	argv, err := fill(runner["room"], object{"account": account})
	if err != nil || len(argv) == 0 {
		return false, failure
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	read, write, err := os.Pipe()
	if err != nil {
		return false, failure
	}
	defer read.Close()
	command.Stdout = write
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		write.Close()
		return false, failure
	}
	write.Close()
	pid := command.Process.Pid
	known := []object{}
	if id, e := processIdentity(pid); e == nil && id != nil {
		known = append(known, id)
	}
	discover := func() ([]object, error) {
		table, err := processSnapshot()
		if err != nil {
			return nil, err
		}
		roots := []int{pid}
		for _, id := range known {
			alive, e := identityAlive(id, table)
			if e != nil {
				return nil, e
			}
			if alive {
				roots = append(roots, integer(id["pid"]))
			}
		}
		found := discoverProcesses(table, roots, pid)
		known, _ = mergeIdentities(known, found)
		return found, nil
	}
	type answerBytes struct {
		data []byte
		err  error
	}
	output := make(chan answerBytes, 1)
	go func() { b, err := io.ReadAll(io.LimitReader(read, 4097)); output <- answerBytes{b, err} }()
	seconds := number(valueOr(obj(s.c.data["lanes"]), "room_timeout_seconds", 20))
	grace := number(valueOr(obj(s.c.data["lanes"]), "stop_grace_seconds", 10))
	deadline := time.Now().Add(time.Duration(seconds * float64(time.Second)))
	var captured answerBytes
	closed, ended := false, false
	for time.Now().Before(deadline) {
		select {
		case captured = <-output:
			closed = true
		default:
		}
		p, e := processEntry(pid)
		if e != nil {
			break
		}
		ended = p == nil || strings.HasPrefix(p.state, "Z")
		if closed && (ended || len(captured.data) > 4096) {
			break
		}
		if _, e = discover(); e != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	inTime := closed && ended && captured.err == nil && time.Now().Before(deadline)
	stopped := false
	_, left, stopError := stopIdentities(known, grace, discover)
	if stopError != nil || len(left) > 0 {
		// This is still our own uncollected child. Its PID cannot have been reused,
		// and os.Process also retains the kernel process handle where available.
		killError := command.Process.Kill()
		if killError != nil && killError != os.ErrProcessDone {
			inTime = false
		}
		_, left, stopError = stopIdentities(known, grace, discover)
	}
	if stopError == nil && len(left) == 0 {
		// Observe once more after the stop. A child created during the last snapshot
		// must never turn an incomplete cleanup into a successful room answer.
		if _, e := discover(); e == nil {
			left, e = living(known, nil)
			stopped = e == nil && len(left) == 0
		}
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case waitError := <-waited:
		if waitError != nil {
			inTime = false
		}
	case <-time.After(5 * time.Second):
		return false, failure
	}
	data := captured.data
	if !stopped || !inTime || command.ProcessState == nil || command.ProcessState.ExitCode() != 0 || len(data) > 4096 || !utf8.Valid(data) {
		return false, failure
	}
	v, err := parseJSON(data)
	answer := obj(v)
	if err != nil || !exactKeys(answer, strings.Fields("room slots reason")) {
		return false, failure
	}
	_, boolean := answer["room"].(bool)
	reason, ok := answer["reason"].(string)
	slots := integer(answer["slots"])
	if !boolean || !whole(answer["slots"], 0, 64) || !ok || len([]rune(reason)) > 200 || strings.IndexFunc(reason, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || flag(answer["room"]) && slots < 1 || !flag(answer["room"]) && (slots != 0 || reason == "") {
		return false, failure
	}
	if rule, _ := credential(reason); rule != "" {
		reason = "(withheld)"
	}
	return flag(answer["room"]), reason
}
