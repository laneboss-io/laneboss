package laneturns

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

type roomAnswer struct {
	room   bool
	slots  int
	reason string
}

func noRoom(account string) roomAnswer {
	return roomAnswer{false, 0, fmt.Sprintf("the room command of account %s did not answer in the documented form", account)}
}
func isWhole(v any) bool {
	switch n := v.(type) {
	case int:
		return true
	case int64:
		return true
	case json.Number:
		return !strings.ContainsAny(string(n), ".eE")
	}
	return false
}
func isFloat(v any) bool {
	switch n := v.(type) {
	case float64:
		return true
	case json.Number:
		return strings.ContainsAny(string(n), ".eE")
	}
	return false
}
func readRoom(data []byte, account string) roomAnswer {
	no := noRoom(account)
	if len(data) > 4096 || !utf8.Valid(data) {
		return no
	}
	v, err := decodeJSON(data)
	if err != nil || !exactKeys(v, "room slots reason") {
		return no
	}
	b, ok := v["room"].(bool)
	if !ok || !isWhole(v["slots"]) {
		return no
	}
	reason, ok := v["reason"].(string)
	slots := integer(v["slots"])
	if !ok || slots < 0 || slots > 64 || b && slots < 1 || !b && slots != 0 || !b && reason == "" || len([]rune(reason)) > 200 || shown(reason) != reason {
		return no
	}
	return roomAnswer{b, slots, screened(reason)}
}
func probeRoom(c *configuration, r object, account string) roomAnswer {
	no := noRoom(account)
	argv, err := fillTemplate(r["room"], object{"account": account})
	if err != nil {
		return no
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return no
	}
	defer outRead.Close()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = outWrite
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		outWrite.Close()
		return no
	}
	outWrite.Close()
	entry, err := processInfo(cmd.Process.Pid)
	if err != nil || entry == nil || entry.start == "" {
		cmd.Process.Kill()
		cmd.Wait()
		return no
	}
	identity := identityOf(*entry)
	known := []object{identity}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() { data, err := io.ReadAll(io.LimitReader(outRead, 4097)); read <- readResult{data, err} }()
	deadline := time.Now().Add(time.Duration(c.setting("lanes", "room_timeout_seconds", 20) * float64(time.Second)))
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var output []byte
	complete, ended, bad := false, false, false
	discover := func() ([]object, error) { return discoverProcesses(known, integer(identity["pid"]), false) }
	for !bad && !(complete && ended) && time.Now().Before(deadline) {
		select {
		case result := <-read:
			output = result.data
			complete = true
			if result.err != nil || len(output) > 4096 {
				bad = true
			}
		case <-ticker.C:
			found, e := discover()
			if e != nil {
				bad = true
				break
			}
			mergeIdentities(&known, found)
			entry, e := observeRunner(identity)
			if e != nil {
				bad = true
				break
			}
			ended = strings.HasPrefix(entry.state, "Z")
		}
	}
	_, survivors, stopErr := stopIdentities(&known, c.setting("lanes", "stop_grace_seconds", 10), discover)
	if stopErr != nil || len(survivors) > 0 {
		signalChecked(identity, syscall.SIGKILL)
		bad = true
	}
	waitErr := cmd.Wait()
	if !complete {
		select {
		case result := <-read:
			output = result.data
			complete = true
			if result.err != nil {
				bad = true
			}
		case <-time.After(time.Second):
			bad = true
		}
	}
	if !complete || !ended || bad || waitErr != nil {
		return no
	}
	after, e := discover()
	if e != nil || len(after) > 0 {
		return no
	}
	return readRoom(output, account)
}
func chooseAccount(c *configuration, r object, named, previous any, project object, started map[string]int) (any, any, error) {
	choice := accountChoice(c, r, named, previous, project, started)
	if choice.Account == nil {
		return nil, nil, refused("%s", str(choice.Reason))
	}
	return choice.Account, choice.ChosenBy, nil
}

type choice struct {
	Account  any    `json:"account"`
	ChosenBy any    `json:"chosen_by"`
	Reason   any    `json:"reason"`
	Outcome  string `json:"outcome"`
}

// accountChoice is the shared decision used by real turns and private probes.
func accountChoice(c *configuration, r object, named, previous any, project object, started map[string]int) choice {
	if named != nil && (!contains(r["accounts"], str(named)) || contains(project["excluded_accounts"], str(named))) {
		reason := "the named account is not one the runner lists"
		if contains(r["accounts"], str(named)) {
			reason = fmt.Sprintf("account %s is excluded by the project", screened(str(named)))
		}
		return choice{Reason: reason, Outcome: "named-unusable"}
	}
	if r["room"] == nil {
		if named != nil {
			return choice{Account: named, ChosenBy: "supervisor", Outcome: "chosen"}
		}
		if previous != nil {
			return choice{Account: previous, ChosenBy: "previous", Outcome: "chosen"}
		}
		return choice{Reason: "runner has no room command and the lane has no previous run's account", Outcome: "no-check"}
	}
	candidates := []string{}
	if named != nil {
		candidates = append(candidates, str(named))
	} else {
		if previous != nil && contains(r["accounts"], str(previous)) && !contains(project["excluded_accounts"], str(previous)) {
			candidates = append(candidates, str(previous))
		}
		for _, account := range texts(r["accounts"]) {
			if account != str(previous) && !contains(project["excluded_accounts"], account) {
				candidates = append(candidates, account)
			}
		}
	}
	asked := []string{}
	for _, account := range candidates {
		answer := probeRoom(c, r, account)
		if answer.room && answer.slots >= 1 && started[account] < answer.slots {
			by := "room"
			if named != nil {
				by = "supervisor"
			} else if account == str(previous) {
				by = "previous"
			}
			return choice{Account: account, ChosenBy: by, Outcome: "chosen"}
		}
		reason := answer.reason
		if answer.room {
			reason = fmt.Sprintf("account %s has taken its %d turn(s) for this pass", account, answer.slots)
		}
		if named != nil {
			return choice{Reason: reason, Outcome: "named-no-room"}
		}
		asked = append(asked, account+": "+reason)
	}
	if len(asked) == 0 {
		return choice{Reason: "no account is left to ask", Outcome: "no-room"}
	}
	return choice{Reason: fmt.Sprintf("no account has room (%s)", strings.Join(asked, "; ")), Outcome: "no-room"}
}
