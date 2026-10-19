package orghook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Keep callback provenance and path hashes, never tool arguments or file contents. guard is what the decision guard did
// (decision ids, outcomes and scores, never the call's text); it is nil when the guard asked nobody anything.
func recordCallback(event map[string]any, runner, pinned string, allowed bool, reason string, guard map[string]any) error {
	if pinned == "" {
		return nil
	}
	instance, err := loadInstance(pinned)
	if err != nil {
		return err
	}
	directory := filepath.Join(instance.directory, "hooks")
	if err := os.Mkdir(directory, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return invalid("hook receipt directory must be a real directory")
	}
	dirFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(dirFD), directory)
	defer dir.Close()
	openedDir, err := dir.Stat()
	if err != nil || !os.SameFile(info, openedDir) {
		return invalid("hook receipt directory changed while opening")
	}
	cwd, _ := event["cwd"].(string)
	if cwd == "" {
		var err error
		cwd, err = currentDirectory()
		if err != nil {
			return err
		}
	}
	act, err := eventAction(event, runner, cwd)
	complete := err == nil
	if err != nil && allowed && isObservationGap(err) {
		tool, _ := event["tool_name"].(string)
		if runner == "codex" {
			tool = strings.TrimPrefix(tool, "functions.")
		}
		if len(act.commands) == 0 {
			act.commands = []command{{argv: []string{tool}, directory: cwd, opaque: true}}
		}
		for i := range act.commands {
			act.commands[i].opaque = true
		}
		complete = false
	} else if err != nil && allowed {
		return err
	}
	if err != nil {
		tool, ok := event["tool_name"].(string)
		if !ok || tool == "" {
			return invalid("denied callback has no tool identity")
		}
		act = action{tool: tool}
	}
	effects := []fileEffect{}
	for _, word := range act.reads {
		effects = append(effects, fileEffect{word: word, directory: cwd})
	}
	for _, command := range act.commands {
		for _, directory := range commandDirectories(command) {
			for _, word := range command.reads {
				effects = append(effects, fileEffect{word: word, directory: directory})
			}
		}
	}
	for _, command := range act.commands {
		if command.opaque || command.changesState || command.directoryUncertain {
			complete = false
		}
	}
	paths := []string{}
	for _, effect := range effects {
		path, err := pathAt(effect.word, effect.directory)
		if err != nil {
			if allowed {
				return err
			}
			complete = false
			continue
		}
		sum := sha256.Sum256([]byte(path))
		paths = append(paths, hex.EncodeToString(sum[:]))
	}
	decision := "deny"
	if allowed {
		decision = "allow"
	}
	entry := map[string]any{"event": event["hook_event_name"], "tool": act.tool,
		"decision": decision, "reason": reason, "read_path_sha256": paths, "runner": runner, "inspection_complete": complete}
	if !complete && allowed {
		entry["inspection_notice"] = "file effects were not fully inspected; blacklist mode allowed the call"
	}
	if guard != nil {
		entry["guard"] = guard
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "callbacks.jsonl")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return invalid("hook receipt must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return invalid("hook receipt is unreadable")
	}
	fd, err := unix.Openat(dirFD, "callbacks.jsonl", unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err = os.Lstat(path)
	opened, openedErr := file.Stat()
	if err != nil || openedErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, opened) {
		return invalid("hook receipt changed while opening")
	}
	metadata, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || metadata.Nlink != 1 || metadata.Uid != uint32(os.Geteuid()) {
		return invalid("hook receipt has unsafe ownership or links")
	}
	_, err = file.Write(append(data, '\n'))
	if err != nil {
		return err
	}
	return file.Close()
}
