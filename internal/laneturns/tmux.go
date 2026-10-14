package laneturns

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func socketPath(config, state string) string {
	return filepath.Join("/tmp", "laneboss-"+strconv.Itoa(os.Getuid()), config+"-"+digest([]byte(state))[:12])
}
func sessionName(lane string) string { return strings.ReplaceAll(lane, ".", "_") }
func checkSocket(socket string) error {
	dir := filepath.Dir(socket)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || int(stat.Uid) != os.Getuid() {
		return refused("%s must be a directory of this user's alone (mode 0700, not a link); it holds the lanes' tmux sockets", dir)
	}
	info, err = os.Lstat(socket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return refused("the tmux socket is a symbolic link; the launcher reaches its server only through its own socket")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return refused("the tmux socket is not a socket")
	}
	return nil
}
func tmuxCommand(socket string, args ...string) (int, string, string, error) {
	if _, err := exec.LookPath("tmux"); err != nil {
		return 0, "", "", refused("tmux is not on PATH; lanes run in tmux sessions")
	}
	if err := checkSocket(socket); err != nil {
		return 0, "", "", err
	}
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		argv := append([]string{"-S", socket, "-f", os.DevNull}, args...)
		cmd := exec.CommandContext(ctx, "tmux", argv...)
		cmd.Env = []string{}
		for _, key := range []string{"PATH", "HOME", "LANG", "TMPDIR", "USER"} {
			if value, ok := os.LookupEnv(key); ok {
				cmd.Env = append(cmd.Env, key+"="+value)
			}
		}
		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut
		err := cmd.Run()
		expired := ctx.Err() != nil
		cancel()
		if expired {
			return 0, "", "", refused("tmux did not answer within 30 seconds")
		}
		code := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				code = exit.ExitCode()
			} else {
				return 0, "", "", refused("tmux could not be run")
			}
		}
		errors := errOut.String()
		if code != 0 && (strings.Contains(errors, "server exited unexpectedly") || strings.Contains(errors, "lost server")) && attempt < 4 {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			continue
		}
		return code, out.String(), errors, nil
	}
	return 0, "", "", refused("tmux could not be reached")
}
func tmuxAlive(socket, name string) (bool, error) {
	if err := checkSocket(socket); err != nil {
		return false, err
	}
	if _, err := os.Lstat(socket); os.IsNotExist(err) {
		return false, nil
	}
	code, out, errorText, err := tmuxCommand(socket, "list-sessions", "-F", "#{session_name}")
	if err != nil {
		return false, err
	}
	if code == 0 {
		for _, line := range strings.Split(out, "\n") {
			if line == name {
				return true, nil
			}
		}
		return false, nil
	}
	if strings.HasPrefix(strings.TrimSpace(errorText), "no server running") || strings.Contains(errorText, "No such file or directory") || strings.Contains(errorText, "Connection refused") || strings.Contains(errorText, "server exited unexpectedly") || strings.Contains(errorText, "lost server") {
		return false, nil
	}
	return false, refused("tmux could not list its sessions: %s", screened(shown(strings.SplitN(errorText, "\n", 2)[0])))
}
func tmuxNew(socket, name, dir string, argv []string) (object, error) {
	err := os.Mkdir(filepath.Dir(socket), 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err = checkSocket(socket); err != nil {
		return nil, err
	}
	args := append([]string{"new-session", "-d", "-s", name, "-c", dir, "-x", "200", "-y", "50"}, argv...)
	code, _, errorText, err := tmuxCommand(socket, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, refused("tmux could not create session %s: %s", name, screened(shown(strings.SplitN(errorText, "\n", 2)[0])))
	}
	code, out, _, err := tmuxCommand(socket, "list-panes", "-t", "="+name, "-F", "#{pane_pid}")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, refused("the supervising process ended at once")
	}
	for _, line := range strings.Fields(out) {
		if pid, err := strconv.Atoi(line); err == nil {
			identity, err := processIdentity(pid)
			if err != nil {
				return nil, err
			}
			if identity != nil {
				return identity, nil
			}
		}
	}
	return nil, refused("the supervising process is not in the process table")
}
