package lane

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func socketPath(c *configuration) string {
	return filepath.Join(fmt.Sprintf("/tmp/laneboss-%d", os.Getuid()), c.name+"-"+digest([]byte(c.state))[:12])
}
func sessionName(lane string) string { return strings.ReplaceAll(lane, ".", "_") }
func checkPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0077 != 0 {
		return refuse("%s must be a directory of this user's alone (mode 0700, not a link)", path)
	}
	return nil
}
func checkSocket(socket string) error {
	err := checkPrivateDirectory(filepath.Dir(socket))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := os.Lstat(socket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return refuse("the tmux socket %s is a symbolic link or not a socket", socket)
	}
	return nil
}
func tmuxRun(socket string, args ...string) (int, string, string, error) {
	if _, err := exec.LookPath("tmux"); err != nil {
		return 0, "", "", refuse("tmux is not on PATH; lanes run in tmux sessions")
	}
	if err := checkSocket(socket); err != nil {
		return 0, "", "", err
	}
	environment := []string{}
	for _, key := range []string{"PATH", "HOME", "LANG", "TMPDIR", "USER"} {
		if v, ok := os.LookupEnv(key); ok {
			environment = append(environment, key+"="+v)
		}
	}
	for attempt := 0; attempt < 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, "tmux", append([]string{"-S", socket, "-f", os.DevNull}, args...)...)
		command.Env = environment
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		expired := ctx.Err() != nil
		cancel()
		if expired {
			return 0, "", "", refuse("tmux did not answer within 30 seconds")
		}
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				return 0, "", "", refuse("tmux cannot be run")
			}
		}
		errors := stderr.String()
		if code != 0 && (strings.Contains(errors, "server exited unexpectedly") || strings.Contains(errors, "lost server")) && attempt < 4 {
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			continue
		}
		return code, stdout.String(), errors, nil
	}
	return 0, "", "", refuse("tmux server could not be reached")
}
func tmuxSessions(socket string) ([]string, error) {
	if err := checkSocket(socket); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(socket); os.IsNotExist(err) {
		return []string{}, nil
	}
	code, out, errors, err := tmuxRun(socket, "list-sessions", "-F", "#{session_name}")
	if err != nil {
		return nil, err
	}
	if code == 0 {
		return strings.Fields(out), nil
	}
	if strings.HasPrefix(strings.TrimSpace(errors), "no server running") || strings.Contains(errors, "No such file or directory") || strings.Contains(errors, "Connection refused") || strings.Contains(errors, "server exited unexpectedly") || strings.Contains(errors, "lost server") {
		return []string{}, nil
	}
	return nil, refuse("tmux could not list sessions at %s: %s", socket, safeMessage(errors))
}
func tmuxAlive(socket, name string) (bool, error) {
	sessions, err := tmuxSessions(socket)
	return contains(sessions, name), err
}
func safeMessage(s string) string {
	s = strings.Split(strings.TrimSpace(s), "\n")[0]
	if rule, _ := credential(s); rule != "" {
		return "(message withheld: looks like a credential)"
	}
	r := []rune(s)
	if len(r) > 300 {
		s = string(r[:300])
	}
	return s
}
