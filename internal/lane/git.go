package lane

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func gitRun(directory string, args ...string) (int, string, string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return 0, "", "", refuse("git is not on PATH, so it cannot be told whether the directory lies inside a Git repository")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "git", append([]string{"-C", directory}, args...)...)
	command.Env = changedEnv(os.Environ(), map[string]string{"LC_ALL": "C", "LANG": "C"}, func(k string) bool { return strings.HasPrefix(k, "GIT_") || k == "LANGUAGE" })
	var out, errors bytes.Buffer
	command.Stdout = &out
	command.Stderr = &errors
	err := command.Run()
	if ctx.Err() != nil {
		return 0, "", "", refuse("git did not finish within 120 seconds")
	}
	code := 0
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else {
			return 0, "", "", refuse("Git cannot be run")
		}
	}
	return code, strings.TrimSpace(out.String()), strings.TrimSpace(errors.String()), nil
}
func dotGitAbove(directory string) bool {
	for p := realPath(directory); ; p = filepath.Dir(p) {
		if _, err := os.Lstat(filepath.Join(p, ".git")); err == nil {
			return true
		}
		if p == filepath.Dir(p) {
			return false
		}
	}
}
func gitKind(directory string) (string, string, error) {
	code, out, errors, err := gitRun(directory, "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir", "--git-common-dir")
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(out, "\n")
	if code == 0 && len(lines) == 3 && filepath.IsAbs(lines[0]) && filepath.IsAbs(lines[1]) && filepath.IsAbs(lines[2]) {
		top, admin, common := realPath(lines[0]), realPath(lines[1]), realPath(lines[2])
		if admin == common {
			return "main", top, nil
		}
		return "linked", admin, nil
	}
	if code != 0 && strings.Contains(errors, "not a git repository") && !dotGitAbove(directory) {
		return "none", "", nil
	}
	return "", "", refuse("Git cannot be asked whether %s lies inside a repository (%s)", directory, safeMessage(errors))
}
func gitRequired(directory string, args ...string) error {
	code, _, errors, err := gitRun(directory, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return refuse("Git refused the lane operation: %s", safeMessage(errors))
	}
	return nil
}
