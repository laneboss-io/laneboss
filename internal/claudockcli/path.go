// Package claudockcli locates the cross-platform Claudock command line.
package claudockcli

import (
	"errors"
	"os/exec"
	"path/filepath"
)

// Resolve returns the absolute executable found on PATH, without a fallback.
func Resolve() (string, error) { return resolve(exec.LookPath) }

func resolve(find func(string) (string, error)) (string, error) {
	path, err := find("claudock")
	if err == nil {
		path, err = filepath.Abs(path)
		if err == nil {
			path, err = filepath.EvalSymlinks(path)
		}
	}
	if err != nil {
		return "", errors.New("claudock is not executable on PATH; install claudock-cli from https://github.com/laneboss-io/claudock-cli and add its claudock binary to PATH")
	}
	return path, nil
}
