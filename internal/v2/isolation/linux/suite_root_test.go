//go:build linux && laneboss_root_canary

package linux

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func init() { rootSuite = runInstalledLinuxSuite }

// Only test setup runs as root. The same compiled suite and its real bootstrap
// execute as nobody; no test is filtered, skipped or credited from root.
func runInstalledLinuxSuite() (exitCode int) {
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "Linux suite installation failed:", err)
		return 1
	}
	account, err := user.Lookup("nobody")
	if err != nil {
		return fail(err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if err := errors.Join(uidErr, gidErr); err != nil || uid == 0 || gid == 0 {
		return fail(errors.Join(err, errors.New("non-root test account is required")))
	}
	directory, err := os.MkdirTemp("/run", "lb-v2-gr-issue-linux-suite-")
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			fmt.Fprintln(os.Stderr, "Linux suite retained installation cleanup failed:", err)
			exitCode = 1
		}
	}()
	if err := os.Chmod(directory, 0755); err != nil {
		return fail(err)
	}
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return fail(err)
	}
	helper := filepath.Join(directory, "linux.test")
	file, err := os.OpenFile(helper, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0555)
	if err != nil {
		return fail(errors.Join(err, self.Close()))
	}
	_, copyErr := io.Copy(file, self)
	if err := errors.Join(copyErr, file.Chmod(0555), file.Sync(), file.Close(), self.Close()); err != nil {
		return fail(err)
	}
	if _, err := safeSystemPath(helper); err != nil {
		return fail(err)
	}
	// Writable test inputs must be outside the protected helper tree, and
	// outside HOME, so positive export controls remain independent sources.
	scratch, err := os.MkdirTemp("/var/tmp", "lb-v2-gr-issue-linux-inputs-")
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := os.RemoveAll(scratch); err != nil {
			fmt.Fprintln(os.Stderr, "Linux suite input cleanup failed:", err)
			exitCode = 1
		}
	}()
	if err := os.Chown(scratch, int(uid), int(gid)); err != nil {
		return fail(err)
	}
	home := filepath.Join(scratch, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		return fail(err)
	}
	if err := os.Chown(home, int(uid), int(gid)); err != nil {
		return fail(err)
	}
	temporary := filepath.Join(scratch, "temporary")
	if err := os.Mkdir(temporary, 0700); err != nil {
		return fail(err)
	}
	if err := os.Chown(temporary, int(uid), int(gid)); err != nil {
		return fail(err)
	}
	arguments := append([]string{}, os.Args[1:]...)
	var originalLog string
	for i, argument := range arguments {
		if strings.HasPrefix(argument, "-test.testlogfile=") {
			originalLog = strings.TrimPrefix(argument, "-test.testlogfile=")
			arguments[i] = "-test.testlogfile=" + filepath.Join(temporary, "testlog")
		}
	}
	arguments = append(arguments, "-linux-helper="+helper)
	command := exec.Command(helper, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + temporary}
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	runErr := command.Run()
	if originalLog != "" {
		raw, err := os.ReadFile(filepath.Join(temporary, "testlog"))
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(originalLog, raw, 0600); err != nil {
			return fail(err)
		}
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			return exit.ExitCode()
		}
		return fail(runErr)
	}
	return 0
}
