package box

import (
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

const suiteLimit = 1 << 20

func regularFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

func readSuite(a arguments) (string, error) {
	if a.set["suite"] == a.set["suite-file"] {
		return "", errors.New("exactly one suite argument is required")
	}
	suite := a.suite
	if a.set["suite-file"] {
		if !regularFile(a.suiteFile) {
			return "", errors.New("the suite file cannot be read")
		}
		f, err := os.Open(a.suiteFile)
		if err != nil {
			return "", errors.New("the suite file cannot be read")
		}
		data, readErr := io.ReadAll(io.LimitReader(f, suiteLimit+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return "", errors.New("the suite file cannot be read")
		}
		suite = string(data)
	}
	if len(suite) > suiteLimit || !utf8.ValidString(suite) || strings.ContainsRune(suite, 0) {
		return "", errors.New("the suite text is not accepted")
	}
	return suite, nil
}

func parsePuts(values []string) ([]boxcore.Put, error) {
	var puts []boxcore.Put
	for _, value := range values {
		local, remote, hasRemote := strings.Cut(value, ":")
		base := filepath.Base(local)
		if strings.HasPrefix(base, "-") || !regularFile(local) {
			return nil, errors.New("a put source is not accepted")
		}
		if !hasRemote {
			remote = "/tmp/" + base
		}
		if !path.IsAbs(remote) || strings.HasPrefix(path.Base(remote), "-") ||
			strings.ContainsRune(remote, 0) {
			return nil, errors.New("a put destination is not accepted")
		}
		puts = append(puts, boxcore.Put{Local: local, Remote: remote})
	}
	return puts, nil
}

func prepareRun(ctx context.Context, a arguments, e environment) (boxcore.RunOptions, func() error, error) {
	o := boxcore.RunOptions{Request: a.request, OutDir: a.out, TimeoutMin: a.timeout}
	noop := func() error { return nil }
	if !a.set["timeout-min"] {
		o.TimeoutMin = a.request.HardMin
	}
	if o.TimeoutMin < 1 || o.TimeoutMin > 10080 {
		return o, noop, errors.New("--timeout-min is outside its range")
	}
	var err error
	o.Suite, err = readSuite(a)
	if err != nil {
		return o, noop, err
	}
	o.Puts, err = parsePuts(a.puts)
	if err != nil {
		return o, noop, err
	}
	if a.set["git-sha"] != a.set["repo"] ||
		a.set["archive"] && (a.set["git-sha"] || a.set["repo"]) {
		return o, noop, errors.New("the source arguments are not accepted together")
	}
	if a.set["archive"] {
		if !regularFile(a.archive) {
			return o, noop, errors.New("the archive is not a regular file")
		}
		o.Archive = a.archive
		return o, noop, nil
	}
	if !a.set["git-sha"] {
		return o, noop, nil
	}
	if !regexp.MustCompile(`^[0-9a-f]{7,40}$`).MatchString(a.gitSHA) || a.repo == "" {
		return o, noop, errors.New("the git source is not accepted")
	}
	f, err := os.CreateTemp(os.TempDir(), "lb-box-source-*.tar")
	if err != nil {
		return o, noop, errors.New("the source archive cannot be created")
	}
	cleanup := func() error { return os.Remove(f.Name()) }
	// The runner receives only the basic process environment, never inherited credentials.
	childEnv := make([]string, 0, 5)
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "TERM"} {
		if value := e.getenv(key); value != "" {
			childEnv = append(childEnv, key+"="+value)
		}
	}
	result, runErr := e.archiveRun.Run(ctx, boxexec.Cmd{
		Name: "git", Args: []string{"-C", a.repo, "archive", "--format=tar", a.gitSHA},
		Env: childEnv, Stdout: f,
	})
	closeErr := f.Close()
	if runErr != nil || result.Code != 0 || closeErr != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			return o, noop, errors.New("the failed source archive cannot be removed")
		}
		return o, noop, errors.New("the git archive could not be made")
	}
	o.Archive = f.Name()
	return o, cleanup, nil
}
