package box

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

func TestRunSourceArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"sha-without-repo", []string{"--git-sha", "abcdef1", "--suite", "SECRET-NEEDLE"}},
		{"repo-without-sha", []string{"--repo", "SECRET-NEEDLE", "--suite", "exit 0"}},
		{"both-sources", []string{"--git-sha", "abcdef1", "--repo", "demo", "--archive", "SECRET-NEEDLE", "--suite", "exit 0"}},
		{"no-suite", nil},
		{"both-suites", []string{"--suite", "SECRET-NEEDLE", "--suite-file", "demo"}},
		{"bad-sha", []string{"--git-sha", "SECRET-NEEDLE", "--repo", "demo", "--suite", "exit 0"}},
		{"short-sha", []string{"--git-sha", "abcdef", "--repo", "demo", "--suite", "exit 0"}},
		{"long-sha", []string{"--git-sha", strings.Repeat("a", 41), "--repo", "demo", "--suite", "exit 0"}},
		{"missing-archive", []string{"--archive", "SECRET-NEEDLE", "--suite", "exit 0"}},
		{"bad-timeout", []string{"--suite", "SECRET-NEEDLE", "--timeout-min", "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newFixture(t)
			args := append([]string{"run", "--purpose", "demo"}, tc.args...)
			code := h.call(args...)
			if code != 2 || h.built != 0 || h.out.Len() != 0 ||
				!strings.HasPrefix(h.notes.String(), usage) || strings.Contains(h.notes.String(), "SECRET-NEEDLE") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, h.out.String(), h.notes.String())
			}
		})
	}
}

func TestRunInputs(t *testing.T) {
	h := newFixture(t)
	dir := t.TempDir()
	suite := writeTemp(t, dir, "suite.sh", "printf demo\n")
	archive := writeTemp(t, dir, "source.tar", "demo source")
	one := writeTemp(t, dir, "one.txt", "one")
	two := writeTemp(t, dir, "two.txt", "two")
	code := h.call("run", "--purpose", "demo", "--suite-file", suite, "--archive", archive,
		"--put", one, "--put", two+":/tmp/custom.txt", "--timeout-min", "25", "--out", "/tmp/demo-out")
	if code != 0 || len(h.svc.runs) != 1 {
		t.Fatalf("code=%d stderr=%q", code, h.notes.String())
	}
	o := h.svc.runs[0]
	wantPuts := []boxcore.Put{{Local: one, Remote: "/tmp/one.txt"}, {Local: two, Remote: "/tmp/custom.txt"}}
	if o.Suite != "printf demo\n" || o.Archive != archive || !reflect.DeepEqual(o.Puts, wantPuts) ||
		o.TimeoutMin != 25 || o.OutDir != "/tmp/demo-out" {
		t.Fatalf("run inputs lost or reordered: %+v", o)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("the caller's archive was removed: %v", err)
	}
}

func TestPutErrors(t *testing.T) {
	dir := t.TempDir()
	local := writeTemp(t, dir, "demo.txt", "demo")
	leading := writeTemp(t, dir, "-demo.txt", "demo")
	cases := []string{local + ":relative", filepath.Join(dir, "missing"), leading, dir,
		local + ":", local + ":/tmp/-demo.txt"}
	for i, put := range cases {
		h := newFixture(t)
		code := h.call("run", "--purpose", "demo", "--suite", "exit 0", "--put", put)
		if code != 2 || h.built != 0 || !strings.HasPrefix(h.notes.String(), usage) || strings.Contains(h.notes.String(), put) {
			t.Fatalf("case %d: code=%d stderr=%q", i, code, h.notes.String())
		}
	}
}

func TestSuiteLimits(t *testing.T) {
	cases := []struct {
		name, data string
		code       int
	}{
		{"limit", strings.Repeat("a", suiteLimit), 0},
		{"too-large", strings.Repeat("a", suiteLimit+1), 2},
		{"nul", "demo\x00text", 2},
		{"utf8", "demo\xfftext", 2},
	}
	for _, file := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(tc.name+map[bool]string{true: "/file", false: "/text"}[file], func(t *testing.T) {
				h := newFixture(t)
				args := []string{"run", "--purpose", "demo", "--suite", tc.data}
				if file {
					name := writeTemp(t, t.TempDir(), "suite.sh", tc.data)
					args = []string{"run", "--purpose", "demo", "--suite-file", name}
				}
				code := h.call(args...)
				if code != tc.code || (tc.code == 0) != (len(h.svc.runs) == 1) {
					t.Fatalf("code=%d want=%d stderr=%q", code, tc.code, h.notes.String())
				}
				if tc.code == 0 && h.svc.runs[0].Suite != tc.data {
					t.Fatal("suite bytes changed")
				}
			})
		}
	}
}

func TestGitArchive(t *testing.T) {
	h := newFixture(t)
	h.vars["PATH"] = "/tmp/demo-bin"
	h.vars["HOME"] = "/tmp/demo-home"
	h.vars["DEMO_SECRET"] = "SECRET-NEEDLE"
	var name string
	var calls int
	h.env.archiveRun = runnerFunc(func(ctx context.Context, cmd boxexec.Cmd) (boxexec.Result, error) {
		calls++
		want := []string{"-C", "/tmp/demo-repo", "archive", "--format=tar", "abcdef1"}
		if cmd.Name != "git" || !reflect.DeepEqual(cmd.Args, want) ||
			!reflect.DeepEqual(cmd.Env, []string{"PATH=/tmp/demo-bin", "HOME=/tmp/demo-home"}) || cmd.Stderr != nil {
			t.Error("git command or its clean environment changed")
		}
		f, ok := cmd.Stdout.(*os.File)
		if !ok {
			t.Fatal("git stdout must go directly to a file")
		}
		name = f.Name()
		info, err := f.Stat()
		if err != nil || info.Mode().Perm() != 0600 || filepath.Dir(name) != filepath.Clean(os.TempDir()) {
			t.Fatalf("archive permissions or location: %v", err)
		}
		_, err = io.WriteString(cmd.Stdout, "demo archive bytes")
		return boxexec.Result{Code: 0}, err
	})
	h.svc.during = func(ctx context.Context, o boxcore.RunOptions) {
		data, err := os.ReadFile(o.Archive)
		if err != nil || string(data) != "demo archive bytes" || o.Archive != name {
			t.Errorf("archive did not reach service: %v", err)
		}
	}
	code := h.call("run", "--purpose", "demo", "--suite", "exit 0", "--git-sha", "abcdef1", "--repo", "/tmp/demo-repo")
	if code != 0 || calls != 1 || len(h.svc.runs) != 1 {
		t.Fatalf("code=%d git calls=%d stderr=%q", code, calls, h.notes.String())
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary archive was not removed: %v", err)
	}
}

func TestGitFailure(t *testing.T) {
	for _, transportError := range []bool{false, true} {
		h := newFixture(t)
		var name string
		h.env.archiveRun = runnerFunc(func(ctx context.Context, cmd boxexec.Cmd) (boxexec.Result, error) {
			f, ok := cmd.Stdout.(*os.File)
			if !ok {
				t.Fatal("git stdout must be a temporary file")
			}
			name = f.Name()
			if transportError {
				return boxexec.Result{Code: -1}, errors.New("SECRET-NEEDLE")
			}
			return boxexec.Result{Code: 1, Stderr: []byte("SECRET-NEEDLE")}, nil
		})
		code := h.call("run", "--purpose", "demo", "--suite", "exit 0", "--git-sha", "abcdef1", "--repo", "/tmp/demo-repo")
		if code != 2 || h.built != 0 || strings.Contains(h.notes.String(), "SECRET-NEEDLE") ||
			!strings.HasPrefix(h.notes.String(), usage) || name == "" {
			t.Fatalf("git failure: code=%d stderr=%q", code, h.notes.String())
		}
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed archive was not removed: %v", err)
		}
	}
}
