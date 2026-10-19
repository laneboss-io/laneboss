//go:build unix

package boxexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecStreams(t *testing.T) {
	for _, name := range []string{"capture", "stdout-writer", "stderr-writer", "both-writers"} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			c := Cmd{
				Name: "sh", Env: []string{"PATH=/bin:/usr/bin"},
				Args: []string{"-c", "printf out; printf err >&2; exit 3"},
			}
			if name == "stdout-writer" || name == "both-writers" {
				c.Stdout = &out
			}
			if name == "stderr-writer" || name == "both-writers" {
				c.Stderr = &errOut
			}
			got, err := (ExecRunner{}).Run(context.Background(), c)
			if err != nil || got.Code != 3 {
				t.Fatalf("run code = %d, error = %v", got.Code, err)
			}
			if c.Stdout != nil {
				if out.String() != "out" || got.Stdout != nil {
					t.Fatal("stdout writer or result is wrong")
				}
			} else if string(got.Stdout) != "out" {
				t.Fatal("stdout capture is wrong")
			}
			if c.Stderr != nil {
				if errOut.String() != "err" || got.Stderr != nil {
					t.Fatal("stderr writer or result is wrong")
				}
			} else if string(got.Stderr) != "err" {
				t.Fatal("stderr capture is wrong")
			}
		})
	}
}

func TestExecNotFound(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
	}{
		{"missing-name", "boxexec-missing-tool"},
		{"missing-path", filepath.Join(t.TempDir(), "missing")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (ExecRunner{}).Run(context.Background(), Cmd{
				Name: tc.cmd, Env: []string{"PATH=/bin:/usr/bin"},
			})
			if err == nil || got.Code != -1 {
				t.Fatalf("missing program: code = %d, error present = %t", got.Code, err != nil)
			}
		})
	}
}

func TestExecChildPath(t *testing.T) {
	cases := []struct {
		name   string
		parent string
		env    []string
		ok     bool
	}{
		{"child-only", "/demo/no-tools", []string{"PATH=/bin:/usr/bin"}, true},
		{"parent-only", "/bin:/usr/bin", []string{"PATH="}, false},
		{"no-path", "/bin:/usr/bin", []string{}, false},
		{"last-path", "/demo/no-tools",
			[]string{"PATH=/demo/no-tools", "PATH=/bin:/usr/bin"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.parent)
			got, err := (ExecRunner{}).Run(context.Background(), Cmd{
				Name: "sh", Args: []string{"-c", "printf done"}, Env: tc.env,
			})
			if tc.ok {
				if err != nil || got.Code != 0 || string(got.Stdout) != "done" {
					t.Fatal("child PATH did not find the program")
				}
			} else if err == nil || got.Code != -1 {
				t.Fatal("program was found outside the child PATH")
			}
		})
	}
}

func TestExecPathSearch(t *testing.T) {
	root := t.TempDir()
	for _, part := range []string{"bad", "folder", "first", "second", "work"} {
		if err := os.Mkdir(filepath.Join(root, part), 0700); err != nil {
			t.Fatal("could not create a fixture directory")
		}
	}
	if err := os.WriteFile(filepath.Join(root, "bad", "demo-tool"), []byte("unused"), 0600); err != nil {
		t.Fatal("could not create the non-executable fixture")
	}
	if err := os.Mkdir(filepath.Join(root, "folder", "demo-tool"), 0700); err != nil {
		t.Fatal("could not create the directory fixture")
	}
	for _, part := range []string{"first", "second", "work"} {
		body := "#!/bin/sh\nprintf " + part + "\n"
		if err := os.WriteFile(filepath.Join(root, part, "demo-tool"), []byte(body), 0700); err != nil {
			t.Fatal("could not create the executable fixture")
		}
	}
	cases := []struct {
		name string
		path string
		dir  string
		want string
		ok   bool
	}{
		{"first-wins", filepath.Join(root, "first") + ":" + filepath.Join(root, "second"), "", "first", true},
		{"skip-invalid", filepath.Join(root, "bad") + ":" + filepath.Join(root, "folder") +
			"::" + filepath.Join(root, "second"), "", "second", true},
		{"relative-path", "first", root, "first", true},
		{"dot-path", ".", filepath.Join(root, "work"), "work", true},
		{"skip-empty", ":", filepath.Join(root, "work"), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (ExecRunner{}).Run(context.Background(), Cmd{
				Name: "demo-tool", Env: []string{"PATH=" + tc.path}, Dir: tc.dir,
			})
			if tc.ok {
				if err != nil || got.Code != 0 || string(got.Stdout) != tc.want {
					t.Fatal("PATH search chose the wrong executable")
				}
			} else if err == nil || got.Code != -1 {
				t.Fatal("empty PATH entries must be skipped")
			}
		})
	}
}

func TestExecEnv(t *testing.T) {
	t.Setenv("BOX_HIDDEN", "demo")
	cases := []struct {
		name string
		env  []string
		line string
	}{
		{"explicit", []string{"BOX_TEST=demo"},
			"test \"$BOX_TEST\" = demo && test -z \"${BOX_HIDDEN+x}\""},
		{"default", nil, "test -z \"${BOX_HIDDEN+x}\""},
		{"empty", []string{}, "test -z \"${BOX_HIDDEN+x}\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := (ExecRunner{}).Run(context.Background(), Cmd{
				Name: "/bin/sh", Args: []string{"-c", tc.line}, Env: tc.env,
			})
			if err != nil || got.Code != 0 {
				t.Fatal("child environment differs from the requested environment")
			}
		})
	}
}

func TestExecDirStdin(t *testing.T) {
	dir := t.TempDir()
	got, err := (ExecRunner{}).Run(context.Background(), Cmd{
		Name: "/bin/sh", Env: []string{}, Dir: dir,
		Args:  []string{"-c", "test \"$PWD\" = \"$1\" || exit 9; IFS= read -r line; printf '%s' \"$line\"", "sh", dir},
		Stdin: strings.NewReader("payload\n"),
	})
	if err != nil || got.Code != 0 || string(got.Stdout) != "payload" {
		t.Fatal("working directory or stdin was not forwarded")
	}
}

func TestExecSignal(t *testing.T) {
	got, err := (ExecRunner{}).Run(context.Background(), Cmd{
		Name: "sh", Args: []string{"-c", "kill -TERM $$"}, Env: []string{"PATH=/bin:/usr/bin"},
	})
	if err != nil || got.Code != 143 {
		t.Fatalf("signal exit: code = %d, error = %v", got.Code, err)
	}
}

func TestExecCaptureLimit(t *testing.T) {
	got, err := (ExecRunner{}).Run(context.Background(), Cmd{
		Name: "sh", Env: []string{"PATH=/bin:/usr/bin"},
		Args: []string{"-c", "head -c 20000000 /dev/zero; head -c 20000000 /dev/zero >&2"},
	})
	if err != nil || got.Code != 0 {
		t.Fatalf("large output: code = %d, error = %v", got.Code, err)
	}
	for _, stream := range []struct {
		name string
		data []byte
	}{{"stdout", got.Stdout}, {"stderr", got.Stderr}} {
		if len(stream.data) != 16<<20 || bytes.Count(stream.data, []byte{0}) != len(stream.data) {
			t.Fatalf("%s capture has the wrong length or contents", stream.name)
		}
	}
}
