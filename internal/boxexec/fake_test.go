package boxexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestFakeMatch(t *testing.T) {
	f := &Fake{}
	f.Handlers = []Handler{
		{Name: "cloud", ArgsContain: []string{"create", "--zone a"},
			Respond: func(c Cmd, n int) (Result, error) {
				if len(f.CallsMatching(c.Name)) == 0 {
					return Result{Code: -1}, errors.New("call was not recorded before the handler")
				}
				return Result{Code: 3}, nil
			}},
		{Name: "cloud", ArgsContain: []string{"create"},
			Respond: func(Cmd, int) (Result, error) { return Result{Code: 4}, nil }},
		{Respond: func(Cmd, int) (Result, error) { return Result{Code: 5}, nil }},
	}
	cases := []struct {
		name string
		cmd  Cmd
		want int
	}{
		{"first", Cmd{Name: "cloud", Args: []string{"create", "--zone", "a"}}, 3},
		{"second", Cmd{Name: "cloud", Args: []string{"create", "--zone", "b"}}, 4},
		{"all-substrings", Cmd{Name: "cloud", Args: []string{"list", "--zone", "a"}}, 5},
		{"wildcard", Cmd{Name: "other", Args: []string{"create", "--zone", "a"}}, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.Run(context.Background(), tc.cmd)
			if err != nil || got.Code != tc.want {
				t.Fatalf("fake result: code = %d, error = %v; want %d", got.Code, err, tc.want)
			}
		})
	}
}

func TestFakeUnmatched(t *testing.T) {
	var f Fake
	c := Cmd{Name: "cloud", Args: []string{"one", "two", "third-hidden"}}
	got, err := f.Run(context.Background(), c)
	if err == nil || got.Code != -1 {
		t.Fatal("unmatched call did not fail")
	}
	text := err.Error()
	if !strings.HasPrefix(text, "boxexec fake: no handler for") ||
		!strings.Contains(text, "cloud") || !strings.Contains(text, "one") || !strings.Contains(text, "two") ||
		strings.Contains(text, "third-hidden") {
		t.Fatal("unmatched error does not describe only the program and first two arguments")
	}
	if len(f.Calls) != 1 || f.Calls[0].Name != c.Name || len(f.Calls[0].Args) != 3 {
		t.Fatal("unmatched call was not recorded")
	}
}

func TestFakeStreams(t *testing.T) {
	for _, name := range []string{"capture", "stdout-writer", "stderr-writer", "both-writers"} {
		t.Run(name, func(t *testing.T) {
			f := &Fake{Handlers: []Handler{{Respond: func(Cmd, int) (Result, error) {
				return Result{Code: 3, Stdout: []byte("out"), Stderr: []byte("err")}, nil
			}}}}
			var out, errOut bytes.Buffer
			c := Cmd{Name: "cloud"}
			if name == "stdout-writer" || name == "both-writers" {
				c.Stdout = &out
			}
			if name == "stderr-writer" || name == "both-writers" {
				c.Stderr = &errOut
			}
			got, err := f.Run(context.Background(), c)
			if err != nil || got.Code != 3 {
				t.Fatal("fake lost the exit status")
			}
			if c.Stdout != nil {
				if out.String() != "out" || got.Stdout != nil {
					t.Fatal("fake stdout writer or result is wrong")
				}
			} else if string(got.Stdout) != "out" {
				t.Fatal("fake stdout capture is wrong")
			}
			if c.Stderr != nil {
				if errOut.String() != "err" || got.Stderr != nil {
					t.Fatal("fake stderr writer or result is wrong")
				}
			} else if string(got.Stderr) != "err" {
				t.Fatal("fake stderr capture is wrong")
			}
		})
	}
}

func TestFakeCopies(t *testing.T) {
	f := &Fake{Handlers: []Handler{{}}}
	c := Cmd{Name: "a", Args: []string{"create"}, Env: []string{"BOX_TEST=demo"}, Dir: "work"}
	if got, err := f.Run(context.Background(), c); err != nil || got.Code != 0 {
		t.Fatal("fake call failed")
	}
	c.Args[0] = "changed"
	c.Env[0] = "BOX_TEST=changed"
	got := f.CallsMatching("a")
	if len(got) != 1 || got[0].Args[0] != "create" || got[0].Env[0] != "BOX_TEST=demo" || got[0].Dir != "work" {
		t.Fatal("recorded call aliases the caller's slices or lost the directory")
	}
	got[0].Args[0] = "changed"
	got[0].Env[0] = "BOX_TEST=changed"
	again := f.CallsMatching("a")
	if len(again) != 1 || again[0].Args[0] != "create" || again[0].Env[0] != "BOX_TEST=demo" {
		t.Fatal("query results alias recorded slices")
	}
}

func TestFakeConcurrent(t *testing.T) {
	f := &Fake{Handlers: []Handler{{Respond: func(c Cmd, n int) (Result, error) {
		return Result{Stdout: []byte(strconv.Itoa(n))}, nil
	}}}}
	const total = 32
	answers := make(chan Result, total)
	failures := make(chan error, total)
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := f.Run(context.Background(), Cmd{Name: "cloud"})
			if err != nil {
				failures <- err
				return
			}
			if got.Code != 0 {
				failures <- fmt.Errorf("unexpected fake exit %d", got.Code)
				return
			}
			answers <- got
			if len(f.CallsMatching("cloud")) == 0 {
				failures <- errors.New("concurrent query lost the calls")
			}
		}()
	}
	wg.Wait()
	close(answers)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	seen := make(map[int]bool)
	for got := range answers {
		n, err := strconv.Atoi(string(got.Stdout))
		if err != nil || n < 0 || n >= total || seen[n] {
			t.Fatal("concurrent handler counts are invalid or duplicated")
		}
		seen[n] = true
	}
	if len(seen) != total || len(f.Calls) != total || len(f.CallsMatching("cloud")) != total {
		t.Fatal("concurrent calls or handler counts were lost")
	}
}

func TestFakeErrors(t *testing.T) {
	cause := errors.New("demo failure")
	t.Run("handler", func(t *testing.T) {
		f := &Fake{Handlers: []Handler{{Respond: func(Cmd, int) (Result, error) {
			return Result{Code: -1}, cause
		}}}}
		got, err := f.Run(context.Background(), Cmd{Name: "cloud"})
		if !errors.Is(err, cause) || got.Code != -1 || len(f.Calls) != 1 {
			t.Fatal("handler error was lost")
		}
	})
	t.Run("stdin", func(t *testing.T) {
		f := &Fake{Handlers: []Handler{{}}}
		got, err := f.Run(context.Background(), Cmd{Name: "cloud", Stdin: failingReader{cause}})
		if !errors.Is(err, cause) || got.Code != -1 || len(f.Calls) != 1 {
			t.Fatal("stdin error was lost or its call was not recorded")
		}
	})
	for _, name := range []string{"stdout", "stderr"} {
		t.Run(name, func(t *testing.T) {
			f := &Fake{Handlers: []Handler{{Respond: func(Cmd, int) (Result, error) {
				return Result{Stdout: []byte("out"), Stderr: []byte("err")}, nil
			}}}}
			c := Cmd{Name: "cloud"}
			if name == "stdout" {
				c.Stdout = failingWriter{cause}
			} else {
				c.Stderr = failingWriter{cause}
			}
			got, err := f.Run(context.Background(), c)
			if !errors.Is(err, cause) {
				t.Fatal("stream writer error was lost")
			}
			if name == "stdout" && got.Stdout != nil || name == "stderr" && got.Stderr != nil {
				t.Fatal("a forwarded stream remained in the result")
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		f := &Fake{Handlers: []Handler{{}}}
		got, err := f.Run(ctx, Cmd{Name: "cloud"})
		if !errors.Is(err, context.Canceled) || got.Code != -1 || len(f.Calls) != 1 {
			t.Fatal("cancelled fake call was not recorded and rejected")
		}
	})
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}
