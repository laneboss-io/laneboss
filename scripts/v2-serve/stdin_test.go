//go:build linux

package fixtures

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Compile the actual constructors and command field assignments, rather than
// recreating their stdin setup in the test. Only the client and its argv are
// replaced with an EOF-checking child. Authentication and lifecycle are outside
// this narrowly scoped child-launch regression.
func TestFixtureStdin(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"scripts/v2-serve/grants_actor/main.go",
		"e2e/v2/cases/dashboard/actor/main.go",
		"e2e/v2/cases/watchdog/native/main.go",
		"e2e/v2/cases/watchdog/native/relay.go",
		"scripts/v2-serve/policy_agent/main.go",
		"cmd/laneboss/serve-fixture/main.go",
	}
	var cases strings.Builder
	var names []string
	for _, path := range paths {
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, filepath.Join(root, path), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			block, ok := node.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, statement := range block.List {
				assignment, ok := statement.(*ast.AssignStmt)
				if !ok || len(assignment.Rhs) == 0 {
					continue
				}
				var constructor *ast.CallExpr
				ast.Inspect(assignment.Rhs[0], func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					selector, ok := call.Fun.(*ast.SelectorExpr)
					if ok {
						pkg, ok := selector.X.(*ast.Ident)
						if ok && pkg.Name == "exec" &&
							(selector.Sel.Name == "CommandContext" || selector.Sel.Name == "Command") {
							constructor = call
						}
					}
					return true
				})
				if constructor == nil {
					continue
				}
				name := fmt.Sprintf("%s:%d", path, set.Position(constructor.Pos()).Line)
				names = append(names, name)
				fmt.Fprintf(&cases, "case %q: {\n", strconv.Itoa(len(names)-1))
				for _, argument := range constructor.Args {
					if index, ok := argument.(*ast.IndexExpr); ok {
						if id, ok := index.X.(*ast.Ident); ok && id.Name == "argv" {
							cases.WriteString("argv := append([]string{os.Args[0]}, argv...)\n")
						}
					}
				}
				command := "command"
				if assignment.Rhs[0] == constructor {
					command = assignment.Lhs[0].(*ast.Ident).Name
				}
				fmt.Fprintf(&cases, "%s := ", command)
				if err := format.Node(&cases, set, constructor); err != nil {
					t.Fatal(err)
				}
				cases.WriteByte('\n')
				// Retain the fixture's real command settings up to its launch.
				for _, next := range block.List[i+1:] {
					field, ok := next.(*ast.AssignStmt)
					if !ok {
						continue
					}
					for _, left := range field.Lhs {
						selector, ok := left.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						owner, ok := selector.X.(*ast.Ident)
						if ok && owner.Name == command {
							if err := format.Node(&cases, set, field); err != nil {
								t.Fatal(err)
							}
							cases.WriteByte('\n')
							break
						}
					}
				}
				fmt.Fprintf(&cases, "selected = %s\n}\n", command)
			}
			return true
		})
	}
	if len(names) != 7 {
		t.Fatalf("child launch inventory changed: got %d, want 7", len(names))
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "probe.go")
	if err := os.WriteFile(source, []byte(stdinProbe+cases.String()+stdinEnd), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "probe")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual fixture launches: %v\n%s", err, output)
	}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"nil", "fixture"} {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				cmd := exec.CommandContext(ctx, binary, strconv.Itoa(i), mode)
				cmd.Stdin = strings.NewReader("")
				output, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("%s launch failed: %v\n%s", mode, err, output)
				}
				want := "child EOF\n"
				if mode == "nil" {
					want = "open /dev/null: permission denied\n"
				}
				if !bytes.Equal(output, []byte(want)) {
					t.Fatalf("%s launch output: %q, want %q", mode, output, want)
				}
				t.Logf("%s: %s", mode, strings.TrimSpace(string(output)))
			}
		})
	}
}

const stdinProbe = `package main
import (
 "bytes"
 "context"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "runtime"
 "strings"
 "time"
 "unsafe"
 "golang.org/x/sys/unix"
)
func main() {
 if len(os.Args) == 2 {
  raw, err := io.ReadAll(os.Stdin)
  if err != nil || len(raw) != 0 { panic("child stdin did not reach empty EOF") }
  fmt.Println("child EOF")
  return
 }
 ctx := context.Background()
 bounded := ctx
 opt := struct{ Client string }{os.Args[0]}
 o, f := opt, opt
 argv := []string{"child"}
 args := argv
 var stdout, stderr bytes.Buffer
 var selected *exec.Cmd
 // Every prelude name is shared by the source-derived launch cases.
 _, _, _, _, _, _, _, _ = bounded, o, f, argv, args, stdout, stderr, time.Second
 _ = strings.NewReader
 switch os.Args[1] {
`

const stdinEnd = `default: panic("unknown launch")
 }
 cmd := selected
 if os.Args[2] == "nil" { cmd.Stdin = nil }
 cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
 // Confine all threads before Start: Go's nil-stdin openat must fail with
 // EACCES. Already-open streams and pipes remain usable. No root is needed.
 runtime.LockOSThread()
 if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil { panic(err) }
 filter := []unix.SockFilter{
  {Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
  {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_OPENAT, Jf: 1},
  {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)},
  {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
 }
 program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
 _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER,
  unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
 if errno != 0 { panic(errno) }
 // Independently prove that the sandbox refuses this real file open.
 file, err := os.Open("/dev/null")
 if file != nil { file.Close(); panic("sandbox allowed /dev/null") }
 if !errors.Is(err, unix.EACCES) { panic(fmt.Sprint("sandbox: ", err)) }
 err = cmd.Run()
 if os.Args[2] == "nil" {
  var path *os.PathError
  if !errors.As(err, &path) || path.Path != "/dev/null" || !errors.Is(err, unix.EACCES) {
   panic(fmt.Sprint("nil stdin did not reproduce /dev/null: ", err))
  }
  fmt.Println(err)
 } else if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
`
