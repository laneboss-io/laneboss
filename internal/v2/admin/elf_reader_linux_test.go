//go:build linux

package admin

import (
	"debug/elf"
	"encoding/json"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestRuntimeELF(t *testing.T) {
	run := func(args ...string) {
		t.Helper()
		command := exec.Command("/usr/bin/python3", append([]string{"-I", "-B", "runtime_elf_test.py"}, args...)...)
		command.Dir = "../../../scripts/v2-admin"
		output, err := command.CombinedOutput()
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			t.Log(line)
		}
		if err != nil {
			t.Fatal("stdlib ELF reader", err)
		}
	}
	run()
	triplet := map[string]string{"arm64": "aarch64-linux-gnu", "amd64": "x86_64-linux-gnu"}[runtime.GOARCH]
	if triplet == "" {
		t.Fatal("ELF regression requires a supported Linux architecture")
	}
	paths := []string{"/usr/bin/dash"}
	// The seven measured library names come from rtmeasure1-opens.txt.
	for _, name := range []string{"libc.so.6", "libdl.so.2", "libm.so.6", "libpcre2-8.so.0", "libpthread.so.0", "librt.so.1", "libz.so.1"} {
		paths = append(paths, "/lib/"+triplet+"/"+name)
	}
	for _, path := range paths {
		file, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var interpreter any
		for _, program := range file.Progs {
			if program.Type == elf.PT_INTERP {
				raw, err := io.ReadAll(program.Open())
				if err != nil {
					t.Fatal(err)
				}
				interpreter = strings.TrimSuffix(string(raw), "\x00")
			}
		}
		needed, err := file.DynString(elf.DT_NEEDED)
		if err != nil {
			t.Fatal(err)
		}
		if needed == nil {
			needed = []string{}
		}
		sonames, err := file.DynString(elf.DT_SONAME)
		if err != nil {
			t.Fatal(err)
		}
		file.Close()
		var soname any
		if len(sonames) == 1 {
			soname = sonames[0]
		}
		expected, err := json.Marshal(map[string]any{"format": "ELF", "interpreter": interpreter, "soname": soname, "needed": needed})
		if err != nil {
			t.Fatal(err)
		}
		run("real", path, string(expected))
		t.Logf("independent ELF match: %s", path)
	}
}
