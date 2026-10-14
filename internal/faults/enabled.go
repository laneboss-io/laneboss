//go:build laneboss_faults

package faults

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

type storageFault struct{}

func (storageFault) Error() string { return "disk I/O error" }
func (storageFault) Code() int     { return 10 }

// LANEBOSS_FAULTS is the only variable interpreted by the test instrumentation.
// Its JSON names a point and evidence paths; no hook manufactures product output.
func Get(point string) Options {
	var option Options
	if json.Unmarshal([]byte(os.Getenv("LANEBOSS_FAULTS")), &option) != nil {
		return Options{}
	}
	if point != "" && point != option.Point {
		return Options{}
	}
	return option
}
func Reach(point string) error {
	o := Get(point)
	if o.Point == "" {
		return nil
	}
	if !filepath.IsAbs(o.Marker) {
		return fmt.Errorf("fault marker must be an absolute path")
	}
	f, err := os.OpenFile(o.Marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}
func SQL(statement string) error {
	statement = strings.ToUpper(strings.TrimSpace(statement))
	if strings.HasPrefix(statement, "BEGIN IMMEDIATE") {
		if err := Reach("lock-wanted"); err != nil {
			return err
		}
	}
	if Get("io-error").Point != "" && !strings.HasPrefix(statement, "PRAGMA") {
		if err := Reach("io-error"); err != nil {
			return err
		}
		return storageFault{}
	}
	return nil
}
func DirectoryFlock(f *os.File, operation int) error {
	if Get("directory-lock").Point != "" {
		return syscall.EOPNOTSUPP
	}
	return syscall.Flock(int(f.Fd()), operation)
}

var eventMutex sync.Mutex
var events []map[string]any

func record(kind, target string) {
	o := Get("")
	if o.Point != "judge-sync" && o.Point != "judge-kill" {
		return
	}
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(o.State, name)); return err == nil }
	data, _ := os.ReadFile(filepath.Join(o.State, "judges", "egress.jsonl"))
	event := map[string]any{"event": kind, "marker": exists(".laneboss-state"), "judges": exists("judges"), "log": exists("judges/egress.jsonl"), "log_lines": len(strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' }))}
	if target != "" {
		event["target"] = target
	}
	eventMutex.Lock()
	defer eventMutex.Unlock()
	events = append(events, event)
	bytes, err := json.Marshal(events)
	if err != nil {
		panic(err)
	}
	if !filepath.IsAbs(o.Record) {
		panic("fault record must be an absolute path")
	}
	if err := os.WriteFile(o.Record, bytes, 0600); err != nil {
		panic(err)
	}
}
func Sync(f *os.File) error {
	o := Get("")
	target := "file"
	if info, err := f.Stat(); err == nil {
		for label, path := range map[string]string{"state": o.State, "judges": filepath.Join(o.State, "judges")} {
			if other, err := os.Stat(path); err == nil && os.SameFile(info, other) {
				target = label
				break
			}
		}
	}
	record("fsync", target)
	return f.Sync()
}
func BeforeJudgeStart() {
	record("start", "")
	if Get("judge-kill").Point != "" {
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			panic(err)
		}
	}
}

// Inject one wrapped kernel error at the actual read boundary, never a product
// result. The marker proves the read was reached; subsequent reads are real.
func ProcStat(path string) ([]byte, error) {
	o := Get("")
	if (o.Point == "proc-esrch" || o.Point == "proc-denied") && o.PID > 0 && path == fmt.Sprintf("/proc/%d/stat", o.PID) {
		if _, err := os.Stat(o.Marker); os.IsNotExist(err) {
			if err := Reach(o.Point); err != nil {
				return nil, err
			}
			failure := syscall.ESRCH
			if o.Point == "proc-denied" {
				failure = syscall.EACCES
			}
			return nil, &os.PathError{Op: "read", Path: path, Err: failure}
		} else if err != nil {
			return nil, err
		}
	}
	return os.ReadFile(path)
}
