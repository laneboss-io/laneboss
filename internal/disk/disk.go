// Package disk reads the kernel's filesystem statistics and maintains the
// user-wide, device-keyed disk stop latch shared with the Python launcher.
package disk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/doctorbase"
)

const OK = "ok"
const WARN = "warn"
const STOP = "stop"
const Latches = "disk-latches"

type Reading struct {
	UsedPercent float64
	FreeBytes   uint64
	Device      uint64
}
type Report struct {
	Path        string  `json:"path"`
	UsedPercent float64 `json:"used_percent"`
	FreeBytes   uint64  `json:"free_bytes"`
	WarnPercent int     `json:"warn_percent"`
	StopPercent int     `json:"stop_percent"`
	State       string  `json:"state"`
	Latched     bool    `json:"latched"`
}

// UsedPercent uses the same reserved-block convention as df and os.statvfs.
func UsedPercent(blocks, free, available uint64) float64 {
	used := blocks - free
	return float64(used) * 100 / (float64(used) + float64(available))
}
func readFile(path string, f *os.File) (Reading, error) {
	blocks, free, available, fragment, err := filesystemStats(f)
	if err != nil {
		return Reading{}, doctorbase.Refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	info, err := f.Stat()
	if err != nil {
		return Reading{}, doctorbase.Refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	if free > blocks || (blocks-free) == 0 && available == 0 || fragment == 0 || available > math.MaxUint64/fragment {
		return Reading{}, doctorbase.Refuse("the disk reading failed: %s reports no usable blocks (blocks %d, free %d, available %d); a file system that cannot be read is never taken for an empty one, and no new lane or worktree starts", path, blocks, free, available)
	}
	return Reading{UsedPercent(blocks, free, available), available * fragment, doctorbase.Device(info)}, nil
}
func openPath(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, doctorbase.Refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	return f, nil
}
func Read(path string) (Reading, error) {
	f, err := openPath(path)
	if err != nil {
		return Reading{}, err
	}
	defer f.Close()
	return readFile(path, f)
}

func note(stderr io.Writer, format string, args ...any) {
	fmt.Fprintf(stderr, "note: "+format+"\n", args...)
}
func Check(c *doctorbase.Configuration, path string, warn, stop int, stderr io.Writer) (Report, error) {
	f, err := openPath(path)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Report{}, doctorbase.Refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	directory := filepath.Join(c.StateHome, Latches)
	name := fmt.Sprintf("%d.latch", doctorbase.Device(info))
	latchPath := filepath.Join(directory, name)
	var dir *doctorbase.Directory
	var lock *doctorbase.Lock
	if err = os.MkdirAll(directory, 0700); err == nil {
		dir, err = doctorbase.OpenDirectory(directory)
		if err == nil {
			lock, err = dir.Lock(false)
		}
	}
	if dir != nil {
		defer dir.Close()
	}
	if lock != nil {
		defer lock.Close()
	}
	was := true
	if err != nil {
		note(stderr, "the disk latch %s cannot be held (%s); a latch that cannot be read never opens the gate", latchPath, doctorbase.OSReason(err))
	} else {
		_, lookupErr := dir.Root.Lstat(name)
		was = !os.IsNotExist(lookupErr)
	}
	// Measure while holding the directory lock. The opened path also pins the
	// filesystem identity used for its latch, so a renamed path cannot mix devices.
	reading, err := readFile(path, f)
	if err != nil {
		return Report{}, err
	}
	now := was
	if reading.UsedPercent >= float64(stop) {
		now = true
	} else if reading.UsedPercent < float64(warn) {
		now = false
	}
	if lock != nil {
		var writeErr error
		if now && !was {
			b, marshalErr := json.Marshal(map[string]any{"used_percent": math.RoundToEven(reading.UsedPercent*10) / 10, "stop_percent": stop, "at": doctorbase.UTCNow()})
			if marshalErr != nil {
				return Report{}, marshalErr
			}
			writeErr = doctorbase.WriteAtomic(dir.Root, name, append(b, '\n'), true)
		} else if was && !now {
			info, statErr := dir.Root.Lstat(name)
			if statErr == nil && info.IsDir() {
				writeErr = syscall.EISDIR
			} else {
				writeErr = dir.Root.Remove(name)
			}
			if os.IsNotExist(writeErr) {
				writeErr = nil
			}
		}
		if writeErr != nil {
			note(stderr, "the disk latch %s could not be written (%s); the reading stands", latchPath, doctorbase.OSReason(writeErr))
		}
	}
	state := OK
	if now {
		state = STOP
	} else if reading.UsedPercent >= float64(warn) {
		state = WARN
	}
	return Report{path, math.RoundToEven(reading.UsedPercent*10) / 10, reading.FreeBytes, warn, stop, state, now}, nil
}
func Examine(c *doctorbase.Configuration, stderr io.Writer) (Report, error) {
	settings := doctorbase.Object(c.Data["disk"])
	path := doctorbase.String(settings["path"])
	if path == "" {
		var err error
		path, err = os.UserHomeDir()
		if err != nil {
			return Report{}, err
		}
	}
	warn, stop := 85, 90
	if n, ok := settings["warn_percent"].(int64); ok {
		warn = int(n)
	}
	if n, ok := settings["stop_percent"].(int64); ok {
		stop = int(n)
	}
	return Check(c, path, warn, stop, stderr)
}
func Warning(report Report) string {
	return fmt.Sprintf("warning: disk %s is %.1f%% used (warn line %d%%)", report.Path, report.UsedPercent, report.WarnPercent)
}
func Refusal(report Report) string {
	return fmt.Sprintf("disk %s is %.1f%% used (stop line %d%%); no new lane or worktree starts until it is under %d%%", report.Path, report.UsedPercent, report.StopPercent, report.WarnPercent)
}
func EventPayload(report Report) map[string]any {
	return map[string]any{"path": report.Path, "used_percent": report.UsedPercent, "free_bytes": report.FreeBytes, "warn_percent": report.WarnPercent, "stop_percent": report.StopPercent}
}

// Gate is available to the start port. A failed event write never opens a stopped
// disk's gate; the reading's warning or refusal remains the outcome.
func Gate(c *doctorbase.Configuration, state *doctorbase.State, stderr io.Writer) (Report, error) {
	report, err := Examine(c, stderr)
	if err != nil {
		return Report{}, err
	}
	if report.State == OK {
		return report, nil
	}
	kind := "disk.warn"
	if report.State == STOP {
		kind = "disk.stop"
	}
	if err := doctorbase.Record(state, kind, EventPayload(report)); err != nil {
		var problem *doctorbase.Error
		if errors.As(err, &problem) {
			return report, err
		}
		note(stderr, "the disk reading could not be recorded: %s; the reading and its outcome stand", doctorbase.OSReason(err))
	}
	if report.State == STOP {
		return report, doctorbase.Refuse("%s", Refusal(report))
	}
	fmt.Fprintln(stderr, Warning(report))
	return report, nil
}
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			fmt.Fprintln(stdout, "usage: laneboss disk [-h] [--config NAME]\nRead the watched filesystem and its shared stop latch.")
			return 0
		}
	}
	name, err := doctorbase.Bind(args)
	if err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	c, err := doctorbase.Load(name)
	if err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	zones := doctorbase.NewZones(c)
	s, err := doctorbase.OpenState(c, zones, true)
	if err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	defer s.Close()
	report, err := Examine(c, stderr)
	if err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		return doctorbase.ExitError(stderr, err)
	}
	if report.State == STOP {
		return 3
	}
	return 0
}
