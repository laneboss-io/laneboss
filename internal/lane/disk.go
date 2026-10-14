package lane

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"

	"laneboss.io/laneboss/internal/doctorbase"
)

func (s *session) diskGate(stderr io.Writer) error {
	settings := obj(s.c.data["disk"])
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := str(valueOr(settings, "path", home))
	warn, stop := number(valueOr(settings, "warn_percent", 85)), number(valueOr(settings, "stop_percent", 90))
	if warn < 1 || stop > 99 || warn >= stop {
		return invalid("configuration "+s.c.name+": config.toml", "disk", "warn_percent must be below stop_percent")
	}
	var stat syscall.Statfs_t
	if err = syscall.Statfs(path, &stat); err != nil {
		return refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	blocks, free, available := float64(stat.Blocks), float64(stat.Bfree), float64(stat.Bavail)
	if free > blocks || (blocks-free)+available <= 0 {
		return refuse("the disk reading failed: %s reports no usable blocks; no new lane or worktree starts", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return refuse("the disk reading failed: %s cannot be read (%s); no new lane or worktree starts", path, doctorbase.OSReason(err))
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return refuse("the disk device cannot be read")
	}
	percent := (blocks - free) * 100 / ((blocks - free) + available)
	directory := filepath.Join(s.c.states, "disk-latches")
	latched := true
	if err = os.MkdirAll(directory, 0700); err == nil {
		r, e := rootDirectory(directory)
		if e == nil {
			f, e := r.Open(".")
			if e == nil {
				unlock, e := lockFile(f, 10, false)
				if e == nil {
					name := fmt.Sprintf("%d.latch", st.Dev)
					_, e = r.Lstat(name)
					latched = !os.IsNotExist(e)
					if percent >= stop {
						latched = true
						if e = rootWrite(r, name, append(canonical(object{"used_percent": math.Round(percent*10) / 10, "stop_percent": int(stop), "at": utcNow()}), '\n'), true, 0600); e != nil {
							fmt.Fprintln(stderr, "note: the disk latch could not be written; the reading stands")
						}
					} else if percent < warn {
						latched = false
						e = r.Remove(name)
						if e != nil && !os.IsNotExist(e) {
							fmt.Fprintln(stderr, "note: the disk latch could not be cleared; the reading stands")
						}
					}
					unlock()
				}
				f.Close()
			}
			r.Close()
		}
	}
	if percent < warn {
		latched = false
	}
	payload := object{"path": path, "used_percent": math.Round(percent*10) / 10, "free_bytes": int64(math.Max(0, available*float64(stat.Bsize))), "warn_percent": int(warn), "stop_percent": int(stop)}
	if latched || percent >= warn {
		kind := "disk.warn"
		if latched {
			kind = "disk.stop"
		}
		if _, e := s.append(envelope("", kind, payload, "laneboss"), 10); e != nil {
			fmt.Fprintln(stderr, "note: the disk reading could not be recorded; its outcome stands")
		}
		if latched {
			return refuse("disk %s is %.1f%% used (stop line %.0f%%); no new lane or worktree starts until it is under %.0f%%", path, percent, stop, warn)
		}
		fmt.Fprintf(stderr, "warning: disk %s is %.1f%% used (warn line %.0f%%)\n", path, percent, warn)
	}
	return nil
}
