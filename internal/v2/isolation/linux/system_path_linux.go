//go:build linux

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type systemIDLimits struct {
	uidMax, gidMax uint32
	uidMin, gidMin uint32
}

type runtimePathStat struct {
	uid, gid uint32
	mode     fs.FileMode
}

type runtimePathPolicy struct {
	limits  systemIDLimits
	laneUID uint32
	laneGID uint32
	uidPool []IDRange
	gidPool []IDRange
}

// IDRange is installed administrator inventory, not a range supplied by a
// lane. An absent pool inventory permits root ownership only.
type IDRange struct{ First, Last uint32 }

func outsidePool(id uint32, pool []IDRange) bool {
	if len(pool) == 0 {
		return false
	}
	for _, block := range pool {
		if block.First > block.Last || block.First == 0 || id >= block.First && id <= block.Last {
			return false
		}
	}
	return true
}

func parseSystemIDLimits(reader io.Reader) (systemIDLimits, error) {
	limits := systemIDLimits{uidMax: 999, gidMax: 999, uidMin: 1000, gidMin: 1000}
	values := map[string]*uint32{"SYS_UID_MAX": &limits.uidMax, "SYS_GID_MAX": &limits.gidMax,
		"UID_MIN": &limits.uidMin, "GID_MIN": &limits.gidMin}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		target, relevant := values[fields[0]]
		if !relevant {
			continue
		}
		if len(fields) != 2 || seen[fields[0]] {
			return limits, fmt.Errorf("invalid or repeated %s in login.defs", fields[0])
		}
		number, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil || number == 0 {
			return limits, fmt.Errorf("invalid %s in login.defs", fields[0])
		}
		*target = uint32(number)
		seen[fields[0]] = true
	}
	return limits, scanner.Err()
}

// The supervisor's policy requires IDs below SYS_*_MAX, and never IDs in the
// login range. Checking *_MIN too prevents overlapping host ranges from turning
// a login account into a trusted runtime owner. Root is always administrator.
func (p runtimePathPolicy) systemUID(uid uint32) bool {
	return uid == 0 || uid != p.laneUID && outsidePool(uid, p.uidPool) &&
		uid < p.limits.uidMax && uid < p.limits.uidMin
}

func (p runtimePathPolicy) systemGID(gid uint32) bool {
	return gid == 0 || gid != p.laneGID && outsidePool(gid, p.gidPool) &&
		gid < p.limits.gidMax && gid < p.limits.gidMin
}

func (p runtimePathPolicy) check(stat runtimePathStat) error {
	if stat.mode&os.ModeSymlink != 0 || !p.systemUID(stat.uid) ||
		(stat.gid != 0 && !p.systemGID(stat.gid)) {
		return errors.New("owner is not an administrator or permitted system account")
	}
	if stat.mode.Perm()&0022 != 0 &&
		!(stat.uid == 0 && stat.mode.IsDir() && stat.mode&os.ModeSticky != 0 && p.systemGID(stat.gid)) {
		return errors.New("group/other writes require a root-owned sticky directory and system group")
	}
	return nil
}

func runtimeLstat(path string) (runtimePathStat, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return runtimePathStat{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return runtimePathStat{}, errors.New("missing runtime ownership facts")
	}
	return runtimePathStat{uid: stat.Uid, gid: stat.Gid, mode: info.Mode()}, nil
}

// Check the resolved file AND each ancestor. Resolving first and returning only
// that resolved path ensures a symlink cannot smuggle a user-owned target into
// the runtime mounts. The caller still requires quiescent administrator data.
func checkSystemPath(path string, policy runtimePathPolicy,
	resolve func(string) (string, error), lstat func(string) (runtimePathStat, error)) (string, error) {
	resolved, err := resolve(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("runtime path must resolve to a canonical absolute path")
	}
	for current := resolved; ; current = filepath.Dir(current) {
		stat, err := lstat(current)
		if err != nil {
			return "", err
		}
		if err := policy.check(stat); err != nil {
			return "", fmt.Errorf("runtime path component %q is not controlled by the administrator: %w", current, err)
		}
		if current == "/" {
			break
		}
	}
	return resolved, nil
}

func hostSystemIDLimits() (systemIDLimits, error) {
	defaults, err := parseSystemIDLimits(strings.NewReader(""))
	if err != nil {
		return defaults, err
	}
	// The file defining trusted account ranges must itself remain root-only
	// controlled. Otherwise a user could enlarge the range to admit themselves.
	rootOnly := runtimePathPolicy{limits: systemIDLimits{uidMax: 1, gidMax: 1, uidMin: 1, gidMin: 1}}
	path, err := checkSystemPath("/etc/login.defs", rootOnly, filepath.EvalSymlinks, runtimeLstat)
	if errors.Is(err, fs.ErrNotExist) {
		return defaults, nil
	}
	if err != nil {
		return defaults, err
	}
	f, err := os.Open(path)
	if err != nil {
		return defaults, err
	}
	defer f.Close()
	return parseSystemIDLimits(f)
}

func safeSystemPath(path string) (string, error) {
	limits, err := hostSystemIDLimits()
	if err != nil {
		return "", err
	}
	policy := runtimePathPolicy{limits: limits, laneUID: uint32(os.Geteuid()), laneGID: uint32(os.Getegid())}
	return checkSystemPath(path, policy, filepath.EvalSymlinks, runtimeLstat)
}
