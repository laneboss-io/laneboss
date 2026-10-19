//go:build linux

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/fdpath"
)

type objectIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mount  uint64 `json:"mount"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Links  uint64 `json:"links"`
}

type pinnedMount struct {
	file      *os.File
	source    string // for overlap checks/diagnosis only; never a bind operand
	target    string
	identity  objectIdentity
	readOnly  bool
	directory bool
}

func identify(fd int) (objectIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return objectIdentity{}, err
	}
	var extended unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW,
		unix.STATX_MNT_ID, &extended); err != nil {
		return objectIdentity{}, err
	}
	if extended.Mask&unix.STATX_MNT_ID == 0 {
		return objectIdentity{}, errors.New("kernel did not report mount identity")
	}
	return objectIdentity{Device: uint64(stat.Dev), Inode: stat.Ino, Mount: extended.Mnt_id,
		Mode: stat.Mode, UID: stat.Uid, GID: stat.Gid, Links: uint64(stat.Nlink)}, nil
}

func pinPath(source, target string, ro bool) (*pinnedMount, error) {
	if !canonical(source) {
		return nil, fmt.Errorf("export %s source must be a canonical absolute path", target)
	}
	fd, err := fdpath.Open(unix.AT_FDCWD, source, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, fmt.Errorf("pin export for %s: %w", target, err)
	}
	file := os.NewFile(uintptr(fd), "pinned-export")
	identity, err := identify(fd)
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if identity.Mode&unix.S_IFMT == unix.S_IFLNK {
		return nil, errors.Join(errors.New("export source must not be a symlink"), file.Close())
	}
	return &pinnedMount{file: file, source: source, target: target, identity: identity,
		readOnly: ro, directory: identity.Mode&unix.S_IFMT == unix.S_IFDIR}, nil
}

type mountInfo struct {
	id, parent   uint64
	target, root string
}

func readMountInfo(reader io.Reader) ([]mountInfo, error) {
	var points []mountInfo
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, errors.New("malformed mountinfo")
		}
		id, idErr := strconv.ParseUint(fields[0], 10, 64)
		parent, parentErr := strconv.ParseUint(fields[1], 10, 64)
		if idErr != nil || parentErr != nil || id == 0 {
			return nil, errors.New("invalid mountinfo identity")
		}
		point := mountInfo{id: id, parent: parent, target: decode.Replace(fields[4]), root: decode.Replace(fields[3])}
		if !canonical(point.target) || !canonical(point.root) {
			return nil, errors.New("invalid mountinfo path")
		}
		points = append(points, point)
	}
	return points, scanner.Err()
}

func mountPoints() ([]mountInfo, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readMountInfo(file)
}

func checkMounts(source string, points []mountInfo, mountID uint64) error {
	var containing mountInfo
	for _, point := range points {
		if point.target != source && within(point.target, source) {
			return errors.New("nested mounts require a sealed independent projection")
		}
		if within(source, point.target) && len(point.target) >= len(containing.target) {
			containing = point
		}
	}
	if containing.target == "" || containing.root != "/" {
		// A pathname alias of a bind-mounted subtree cannot establish the
		// original object's authority. Live/idmapped exports require the
		// missing broker lease/receipt, rather than a permissive path fallback.
		return errors.New("mount alias requires a registered export lease")
	}
	if mountID == 0 || containing.id != mountID {
		return errors.New("active mount differs from the pinned descriptor mount")
	}
	for _, point := range points {
		if point.parent == mountID && within(point.target, source) {
			return errors.New("descendant mount requires an independent projection")
		}
	}
	return nil
}

func checkPinnedMounts(item *pinnedMount) error {
	// The snapshot follows the open. The active pathname view must still
	// correspond to STATX_MNT_ID on the descriptor that will be mounted.
	points, err := mountPoints()
	if err != nil {
		return err
	}
	return checkMounts(item.source, points, item.identity.Mount)
}

func walkPinned(root *pinnedMount, check func(string, objectIdentity) error) error {
	visited := 0
	var visit func(int, string) error
	visit = func(fd int, relative string) error {
		visited++
		if visited > 250000 {
			return errors.New("export exceeds bounded validation size")
		}
		identity, err := identify(fd)
		if err != nil {
			return err
		}
		if identity.Mount != root.identity.Mount {
			return errors.New("nested mount identity in pinned export")
		}
		if err := check(relative, identity); err != nil {
			return err
		}
		if identity.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil
		}
		// Reopening this process's pinned descriptor does not resolve any
		// caller-controlled source name. Children are opened relative to fd.
		readFD, err := unix.Open("/proc/self/fd/"+strconv.Itoa(fd),
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		directory := os.NewFile(uintptr(readFD), "pinned-directory")
		names, readErr := directory.Readdirnames(-1)
		closeErr := directory.Close()
		if readErr != nil || closeErr != nil {
			return errors.Join(readErr, closeErr)
		}
		for _, name := range names {
			if name == "." || name == ".." || strings.ContainsRune(name, '/') {
				return errors.New("invalid directory entry")
			}
			child, err := fdpath.Inspect(fd, name)
			if err != nil {
				return err
			}
			visitErr := visit(child, filepath.Join(relative, name))
			closeErr := unix.Close(child)
			if visitErr != nil || closeErr != nil {
				return errors.Join(visitErr, closeErr)
			}
		}
		return nil
	}
	return visit(int(root.file.Fd()), ".")
}

func validatePinnedExport(item *pinnedMount, private bool, uid uint32, protected []string) error {
	for _, root := range append(append([]string{}, protected...), "/proc", "/sys", "/dev", "/run", "/etc") {
		if overlaps(item.source, root) {
			return fmt.Errorf("export %s overlaps a protected source", item.target)
		}
	}
	if private && !item.directory {
		return fmt.Errorf("export %s requires a private mode-0700 directory", item.target)
	}
	if private && item.identity.Mode&0777 != 0700 {
		allowAndLog("export_private_mode")
	}
	if item.target == "/work/main" && !item.directory {
		return errors.New("main worktree must be a directory")
	}
	type linkKey struct{ device, inode uint64 }
	type linkCount struct{ inside, total uint64 }
	links := map[linkKey]linkCount{}
	err := walkPinned(item, func(relative string, identity objectIdentity) error {
		if !item.readOnly && identity.UID != uid {
			allowAndLog("export_lane_uid")
		}
		kind := identity.Mode & unix.S_IFMT
		// Administrative indirections must be rejected before the type switch:
		// an internal symlink is still external Git authority, not ordinary data.
		gitPath := "/" + filepath.ToSlash(relative)
		inGit := strings.Contains(gitPath+"/", "/.git/") || filepath.Base(item.source) == ".git"
		if filepath.Base(relative) == ".git" && kind != unix.S_IFDIR ||
			inGit && kind == unix.S_IFLNK ||
			strings.HasSuffix(gitPath, "/commondir") || strings.HasSuffix(gitPath, "/worktrees") ||
			strings.HasSuffix(gitPath, "/objects/info/alternates") ||
			strings.HasSuffix(gitPath, "/objects/info/http-alternates") {
			return fmt.Errorf("export %s has external Git administration", item.target)
		}
		switch kind {
		case unix.S_IFREG:
			key := linkKey{device: identity.Device, inode: identity.Inode}
			count := links[key]
			if count.total != 0 && count.total != identity.Links {
				return fmt.Errorf("export %s changed its link topology", item.target)
			}
			count.inside++
			count.total = identity.Links
			links[key] = count
		case unix.S_IFDIR:
		case unix.S_IFLNK:
			// Symlink resolution must stay beneath the pinned root, including
			// chained links. Dangling/escaping/magic links fail closed.
			fd, err := fdpath.ResolveBeneath(int(item.file.Fd()), relative)
			if err != nil {
				return fmt.Errorf("export %s has an unresolved or escaping link: %w", item.target, err)
			}
			return unix.Close(fd)
		default:
			return fmt.Errorf("export %s contains a socket, FIFO or device", item.target)
		}
		if identity.Mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
			return fmt.Errorf("export %s has privilege bits", item.target)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("export %s validation: %w", item.target, err)
	}
	for _, count := range links {
		if count.inside != count.total {
			return fmt.Errorf("export %s has links outside its pinned tree", item.target)
		}
	}
	return nil
}
