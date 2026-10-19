package linux

import (
	"fmt"
	"sort"
)

const (
	MinLaunchABI = 3
	MaxKnownABI  = 8
	execute      = uint64(1 << 0)
	writeFile    = uint64(1 << 1)
	readFile     = uint64(1 << 2)
	readDir      = uint64(1 << 3)
	removeDir    = uint64(1 << 4)
	removeFile   = uint64(1 << 5)
	makeChar     = uint64(1 << 6)
	makeDir      = uint64(1 << 7)
	makeReg      = uint64(1 << 8)
	makeSock     = uint64(1 << 9)
	makeFIFO     = uint64(1 << 10)
	makeBlock    = uint64(1 << 11)
	makeSym      = uint64(1 << 12)
	refer        = uint64(1 << 13)
	truncate     = uint64(1 << 14)
	ioctlDev     = uint64(1 << 15)
)

type Access uint8

const (
	ReadOnly Access = iota
	ReadWrite
)

// PathAccess describes filesystem resources, never a command/tool allowlist.
// Paths refer to the final mount view. New files in a writable directory can
// execute without program registration. Device creation remains denied.
type PathAccess struct {
	Path       string `json:"path"`
	Directory  bool   `json:"directory"`
	Access     Access `json:"access"`
	Executable bool   `json:"executable"`
}

type PathRule struct {
	Path          string `json:"path"`
	Directory     bool   `json:"directory"`
	AllowedAccess uint64 `json:"allowed_access"`
}

type Ruleset struct {
	ABI             int        `json:"abi"`
	RuleABI         int        `json:"rule_abi"`
	HandledAccessFS uint64     `json:"handled_access_fs"`
	Rules           []PathRule `json:"rules"`
}

// BuildRuleset handles reads and execution as well as writes. ABI 3 contains
// REFER and TRUNCATE; ABI 5 adds IOCTL_DEV. Network/IPC/signal mediation does
// not rely on ABI 4/6 features unavailable at the supported floor.
func BuildRuleset(abi int, paths []PathAccess) (Ruleset, error) {
	result := Ruleset{ABI: abi, RuleABI: abi}
	if abi < MinLaunchABI {
		return result, fmt.Errorf("unsupported Landlock ABI %d", abi)
	}
	if result.RuleABI > MaxKnownABI {
		result.RuleABI = MaxKnownABI
	}
	result.HandledAccessFS = execute | writeFile | readFile | readDir | removeDir |
		removeFile | makeChar | makeDir | makeReg | makeSock | makeFIFO | makeBlock |
		makeSym | refer | truncate
	if abi >= 5 {
		result.HandledAccessFS |= ioctlDev
	}
	for _, item := range paths {
		if !canonical(item.Path) || item.Path == "/" ||
			(item.Access != ReadOnly && item.Access != ReadWrite) {
			return result, fmt.Errorf("invalid Landlock resource path or access")
		}
		for _, previous := range result.Rules {
			if overlaps(item.Path, previous.Path) {
				// Landlock rules add authority. A nested denial cannot subtract
				// a right already granted on a broad writable parent.
				return result, fmt.Errorf("overlapping Landlock resources")
			}
		}
		allowed := readFile
		if item.Directory {
			allowed |= readDir
		}
		if item.Executable {
			allowed |= execute
		}
		if item.Access == ReadWrite {
			allowed |= writeFile | truncate
			if item.Directory {
				allowed |= removeDir | removeFile | makeDir | makeReg |
					makeSock | makeFIFO | makeSym | refer
			}
			if abi >= 5 {
				allowed |= ioctlDev
			}
		}
		result.Rules = append(result.Rules, PathRule{
			Path: item.Path, Directory: item.Directory, AllowedAccess: allowed})
	}
	sort.Slice(result.Rules, func(i, j int) bool { return result.Rules[i].Path < result.Rules[j].Path })
	return result, nil
}
