package lane

import (
	"os"
	"path/filepath"

	"laneboss.io/laneboss/internal/faults"
)

type collectionWorktree struct {
	claim *claim
	owned bool
	why   string
}

// Planning and cleanup must agree on which directory belongs to this lane.
// Missing or unowned paths contribute no archive members and are never removed.
// A symlink is a refusal even when its target is absent.
func (s *session) worktreeForCollection(lane string, p object) (*collectionWorktree, error) {
	path := str(p["worktree"])
	if err := s.c.checkPath(path, "the archive worktree", true); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if faults.Get("archive-refuse-missing-worktree").Point != "" {
			if err = faults.Reach("archive-refuse-missing-worktree"); err != nil {
				return nil, err
			}
			return nil, refuse("the worktree is missing or linked; nothing was archived or removed")
		}
		return &collectionWorktree{why: "missing"}, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, refuse("the worktree is a symbolic link; nothing was archived or removed")
	}
	if !info.IsDir() {
		return &collectionWorktree{why: "not-this-lane"}, nil
	}
	claim, err := locateClaim(path, false, p["claims"])
	if err != nil {
		return nil, err
	}
	value, err := readClaim(claim)
	if err != nil {
		return nil, err
	}
	worktree := &collectionWorktree{claim: claim, owned: sameLane(value, s.claimOwner(lane, str(p["launch"]), ""))}
	if !worktree.owned {
		// An absent or malformed claim is collectable without touching the
		// directory. A positively identified foreign configuration is different:
		// refuse before archiving or removing even the old lane's branch.
		if match(`[a-z0-9][a-z0-9-]{0,31}`, str(value["config"])) &&
			match(`[a-z0-9][a-z0-9._-]{0,63}`, str(value["lane"])) &&
			filepath.IsAbs(str(value["state"])) &&
			(value["config"] != s.c.name || value["state"] != s.c.state) {
			return nil, refuse("the working directory is claimed by %s; nothing was archived or removed", claimDescription(value))
		}
		worktree.why = "not-this-lane"
		return worktree, nil
	}
	if str(p["repository"]) != "" {
		code, branch, _, err := gitRun(path, "symbolic-ref", "--quiet", "--short", "HEAD")
		if err != nil {
			return nil, err
		}
		if code != 0 || branch != str(p["branch"]) {
			worktree.why = "not-this-lane"
		}
	}
	return worktree, nil
}
