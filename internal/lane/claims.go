package lane

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

type claim struct{ holder, name string }

func claimsRegistry() (string, error) {
	p := os.Getenv("LANEBOSS_TEST_CLAIMS_DIR")
	if p != "" {
		if !filepath.IsAbs(p) {
			return "", refuse("LANEBOSS_TEST_CLAIMS_DIR must be an absolute path")
		}
		return filepath.Clean(p), nil
	}
	u, err := user.Current()
	if err != nil || !filepath.IsAbs(u.HomeDir) {
		return "", refuse("the account's home directory in the user database cannot be found")
	}
	return filepath.Join(u.HomeDir, ".local", "state", "laneboss", ".lane-claims"), nil
}
func sameRegistry(recorded any) (string, error) {
	p, err := claimsRegistry()
	if err != nil {
		return "", err
	}
	if recorded != nil && str(recorded) != p {
		return "", refuse("the lane's claim was recorded in another claims registry; nothing was done (LANEBOSS_TEST_CLAIMS_DIR differs)")
	}
	return p, nil
}
func registeredClaim(path, registry string) (*claim, error) {
	if err := os.MkdirAll(registry, 0700); err != nil {
		return nil, refuse("cannot create the claims registry")
	}
	if err := checkPrivateDirectory(registry); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, refuse("the working directory's identity cannot be read")
	}
	return &claim{registry, fmt.Sprintf("%d-%d.json", st.Dev, st.Ino)}, nil
}
func locateClaim(path string, starting bool, recorded any) (*claim, error) {
	registry, err := sameRegistry(recorded)
	if err != nil {
		return nil, err
	}
	if !starting && recorded != nil {
		c, err := registeredClaim(path, registry)
		if err != nil {
			return nil, err
		}
		v, err := readClaim(c)
		if err != nil {
			return nil, err
		}
		if v != nil {
			return c, nil
		}
	}
	kind, place, err := gitKind(path)
	if err != nil {
		return nil, err
	}
	if kind == "main" && starting {
		return nil, refuse("--worktree %s is inside the main working copy of the repository at %s; a lane works in its own worktree", path, place)
	}
	if kind == "linked" {
		return &claim{place, "laneboss-claim"}, nil
	}
	return registeredClaim(path, registry)
}
func readClaim(c *claim) (object, error) {
	if c == nil {
		return nil, nil
	}
	r, err := rootDirectory(c.holder)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := rootRead(r, c.name, 64*1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return object{}, nil
	}
	v, err := parseJSON(b)
	if err != nil || obj(v) == nil {
		return object{}, nil
	}
	return obj(v), nil
}
func (s *session) claimOwner(lane, launch, path string) object {
	m := object{"config": s.c.name, "state": s.c.state, "lane": lane, "launch": nullable(launch)}
	if path != "" {
		m["path"] = path
	}
	return m
}
func sameLane(v, mine object) bool {
	if v == nil || len(v) == 0 {
		return false
	}
	for _, k := range []string{"config", "state", "lane"} {
		if v[k] != mine[k] {
			return false
		}
	}
	return true
}
func claimDescription(v object) string {
	if match(`[a-z0-9][a-z0-9-]{0,31}`, str(v["config"])) && match(`[a-z0-9][a-z0-9._-]{0,63}`, str(v["lane"])) {
		if r, _ := credential(str(v["lane"]) + " " + str(v["config"])); r == "" {
			return "lane " + str(v["lane"]) + " of configuration " + str(v["config"])
		}
	}
	return "another lane"
}
func takeClaim(c *claim, mine object) (bool, error) {
	r, err := rootDirectory(c.holder)
	if err != nil {
		return false, err
	}
	defer r.Close()
	b := append(canonical(mine), '\n')
	err = rootWrite(r, c.name, b, false, 0600)
	if err == nil {
		return true, nil
	}
	if !os.IsExist(err) {
		return false, err
	}
	old, err := readClaim(c)
	if err != nil {
		return false, err
	}
	if !sameLane(old, mine) {
		return false, refuse("the working directory is claimed by %s; one lane works in a directory at a time", claimDescription(old))
	}
	return false, rootWrite(r, c.name, b, true, 0600)
}
func checkClaim(c *claim, mine object) error {
	v, err := readClaim(c)
	if err != nil {
		return err
	}
	if v == nil {
		return refuse("the working directory no longer carries lane %s's claim", str(mine["lane"]))
	}
	if !sameLane(v, mine) {
		return refuse("the working directory is claimed by %s", claimDescription(v))
	}
	return nil
}
func releaseClaim(c *claim, mine object) (bool, error) {
	if c == nil {
		return false, nil
	}
	v, err := readClaim(c)
	if err != nil {
		return false, err
	}
	if !sameLane(v, mine) {
		return false, nil
	}
	r, err := rootDirectory(c.holder)
	if err != nil {
		return false, err
	}
	defer r.Close()
	err = r.Remove(c.name)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func releaseStale(registry any, mine object, path, keep string) error {
	if registry == nil {
		return nil
	}
	r, err := rootDirectory(str(registry))
	if err != nil {
		if _, e := os.Stat(str(registry)); os.IsNotExist(e) {
			return nil
		}
		return err
	}
	defer r.Close()
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == keep || !strings.HasSuffix(name, ".json") {
			continue
		}
		c := &claim{str(registry), name}
		v, err := readClaim(c)
		if err != nil {
			return err
		}
		if sameLane(v, mine) && str(v["path"]) == path {
			if _, err = releaseClaim(c, mine); err != nil {
				return err
			}
		}
	}
	return nil
}
