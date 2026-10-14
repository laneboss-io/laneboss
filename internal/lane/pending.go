package lane

import (
	"os"
	"sort"
	"strings"
)

type storeRefusalError struct{ cause error }

func (e *storeRefusalError) Error() string { return e.cause.Error() }

type storeUnavailableError struct{ cause error }

func (e *storeUnavailableError) Error() string { return e.cause.Error() }

func linesAt(r *os.Root, name string) ([]string, error) {
	b, err := rootRead(r, name, 16*1024*1024)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, refuse("%s: cannot read as a regular file", name)
	}
	lines := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}
func pendingNames(r *os.Root) ([]string, error) {
	f, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	aside := []string{}
	for _, n := range names {
		if strings.HasPrefix(n, "pending-") && strings.HasSuffix(n, ".jsonl") {
			aside = append(aside, n)
		}
	}
	sort.Slice(aside, func(i, j int) bool {
		a, ea := r.Lstat(aside[i])
		b, eb := r.Lstat(aside[j])
		if ea != nil || eb != nil {
			return aside[i] < aside[j]
		}
		if a.ModTime().Equal(b.ModTime()) {
			return aside[i] < aside[j]
		}
		return a.ModTime().Before(b.ModTime())
	})
	return append([]string{"pending.jsonl"}, aside...), nil
}
func queueAt(r *os.Root) ([]string, error) {
	names, err := pendingNames(r)
	if err != nil {
		return nil, err
	}
	result := []string{}
	for _, name := range names {
		lines, err := linesAt(r, name)
		if err != nil {
			return nil, err
		}
		result = append(result, lines...)
	}
	return result, nil
}
func rewriteLines(r *os.Root, name string, lines []string) error {
	if len(lines) == 0 {
		err := r.Remove(name)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return rootWrite(r, name, []byte(strings.Join(lines, "\n")+"\n"), true, 0600)
}
func (s *session) pendingCount(lane string) (int, error) {
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer r.Close()
	q, err := queueAt(r)
	return len(q), err
}
func (s *session) refusedCount(lane string) (int, error) {
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer r.Close()
	q, err := linesAt(r, "refused.jsonl")
	return len(q), err
}
func (s *session) waiting(lane string) ([]object, error) {
	r, err := s.laneRoot(lane, false)
	if os.IsNotExist(err) {
		return []object{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer r.Close()
	q, err := queueAt(r)
	if err != nil {
		return nil, err
	}
	result := []object{}
	for _, line := range q {
		v, err := parseJSON([]byte(line))
		if err == nil && obj(v) != nil {
			result = append(result, obj(v))
		}
	}
	return result, nil
}
func keepRefused(r *os.Root, e object, reason, line string) error {
	old, err := linesAt(r, "refused.jsonl")
	if err != nil {
		return err
	}
	for _, s := range old {
		v, err := parseJSON([]byte(s))
		if err == nil && e != nil && obj(obj(v)["envelope"])["id"] == e["id"] {
			return nil
		}
	}
	entry := object{"envelope": e, "reason": reason}
	if e == nil {
		entry["line"] = line
	}
	return rewriteLines(r, "refused.jsonl", append(old, string(canonical(entry))))
}
func mergeAside(r *os.Root) error {
	names, err := pendingNames(r)
	if err != nil {
		return err
	}
	if len(names) < 2 {
		return nil
	}
	q, err := queueAt(r)
	if err != nil {
		return err
	}
	if err = rewriteLines(r, "pending.jsonl", q); err != nil {
		return err
	}
	for _, name := range names[1:] {
		if err = r.Remove(name); err != nil {
			return err
		}
	}
	return nil
}
func (s *session) flushAt(r *os.Root, timeout float64) (int, int, int, error) {
	if err := mergeAside(r); err != nil {
		return 0, 0, 0, err
	}
	q, err := linesAt(r, "pending.jsonl")
	if err != nil {
		return 0, 0, 0, err
	}
	done, rejected := 0, 0
	for len(q) > 0 {
		v, e := parseJSON([]byte(q[0]))
		if e != nil || obj(v) == nil {
			if err = keepRefused(r, nil, "the line is not an event (not a JSON object)", q[0]); err != nil {
				return done, rejected, len(q), err
			}
			rejected++
		} else {
			_, e = s.appendRaw(obj(v), timeout)
			if e != nil {
				p, refused := e.(*problem)
				if !refused || p.code != 2 {
					break
				}
				if err = keepRefused(r, obj(v), e.Error(), ""); err != nil {
					return done, rejected, len(q), err
				}
				rejected++
			} else {
				done++
			}
		}
		q = q[1:]
		if err = rewriteLines(r, "pending.jsonl", q); err != nil {
			return done, rejected, len(q), err
		}
	}
	return done, rejected, len(q), nil
}
func (s *session) laneLock(lane string, create bool) (*os.Root, func(), error) {
	r, err := s.laneRoot(lane, create)
	if err != nil {
		return nil, nil, err
	}
	f, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, nil, err
	}
	unlock, err := lockFile(f, 60, false)
	if err != nil {
		r.Close()
		f.Close()
		return nil, nil, err
	}
	return r, func() { unlock(); f.Close(); r.Close() }, nil
}
func (s *session) flush(lane string, timeout float64) (int, int, int, error) {
	r, unlock, err := s.laneLock(lane, false)
	if os.IsNotExist(err) {
		return 0, 0, 0, nil
	}
	if err != nil {
		return 0, 0, 0, err
	}
	defer unlock()
	return s.flushAt(r, timeout)
}
func (s *session) drain(lane string) error {
	count, err := s.pendingCount(lane)
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	_, _, left, err := s.flush(lane, 10)
	if err != nil {
		return err
	}
	if err = s.refresh(); err != nil {
		return err
	}
	if left > 0 {
		return refuse("lane %s has %d event(s) waiting to be recorded; lane check records them first", lane, left)
	}
	return nil
}
func (s *session) append(e object, timeout float64) (object, error) {
	lane := str(e["lane"])
	if lane == "" {
		return s.appendRaw(e, timeout)
	}
	r, unlock, err := s.laneLock(lane, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	q, err := queueAt(r)
	if err != nil {
		return nil, err
	}
	if len(q) > 0 {
		_, _, left, err := s.flushAt(r, timeout)
		if err != nil {
			return nil, err
		}
		if left > 0 {
			return nil, refuse("lane %s has %d events waiting to be recorded; lane check records them first", lane, left)
		}
	}
	return s.appendRaw(e, timeout)
}
func (s *session) record(e object, timeout float64) (bool, error) {
	lane := str(e["lane"])
	r, unlock, err := s.laneLock(lane, true)
	if err != nil {
		return false, err
	}
	defer unlock()
	if err = mergeAside(r); err != nil {
		return false, err
	}
	q, err := linesAt(r, "pending.jsonl")
	if err != nil {
		return false, err
	}
	if len(q) == 0 {
		_, err = s.appendRaw(e, timeout)
		if err == nil {
			return true, nil
		}
		if p, ok := err.(*problem); ok && p.code == 2 {
			if e2 := keepRefused(r, e, err.Error(), ""); e2 != nil {
				return false, e2
			}
			return false, &storeRefusalError{err}
		}
	}
	q = append(q, string(canonical(e)))
	if err = rewriteLines(r, "pending.jsonl", q); err != nil {
		return false, err
	}
	if len(q) > 1 {
		_, _, left, e := s.flushAt(r, timeout)
		return left == 0, e
	}
	return false, nil
}
