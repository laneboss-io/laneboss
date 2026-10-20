package pollgate

import (
	"context"
	"errors"
	"sync"
	"time"
)

const VerdictAge = 100 * time.Millisecond
const ReadWait = 75 * time.Millisecond

var ErrChanged = errors.New("containment observation crossed a state change")
var ErrExpired = errors.New("containment observation expired")

type Proof struct {
	era    uint64
	until  time.Time
	direct bool
	during bool
}

type memoRead struct {
	done     chan struct{}
	err      error
	cancel   context.CancelFunc
	finished bool
}

// The owning memo mutex serializes completion and invalidation. An old
// completion cannot overwrite the refusal already delivered to its waiters.
func (r *memoRead) finish(err error) {
	if !r.finished {
		r.err, r.finished = err, true
		close(r.done)
	}
}

// Memo shares steady observations of an exact comparable authority key.
// Begin fences values and flights around a mutation. Reads during a mutation
// are direct; its first subsequent read retains the existing caller deadline.
type Memo[T comparable] struct {
	mu       sync.Mutex
	key      T
	known    bool
	warm     bool
	until    time.Time
	era      uint64
	changing int
	read     *memoRead
}

func (m *Memo[T]) reset() {
	if m.read != nil {
		m.read.cancel()
		m.read.finish(ErrChanged)
	}
	m.era++
	m.warm, m.until, m.read = false, time.Time{}, nil
}

func (m *Memo[T]) Invalidate() {
	m.mu.Lock()
	m.reset()
	m.mu.Unlock()
}

func (m *Memo[T]) Begin() func() {
	m.mu.Lock()
	m.reset()
	m.changing++
	m.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mu.Lock()
			m.changing--
			m.reset()
			m.mu.Unlock()
		})
	}
}

func (m *Memo[T]) Check(proof Proof) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if proof.era != m.era || m.changing != 0 && !proof.during {
		return ErrChanged
	}
	if !proof.direct && !time.Now().Before(proof.until) {
		return ErrExpired
	}
	return nil
}

func (m *Memo[T]) Eval(ctx context.Context, key T, refresh func(context.Context) (T, error)) (T, Proof, error) {
	return m.eval(ctx, key, func(ctx context.Context) (T, time.Time, error) {
		current, err := refresh(ctx)
		return current, time.Time{}, err
	}, false)
}

// EvalTimed uses the authority's measured expiry, rather than counting queue
// wait as observation age. Waiting grants no authority. Every returned proof
// still expires and is fenced, including first reads and transition reads.
func (m *Memo[T]) EvalTimed(ctx context.Context, key T, refresh func(context.Context) (T, time.Time, error)) (T, Proof, error) {
	return m.eval(ctx, key, refresh, true)
}

func (m *Memo[T]) eval(ctx context.Context, key T, refresh func(context.Context) (T, time.Time, error), timed bool) (T, Proof, error) {
	var empty T
	for {
		if err := ctx.Err(); err != nil {
			return empty, Proof{}, err
		}
		m.mu.Lock()
		if !m.known || m.key != key {
			m.reset()
			m.key, m.known = key, true
		}
		if m.changing != 0 && !timed {
			era := m.era
			m.mu.Unlock()
			current, _, err := refresh(ctx)
			m.mu.Lock()
			if m.era != era {
				err = ErrChanged
			}
			m.mu.Unlock()
			if err == nil && current != key {
				err = ErrChanged
			}
			return current, Proof{era: era, direct: true, during: true}, err
		}
		if time.Now().Before(m.until) {
			proof := Proof{era: m.era, until: m.until}
			m.mu.Unlock()
			return key, proof, nil
		}
		if read := m.read; read != nil {
			m.mu.Unlock()
			select {
			case <-ctx.Done():
				return empty, Proof{}, ctx.Err()
			case <-read.done:
				if read.err != nil {
					return empty, Proof{}, read.err
				}
			}
			continue
		}
		era, warm, started := m.era, m.warm, time.Now()
		until := started.Add(VerdictAge)
		readCtx, cancel := context.WithCancel(ctx)
		if warm && !timed {
			cancel()
			readCtx, cancel = context.WithDeadline(ctx, started.Add(ReadWait))
		}
		read := &memoRead{done: make(chan struct{}), cancel: cancel}
		m.read = read
		m.mu.Unlock()
		current, measured, err := refresh(readCtx)
		expired := !timed && warm && readCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		cancel()
		if timed {
			until = measured
		}
		if expired {
			err = ErrExpired
		}
		m.mu.Lock()
		if m.era != era || err == nil && current != key {
			err = ErrChanged
		}
		proof := Proof{era: era, direct: true}
		if err == nil {
			m.warm = true
			if time.Now().Before(until) {
				if m.changing == 0 {
					m.until = until
				}
				proof = Proof{era: era, until: until, during: m.changing != 0}
			} else if warm || timed {
				err = ErrExpired
			}
		}
		read.finish(err)
		if m.read == read {
			m.read = nil
		}
		m.mu.Unlock()
		return current, proof, err
	}
}
