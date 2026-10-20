// Package pollgate bounds containment reads and shares bounded observations.
package pollgate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Each helper admits at most one fresh containment read every 8 ms. This
// schedules work, never caches a verdict: every admitted turn still validates
// the current journal, gate, cgroup and peer. Ordinary mutations bypass it.
const interval = 8 * time.Millisecond
const pending = 32

var ErrBusy = errors.New("containment read admission is full")

type Gate struct {
	mu      sync.Mutex
	next    time.Time
	changed chan struct{}
	leases  map[string]*leaseQueue
	order   []string
	used    int
}

type leaseQueue struct {
	active  bool
	waiting []*ticket
}

type ticket struct{ err error }

func (p *Gate) Enter(ctx context.Context, lease string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lease == "" {
		return nil, errors.New("containment read requires a lease")
	}
	p.mu.Lock()
	if p.changed == nil {
		p.changed = make(chan struct{})
		p.leases = make(map[string]*leaseQueue)
	}
	if p.used >= pending {
		// A new lease may displace only unstarted work from a lease with
		// multiple turns. Active authority checks are never interrupted.
		if p.leases[lease] != nil || !p.evictWaiting() {
			p.mu.Unlock()
			return nil, ErrBusy
		}
	}
	queue := p.leases[lease]
	if queue == nil {
		queue = &leaseQueue{}
		p.leases[lease] = queue
		p.order = append(p.order, lease)
	}
	turn := &ticket{}
	queue.waiting = append(queue.waiting, turn)
	p.used++
	p.notify()
	for {
		if err := ctx.Err(); err != nil {
			p.removeWaiting(lease, turn)
			p.mu.Unlock()
			return nil, err
		}
		if turn.err != nil {
			p.mu.Unlock()
			return nil, turn.err
		}
		eligible := p.firstReady() == lease && queue.waiting[0] == turn
		delay := time.Until(p.next)
		if eligible && delay <= 0 {
			queue.waiting = queue.waiting[1:]
			queue.active = true
			p.rotate(lease)
			p.next = time.Now().Add(interval)
			p.notify()
			p.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					p.mu.Lock()
					queue.active = false
					p.used--
					p.removeEmpty(lease)
					p.notify()
					p.mu.Unlock()
				})
			}, nil
		}
		changed := p.changed
		p.mu.Unlock()
		if eligible {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
			case <-changed:
			case <-timer.C:
			}
			timer.Stop()
		} else {
			select {
			case <-ctx.Done():
			case <-changed:
			}
		}
		p.mu.Lock()
	}
}

// All queue helpers run under mu. The order rotates on each grant, skipping
// leases that still have an active turn, rather than favoring a busy waiter.
func (p *Gate) firstReady() string {
	for _, lease := range p.order {
		queue := p.leases[lease]
		if !queue.active && len(queue.waiting) != 0 {
			return lease
		}
	}
	return ""
}

func (p *Gate) rotate(lease string) {
	for i, key := range p.order {
		if key == lease {
			p.order = append(append(p.order[:i], p.order[i+1:]...), lease)
			return
		}
	}
}

func (p *Gate) evictWaiting() bool {
	var victim *leaseQueue
	for _, lease := range p.order {
		queue := p.leases[lease]
		if len(queue.waiting) == 0 || !queue.active && len(queue.waiting) < 2 {
			continue
		}
		if victim == nil || len(queue.waiting) > len(victim.waiting) {
			victim = queue
		}
	}
	if victim == nil {
		return false
	}
	last := len(victim.waiting) - 1
	victim.waiting[last].err = ErrBusy
	victim.waiting = victim.waiting[:last]
	p.used--
	return true
}

func (p *Gate) removeWaiting(lease string, turn *ticket) {
	queue := p.leases[lease]
	if queue == nil {
		return
	}
	for i, current := range queue.waiting {
		if current == turn {
			queue.waiting = append(queue.waiting[:i], queue.waiting[i+1:]...)
			p.used--
			p.removeEmpty(lease)
			p.notify()
			return
		}
	}
}

func (p *Gate) removeEmpty(lease string) {
	queue := p.leases[lease]
	if queue.active || len(queue.waiting) != 0 {
		return
	}
	delete(p.leases, lease)
	for i, key := range p.order {
		if key == lease {
			p.order = append(p.order[:i], p.order[i+1:]...)
			return
		}
	}
}

func (p *Gate) notify() {
	close(p.changed)
	p.changed = make(chan struct{})
}
