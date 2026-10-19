package laneturns

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"laneboss.io/laneboss/internal/caller"
)

// A store writer owns event order independently of process and budget control.
type turnRecorder struct {
	s            *laneSession
	lane, launch string
	watch        io.Writer
	queue        []object
	mutex        sync.Mutex
	ready        *sync.Cond
	finishing    bool
	done         chan error
}

func newRecorder(s *laneSession, lane, launch string, watch io.Writer) *turnRecorder {
	r := &turnRecorder{s: s, lane: lane, launch: launch, watch: watch, done: make(chan error, 1)}
	r.ready = sync.NewCond(&r.mutex)
	go func() {
		var failure error
		for {
			r.mutex.Lock()
			for len(r.queue) == 0 && !r.finishing {
				r.ready.Wait()
			}
			if len(r.queue) == 0 && r.finishing {
				r.mutex.Unlock()
				break
			}
			e := r.queue[0]
			r.queue[0] = nil
			r.queue = r.queue[1:]
			r.mutex.Unlock()
			if err := recordOrQueue(s, lane, e, watch); err != nil {
				failure = errors.Join(failure, err)
			}
		}
		r.done <- failure
	}()
	return r
}
func (r *turnRecorder) put(e object) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.queue = append(r.queue, e)
	r.ready.Signal()
}
func (r *turnRecorder) finish() error {
	r.mutex.Lock()
	r.finishing = true
	r.ready.Broadcast()
	r.mutex.Unlock()
	return <-r.done
}
func (r *turnRecorder) ending(end, started object, actors ...string) error {
	actor := "laneboss"
	if len(actors) > 0 {
		actor = actors[0]
	}
	e, err := envelope("lane.ended", r.lane, caller.LifecycleActor(actor), end)
	if err != nil {
		return err
	}
	r.put(e)
	if carried := array(started["mail"]); len(carried) > 0 {
		outcome, reason := settlement("lane.ended", end)
		p := object{"run": started["run"], "sequences": carried}
		if outcome == "returned" {
			p["reason"] = reason
		}
		e, err = envelope("lane."+outcome, r.lane, "laneboss", p)
		if err != nil {
			return err
		}
		r.put(e)
	}
	fmt.Fprintf(r.watch, "%s run %d: ended, reason %s\n", nowStamp(), integer(end["run"]), str(end["reason"]))
	return nil
}
