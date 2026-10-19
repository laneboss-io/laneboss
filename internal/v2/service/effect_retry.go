package service

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type effectRetry struct {
	attempts uint8
	after    time.Time
	held     bool
}

type effectRetries map[api.ID]effectRetry

func (r effectRetries) ready(id api.ID, now time.Time) bool {
	return !r[id].held && !now.Before(r[id].after)
}

func (r effectRetries) hold(id api.ID) {
	retry := r[id]
	retry.held = true
	r[id] = retry
}

func (r effectRetries) refused(id api.ID, now time.Time) {
	retry := r[id]
	if retry.attempts < 8 {
		retry.attempts++
	}
	delay := min(30*time.Second, 250*time.Millisecond<<uint(retry.attempts-1))
	retry.after = now.Add(delay)
	r[id] = retry
}

func (r effectRetries) completed(id api.ID) {
	delete(r, id)
}
