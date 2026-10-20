//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type helperCallerKey struct{}

type helperCaller struct {
	request context.Context
	target  api.LifeRef
	launch  api.ID
	lease   api.ID
	pid     int
}

// Copy diagnostic IDs only from the registered containment. They cannot admit
// a peer or replace any of resolveContainment's subsequent native checks.
func (s *Service) containmentCallContext(ctx context.Context, id api.ID, pid int) context.Context {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	entry := s.containments[id]
	if entry == nil {
		return ctx
	}
	return context.WithValue(ctx, helperCallerKey{}, helperCaller{ctx, entry.Ticket.Target,
		entry.Ticket.LaunchID, entry.Ticket.Lease.ID, pid})
}

func helperContextState(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	switch ctx.Err() {
	case context.Canceled:
		return "cancelled"
	case context.DeadlineExceeded:
		return "deadline"
	default:
		return "live"
	}
}

// This observes the existing transport context; it never changes its deadline
// or closes it. Invalidation may cancel a memo read while its request is live.
func journalHelperCall(ctx context.Context, method string, nonce api.ID) func(error, string) {
	if method != "containment_live" && method != "open_gate" {
		return func(error, string) {}
	}
	caller, _ := ctx.Value(helperCallerKey{}).(helperCaller)
	started := time.Now()
	var budget int64
	if deadline, ok := ctx.Deadline(); ok {
		budget = time.Until(deadline).Milliseconds()
	}
	write := func(event, result, stage string) {
		data, err := json.Marshal(struct {
			Event        string        `json:"event"`
			Method       string        `json:"method"`
			Nonce        api.ID        `json:"helper_nonce"`
			Life         api.ID        `json:"life_id,omitempty"`
			Run          api.RunNumber `json:"run,omitempty"`
			Launch       api.ID        `json:"launch_id,omitempty"`
			Lease        api.ID        `json:"lease_id,omitempty"`
			PeerPID      int           `json:"peer_pid,omitempty"`
			CallerPID    int           `json:"caller_pid"`
			Started      int64         `json:"started_unix_ms"`
			Elapsed      int64         `json:"elapsed_ms"`
			Budget       int64         `json:"budget_ms"`
			CallState    string        `json:"call_state"`
			RequestState string        `json:"request_state"`
			Result       string        `json:"result"`
			Stage        string        `json:"stage"`
		}{event, method, nonce, caller.target.LifeID, caller.target.Run, caller.launch, caller.lease,
			caller.pid, os.Getpid(), started.UnixMilli(), time.Since(started).Milliseconds(), budget,
			helperContextState(ctx), helperContextState(caller.request), result, stage})
		if err == nil {
			_, _ = os.Stderr.Write(append(data, '\n'))
		}
	}
	write("helper_call_start", "pending", "call_write")
	return func(err error, stage string) {
		result := "ok"
		if err != nil {
			result = "refused"
		}
		write("helper_call_end", result, stage)
	}
}
