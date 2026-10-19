package box

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func TestFirstSignal(t *testing.T) {
	h := newFixture(t)
	signals := make(chan os.Signal, 2)
	h.env.signals = signals
	exits := make(chan int, 1)
	h.env.exit = func(code int) { exits <- code }
	h.svc.run = boxcore.RunResult{SuiteExit: -1, ExitCode: 11}
	cleaned := false
	h.svc.during = func(ctx context.Context, o boxcore.RunOptions) {
		signals <- os.Interrupt
		select {
		case <-ctx.Done():
			cleaned = true
		case <-time.After(2 * time.Second):
			t.Error("first signal did not cancel the service context")
		}
	}
	code := h.call("run", "--purpose", "demo", "--suite", "exit 0")
	if code != 11 || !cleaned || len(h.svc.runs) != 1 || h.notes.Len() != 0 {
		t.Fatalf("first signal: code=%d cleanup=%t stderr=%q", code, cleaned, h.notes.String())
	}
	select {
	case code := <-exits:
		t.Fatalf("first signal forced exit %d", code)
	default:
	}
}

func TestSecondSignal(t *testing.T) {
	h := newFixture(t)
	signals := make(chan os.Signal, 2)
	h.env.signals = signals
	exits := make(chan int, 1)
	h.env.exit = func(code int) { exits <- code }
	h.svc.run = boxcore.RunResult{SuiteExit: -1, ExitCode: 15}
	exitCode := -1
	h.svc.during = func(ctx context.Context, o boxcore.RunOptions) {
		signals <- os.Interrupt
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
			t.Error("first signal did not reach the service")
			return
		}
		signals <- syscall.SIGTERM
		select {
		case exitCode = <-exits:
		case <-time.After(2 * time.Second):
			t.Error("second signal did not force exit")
		}
	}
	code := h.call("run", "--purpose", "demo", "--suite", "exit 0")
	if code != 15 || exitCode != 130 || len(h.svc.runs) != 1 ||
		h.notes.String() != "laneboss box: second signal, leaving now\n" ||
		!strings.Contains(h.out.String(), "exit=15 (end-pending)\n") {
		t.Fatalf("second signal: code=%d exit=%d stdout=%q stderr=%q", code, exitCode, h.out.String(), h.notes.String())
	}
}
