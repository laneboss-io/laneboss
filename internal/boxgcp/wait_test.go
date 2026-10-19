package boxgcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestWaitEnded rejects waiting through ended boxes or returning not-found directly.
func TestWaitEnded(t *testing.T) {
	for _, status := range []string{"STOPPING", "SUSPENDING", "TERMINATED", "SUSPENDED", "STOPPED", "gone"} {
		t.Run(status, func(t *testing.T) {
			result := boxexec.Result{Stdout: instanceJSON(t, "lb-box-1", status, nil, "")}
			if status == "gone" {
				result = boxexec.Result{Code: 1, Stderr: []byte("HTTPError 404: " + goneText("demo-zone-a", "lb-box-1"))}
			}
			f := resultFake(result, nil)
			_, err := New(testConfig(), f, testOptions()).WaitRunning(context.Background(), testBox())
			requireKind(t, err, boxcore.KindOther)
			var failure *boxcore.Error
			if !errors.As(err, &failure) || failure.Detail != "box ended while starting" {
				t.Fatal("ended box did not report the required reason")
			}
			onlyCall(t, f)
		})
	}
}

// TestWaitTimeout rejects a missing deadline, late success and ignored cancellation.
func TestWaitTimeout(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		o := testOptions()
		start, now := o.Now(), o.Now()
		sleeps := 0
		o.Now = func() time.Time { return now }
		o.Sleep = func(ctx context.Context, d time.Duration) error {
			if d != 5*time.Second || now.Sub(start)+d > 5*time.Minute {
				t.Fatal("wait exceeded its five minute budget")
			}
			sleeps++
			now = now.Add(d)
			return nil
		}
		f := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "gcloud", ArgsContain: []string{"instances describe"},
			Respond: func(_ boxexec.Cmd, n int) (boxexec.Result, error) {
				if n >= 60 {
					t.Fatal("describe ran at or after the deadline")
				}
				return boxexec.Result{Stdout: instanceJSON(t, "lb-box-1", "PROVISIONING", nil, "")}, nil
			},
		}}}
		_, err := New(testConfig(), f, o).WaitRunning(context.Background(), testBox())
		requireKind(t, err, boxcore.KindOther)
		if !strings.Contains(err.Error(), "timed out") || sleeps != 60 || len(f.Calls) != 60 || now.Sub(start) != 5*time.Minute {
			t.Fatal("timeout was early, late or did not use the injected clock")
		}
	})
	t.Run("late-running", func(t *testing.T) {
		o := testOptions()
		now := o.Now()
		o.Now = func() time.Time { return now }
		f := &boxexec.Fake{Handlers: []boxexec.Handler{{Name: "gcloud",
			Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
				now = now.Add(5 * time.Minute)
				return boxexec.Result{Stdout: instanceJSON(t, "lb-box-1", "RUNNING", nil, "")}, nil
			},
		}}}
		_, err := New(testConfig(), f, o).WaitRunning(context.Background(), testBox())
		requireKind(t, err, boxcore.KindOther)
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatal("a response beyond the budget was accepted")
		}
		onlyCall(t, f)
	})
	for _, duringSleep := range []bool{false, true} {
		t.Run("cancel-"+fmt.Sprint(duringSleep), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			o := testOptions()
			f := resultFake(boxexec.Result{Stdout: instanceJSON(t, "lb-box-1", "PROVISIONING", nil, "")}, nil)
			if duringSleep {
				o.Sleep = func(ctx context.Context, d time.Duration) error {
					cancel()
					return ctx.Err()
				}
			} else {
				cancel()
			}
			_, err := New(testConfig(), f, o).WaitRunning(ctx, testBox())
			if !errors.Is(err, context.Canceled) || boxcore.KindOf(err) != boxcore.KindOther {
				t.Fatal("context cancellation was lost")
			}
			wantCalls := 0
			if duringSleep {
				wantCalls = 1
			}
			if len(f.Calls) != wantCalls {
				t.Fatal("wait continued after cancellation")
			}
		})
	}
}
