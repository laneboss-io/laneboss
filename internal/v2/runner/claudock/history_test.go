package claudock

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Draft.4 makes the retained history identity explicit in Session. Neither a
// plan nor capture extraction can omit it or select another home's history.
func TestSessionHistoryBinding(t *testing.T) {
	ctx := context.Background()
	control := runnerSetup(t)
	plan, err := control.service.Start(ctx, control.request)
	if err != nil || plan.Session.HistoryID != control.request.Home.HistoryID {
		t.Fatal("matching session history control failed", err)
	}
	for _, operation := range []string{"start", "resume", "turn", "session", "limit"} {
		t.Run(operation, func(t *testing.T) {
			for _, history := range []api.ID{"", "history-other", "invalid history"} {
				f := runnerSetup(t)
				if operation == "resume" || operation == "turn" {
					if _, err := f.service.Start(ctx, f.request); err != nil {
						t.Fatal(err)
					}
					f.history(t)
				}
				f.request.Session.HistoryID = history
				f.launch.retainRun(f.request)
				var err error
				switch operation {
				case "start":
					_, err = f.service.Start(ctx, f.request)
				case "resume":
					_, err = f.service.Resume(ctx, f.request)
				case "turn":
					_, err = f.service.Turn(ctx, f.request)
				case "session":
					record := f.setCapture(encodeEvent(t, f.initEvent()), "stdout")
					_, err = f.service.SessionFromCapture(ctx, record)
				case "limit":
					f.installLimitGuard()
					record := f.setCapture(encodeEvent(t, f.quotaEvent("Usage limit reached")), "stdout")
					_, err = f.service.LimitFromCapture(ctx, record, f.observation)
				}
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
					t.Fatal("invalid session history reached runner", err)
				}
			}
		})
	}
}
