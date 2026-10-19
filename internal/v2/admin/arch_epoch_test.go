package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type archiveEpochSource struct {
	api.StateStore
	intent archivejob.Intent
	fence  *archivejob.EpochFence
	err    error
	reads  int
}

func (s *archiveEpochSource) ReadArchiveEpochFence(ctx context.Context, intent archivejob.Intent) (*archivejob.EpochFence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if intent != s.intent {
		return nil, failure(api.CodeConflict, "component writer selected another archive intent")
	}
	s.reads++
	return s.fence, s.err
}

func TestArchiveEpochClient(t *testing.T) {
	intent := archivejob.Intent{OperationID: "epoch-archive-operation", Request: api.ArchiveRequest{Target: api.LifeRef{LifeID: "epoch-life", Run: 1}, ExpectedGeneration: 4}, CancellationEpoch: 2}
	lane := api.Lane{LifeID: intent.Request.Target.LifeID, Run: 1, Generation: 4, CancellationEpoch: 2, State: "abandoned", LaunchID: "epoch-launch"}
	fence := &archivejob.EpochFence{Intent: intent, LaunchID: lane.LaunchID, LaunchEpoch: 1}
	for _, mode := range []string{"exact", "missing", "refused", "intent", "launch", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			source := &archiveEpochSource{intent: intent, fence: fence}
			service := &Service{deps: Dependencies{Store: source}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing":
				service.deps.Store = &struct{ api.StateStore }{}
			case "refused":
				source.err = failure(api.CodeConflict, "component current archive fence changed")
			case "intent", "launch":
				changed := *fence
				if mode == "intent" {
					changed.Intent.CancellationEpoch++
				} else {
					changed.LaunchID = "foreign-epoch-launch"
				}
				source.fence = &changed
			case "cancelled":
				cancel()
			}
			query, err := service.archiveFreezeQuery(ctx, intent, lane)
			if mode == "exact" {
				if err != nil || source.reads != 1 || !reflect.DeepEqual(query.Epoch, fence) || query.Intent != intent || !reflect.DeepEqual(query.Lane, lane) {
					t.Fatal("archive client omitted or changed its writer epoch handoff", err)
				}
				return
			}
			var typed *api.Error
			if !errors.As(err, &typed) {
				t.Fatal("archive epoch client accepted absent or changed writer authority", mode, err)
			}
			if mode == "cancelled" && source.reads != 0 {
				t.Fatal("cancelled archive epoch query read mutable writer state")
			}
		})
	}
}
