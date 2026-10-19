package codex

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	secretport "laneboss.io/laneboss/internal/v2/secrets"
)

type changedUsageSource struct{ api.UsageWindowSource }

func (s changedUsageSource) ReadUsageWindow(ctx context.Context, scope api.Scope, query api.UsageWindowRequest) (api.UsageWindowEvidence, error) {
	result, err := s.UsageWindowSource.ReadUsageWindow(ctx, scope, query)
	// Still fresh/post-exit and otherwise valid, but different retained bytes.
	result.ObservedAt = query.RunEndedAt
	return result, err
}

func TestOutsideUsage(t *testing.T) {
	for _, fault := range []string{"profile", "provider", "operation", "producer", "worker", "native", "stale", "pre-exit", "future", "available", "reset", "reset-past", "raw-percent", "raw-profile", "raw-header", "raw-reset", "private", "origin", "object-operation", "life", "envelope", "source", "worker-port", "profile-port"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t)
			f.quotaProof()
			record, exit := f.endCapture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), 1)
			ctx := context.Background()
			signal, err := f.service.LimitFromCapture(ctx, record, exit)
			if err != nil || signal == nil || signal.UsageEvidence == nil || *signal.UsageEvidence != f.store.usage[record.Target].Evidence {
				t.Fatal("outside usage evidence was not retained in the limit signal", err)
			}
			evidence, raw := f.retainedUsage()
			refs := f.store.usage[record.Target]
			code := api.CodeInvalid
			switch fault {
			case "profile":
				evidence.ProfileID = "destination_profile"
			case "provider":
				evidence.Provider = "foreign-provider"
			case "operation":
				evidence.OperationID = "foreign_operation"
			case "producer":
				evidence.ProducerGeneration = "lane_writer_generation"
			case "worker", "native":
				var producer api.WorkerPrincipal
				if err := f.store.retainedInternal(refs.Principal, &producer); err != nil {
					t.Fatal(err)
				}
				if fault == "worker" {
					producer.Lease.Kind = "materialize"
				} else {
					producer.Record.HostUID++
				}
				refs.Principal = f.keepJSON(producer, "record")
				f.store.usage[record.Target] = refs
			case "stale":
				f.clock.now = f.clock.Now().Add(31 * time.Second)
				f.service.deps.Clock = f.clock
			case "pre-exit":
				ended, err := timestamp(exit.ObservedAt)
				if err != nil {
					t.Fatal(err)
				}
				evidence.ObservedAt = api.Timestamp(ended.Add(-time.Second).Format(time.RFC3339Nano))
			case "future":
				evidence.ObservedAt = api.Timestamp(f.clock.Now().Add(time.Second).Format(time.RFC3339Nano))
			case "available":
				evidence.UsedPercent = 99
				raw = bytes.Replace(raw, []byte("\t100\t"), []byte("\t99\t"), 1)
			case "reset":
				raw = bytes.Replace(raw, []byte(evidence.ResetsAt), []byte("unknown"), 1)
				evidence.ResetsAt = "unknown"
			case "reset-past":
				evidence.ObservedAt = exit.ObservedAt
				reset := api.Timestamp(f.clock.Now().Format(time.RFC3339Nano))
				raw = bytes.Replace(raw, []byte(evidence.ResetsAt), []byte(reset), 1)
				evidence.ResetsAt = reset
				code = api.CodeIntegrity
			case "raw-percent":
				raw = bytes.Replace(raw, []byte("\t100\t"), []byte("\t99\t"), 1)
			case "raw-profile":
				raw = bytes.Replace(raw, []byte("fixture-profile"), []byte("foreign-profile"), 1)
			case "raw-header":
				raw = bytes.Replace(raw, []byte("USED_PERCENT"), []byte("USAGE"), 1)
			case "raw-reset":
				raw = bytes.Replace(raw, []byte(evidence.ResetsAt), []byte("unknown"), 1)
			case "envelope":
				f.service.deps.UsageWindows = changedUsageSource{f.store}
				code = api.CodeIntegrity
			case "source":
				f.service.deps.UsageWindows = nil
				code = api.CodeNotImplemented
			case "worker-port":
				f.service.deps.UsageWorker = nil
				code = api.CodeNotImplemented
			case "profile-port":
				f.service.deps.UsageProfile = nil
				code = api.CodeNotImplemented
			}
			f.retainUsage(evidence, raw)
			if fault == "private" || fault == "origin" || fault == "object-operation" || fault == "life" {
				evidence, _ = f.retainedUsage()
				metadata := f.store.metadata[evidence.Raw.ID]
				switch fault {
				case "private":
					metadata.ACL.Audience = "lane"
				case "origin":
					metadata.Origin = "lane"
				case "object-operation":
					metadata.SourceOperationID = "foreign_operation"
				case "life":
					metadata.ACL.LifeID = "foreign_life"
				}
				f.store.metadata[evidence.Raw.ID] = metadata
				code = api.CodeIntegrity
			}
			signal, err = f.service.LimitFromCapture(ctx, record, exit)
			wantCode(t, err, code)
			if signal != nil {
				t.Fatal("unverified outside usage returned a limit signal")
			}
		})
	}
}

func TestUsageEvidence(t *testing.T) {
	f := newFixture(t)
	f.quotaProof()
	record, exit := f.endCapture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), 1)
	signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
	if err != nil || signal == nil || signal.UsageEvidence == nil || *signal.UsageEvidence != f.store.usage[record.Target].Evidence {
		t.Fatal("limit omitted exact retained outside usage reference", err)
	}
}

func TestUsageOwnerRefusal(t *testing.T) {
	f := newFixture(t)
	f.quotaProof()
	record, exit := f.endCapture([]byte("{\"type\":\"turn.failed\",\"error\":{\"code\":\"synthetic_quota\"}}\n"), 1)
	actual := &secretport.Service{}
	var query api.UsageWindowRequest
	if err := f.store.retainedInternal(f.store.usage[record.Target].Query, &query); err != nil {
		t.Fatal(err)
	}
	_, expected := actual.ReadUsageWindow(context.Background(), f.service.deps.ReadScope, query)
	if expected == nil {
		t.Fatal("usage owner unexpectedly available without installation")
	}
	f.service.deps.UsageWindows = actual
	signal, err := f.service.LimitFromCapture(context.Background(), record, exit)
	if signal != nil || !reflect.DeepEqual(err, expected) {
		t.Fatal("usage owner's refusal was not preserved", err)
	}
}
