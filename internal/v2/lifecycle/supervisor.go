package lifecycle

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type supervisorKey struct{}

// SupervisorBootstrap is installed process wiring. OpenSupervisor authenticates
// the native worker endpoint, current helper/kernel/job mapping and inherited
// pipes. argv supplies only the lease selector; it cannot supply a Scope, actor,
// file descriptor, command or unverified producer. Endpoint/Peer are the actual
// authenticated connection facts, separately compared with the retained claim.
type SupervisorBootstrap interface {
	OpenSupervisor(context.Context, string, api.ID) (SupervisorJob, error)
}

type SupervisorIngress interface {
	State(context.Context, api.ID) (api.CaptureState, error)
	RetainCapture(context.Context, api.ID, api.ID, int64, []byte) (api.BlobRef, error)
	Append(context.Context, api.CaptureAppendRequest) (api.CaptureAppendReceipt, error)
	Gap(context.Context, api.CaptureGap) error
}

type SupervisorPipe struct {
	StreamID api.ID
	PipeID   api.ID
	Offset   int64
	Reader   io.ReadCloser
}

type SupervisorJob struct {
	Principal api.WorkerPrincipal
	Endpoint  api.InstalledBinding
	Peer      api.PeerFacts
	Binding   api.CaptureBinding
	Pipes     []SupervisorPipe
	Ingress   SupervisorIngress
	Clock     api.Clock
	Close     func() error
}

// WithSupervisor binds an installed native capability once to this process's
// command context. It adds no public RPC, flag or serialized authority marker.
func WithSupervisor(ctx context.Context, bootstrap SupervisorBootstrap) (context.Context, error) {
	if err := contextReady(ctx); err != nil {
		return nil, err
	}
	if absent(bootstrap) {
		return nil, invalid("supervisor bootstrap required")
	}
	if ctx.Value(supervisorKey{}) != nil {
		return nil, problem(api.CodeConflict, "supervisor bootstrap is already bound", "Keep the original installed process capability.")
	}
	return context.WithValue(ctx, supervisorKey{}, bootstrap), nil
}

type supervisorPump struct {
	job SupervisorJob
	mu  sync.Mutex
}

func runSupervisor(ctx context.Context, config string, lease api.ID, bootstrap SupervisorBootstrap) (result error) {
	job, err := bootstrap.OpenSupervisor(ctx, config, lease)
	if err != nil {
		return failure(err)
	}
	if job.Close == nil {
		return integrity("supervisor job has no owned endpoint closer")
	}
	defer func() { result = errors.Join(result, failure(job.Close())) }()
	if absent(job.Clock) || absent(job.Ingress) {
		return api.NotImplemented("lb-v2-service", "supervisor clock and authenticated capture ingress")
	}
	p, binding := job.Principal, job.Binding
	if err := api.ValidateWorkerPrincipal(p, job.Endpoint, job.Peer, api.WorkerCaptureState, job.Clock.Now()); err != nil {
		return failure(err)
	}
	if api.ValidateCaptureBinding(binding) != nil || binding.Status != "registered" || binding.Config != config ||
		p.Lease.ID != lease || p.Lease.Kind != "capture" || p.Claim.Record.Outcome != nil || p.CaptureBindingID != binding.ID ||
		p.Lease.ID != binding.WorkerLeaseID || p.Lease.OperationID != binding.OperationID || p.Lease.EffectID != binding.EffectID ||
		p.Record.Actor.ID != binding.ProducerID || p.Record.ProcessGeneration != binding.ProducerGeneration || p.BootID != binding.BootID ||
		p.Record.Target != binding.Target || len(job.Pipes) != len(binding.Streams) {
		return integrity("supervisor job differs from its registered native producer")
	}
	seen := map[api.ID]bool{}
	for _, pipe := range job.Pipes {
		matched := false
		for _, stream := range binding.Streams {
			matched = matched || stream.ID == pipe.StreamID && stream.PipeID == pipe.PipeID
		}
		if !matched || seen[pipe.StreamID] || absent(pipe.Reader) || pipe.Offset < 0 || uint64(pipe.Offset) > maxInteger {
			return integrity("supervisor pipe is outside its registered stream set")
		}
		seen[pipe.StreamID] = true
	}
	pump := &supervisorPump{job: job}
	initial, err := pump.state(ctx)
	if err != nil {
		return err
	}
	for _, pipe := range job.Pipes {
		position, ok := capturePosition(initial, pipe.StreamID)
		if !ok || position.NextOffset != pipe.Offset {
			return integrity("supervisor pipe does not begin at its acknowledged offset")
		}
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, len(job.Pipes))
	var group sync.WaitGroup
	for _, pipe := range job.Pipes {
		group.Add(1)
		go func() {
			defer group.Done()
			next, err := CapturePipe(child, pipe.Reader, pipe.Offset, func(current context.Context, offset int64, data []byte) error {
				return pump.append(current, pipe.StreamID, offset, data, false)
			})
			if err == nil {
				err = pump.append(child, pipe.StreamID, next, nil, true)
			}
			if err != nil {
				cancel()
				gapCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				gapErr := job.Ingress.Gap(gapCtx, api.CaptureGap{BindingID: binding.ID, Target: binding.Target,
					Stream: pump.streamName(pipe.StreamID), StartOffset: next, Reason: "outside capture drain failed",
					ObservedAt: api.Timestamp(job.Clock.Now().UTC().Format(time.RFC3339Nano))})
				stop()
				failures <- errors.Join(err, failure(gapErr))
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		result = errors.Join(result, err)
	}
	if result != nil {
		return result
	}
	final, err := pump.state(ctx)
	if err != nil {
		return err
	}
	for _, position := range final.Positions {
		if !position.EOF {
			return integrity("supervisor returned before every committed EOF")
		}
	}
	return nil
}

func capturePosition(state api.CaptureState, stream api.ID) (api.CapturePosition, bool) {
	for _, position := range state.Positions {
		if position.StreamID == stream {
			return position, true
		}
	}
	return api.CapturePosition{}, false
}

func (pump *supervisorPump) streamName(id api.ID) string {
	for _, stream := range pump.job.Binding.Streams {
		if stream.ID == id {
			return stream.Stream
		}
	}
	return ""
}

func (pump *supervisorPump) state(ctx context.Context) (api.CaptureState, error) {
	state, err := pump.job.Ingress.State(ctx, pump.job.Binding.ID)
	if err != nil {
		return api.CaptureState{}, failure(err)
	}
	if !reflect.DeepEqual(state.Binding, pump.job.Binding) || !validGeneration(state.Generation) || len(state.Positions) != len(pump.job.Binding.Streams) {
		return api.CaptureState{}, integrity("supervisor capture state lost its registered mapping")
	}
	seen := map[api.ID]bool{}
	for _, position := range state.Positions {
		if pump.streamName(position.StreamID) == "" || seen[position.StreamID] || position.NextOffset < 0 || uint64(position.NextOffset) > maxInteger {
			return api.CaptureState{}, integrity("supervisor capture positions are invalid")
		}
		seen[position.StreamID] = true
	}
	return state, nil
}

func (pump *supervisorPump) append(ctx context.Context, stream api.ID, offset int64, data []byte, eof bool) error {
	pump.mu.Lock()
	defer pump.mu.Unlock()
	state, err := pump.state(ctx)
	if err != nil {
		return err
	}
	position, ok := capturePosition(state, stream)
	if !ok || position.NextOffset != offset || position.EOF && !eof {
		return integrity("supervisor append changed its acknowledged range")
	}
	if eof && position.EOF {
		return nil // Actual retained EOF, observed again from the owned pipe.
	}
	var ref *api.BlobRef
	if !eof {
		digest, length := digestOfBytes(data), int64(len(data))
		retained, err := pump.job.Ingress.RetainCapture(ctx, pump.job.Binding.ID, stream, offset, data)
		if err != nil {
			return failure(err)
		}
		if !validBlob(retained) || retained.Class != "capture" || retained.SHA256 != digest || retained.Bytes != length {
			return integrity("supervisor retained different raw pipe bytes")
		}
		ref = &retained
	}
	binding := pump.job.Binding
	id, err := newID()
	if err != nil {
		return err
	}
	cause := api.InternalIntent{ID: id, Kind: api.InternalCaptureAppend, Config: binding.Config, Actor: pump.job.Principal.Record.Actor,
		RequestedBy: binding.RequestedBy, CauseOperationID: binding.OperationID, CauseRequestID: binding.RequestID,
		EffectID: binding.EffectID, Target: binding.Target, CancellationEpoch: pump.job.Principal.CancellationEpoch}
	cause.LogicalTurnID = pump.job.Principal.Claim.Record.Effect.Context.LogicalTurnID
	request := api.CaptureAppendRequest{Intent: cause, BindingID: binding.ID, ExpectedGeneration: state.Generation,
		StreamID: stream, Offset: offset, Data: ref, EOF: eof}
	if err := api.ValidateCaptureAppend(binding, request); err != nil {
		return failure(err)
	}
	receipt, err := pump.job.Ingress.Append(ctx, request)
	if err != nil {
		return failure(err)
	}
	next := offset + int64(len(data))
	if receipt.BindingID != binding.ID || receipt.StreamID != stream || receipt.Offset != offset || receipt.NextOffset != next || receipt.EOF != eof ||
		!validID(receipt.RecordID) || receipt.LastSeq == 0 || receipt.Generation != state.Generation+1 {
		return integrity("supervisor append lost its actual acknowledgement")
	}
	return nil
}
