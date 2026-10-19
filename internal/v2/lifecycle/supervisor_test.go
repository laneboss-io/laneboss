package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestSupervisorDrain(t *testing.T) {
	for _, mode := range []string{"valid", "ack", "eof", "peer", "read", "close"} {
		t.Run(mode, func(t *testing.T) {
			_, store := newIOFixture(t)
			stdout := bytes.Repeat([]byte{0, 255, 'x'}, api.MaxChunkBytes/3+100)
			stderr := []byte("stderr pipe bytes\n")
			bootstrap := supervisorJob(t, store, stdout, stderr)
			switch mode {
			case "ack":
				store.badAck = true
			case "eof":
				store.dropEOF = true
			case "peer":
				bootstrap.job.Peer.HostUID++
			case "read":
				bootstrap.job.Pipes[0].Reader = &lastRead{err: errors.New("pipe read failure")}
			case "close":
				bootstrap.closeErr = api.NotImplemented("lb-v2-service", "fixture endpoint close")
			}
			ctx, err := WithSupervisor(context.Background(), bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			err = RunInternal(ctx, "example", []string{"--lease", string(store.state.Binding.WorkerLeaseID)})
			if mode == "valid" {
				if err != nil || !sameCaptureBytes(store.accepted["stdout-stream"], stdout) || !sameCaptureBytes(store.accepted["stderr-stream"], stderr) ||
					bootstrap.opens != 1 || bootstrap.closes != 1 || len(store.appends) < 5 || len(store.gaps) != 0 {
					t.Fatalf("supervisor did not drain its actual owned pipes: %v", err)
				}
				for _, position := range store.state.Positions {
					if !position.EOF {
						t.Fatal("supervisor returned without committed EOF")
					}
				}
				for _, request := range store.appends {
					if request.Intent.Actor.ID != store.state.Binding.ProducerID || request.Intent.RequestedBy != store.state.Binding.RequestedBy ||
						request.Intent.CauseOperationID != store.state.Binding.OperationID || request.Intent.Kind != api.InternalCaptureAppend {
						t.Fatal("supervisor relabelled its actual producer or cause")
					}
				}
			} else {
				if err == nil || bootstrap.closes != 1 {
					t.Fatalf("supervisor lost a measured failure: %s: %v", mode, err)
				}
				if mode == "peer" && len(store.appends) != 0 {
					t.Fatal("foreign supervisor reached capture append")
				}
				if mode == "read" && (len(store.gaps) == 0 || !bytes.Equal(store.accepted["stdout-stream"], []byte("last bytes"))) {
					t.Fatal("failed supervisor discarded acknowledged bytes or its gap")
				}
			}
		})
	}
}

func TestSupervisorBinding(t *testing.T) {
	_, store := newIOFixture(t)
	bootstrap := supervisorJob(t, store, []byte("capture"), nil)
	ctx, err := WithSupervisor(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WithSupervisor(ctx, bootstrap); err == nil {
		t.Fatal("supervisor binding was replaced")
	}
	for _, args := range [][]string{nil, {"--lease", ""}, {"--lease", "capture-lease", "--command", "other"}} {
		err := RunInternal(ctx, "example", args)
		if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeInvalid || bootstrap.opens != 0 {
			t.Fatalf("supervisor argv substituted installed authority: %v", err)
		}
	}
	err = RunInternal(context.Background(), "example", []string{"--lease", "capture-lease"})
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-service" {
		t.Fatalf("unbound supervisor claimed a successful drain: %v", err)
	}
}
