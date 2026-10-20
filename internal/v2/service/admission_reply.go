package service

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Refusal IO and journaling must never hold up either accept loop. Slots stay
// occupied until the worker has also journaled any coalesced overflow drops.
func (s *Server) refuseOverload(ctx context.Context, connection net.Conn, cause *api.Error, owner *sync.WaitGroup) {
	s.mu.Lock()
	if s.closed || ctx.Err() != nil {
		s.mu.Unlock()
		connection.Close()
		return
	}
	if s.refusalActive >= 8 {
		s.refusalDrops++
		s.mu.Unlock()
		connection.Close()
		return
	}
	s.refusalActive++
	s.workers.Add(1)
	owner.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.workers.Done()
		defer owner.Done()
		defer s.retireRefusal()
		stop := context.AfterFunc(ctx, func() { connection.Close() })
		defer stop()
		s.refuseAdmission(connection, cause)
	}()
}

func (s *Server) retireRefusal() {
	for {
		s.mu.Lock()
		dropped := s.refusalDrops
		if dropped == 0 {
			s.refusalActive--
			s.mu.Unlock()
			return
		}
		s.refusalDrops = 0
		s.mu.Unlock()
		s.journalConnection("admission", serviceError(api.CodeUnavailable,
			fmt.Sprintf("overload refusal pool is full; closed %d peers", dropped)))
	}
}

// Admission consumes no authority. A bounded complete request gets its
// correlated public refusal, instead of an unexplained EOF/reset. Incomplete
// or stalled peers still have a one-second read bound and no handler access.
func (s *Server) refuseAdmission(connection net.Conn, cause *api.Error) {
	defer s.closeResource(connection)
	s.journalConnection("admission", cause)
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		s.journalConnection("deadline", typedError(err))
		return
	}
	var data []byte
	var err error
	if native, ok := connection.(*net.UnixConn); ok {
		var peer wire.SocketPeer
		peer, err = wire.PeerCredentials(native)
		if err == nil {
			var frame api.FrameContext
			frame, err = wire.ReadPinnedFrame(native, peer)
			if err == nil {
				data = frame.Bytes()
			}
		}
	} else {
		data, err = wire.ReadFrame(connection)
	}
	if err != nil {
		s.journalConnection("frame", typedError(err))
		return
	}
	request, err := wire.DecodeRequest(data)
	if err != nil {
		s.journalConnection("frame", typedError(err))
		return
	}
	// Public health has a one-response contract only after UID admission.
	// An over-limit health connection closes without a response or state read.
	if request.Method == "health" {
		return
	}
	response := api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID,
		Error: connectionRefusal("admission", cause)}
	if err := s.writeResponse(connection, response); err != nil {
		s.journalConnection("response_write", typedError(err))
	}
}
