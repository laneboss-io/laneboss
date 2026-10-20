package service

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Server) InvalidateLaunch(ctx context.Context, decision api.LaunchRevocation) (api.TransportInvalidationReceipt, error) {
	var receipt api.TransportInvalidationReceipt
	if err := api.ValidateLaunchRevocation(decision); err != nil {
		return receipt, err
	}
	actual, err := s.deps.Store.LaunchRevocation(ctx, decision.Record.ID)
	if err != nil {
		return receipt, err
	}
	if !reflect.DeepEqual(actual, decision) {
		return receipt, serviceError(api.CodeForbidden, "transport invalidation differs from the stored revocation decision")
	}
	s.mu.Lock()
	connections := []*connectionContext{}
	if s.revokedLaunches == nil {
		s.revokedLaunches = make(map[api.ID]bool)
	}
	s.revokedLaunches[decision.Record.ID] = true
	for _, connection := range s.connections {
		if connection.Binding().LaunchID == decision.Record.ID {
			connections = append(connections, connection)
		}
	}
	s.mu.Unlock()
	if err := s.stopLaneEndpoint(ctx, decision.Record.ID); err != nil {
		return receipt, err
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			return receipt, err
		}
		s.journalLaneClose(connection.Binding(), connection.ID(), "revocation")
		if connection.finished == nil {
			return receipt, serviceError(api.CodeUnavailable, "revoked connection has no delivery completion observation")
		}
		select {
		case <-ctx.Done():
			return receipt, ctx.Err()
		case <-connection.finished:
		}
	}
	var remaining uint64
	s.mu.RLock()
	for _, connection := range s.connections {
		if connection.Binding().LaunchID == decision.Record.ID {
			remaining++
		}
	}
	fault := s.fault
	s.mu.RUnlock()
	if fault != nil {
		return receipt, fault
	}
	if remaining != 0 {
		return receipt, serviceError(api.CodeUnavailable, "revoked transport connections or deliveries are still closing")
	}
	zero := uint64(0)
	receipt = api.TransportInvalidationReceipt{LaunchID: decision.Record.ID, RevocationEventID: decision.EventID, OperationID: decision.Cause.CauseOperationID, RemainingConnections: &remaining, RemainingDeliveries: &zero, CompletedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))}
	return receipt, api.ValidateTransportInvalidation(decision, receipt)
}
