package admin

import (
	"context"
	"io"
	"sync"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type credentialOperationKey struct{}

func (m *leaseManager) beginHelperTurn(ctx context.Context, metadata bool, method string, journal io.Writer) (context.Context, func()) {
	start := time.Now()
	ctx, unlock := m.lockHelperOperation(ctx, metadata)
	acquired := time.Now()
	wait := acquired.Sub(start)
	return ctx, func() {
		hold := time.Since(acquired)
		// A slow journal sink must not retain either helper lock after the
		// operation has replied, especially while an opened lane authenticates.
		unlock()
		if method == "containment_live" || wait >= helperSlowTurn || hold >= helperSlowTurn {
			journalHelperTurn(journal, method, "turn", wait, hold)
		}
	}
}

func (m *leaseManager) lockHelperOperation(ctx context.Context, metadata bool) (context.Context, func()) {
	// The main listener owns the canonical gate for its complete operation.
	// A credential callback borrows only operationMu, while the pending main
	// request keeps helperMu. Worker handoffs never lend either lock.
	helperWait := time.Now()
	if !metadata {
		m.helperMu.Lock()
	}
	helperAcquired := time.Now()
	m.operationMu.Lock()
	operationAcquired := time.Now()
	return context.WithValue(ctx, credentialOperationKey{}, &m.operationMu), func() {
		operationHold := time.Since(operationAcquired)
		m.operationMu.Unlock()
		if !metadata {
			m.helperMu.Unlock()
			helperLockTiming(ctx, "helper_mu", helperAcquired.Sub(helperWait), time.Since(helperAcquired))
		}
		helperLockTiming(ctx, "operation_mu", operationAcquired.Sub(helperAcquired), operationHold)
	}
}

// The serialized helper operation lends its state lock only while it is
// waiting on an authenticated outside credential owner. The metadata endpoint
// can then run a read under that same lock; mutations resume only afterward.
func lendCredentialOperation(ctx context.Context, mu *sync.Mutex) func() {
	if mu == nil || ctx.Value(credentialOperationKey{}) != mu {
		return func() {}
	}
	mu.Unlock()
	return mu.Lock
}

func helperOperationMutex(ctx context.Context) *sync.Mutex {
	mu, _ := ctx.Value(credentialOperationKey{}).(*sync.Mutex)
	return mu
}

// Native exec acknowledgement can outlive the helper's serialized operation:
// the newly execed lane may authenticate while the gate is being attested.
// Borrow only the operation lock that this helper request owns, then reacquire
// it before the durable gate transition resumes.
func lendHelperOperation(ctx context.Context) func() {
	return lendCredentialOperation(ctx, helperOperationMutex(ctx))
}

func credentialMetadataMethod(method string) bool {
	return method == "containment_live" || method == "credential_projection_source" || method == "credential_projection_observe" ||
		method == "credential_projection_observe_id" || method == "credential_withdrawal_observe" || method == "resolve_runtime" || method == "credential_peer_verify" ||
		method == "credential_gate_observe"
}

// credentialGateObservation is observe_gate's measurement without its record
// update. The metadata endpoint serves it under the operationMu that a pending
// release lends while the broker accepts its Codex refresh; that release still
// holds this lease record and saves it afterward, so this read never saves. An
// exited gate reports zero survivors only after the same quiescence check.
func (m *leaseManager) credentialGateObservation(ctx context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	record, err := m.find(request.LeaseID)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if record.Gate == nil || record.Spec == nil || request.Handle != gateHandle(record) || record.BootID != m.bootID {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "process observation has no exact retained gate binding")
	}
	live := m.gates[record.Lease.ID]
	if live == nil {
		return api.ProcessObservation{}, failure(api.CodeContainmentUnknown, "gate wait status or lifetime was lost during helper restart")
	}
	observation, err := live.Observe(ctx, request.Handle)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if err := m.measureRunningSurvivors(ctx, record, &observation); err != nil {
		return api.ProcessObservation{}, err
	}
	if observation.State == "exited" {
		if err := m.resources.Quiescent(ctx, record); err != nil {
			return api.ProcessObservation{}, err
		}
		zero := uint64(0)
		observation.Survivors = &zero
	}
	return observation, nil
}
