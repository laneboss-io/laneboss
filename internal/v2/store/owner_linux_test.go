//go:build linux

package store

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestReservationOneWinner(t *testing.T) {
	t.Run("identical_invocations", func(t *testing.T) {
		s, _ := testStore(t)
		input := testTransaction(t)
		raw, err := json.Marshal(input.Scope.Request)
		if err != nil {
			t.Fatal(err)
		}
		request := api.RequestReservation{Scope: input.Scope, RawRequest: raw, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))}
		type answer struct {
			receipt api.MutationReceipt
			won     bool
			err     error
		}
		answers := make(chan answer, 8)
		var workers sync.WaitGroup
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				receipt, won, err := s.ReserveMutation(context.Background(), request)
				answers <- answer{receipt, won, err}
			}()
		}
		workers.Wait()
		close(answers)
		var original api.ID
		winners := 0
		for result := range answers {
			if result.err != nil {
				t.Fatal("atomic reservation control failed", result.err)
			}
			if original == "" {
				original = result.receipt.Operation.ID
			}
			if original != result.receipt.Operation.ID || result.receipt.Reply != nil {
				t.Fatal("atomic reservation replaced its original pending operation")
			}
			if result.won {
				winners++
			}
		}
		if winners != 1 {
			t.Fatal("identical reservations did not have exactly one winner")
		}
		replayed, won, err := s.ReserveMutation(context.Background(), request)
		if err != nil || won || replayed.Operation.ID != original {
			t.Fatal("identical reservation retry acquired ownership", err)
		}
	})
}
