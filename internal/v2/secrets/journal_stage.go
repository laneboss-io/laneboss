package secrets

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type journalWrite struct {
	kind string
	id   api.ID
	data []byte
}
type stagedJournal struct {
	bstate.Journal
	writes []journalWrite
	bytes  int
}

func (b *stagedJournal) clear() {
	for _, w := range b.writes {
		clear(w.data)
	}
}
func (b *stagedJournal) Read(kind string, id api.ID, out any) error {
	for i := len(b.writes) - 1; i >= 0; i-- {
		w := b.writes[i]
		if w.kind == kind && w.id == id {
			if json.Unmarshal(w.data, out) != nil {
				return wire.Error(api.CodeIntegrity, "invalid staged credential record")
			}
			return nil
		}
	}
	return b.Journal.Read(kind, id, out)
}
func (b *stagedJournal) Write(kind string, id api.ID, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 192*1024 || b.bytes+len(data) > 32<<20 {
		clear(data)
		return wire.Error(api.CodeBudget, "credential transaction exceeds its staging bound")
	}
	b.bytes += len(data)
	b.writes = append(b.writes, journalWrite{kind, id, data})
	return nil
}
func (b *stagedJournal) flush(skip api.ID) error {
	// Canonical owners are freed only after every slot/refresh write succeeded.
	for _, free := range []bool{false, true} {
		for _, w := range b.writes {
			if w.kind == "slot" && w.id == skip {
				continue
			}
			var owner bstate.Login
			freeing := false
			if w.kind == "login" {
				if json.Unmarshal(w.data, &owner) != nil {
					return wire.Error(api.CodeIntegrity, "invalid staged login")
				}
				freeing = owner.SlotID == ""
				clear(owner.Material)
			}
			if freeing != free {
				continue
			}
			// Keep exact typed integer fields; RawMessage is marshalled verbatim.
			if err := b.Journal.Write(w.kind, w.id, json.RawMessage(w.data)); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) bindMarker(id api.ID, fingerprint api.Digest, result *api.Injection) bstate.Slot {
	return bstate.Slot{Schema: "laneboss.credential-slot.v2", Config: s.deps.Config, ID: id, Kind: "selection", Fingerprint: fingerprint, Injection: result, Material: []byte{}, Returned: []byte{}}
}
func (s *Service) withPreparedBind(ctx context.Context, backend bstate.Backend, id api.ID, complete func() bstate.Slot, fn func(bstate.Journal) error) error {
	return backend.WithBroker(ctx, func(j bstate.Journal) error {
		var prior bstate.Slot
		existing := false
		if err := j.Read("slot", id, &prior); err == nil {
			existing = true
			if prior.Injection == nil {
				return wire.Error(api.CodeConflict, "partial credential bind requires protected reconciliation")
			}
		} else if !hasCode(err, api.CodeNotFound) {
			return err
		}
		b := &stagedJournal{Journal: j}
		defer b.clear()
		if err := fn(b); err != nil {
			return err
		}
		marker := complete()
		if len(b.writes) == 0 {
			if !existing && marker.Injection != nil {
				return wire.Error(api.CodeConflict, "credential bind lacks its completed journal marker")
			}
			return nil
		}
		if marker.Injection == nil {
			return wire.Error(api.CodeConflict, "credential bind has no complete selected result")
		}
		pending := marker
		pending.Injection = nil
		// This is the first persistent mutation. Any failed flush leaves it pending.
		if err := j.Write("slot", id, pending); err != nil {
			return err
		}
		if err := b.flush(id); err != nil {
			return err
		}
		return j.Write("slot", id, marker)
	})
}
