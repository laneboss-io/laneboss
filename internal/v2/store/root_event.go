package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// RootGrantEvent is the private ownership port for grants.get. It exposes
// only the caller's original issuance of the exact requested root template.
// It is not registered as an RPC and does not change public event selectors.
func (s *Service) RootGrantEvent(ctx context.Context, scope api.Scope, id api.ID) (api.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var empty api.Event
	if err := s.available(); err != nil {
		return empty, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return empty, err
	}
	if scope.Actor.Kind != "human" || scope.Request.Method != "grants.get" {
		return empty, fault(api.CodeForbidden, "root issuance requires its original human grant read")
	}
	var request api.GrantGetRequest
	if err := api.DecodeObject(scope.Request.Params, &request); err != nil {
		return empty, err
	}
	if request.GrantSetID != id || !wire.ValidID(string(id)) {
		return empty, wire.Invalid("root issuance selector differs from the exact grant request")
	}
	db, err := s.reader(scope)
	if err != nil {
		return empty, err
	}
	var set api.GrantSet
	if err := storedProjection(ctx, db, "grants", id, &set); err != nil {
		return empty, err
	}
	if set.ID != id || set.ParentLifeID != "" || !wire.ValidID(string(set.LifeID)) {
		return empty, fault(api.CodeNotFound, "selected root issuance is not visible")
	}
	rows, err := db.QueryContext(ctx, `SELECT seq,data FROM events
 WHERE json_extract(data,'$.kind')='grants.issued'
 AND json_extract(data,'$.life_id')=? AND coalesce(json_extract(data,'$.run'),0)=0
 AND json_extract(data,'$.actor.id')=? ORDER BY seq LIMIT 2`, string(set.LifeID), string(scope.Actor.ID))
	if err != nil {
		return empty, fault(api.CodeIntegrity, "cannot read selected root issuance")
	}
	defer rows.Close()
	var result api.Event
	found := false
	for rows.Next() {
		if found {
			return empty, fault(api.CodeIntegrity, "selected root has multiple issuance records")
		}
		var raw []byte
		var sequence uint64
		if err := rows.Scan(&sequence, &raw); err != nil {
			return empty, fault(api.CodeIntegrity, "cannot decode selected root issuance")
		}
		if err := wire.Decode(raw, &result); err != nil {
			return empty, err
		}
		if err := wire.ValidateEvent(result); err != nil {
			return empty, err
		}
		if result.Seq != api.Sequence(sequence) {
			return empty, fault(api.CodeIntegrity, "root issuance changed its stored sequence")
		}
		if result.Config != scope.Config || result.Origin != "service" || result.Actor != scope.Actor ||
			result.RequestedBy != result.Actor || result.LifeID != set.LifeID || result.Run != 0 {
			return empty, fault(api.CodeIntegrity, "root issuance changed its authenticated owner or template")
		}
		var issued api.GrantEvent
		if err := api.DecodeObject(result.Payload, &issued); err != nil {
			return empty, err
		}
		if issued.GrantSet.ID != set.ID || issued.GrantSet.LifeID != set.LifeID || issued.GrantSet.ParentLifeID != "" {
			return empty, fault(api.CodeIntegrity, "root issuance changed its selected grant identity")
		}
		found = true
	}
	if err := rows.Err(); err != nil {
		return empty, err
	}
	if !found {
		return empty, fault(api.CodeNotFound, "selected root issuance is not visible")
	}
	return result, nil
}
