package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) listProjection(ctx context.Context, scope api.Scope, kind string, request api.ListRequest) ([][]byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, "", err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return nil, "", err
	}
	if request.Limit < 1 || request.Limit > 200 {
		return nil, "", wire.Invalid("invalid projection page limit")
	}
	db, err := s.reader(scope)
	if err != nil {
		return nil, "", err
	}
	filter := struct {
		Kind    string
		Request api.ListRequest
	}{kind, request}
	filter.Request.Cursor = ""
	current, err := s.cursor(scope, filter, request.Cursor)
	if err != nil {
		return nil, "", err
	}
	if request.Cursor == "" {
		if err := db.QueryRowContext(ctx, "SELECT coalesce(max(rowid),0) FROM projections WHERE kind=?", kind).Scan(&current.Snapshot); err != nil {
			return nil, "", err
		}
	}
	query := `SELECT rowid,data FROM projections WHERE kind=? AND rowid>? AND rowid<=?`
	args := []any{kind, current.Position, current.Snapshot}
	if kind == "lane" {
		query += ` AND (?='' OR json_extract(data,'$.life_id')=?) AND (? OR json_extract(data,'$.life_id')=? OR EXISTS(SELECT 1 FROM json_each(projections.data,'$.starter_chain') WHERE value=?))`
		args = append(args, string(request.LifeID), string(request.LifeID), administrative(scope), string(scope.Actor.LifeID), string(scope.Actor.LifeID))
	} else if kind == "mail" {
		query += ` AND (?='' OR json_extract(data,'$.recipient_life_id')=? OR json_extract(data,'$.sender.life_id')=?) AND (? OR json_extract(data,'$.recipient_life_id')=? OR json_extract(data,'$.sender.life_id')=?)`
		args = append(args, string(request.LifeID), string(request.LifeID), string(request.LifeID), administrative(scope), string(scope.Actor.LifeID), string(scope.Actor.LifeID))
	} else {
		return nil, "", wire.Invalid("unsupported projection list")
	}
	query += " ORDER BY rowid LIMIT ?"
	args = append(args, request.Limit+1)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	result := make([][]byte, 0, request.Limit)
	bytes := 0
	for rows.Next() {
		var position uint64
		var data []byte
		if err := rows.Scan(&position, &data); err != nil {
			return nil, "", err
		}
		if len(result) == request.Limit || bytes+len(data) > api.MaxFrameBytes/2 {
			if len(result) == 0 {
				return nil, "", fault(api.CodeUnsupported, "projection exceeds bounded page capacity")
			}
			next, err := s.signCursor(current)
			return result, next, err
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return nil, "", err
		}
		current.Position = position
		result = append(result, data)
		bytes += len(data)
	}
	return result, "", rows.Err()
}
