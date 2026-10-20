//go:build linux

package store

import (
	"bytes"
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Explicit component intake gives the new human a genuinely owned object.
// The private blob control proves that only the public enrollment/session
// gate can refuse these exact bytes; a foreign ACL cannot hide its removal.
func inviteOwnRead(t *testing.T, s *Service, reader api.Scope) (api.BlobReadRequest, []byte) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	raw := []byte("private human object " + string(testID(t)))
	object := api.ObjectWrite{ObjectKey: testID(t), Class: "artifact", Bytes: raw, SHA256: testDigest(raw), Origin: "service",
		ACL: api.ObjectACL{Config: s.deps.Config, Owner: reader.Actor, Audience: "owner", Generation: 1}}
	if _, err := s.retain(ctx, tx, api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}}, object, testID(t), archStamp()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	read := api.BlobReadRequest{ObjectID: object.ObjectKey, Limit: len(raw)}
	s.mu.RLock()
	control, err := s.blob(ctx, reader, s.db, read)
	s.mu.RUnlock()
	if err != nil || !bytes.Equal(control.Data, raw) {
		t.Fatal("owned object failed its actual ACL and byte control", err)
	}
	return read, raw
}
