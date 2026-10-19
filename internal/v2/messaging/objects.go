package messaging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"laneboss.io/laneboss/internal/credentialtext"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/objectread"
)

func (s *Service) objectMetadata(ctx context.Context, scope api.Scope, ref api.BlobRef) error {
	metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != ref || metadata.ACL.Config != scope.Config || metadata.ACL.Generation == 0 || metadata.Origin == "" || !validID(metadata.SourceOperationID) || !validTimestamp(metadata.CommittedAt) {
		return problem(api.CodeIntegrity, "mail reference differs from committed object metadata")
	}
	return nil
}

// Artifacts stay immutable references. Read bounded chunks to verify the real
// bytes before creating a recipient's access through the mail transaction.
func (s *Service) artifact(ctx context.Context, scope api.Scope, ref api.BlobRef) (resultErr error) {
	scope, release, err := objectread.Bind(ctx, s.deps.Store, scope)
	if err != nil {
		return err
	}
	defer release(&resultErr)
	if err := s.objectMetadata(ctx, scope, ref); err != nil {
		return err
	}
	hash := sha256.New()
	data := make([]byte, 0, int(ref.Bytes))
	for offset := int64(0); offset < ref.Bytes; {
		if err := ctx.Err(); err != nil {
			return cancelled(err)
		}
		limit := int(min(int64(api.MaxChunkBytes), ref.Bytes-offset))
		chunk, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: offset, Limit: limit})
		if err != nil {
			return err
		}
		if chunk.ObjectID != ref.ID || chunk.Offset != offset || len(chunk.Data) != limit || hashBytes(chunk.Data) != chunk.SHA256 {
			return problem(api.CodeIntegrity, "artifact chunk differs from its retained identity")
		}
		_, _ = hash.Write(chunk.Data) // hash.Hash.Write cannot fail
		data = append(data, chunk.Data...)
		offset += int64(len(chunk.Data))
	}
	tail, err := s.deps.Store.Blob(ctx, scope, api.BlobReadRequest{ObjectID: ref.ID, Offset: ref.Bytes, Limit: 1})
	if err != nil {
		return err
	}
	if api.Digest(hex.EncodeToString(hash.Sum(nil))) != ref.SHA256 || tail.ObjectID != ref.ID || tail.Offset != ref.Bytes || len(tail.Data) != 0 || tail.SHA256 != hashBytes(tail.Data) {
		return problem(api.CodeIntegrity, "artifact length or hash differs from its committed bytes")
	}
	if credentialtext.HasCredential(string(data)) {
		return problem(api.CodeInvalid, "artifact contains a credential-shaped value; nothing was queued")
	}
	return nil
}
